import logging
import random
import re
from datetime import datetime
from itertools import groupby
from pathlib import Path
from typing import Any

import click
from datasets import disable_caching  # pyright: ignore[reportMissingTypeStubs]
from joblib import Memory
from liger_kernel.transformers import (  # pyright: ignore[reportMissingTypeStubs]
    AutoLigerKernelForCausalLM,
)
from llm.api.actors import LlmApiManager
from oss_fuzz.project.models import ProjectCollection
from oss_fuzz.sandbox.actors import Sandbox, SandboxManager
from oss_fuzz.sandbox.contexts import SandboxContext
from oss_fuzz_vulnerability.vulnerability.models import (
    Vulnerability,
    VulnerabilityCollection,
)
from p4 import (
    AIxCCEnvironment,
    BaseEraserPolicy,
    BaseTool,
    CppCallPattern,
    CppFunctionDefinitionTool,
    CppTypeDefinitionTool,
    CppTypeIdentifierPattern,
    Document,
    JavaInvocationPattern,
    JavaMethodDeclarationTool,
    JazzerFunctionSignaturePattern,
    SanitizerFunctionSignaturePattern,
    Symbol,
    generate_patch_using_langchain,
)
from p4_core.pattern.protocols import BasePattern
from p4_core.policy.models import Completion, Prompt
from peft import LoraConfig, get_peft_model
from trainer.curriculum.actors import CurriculumTrainer
from trainer.grpo.actors import GrpoTrainer
from trainer.policy.protocols import HuggingFaceParameterizedChatPolicy
from trainer.scheduler.protocols import BaseScheduler
from transformers import (
    AutoTokenizer,
    GenerationMixin,  # pyright: ignore[reportMissingTypeStubs,reportPrivateImportUsage]
    PreTrainedTokenizer,  # pyright: ignore[reportPrivateImportUsage]
)
from trl import GRPOConfig  # pyright: ignore[reportMissingTypeStubs]

import wandb

disable_caching()
_memory = Memory(".cache", verbose=0)


class _EraserPolicy(
    BaseEraserPolicy, HuggingFaceParameterizedChatPolicy[set[Document], set[Symbol]]
):
    def __init__(
        self,
        model: GenerationMixin,
        processing_class: PreTrainedTokenizer,
        patterns: list[BasePattern],
    ):
        super().__init__(patterns)
        self.model = model
        self.processing_class = processing_class

    def completions_from_prompts(self, prompts: list[Prompt]) -> list[Completion]:
        raise NotImplementedError("Unreachable")


class _VulnerabilityScheduler(BaseScheduler):
    def __init__(self, projects_directory: Path, shuffle: bool):
        self._projects_directory = projects_directory
        self._shuffle = shuffle

    def schedule(self):
        projects = ProjectCollection.from_projects_directory(self._projects_directory)
        vulnerabilities = [
            vulnerability
            for project in projects
            for vulnerability in VulnerabilityCollection.from_project(project)
        ]

        if self._shuffle:
            random.shuffle(vulnerabilities)

        for vulnerability in vulnerabilities:
            yield vulnerability.model_dump()


@click.command()
@click.option("--model-name", default="meta-llama/Llama-3.2-3B-Instruct", type=str)
@click.option(
    "--max-prompt-length",
    default=8192,
    type=int,
    help="Maximum prompt length for the model.",
)
@click.option(
    "--max-seq-length",
    default=8192 + 2048,
    type=int,
)
@click.option("--lora-rank", default=32, type=int, help="Rank for LoRA layers.")
@click.option("--lora-alpha", default=32, type=int, help="Alpha for LoRA layers.")
@click.option(
    "--projects-directory",
    default=(Path(__file__).parent.parent / "projects"),
    type=click.Path(
        exists=True, dir_okay=True, file_okay=False, resolve_path=True, path_type=Path
    ),
)
@click.option(
    "--learning-rate",
    default=5e-6,
    type=float,
    help="Learning rate for the model.",
)
@click.option(
    "--per-device-train-batch-size",
    default=2,
    type=int,
    help="Batch size per device for training.",
)
@click.option(
    "--gradient-accumulation-steps",
    default=1,
    type=int,
    help="Number of gradient accumulation steps.",
)
@click.option(
    "--num-generations",
    default=12,
    type=int,
    help="Number of generations for the model.",
)
@click.option(
    "--save-steps",
    default=32,
    type=int,
    help="Number of steps to save the model.",
)
@click.option(
    "--output-dir",
    default=Path(__file__).parent.parent / "model-eraser",
    type=click.Path(
        exists=False, dir_okay=True, file_okay=False, resolve_path=True, path_type=Path
    ),
    help="Directory to save the model outputs.",
)
@click.option(
    "--epochs",
    default=128,
    type=int,
    help="Number of epochs for training.",
)
@click.option(
    "--teacher-model",
    default="gpt-4.1",
    type=str,
    help="Name of the teacher model to use for training.",
)
@click.option(
    "--episode-length",
    default=4,
    type=int,
)
@click.option(
    "--cache-directory",
    default=Path(__file__).parent.parent / ".cache",
    type=click.Path(
        exists=True, dir_okay=True, file_okay=False, resolve_path=True, path_type=Path
    ),
    help="Directory to cache the model.",
)
@click.option(
    "--logging-level",
    default=logging.INFO,
    type=int,
    help="Logging level for the model.",
)
def main(
    model_name: str,
    max_prompt_length: int,
    max_seq_length: int,
    lora_rank: int,
    lora_alpha: int,
    projects_directory: Path,
    learning_rate: float,
    per_device_train_batch_size: int,
    gradient_accumulation_steps: int,
    num_generations: int,
    save_steps: int,
    output_dir: Path,
    epochs: int,
    teacher_model: str,
    episode_length: int,
    cache_directory: Path,
    logging_level: int = logging.WARNING,
):
    logging.getLogger().setLevel(logging_level)
    output_dir = output_dir / datetime.now().strftime("%Y-%m-%d-%H:%M")

    sandbox_manager = SandboxManager(
        cache_directory=cache_directory,
    )

    def scope_builder(context: SandboxContext):
        return sandbox_manager.scope(**context)

    jazzer_function_signature_pattern = JazzerFunctionSignaturePattern(limit=32)
    sanitizer_function_signature_pattern = SanitizerFunctionSignaturePattern(limit=16)

    tools: list[BaseTool] = [
        CppFunctionDefinitionTool(),
        CppTypeDefinitionTool(),
        JavaMethodDeclarationTool(),
    ]

    tokenizer = AutoTokenizer.from_pretrained(  # type: ignore
        model_name,
    )

    if tokenizer.pad_token is None:  # type: ignore
        tokenizer.pad_token = tokenizer.eos_token  # type: ignore

    model = AutoLigerKernelForCausalLM.from_pretrained(model_name)  # type: ignore

    peft_config = LoraConfig(
        r=lora_rank,
        lora_alpha=lora_alpha,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
        task_type="CAUSAL_LM",
        lora_dropout=0.1,
        bias="none",
    )

    model = get_peft_model(model, peft_config, adapter_name="primary")  # pyright: ignore[reportUnknownArgumentType]

    primary_trainer = GrpoTrainer(
        policy=_EraserPolicy(
            model=model,  # pyright: ignore[reportArgumentType]
            processing_class=tokenizer,  # pyright: ignore[reportUnknownArgumentType]
            patterns=[
                CppCallPattern(limit=None),
                CppTypeIdentifierPattern(limit=None),
                JavaInvocationPattern(limit=None),
                jazzer_function_signature_pattern,
                sanitizer_function_signature_pattern,
            ],
        ),
        environment=AIxCCEnvironment(
            tools=tools,
            episode_length=episode_length,
            scope_builder=scope_builder,
        ).as_trainable_with_chat(
            immediate_reward_functions=[_use_soft_format_reward()],
            immediate_reward_weights=[0.5],
            final_reward_functions=[
                _use_compilable_reward(
                    sandbox_manager=sandbox_manager,
                    llm_api_manager=LlmApiManager.from_dotenv(
                        model=teacher_model,
                    ),
                )
            ],
            final_reward_weights=[0.5],
        ),
        contexts_builder=_contexts_builder,
        on_rewards_computed=_on_rewards_computed,
        args=GRPOConfig(
            temperature=1.0,
            learning_rate=learning_rate,
            adam_beta1=0.9,
            adam_beta2=0.99,
            weight_decay=0.1,
            warmup_ratio=0.1,
            lr_scheduler_type="constant",
            optim="adamw_torch_fused",
            logging_steps=1,
            per_device_train_batch_size=per_device_train_batch_size,
            gradient_accumulation_steps=gradient_accumulation_steps,
            num_generations=num_generations,
            max_prompt_length=max_prompt_length,
            max_completion_length=max_seq_length - max_prompt_length,
            save_steps=save_steps,
            max_grad_norm=0.1,
            report_to="wandb",
            output_dir=str(output_dir),
            log_completions=True,
            num_train_epochs=1,
            gradient_checkpointing=True,
            use_vllm=True,
            vllm_mode="colocate",
            vllm_gpu_memory_utilization=0.6,
            use_liger_loss=True,
            ddp_find_unused_parameters=False,  # https://discuss.huggingface.co/t/training-llama-with-lora-on-multiple-gpus-may-exist-bug/47005/2
            shuffle_dataset=False,
        ),
    )

    scheduler = _VulnerabilityScheduler(
        projects_directory=projects_directory,
        shuffle=True,
    )

    for data in scheduler.as_dataset():
        if not isinstance(data, dict):
            raise ValueError(f"Expected a dictionary, got {type(data)}: {data}")
        vulnerability = Vulnerability.model_validate(data)
        print(vulnerability.as_sandbox_context)

    def steps(index: int) -> int:
        return 64

    def set_primary_trainable(_: int):
        model.set_adapter("primary")  # pyright: ignore[reportUnknownMemberType]

    trainer = CurriculumTrainer(
        primary_trainer=primary_trainer,
        scheduler=scheduler,
        steps=steps,
        epochs=epochs,
        on_primary_training_start=set_primary_trainable,
    )

    if primary_trainer.is_world_process_zero():
        wandb.init(
            project="p2",
            tags=[
                "curriculum",
                "round-3-5",
                model_name.replace("/", "-")[:64],
            ],
        )

    trainer.train()

    trainer.save_model(str(output_dir))


def _on_rewards_computed(
    rewards: list[tuple[SandboxContext, str, float]],
    trainer: GrpoTrainer[set[Document], set[Symbol], SandboxContext],
):
    for function_name, rewards_by_function_name in groupby(
        sorted(rewards, key=lambda x: x[1]),
        key=lambda x: x[1],
    ):
        rewards_by_function_name = list(rewards_by_function_name)

        for (project_name, version), rewards_by_identifier in groupby(
            sorted(
                rewards_by_function_name,
                key=lambda x: (x[0]["project_name"], x[0]["version"]),
            ),
            key=lambda x: (x[0]["project_name"], x[0]["version"]),
        ):
            rewards_by_identifier = list(rewards_by_identifier)
            identifier = f"{project_name}/{version}"
            reward_values = [reward for _, _, reward in rewards_by_identifier]

            if len(reward_values) == 0:
                continue

            min_of_rewards = min(reward_values)
            max_of_rewards = max(reward_values)
            mean_of_rewards = sum(reward_values) / len(reward_values)

            trainer._metrics["train"][  # pyright: ignore[reportPrivateUsage,reportUnknownMemberType]
                f"_/rewards/{function_name}/{identifier}/min"
            ].append(min_of_rewards)
            trainer._metrics["train"][  # pyright: ignore[reportPrivateUsage,reportUnknownMemberType]
                f"_/rewards/{function_name}/{identifier}/max"
            ].append(max_of_rewards)
            trainer._metrics["train"][  # pyright: ignore[reportPrivateUsage,reportUnknownMemberType]
                f"_/rewards/{function_name}/{identifier}/mean"
            ].append(mean_of_rewards)


def _contexts_builder(
    inputs: list[dict[str, Any]],
    trainer: GrpoTrainer[set[Document], set[Symbol], SandboxContext],
) -> list[SandboxContext]:
    assert trainer.args.output_dir is not None, (
        "Output directory must be set in the trainer."
    )
    contexts: list[SandboxContext] = []
    for index, input in enumerate(inputs):
        detection = Vulnerability.model_validate(input)
        logging_directory = (
            Path(trainer.args.output_dir)
            / "logs"
            / f"step-{trainer.state.global_step}"
            / f"{index}-on-{trainer.accelerator.process_index}"
        )
        logging_directory.mkdir(parents=True, exist_ok=True)
        contexts.append(
            {
                **detection.as_sandbox_context,
                "logging_directory": logging_directory,
            }
        )
    return contexts


def _use_compilable_reward(
    llm_api_manager: LlmApiManager,
    sandbox_manager: SandboxManager,
):
    def compilable(
        observation: set[Document],
        action: set[Symbol],
        context: SandboxContext,
        prompt: Prompt,
        completion: Completion,
    ):
        if "logging_directory" in context:
            (context["logging_directory"] / "observation.md").write_text(
                "\n\n".join(document.as_markdown() for document in observation),
            )
            (context["logging_directory"] / "vulnerability-identifier").write_text(
                f"{context['project_name']}/{context['version']}",
            )

        with sandbox_manager.use(**context) as sandbox:
            try:
                relative_patches, diff = generate_patch_using_langchain(
                    documents=observation,
                    source_directory=sandbox.scope["source_directory"],
                    chat_model=llm_api_manager.langchain_chat_model(),
                )
            except Exception as error:
                logging.exception(error)
                logging.info(
                    "[use_compilable_reward] Failed to generate patch, returning 0.0"
                )
                return 0.0

            if diff is None or len(diff.strip()) == 0:
                logging.info("[use_compilable_reward] No changes made, returning 0.0")
                return 0.0

            if "logging_directory" in context:
                (context["logging_directory"] / "diff.patch").write_text(diff)

            reward, (stdout, stderr), output = _cached_build_and_reproduce_score(
                relative_patches=relative_patches,
                sandbox=sandbox,
                diff=diff,
            )

            if "logging_directory" in context:
                (context["logging_directory"] / "compilation.out").write_text(stdout)
                (context["logging_directory"] / "compilation.err").write_text(stderr)
                if output is not None:
                    (context["logging_directory"] / "reproduce.out").write_text(output)

            return reward

    return compilable


@_memory.cache(
    ignore=["relative_patches", "sandbox"],
)
def _cached_build_and_reproduce_score(
    relative_patches: dict[Path, str],
    sandbox: Sandbox,
    diff: str,
) -> tuple[float, tuple[str, str], str | None]:
    for relative_path, after in relative_patches.items():
        (sandbox.scope["source_directory"] / relative_path).write_text(after)

    exit_code, stdout, stderr = sandbox.build()

    if exit_code != 0:
        logging.info("[use_compilable_reward] Compilation failed, returning 0.0625")
        return 0.0625, (stdout, stderr), None

    exit_code, output = sandbox.reproduce()

    if exit_code != 0:
        logging.info("[use_compilable_reward] Vulnerability detected, returning 0.125")
        return 0.125, (stdout, stderr), output

    logging.info("[use_compilable_reward] No vulnerability detected, returning 1.0")
    return 1.0, (stdout, stderr), output


def _use_soft_format_reward():
    def soft_format(
        observation: set[Document],
        action: set[Symbol],
        context: SandboxContext,
        prompt: Prompt,
        completion: Completion,
    ) -> float:
        completion_content = completion["content"]

        if (
            re.match(
                r"^## Reasoning(.|\n)*## Relevant Symbols\n*(\n(\d+\.|\*|-) `\w+`)+$",
                completion_content,
            )
            is not None
        ):
            return 1.0
        elif (
            re.match(
                r"^## Reasoning(.|\n)*## Relevant Symbols\n*(\n(\d+\.|\*|-) `\w+`.*)+$",
                completion_content,
            )
            is not None
        ):
            return 0.8
        elif re.match(
            r"## Reasoning(.|\n)*## Relevant Symbols\n*(\n(\d+\.|\*|-) `\w+`.*)+",
            completion_content,
        ):
            return 0.6
        elif re.match(
            r"^## Reasoning(.|\n)*## Relevant Symbols",
            completion_content,
        ):
            return 0.4
        elif re.match(
            r"## Reasoning(.|\n)*## Relevant Symbols",
            completion_content,
        ):
            return 0.2
        else:
            return 0.0

    return soft_format


if __name__ == "__main__":
    main()
