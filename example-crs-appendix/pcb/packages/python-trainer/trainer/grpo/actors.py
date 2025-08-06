from __future__ import annotations

import copy
import functools
from contextlib import contextmanager
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Optional,
    Union,
    cast,
    override,
)

import torch
from accelerate.utils import (  # pyright: ignore[reportMissingTypeStubs]
    gather,  # pyright: ignore[reportUnknownVariableType]
)
from p4_core.environment.protocols import BaseTrainableEnvironmentWithChat
from p4_core.policy.models import BaseMessage, Completion
from torch import Tensor
from transformers import (
    PreTrainedTokenizerBase,  # pyright: ignore[reportPrivateImportUsage,reportMissingTypeStubs]
    TrainerCallback,  # pyright: ignore[reportPrivateImportUsage]
)
from trl import GRPOConfig, GRPOTrainer  # pyright: ignore[reportMissingTypeStubs]
from trl.trainer import grpo_trainer  # pyright: ignore[reportMissingTypeStubs]
from trl.trainer.grpo_trainer import (  # pyright: ignore[reportMissingTypeStubs]
    nanmax,
    nanmin,
    nanstd,
)

from ..policy.protocols import HuggingFaceParameterizedChatPolicy

if TYPE_CHECKING:
    import optuna  # pyright: ignore[reportMissingImports]

Immediate = tuple[
    list[BaseMessage],  # Prompt
    torch.Tensor,  # Prompt IDs
    torch.Tensor,  # Prompt Mask
    BaseMessage,  # Completion
    torch.Tensor,  # Completion IDs
    torch.Tensor,  # Completion Mask
]


class GrpoTrainer[Observation, Action, Context](GRPOTrainer):
    args: GRPOConfig

    def __init__(
        self,
        policy: HuggingFaceParameterizedChatPolicy[Observation, Action],
        environment: BaseTrainableEnvironmentWithChat[Observation, Action, Context],
        contexts_builder: Callable[
            [list[dict[str, Any]], GrpoTrainer[Observation, Action, Context]],
            list[Context],
        ],
        args: GRPOConfig,
        reward_processing_classes: Optional[
            Union[PreTrainedTokenizerBase, list[PreTrainedTokenizerBase]]
        ] = None,
        callbacks: Optional[list[TrainerCallback]] = None,
        on_rewards_computed: Callable[
            [
                list[tuple[Context, str, float]],
                GrpoTrainer[Observation, Action, Context],
            ],
            None,
        ]
        | None = None,
    ):
        assert args.gradient_accumulation_steps == 1
        assert args.output_dir is not None

        args.reward_weights = []
        args.log_completions = False

        super().__init__(  # pyright: ignore[reportUnknownMemberType]
            model=policy.model,  # pyright: ignore[reportArgumentType]
            processing_class=policy.processing_class,
            reward_funcs=[],
            args=args,
            reward_processing_classes=reward_processing_classes,
            callbacks=callbacks,
        )

        self._policy = policy
        self._environment = environment
        self.contexts_builder = contexts_builder
        self._last_reward: float = 0.0
        self._on_rewards_computed = on_rewards_computed

    @override
    def train(
        self,
        resume_from_checkpoint: Optional[Union[str, bool]] = None,
        trial: Union["optuna.Trial", dict[str, Any], None] = None,  # type: ignore
        ignore_keys_for_eval: Optional[list[str]] = None,
        **kwargs: Any,
    ):
        self._last_reward = 0.0
        super().train(  # pyright: ignore[reportUnknownMemberType]
            resume_from_checkpoint=resume_from_checkpoint,
            trial=trial,
            ignore_keys_for_eval=ignore_keys_for_eval,
            **kwargs,
        )

    @override
    def _generate_and_score_completions(  # pyright: ignore[reportUnknownParameterType]
        self, inputs: list[dict[str, Tensor | Any]]
    ) -> dict[str, Tensor | None]:
        assert self.args.output_dir is not None

        contexts = self.contexts_builder(inputs, self)

        observations = [self._environment.reset(context) for context in contexts]
        previous_observations = copy.deepcopy(observations)
        done = False

        total_completions_ids: torch.Tensor = torch.tensor(
            [], dtype=torch.long, device=self.accelerator.device
        )
        total_completions_mask: torch.Tensor = torch.tensor(
            [], dtype=torch.long, device=self.accelerator.device
        )
        rewards_by_experiment_by_episode: list[list[list[float | None]]] = [
            [] for _ in range(len(inputs))
        ]

        history_by_episode: list[list[BaseMessage]] = [[] for _ in range(len(inputs))]

        while not done:
            prompts = [
                self._policy.prompt_from_observation(observation, previous_observation)
                for observation, previous_observation in zip(
                    observations, previous_observations
                )
            ]
            for i, prompt in enumerate(prompts):
                history_by_episode[i].extend(prompt)

            inputs = [{"prompt": list(prompt), "_": 1337} for prompt in prompts]

            with self._patched_prepare_inputs_for_per_device(inputs):
                with self._truncated_vllm_prompts():
                    prepared = super()._generate_and_score_completions(inputs)  # pyright: ignore[reportArgumentType]

            _: torch.Tensor = prepared["prompt_ids"]
            _: torch.Tensor = prepared["prompt_mask"]
            completions_ids: torch.Tensor = prepared["completion_ids"]
            completions_mask: torch.Tensor = prepared["completion_mask"]

            completions_text: list[str] = self._policy.processing_class.batch_decode(  # pyright: ignore[reportUnknownMemberType]
                completions_ids,
                skip_special_tokens=True,
            )

            completions: list[Completion] = [
                {
                    "role": "assistant",
                    "content": completion,
                }
                for completion in completions_text
            ]

            for i, completion in enumerate(completions):
                history_by_episode[i].extend([completion])

            inputs = [
                {**input, "completion": [completion]}
                for input, completion in zip(inputs, completions)
            ]

            actions = [
                self._policy.action_from_completion(
                    completion=completion, prompt=prompt
                )
                for completion, prompt in zip(completions, prompts)
            ]

            (
                next_observations,
                rewards_by_experiment_of_episode,
                terminateds,
                truncateds,
            ) = cast(
                tuple[
                    list[Observation],
                    list[list[float | None]],
                    list[bool],
                    list[bool],
                ],
                zip(
                    *self._environment.batch(
                        actions=actions,
                        observations=observations,
                        contexts=contexts,
                        prompts=prompts,
                        completions=completions,
                    )
                ),
            )

            for episode_index, rewards in enumerate(rewards_by_experiment_of_episode):
                rewards_by_experiment_by_episode[episode_index].append(rewards)

            done = any(terminateds) or any(truncateds)
            previous_observations = observations
            observations = next_observations

            total_completions_ids = torch.cat(
                (total_completions_ids, completions_ids), dim=1
            )
            total_completions_mask = torch.cat(
                (total_completions_mask, completions_mask), dim=1
            )

        for index, history in enumerate(history_by_episode):
            context = cast(dict[str, Any], contexts[index])

            if "logging_directory" in context and isinstance(
                context["logging_directory"], Path
            ):
                (context["logging_directory"] / "history.md").write_text(
                    "\n\n".join(
                        [
                            f"# {message['role'].capitalize()}\n\n{message['content']}"
                            for message in history
                        ]
                    ),
                    encoding="utf-8",
                )

        rewards_by_episode = [
            [
                sum([reward for reward in rewards_by_function if reward is not None])
                / len([reward for reward in rewards_by_function if reward is not None])
                if not all(reward is None for reward in rewards_by_function)
                else 0.0
                for rewards_by_function in zip(*rewards_by_experiment)
            ]
            for rewards_by_experiment in rewards_by_experiment_by_episode
        ]

        rewards_per_function = torch.tensor(
            rewards_by_episode, device=self.accelerator.device
        )

        rewards_per_function = cast(torch.Tensor, gather(rewards_per_function))

        reward_weights = torch.tensor(
            self._environment.reward_weights,
            device=self.accelerator.device,
        )

        rewards = (rewards_per_function * reward_weights.unsqueeze(0)).sum(dim=1)

        assert isinstance(self.num_generations, int)

        mean_grouped_rewards = rewards.view(-1, self.num_generations).mean(dim=1)
        std_grouped_rewards = rewards.view(-1, self.num_generations).std(dim=1)

        mean_grouped_rewards = mean_grouped_rewards.repeat_interleave(
            self.num_generations, dim=0
        )
        std_grouped_rewards = std_grouped_rewards.repeat_interleave(
            self.num_generations, dim=0
        )
        advantages = (rewards - mean_grouped_rewards) / (std_grouped_rewards + 1e-4)

        process_slice = slice(
            self.accelerator.process_index * len(rewards_by_episode),
            (self.accelerator.process_index + 1) * len(rewards_by_episode),
        )
        advantages = advantages[process_slice]

        reward_functions_name = [f.__name__ for f in self._environment.reward_functions]

        _rewards: list[tuple[Context, str, float]] = []

        for i, reward_function_name in enumerate(reward_functions_name):
            mean_of_rewards = torch.nanmean(rewards_per_function[:, i]).item()
            self._metrics["train"][f"_/rewards/{reward_function_name}/mean"].append(  # pyright: ignore[reportUnknownMemberType]
                mean_of_rewards
            )
            std_of_rewards = nanstd(rewards_per_function[:, i]).item()
            self._metrics["train"][f"_/rewards/{reward_function_name}/std"].append(  # pyright: ignore[reportUnknownMemberType]
                std_of_rewards
            )
            max_of_rewards = nanmax(rewards_per_function[:, i]).item()
            self._metrics["train"][f"_/rewards/{reward_function_name}/max"].append(  # pyright: ignore[reportUnknownMemberType]
                max_of_rewards
            )
            min_of_rewards = nanmin(rewards_per_function[:, i]).item()
            self._metrics["train"][f"_/rewards/{reward_function_name}/min"].append(  # pyright: ignore[reportUnknownMemberType]
                min_of_rewards
            )

            for reward, context in zip(
                cast(list[float], rewards_per_function[:, i].tolist()),  # pyright: ignore[reportUnknownMemberType]
                contexts * self.num_generations,
            ):
                _rewards.append((context, reward_function_name, reward))

            # FIXME: Hardcoded saving condition
            if (
                reward_function_name == "compilable"
                and mean_of_rewards > self._last_reward
            ):
                self._last_reward = mean_of_rewards
                if self.accelerator.is_main_process:
                    self.save_model(
                        f"{self.args.output_dir}/saved-{self.state.global_step}-mean-of-compilable-rewards-{mean_of_rewards:.4f}",
                    )

            # FIXME: Hardcoded stopping condition
            if (
                self.state.global_step > 16
                and reward_function_name == "compilable"
                and max_of_rewards >= 1.0
            ):
                if self.accelerator.is_main_process:
                    self.save_model(
                        f"{self.args.output_dir}/saved-{self.state.global_step}-max-of-compilable-rewards-{max_of_rewards:.4f}",
                    )

                self.control.should_training_stop = True  # pyright: ignore[reportUnknownMemberType]

        reward = mean_grouped_rewards.mean().item()
        self._metrics["train"]["_/reward"].append(reward)  # pyright: ignore[reportUnknownMemberType]
        self._metrics["train"]["_/reward_std"].append(std_grouped_rewards.mean().item())  # pyright: ignore[reportUnknownMemberType]

        if self._on_rewards_computed is not None:
            self._on_rewards_computed(_rewards, self)

        # FIXME: Hardcoded stopping condition
        if reward > 0.8:
            if self.accelerator.is_main_process:
                self.save_model(
                    f"{self.args.output_dir}/saved-{self.state.global_step}-reward-{reward:.4f}",
                )

            self.control.should_training_stop = True  # pyright: ignore[reportUnknownMemberType]

        assert isinstance(
            self._policy.processing_class.pad_token_id,  # pyright: ignore[reportUnknownMemberType]
            int,
        )
        assert isinstance(
            self.args.max_prompt_length,
            int,
        )
        assert isinstance(
            self.args.max_completion_length,
            int,
        )

        return {
            "prompt_ids": torch.tensor(
                [[self._policy.processing_class.pad_token_id] for _ in inputs],
                dtype=torch.long,
                device=self.accelerator.device,
            ),
            "prompt_mask": torch.tensor(
                [[self._policy.processing_class.pad_token_id] for _ in inputs],
                dtype=torch.long,
                device=self.accelerator.device,
            ),
            "completion_ids": total_completions_ids,
            "completion_mask": total_completions_mask,
            "old_per_token_logps": None,
            "advantages": advantages,
        }

    @contextmanager
    def _patched_prepare_inputs_for_per_device(self, inputs: list[dict[str, Any]]):
        with _gather_disabled():
            with self._prepare_per_device(inputs):
                yield

    @contextmanager
    def _prepare_per_device(self, inputs: list[dict[str, Any]]):
        original_num_generations = self.num_generations
        self.num_generations = len(inputs)
        try:
            yield
        finally:
            self.num_generations = original_num_generations

    @contextmanager
    def _truncated_vllm_prompts(self):
        if self.args.use_vllm:
            original_vllm_generate = self.llm.generate  # type: ignore

            @functools.wraps(original_vllm_generate)  # type: ignore
            def generate(
                prompts: list[str],
                *args: Any,
                **kwargs: Any,
            ):
                prompts_ids = self._policy.processing_class(
                    prompts,
                )

                truncated_prompts_ids = [  # type: ignore
                    prompt_ids[-self.max_prompt_length :]  # type: ignore
                    for prompt_ids in prompts_ids["input_ids"]  # type: ignore
                ]

                prompts = self._policy.processing_class.batch_decode(  # type: ignore
                    truncated_prompts_ids,
                    skip_special_tokens=False,
                )

                return original_vllm_generate(
                    prompts=prompts,
                    *args,
                    **kwargs,
                )

            self.llm.generate = generate  # type: ignore

            try:
                yield
            finally:
                self.llm.generate = original_vllm_generate
        else:
            yield


@contextmanager
def _gather_disabled():
    original_gather = grpo_trainer.gather  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    grpo_trainer.gather = lambda x: x  # pyright: ignore[reportUnknownLambdaType]
    try:
        yield
    finally:
        grpo_trainer.gather = original_gather
