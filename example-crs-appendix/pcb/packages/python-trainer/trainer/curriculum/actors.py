from typing import Any, Callable, cast

import torch
from datasets import Dataset  # pyright: ignore[reportMissingTypeStubs]
from transformers.trainer import Trainer

from ..scheduler.protocols import BaseScheduler


class CurriculumTrainer:
    def __init__(
        self,
        primary_trainer: Trainer,
        epochs: int,
        scheduler: BaseScheduler,
        steps: Callable[[int], int],
        adaptation_dataset_builder: Callable[[dict[str, Any]], tuple[Dataset, Dataset]]
        | None = None,
        adaptation: bool = False,
        adaptation_trainer: Trainer | None = None,
        on_adaptation_start: Callable[[int], None] | None = None,
        on_primary_training_start: Callable[[int], None] | None = None,
    ):
        if adaptation and adaptation_trainer is None:
            raise ValueError(
                "If adaptation is True, an adaptation trainer must be provided."
            )
        if adaptation and adaptation_dataset_builder is None:
            raise ValueError(
                "If adaptation is True, an adaptation dataset builder must be provided."
            )

        if (
            adaptation_trainer is not None
            and adaptation_trainer.model != primary_trainer.model  # pyright: ignore[reportUnknownMemberType]
        ):
            raise ValueError(
                "The adaptation trainer and main trainer must use the same model."
            )

        self._adaptation_trainer = adaptation_trainer
        self._main_trainer = primary_trainer
        self._scheduler = scheduler
        self._epochs = epochs
        self._steps = steps
        self._adaptation_dataset_builder = adaptation_dataset_builder
        self._adaptation = adaptation
        self._on_adaptation_start = on_adaptation_start
        self._on_primary_training_start = on_primary_training_start

    def train(self):
        original_output_dir = self._main_trainer.args.output_dir

        for epoch in range(self._epochs):
            for index, data in enumerate(self._scheduler.as_dataset()):  # pyright: ignore[reportUnknownVariableType]
                data = cast(dict[str, Any], data)

                if self._adaptation:
                    assert self._adaptation_dataset_builder is not None
                    assert self._adaptation_trainer is not None

                    adaptation_train_dataset, adaptation_evaluation_dataset = (
                        self._adaptation_dataset_builder(data)
                    )
                    self._adaptation_trainer.train_dataset = adaptation_train_dataset
                    self._adaptation_trainer.eval_dataset = (
                        adaptation_evaluation_dataset
                    )

                    if self._on_adaptation_start is not None:
                        self._on_adaptation_start(index)

                    self._adaptation_trainer.train()  # pyright: ignore[reportUnknownMemberType]

                    torch.cuda.empty_cache()

                dataset = Dataset.from_list([data for _ in range(self._steps(index))])  # pyright: ignore[reportUnknownMemberType]

                if original_output_dir is not None:
                    self._main_trainer.args.output_dir = (
                        f"{original_output_dir}/epoch-{epoch}/{index}"
                    )

                self._main_trainer.train_dataset = dataset

                if self._on_primary_training_start is not None:
                    self._on_primary_training_start(index)

                self._main_trainer.train()  # pyright: ignore[reportUnknownMemberType]

            self._main_trainer.save_model(f"{original_output_dir}/epoch-{epoch}")

    def save_model(self, output_dir: str | None):
        self._main_trainer.save_model(output_dir)
