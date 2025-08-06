from typing import Any, Iterator, Protocol

from datasets import Dataset, disable_caching  # pyright: ignore[reportMissingTypeStubs]

disable_caching()


class BaseScheduler(Protocol):
    def as_dataset(self) -> Dataset:
        return Dataset.from_list(  # pyright: ignore[reportUnknownMemberType]
            list(self.schedule())
        )

    def schedule(self) -> Iterator[dict[str, Any]]: ...
