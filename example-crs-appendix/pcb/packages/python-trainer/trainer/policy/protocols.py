from p4_core.policy.protocols import BaseChatPolicy
from transformers import (
    GenerationMixin,  # pyright: ignore[reportMissingTypeStubs,reportPrivateImportUsage]
    PreTrainedTokenizer,  # pyright: ignore[reportPrivateImportUsage]
)


class HuggingFaceParameterizedChatPolicy[Observation, Action](
    BaseChatPolicy[Observation, Action]
):
    model: GenerationMixin
    processing_class: PreTrainedTokenizer
