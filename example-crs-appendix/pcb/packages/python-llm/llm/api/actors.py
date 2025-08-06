from typing import Callable

from dotenv import dotenv_values
from langchain_litellm import ChatLiteLLM


class LlmApiManager:
    def __init__(
        self, model: str, api_key: Callable[[], str], base_url: Callable[[], str]
    ):
        self._model = model
        self._api_key = api_key
        self._base_url = base_url

    @staticmethod
    def from_dotenv(
        model: str,
        key_of_api_key: str = "LITELLM_API_KEY",
        key_of_base_url: str = "LITELLM_API_BASE",
    ):
        def api_key():
            value = dotenv_values().get(key_of_api_key)
            if not value:
                raise ValueError(f"Environment variable '{key_of_api_key}' is not set.")
            return value

        def base_url():
            value = dotenv_values().get(key_of_base_url)
            if not value:
                raise ValueError(
                    f"Environment variable '{key_of_base_url}' is not set."
                )
            return value

        return LlmApiManager(
            model=model,
            api_key=api_key,
            base_url=base_url,
        )

    def langchain_chat_model(self):
        return ChatLiteLLM(
            model=self._model,
            api_key=self._api_key(),
            api_base=self._base_url(),
        )
