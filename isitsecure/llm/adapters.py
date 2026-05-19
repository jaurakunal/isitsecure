"""LLM client adapters for Anthropic and Google.

Each adapter implements LLMClientProtocol so scanners can use any provider
interchangeably. No LangChain dependency — direct SDK calls only.
"""

from __future__ import annotations

import logging

from isitsecure.llm.protocol import LLMClientProtocol

logger = logging.getLogger(__name__)

# Model defaults
ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
ANTHROPIC_JUDGMENT_MODEL = "claude-sonnet-4-20250514"
GOOGLE_MODEL = "gemini-2.5-pro-preview-05-06"
GOOGLE_JUDGMENT_MODEL = "gemini-2.5-flash-preview-04-17"


def create_llm_client(
    provider: str,
    api_key: str,
    judgment: bool = False,
) -> LLMClientProtocol:
    """Factory for creating LLM clients.

    Args:
        provider: "anthropic" or "google"
        api_key: API key for the provider
        judgment: If True, use the faster/cheaper model for triage

    Returns:
        An LLM client implementing LLMClientProtocol
    """
    if provider == "anthropic":
        model = ANTHROPIC_JUDGMENT_MODEL if judgment else ANTHROPIC_MODEL
        return AnthropicAdapter(api_key=api_key, model=model)
    elif provider == "google":
        model = GOOGLE_JUDGMENT_MODEL if judgment else GOOGLE_MODEL
        return GoogleAdapter(api_key=api_key, model=model)
    else:
        raise ValueError(f"Unknown LLM provider: {provider}. Use 'anthropic' or 'google'.")


class AnthropicAdapter:
    """Adapter for Anthropic's Claude API. Implements LLMClientProtocol."""

    def __init__(self, api_key: str, model: str = ANTHROPIC_MODEL) -> None:
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required. Install with: pip install isitsecure[llm]"
            )
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def llm(self):
        return self._client

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    async def generate_with_system(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
    ) -> str:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text


class GoogleAdapter:
    """Adapter for Google's Gemini API. Implements LLMClientProtocol."""

    def __init__(self, api_key: str, model: str = GOOGLE_MODEL) -> None:
        try:
            from google import genai
        except ImportError:
            raise ImportError(
                "google-genai package required. Install with: pip install isitsecure[llm]"
            )
        self._client = genai.Client(api_key=api_key)
        self._model = model

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def llm(self):
        return self._client

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        from google.genai import types

        response = await self._client.aio.models.generate_content(
            model=self._model,
            contents=prompt,
            config=types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            ),
        )
        return response.text

    async def generate_with_system(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
    ) -> str:
        from google.genai import types

        response = await self._client.aio.models.generate_content(
            model=self._model,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                system_instruction=system_prompt,
            ),
        )
        return response.text
