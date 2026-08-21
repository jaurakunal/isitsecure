"""LLM client adapters for Anthropic and Google.

Each adapter implements LLMClientProtocol so scanners can use any provider
interchangeably. No LangChain dependency — direct SDK calls only.
"""

from __future__ import annotations

import logging

from isitsecure.llm.protocol import LLMClientProtocol

logger = logging.getLogger(__name__)


def _first_text_block(response) -> str:
    """Return the text of the first text block in an Anthropic response.

    Robust against responses whose ``content`` is empty (e.g. a ``max_tokens``
    truncation with no completed text block) or contains only non-text blocks
    (thinking / tool_use). In those cases returns ``""`` instead of raising
    ``IndexError`` — callers already treat an empty response as a graceful
    failure. Emits a warning when the response was truncated or had no text so
    the condition stays visible in logs.
    """
    content = getattr(response, "content", None) or []
    for block in content:
        if getattr(block, "type", None) == "text" or hasattr(block, "text"):
            text = getattr(block, "text", None)
            if isinstance(text, str):
                return text
    stop_reason = getattr(response, "stop_reason", None)
    logger.warning(
        "LLM response had no text block (stop_reason=%s, blocks=%d)",
        stop_reason,
        len(content),
    )
    return ""


# Model roles:
#   planning  — code analysis, attack planning, SAST review, fix generation (most capable)
#   judgment  — triage, result judgment, enrichment (faster/cheaper)
MODEL_ROLES = {
    "anthropic": {
        "planning": "claude-opus-4-7",
        "judgment": "claude-sonnet-4-6",
    },
    "google": {
        "planning": "gemini-3.1-pro-preview",
        "judgment": "gemini-3-flash-preview",
    },
}


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
    if provider not in MODEL_ROLES:
        raise ValueError(f"Unknown LLM provider: {provider}. Use 'anthropic' or 'google'.")

    role = "judgment" if judgment else "planning"
    model = MODEL_ROLES[provider][role]

    if provider == "anthropic":
        return AnthropicAdapter(api_key=api_key, model=model)
    else:  # google
        return GoogleAdapter(api_key=api_key, model=model)


class AnthropicAdapter:
    """Adapter for Anthropic's Claude API. Implements LLMClientProtocol."""

    def __init__(self, api_key: str, model: str = "claude-opus-4-7") -> None:
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required. Install with: pip install isitsecure[llm]"
            )
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model
        # Read by the orchestrator's _collect_token_usage() for cost reporting.
        self._model_name = model
        self.token_usage = {"input_tokens": 0, "output_tokens": 0, "llm_calls": 0}

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def llm(self):
        return self._client

    def _record_usage(self, response) -> None:
        """Accumulate token usage from a response. Best-effort — never raises."""
        try:
            usage = getattr(response, "usage", None)
            if usage is None:
                return
            self.token_usage["input_tokens"] += getattr(usage, "input_tokens", 0) or 0
            self.token_usage["output_tokens"] += getattr(usage, "output_tokens", 0) or 0
            self.token_usage["llm_calls"] += 1
        except Exception as exc:
            logger.debug("Failed to record token usage: %s", exc)

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
        self._record_usage(response)
        return _first_text_block(response)

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
        self._record_usage(response)
        return _first_text_block(response)

    async def generate_with_image(
        self,
        prompt: str,
        image_base64: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Vision: send a base64 PNG plus a text prompt, return the text response.

        The image is carried as an Anthropic ``image`` content block (base64 PNG) alongside
        the text block in a single user message. Reuses the same empty-content hardening
        (``_first_text_block``) and usage accounting as the text paths, so a truncated or
        blocked response degrades to ``""`` instead of raising."""
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": image_base64,
                            },
                        },
                        {"type": "text", "text": prompt},
                    ],
                }
            ],
        )
        self._record_usage(response)
        return _first_text_block(response)


def _response_text(response) -> str:
    """Return the text of a Gemini response, or ``""`` if there is none.

    ``GenerateContentResponse.text`` returns ``None`` when the response has no
    candidates/parts (e.g. a safety block or ``MAX_TOKENS`` finish with no text),
    and some SDK versions raise on ``.text`` for a blocked response. Either way
    the ``-> str`` contract must hold, so coalesce to ``""`` and warn rather than
    letting ``None`` (or an exception) propagate to callers.
    """
    try:
        text = getattr(response, "text", None)
    except Exception as exc:  # SDK raises on some blocked/empty responses
        logger.warning("LLM response text access failed: %s", exc)
        return ""
    if isinstance(text, str) and text:
        return text
    finish_reason = None
    candidates = getattr(response, "candidates", None) or []
    if candidates:
        finish_reason = getattr(candidates[0], "finish_reason", None)
    logger.warning(
        "LLM response had no text (finish_reason=%s, candidates=%d)",
        finish_reason,
        len(candidates),
    )
    return ""


class GoogleAdapter:
    """Adapter for Google's Gemini API. Implements LLMClientProtocol."""

    def __init__(self, api_key: str, model: str = "gemini-3.1-pro-preview") -> None:
        try:
            from google import genai
        except ImportError:
            raise ImportError(
                "google-genai package required. Install with: pip install isitsecure[llm]"
            )
        self._client = genai.Client(api_key=api_key)
        self._model = model
        # Read by the orchestrator's _collect_token_usage() for cost reporting.
        self._model_name = model
        self.token_usage = {"input_tokens": 0, "output_tokens": 0, "llm_calls": 0}

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def llm(self):
        return self._client

    def _record_usage(self, response) -> None:
        """Accumulate token usage from a response. Best-effort — never raises."""
        try:
            meta = getattr(response, "usage_metadata", None)
            if meta is None:
                return
            self.token_usage["input_tokens"] += getattr(meta, "prompt_token_count", 0) or 0
            self.token_usage["output_tokens"] += (
                getattr(meta, "candidates_token_count", 0) or 0
            )
            self.token_usage["llm_calls"] += 1
        except Exception as exc:
            logger.debug("Failed to record token usage: %s", exc)

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
        self._record_usage(response)
        return _response_text(response)

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
        self._record_usage(response)
        return _response_text(response)

    async def generate_with_image(
        self,
        prompt: str,
        image_base64: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Vision: send a base64 PNG as a Gemini inline image part plus a text prompt.

        The image is decoded from base64 and passed as an inline ``Part`` (image/png)
        alongside the text prompt. Reuses ``_response_text`` (empty/blocked → ``""``) and
        ``_record_usage`` so behavior matches the text paths."""
        import base64 as _base64

        from google.genai import types

        image_part = types.Part.from_bytes(
            data=_base64.b64decode(image_base64), mime_type="image/png"
        )
        response = await self._client.aio.models.generate_content(
            model=self._model,
            contents=[prompt, image_part],
            config=types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            ),
        )
        self._record_usage(response)
        return _response_text(response)
