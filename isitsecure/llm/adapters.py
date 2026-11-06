"""LLM client adapters for Anthropic and Google.

Each adapter implements LLMClientProtocol so scanners can use any provider
interchangeably. No LangChain dependency — direct SDK calls only.
"""

from __future__ import annotations

import logging

from isitsecure.llm.protocol import LLMClientProtocol, LLMRefusalError

logger = logging.getLogger(__name__)

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

# Client-side fallback for Anthropic's real-time cyber safeguard. A classifier refusal arrives as
# an HTTP 200 with ``stop_reason="refusal"`` and EMPTY content (benign security work can trip it),
# which otherwise surfaces upstream as "did not return a JSON object". On a refusal we re-issue
# the same request once on this model. Override with ANTHROPIC_FALLBACK_MODEL.
# The id (current Sonnet) was checked against the claude-api skill's model table.
# Client-side retry, not the API's server-side ``fallbacks`` param: that is a beta, Claude-API-only
# feature, while this adapter uses the plain Messages API for any model/platform the key allows.
CYBER_REFUSAL_FALLBACK_MODEL = "claude-sonnet-5-5"

WORKSPACE_ID_HEADER = "anthropic-workspace-id"


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
        from isitsecure.config import load_fallback_model, load_workspace_id

        return AnthropicAdapter(
            api_key=api_key,
            model=model,
            fallback_model=load_fallback_model() or CYBER_REFUSAL_FALLBACK_MODEL,
            workspace_id=load_workspace_id(),
        )
    else:  # google
        return GoogleAdapter(api_key=api_key, model=model)


class AnthropicAdapter:
    """Adapter for Anthropic's Claude API. Implements LLMClientProtocol."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-opus-4-7",
        fallback_model: str | None = None,
        workspace_id: str | None = None,
    ) -> None:
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required. Install with: pip install isitsecure[llm]"
            )
        # Identity-linked keys reject requests without the workspace header; omit it when unset
        # so the client is constructed exactly as before.
        if workspace_id:
            self._client = anthropic.AsyncAnthropic(
                api_key=api_key, default_headers={WORKSPACE_ID_HEADER: workspace_id}
            )
        else:
            self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model
        # Model to retry on after a cyber-safeguard refusal; None (or == primary) disables it.
        self._fallback_model = fallback_model if fallback_model != model else None
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

    @staticmethod
    def _refusal_category(response) -> str | None:
        return getattr(getattr(response, "stop_details", None), "category", None)

    def _text(self, response) -> str:
        """First text block of a response; raises LLMRefusalError if the model refused
        (a refusal carries no content)."""
        if self._is_refusal(response):
            raise LLMRefusalError(self._model, self._refusal_category(response))
        return response.content[0].text

    @staticmethod
    def _is_refusal(response) -> bool:
        """A classifier refusal: 200 with ``stop_reason="refusal"`` (content is empty).
        Keyed on ``stop_reason`` only — the explanation text is documented as unstable."""
        return getattr(response, "stop_reason", None) == "refusal"

    async def _create_with_fallback(self, **kwargs):
        """Create a message on the primary model; on a refusal, re-issue the identical request
        once on the fallback model (if configured). Both attempts are metered."""
        response = await self._client.messages.create(model=self._model, **kwargs)
        self._record_usage(response)
        if self._fallback_model and self._is_refusal(response):
            logger.warning(
                "Anthropic safeguard refused the request on %s (category=%s); "
                "retrying on fallback model %s",
                self._model,
                self._refusal_category(response),
                self._fallback_model,
            )
            response = await self._client.messages.create(model=self._fallback_model, **kwargs)
            self._record_usage(response)
        return response

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        response = await self._create_with_fallback(
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return self._text(response)

    async def generate_with_system(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
    ) -> str:
        response = await self._create_with_fallback(
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return self._text(response)


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
        self._record_usage(response)
        return response.text
