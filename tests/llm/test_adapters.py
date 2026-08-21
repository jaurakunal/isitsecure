"""Robustness tests for the shared LLM client adapters.

Regression coverage for the engagement-ending crash on branch ``pentest``:
the Anthropic adapter did ``response.content[0].text``, which raised
``IndexError`` when the API returned an empty ``content`` array (a
``max_tokens`` truncation with no completed text block, or a response whose
only blocks are non-text). These tests mock the SDK client response — no
network — and assert graceful degradation (return ``""`` + warn) instead.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from isitsecure.llm.adapters import AnthropicAdapter, GoogleAdapter

# --- Fixtures / helpers ---


def _make_anthropic_adapter(response) -> AnthropicAdapter:
    """Build an AnthropicAdapter whose client returns a canned response."""
    adapter = AnthropicAdapter(api_key="test-key", model="claude-opus-4-7")
    adapter._client = MagicMock()
    adapter._client.messages.create = AsyncMock(return_value=response)
    return adapter


def _text_block(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def _anthropic_response(content, stop_reason: str = "end_turn") -> SimpleNamespace:
    return SimpleNamespace(
        content=content,
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
    )


def _make_google_adapter(response) -> GoogleAdapter:
    adapter = GoogleAdapter(api_key="test-key", model="gemini-3.1-pro-preview")
    adapter._client = MagicMock()
    adapter._client.aio.models.generate_content = AsyncMock(return_value=response)
    return adapter


# --- Anthropic: normal path (regression) ---


async def test_generate_returns_text_for_normal_response() -> None:
    adapter = _make_anthropic_adapter(_anthropic_response([_text_block("hello world")]))
    assert await adapter.generate("hi") == "hello world"


async def test_generate_with_system_returns_text_for_normal_response() -> None:
    adapter = _make_anthropic_adapter(_anthropic_response([_text_block("system out")]))
    assert await adapter.generate_with_system("sys", "user") == "system out"


# --- Anthropic: empty content array (the crash) ---


async def test_generate_empty_content_returns_empty_string(caplog) -> None:
    adapter = _make_anthropic_adapter(_anthropic_response([]))
    with caplog.at_level("WARNING"):
        result = await adapter.generate("hi")
    assert result == ""  # not IndexError
    assert any("no text block" in r.message for r in caplog.records)


async def test_generate_with_system_empty_content_returns_empty_string() -> None:
    adapter = _make_anthropic_adapter(_anthropic_response([]))
    assert await adapter.generate_with_system("sys", "user") == ""


# --- Anthropic: non-text-only content (thinking / tool_use) ---


async def test_generate_non_text_block_returns_empty_string(caplog) -> None:
    thinking_block = SimpleNamespace(type="thinking", thinking="pondering...")
    adapter = _make_anthropic_adapter(_anthropic_response([thinking_block]))
    with caplog.at_level("WARNING"):
        result = await adapter.generate("hi")
    assert result == ""
    assert any("no text block" in r.message for r in caplog.records)


async def test_generate_picks_first_text_block_among_mixed() -> None:
    thinking_block = SimpleNamespace(type="thinking", thinking="pondering...")
    adapter = _make_anthropic_adapter(
        _anthropic_response([thinking_block, _text_block("the answer")])
    )
    assert await adapter.generate("hi") == "the answer"


# --- Anthropic: max_tokens truncation with empty content ---


async def test_generate_max_tokens_truncation_returns_empty_and_warns(caplog) -> None:
    adapter = _make_anthropic_adapter(
        _anthropic_response([], stop_reason="max_tokens")
    )
    with caplog.at_level("WARNING"):
        result = await adapter.generate("hi", max_tokens=1)
    assert result == ""
    assert any(
        "no text block" in r.message and "max_tokens" in str(r.args)
        for r in caplog.records
    )


# --- Google: normal path (regression) ---


async def test_google_generate_returns_text() -> None:
    response = SimpleNamespace(text="gemini says hi", candidates=[], usage_metadata=None)
    adapter = _make_google_adapter(response)
    assert await adapter.generate("hi") == "gemini says hi"


# --- Google: blocked/empty response (.text is None) ---


async def test_google_generate_none_text_returns_empty_string(caplog) -> None:
    # google-genai returns None from .text when there are no parts / a safety block.
    response = SimpleNamespace(
        text=None,
        candidates=[SimpleNamespace(finish_reason="SAFETY")],
        usage_metadata=None,
    )
    adapter = _make_google_adapter(response)
    with caplog.at_level("WARNING"):
        result = await adapter.generate("hi")
    assert result == ""  # not None — honors the -> str contract
    assert any("no text" in r.message for r in caplog.records)


# --- Anthropic: vision (generate_with_image) ---

_PNG_B64 = "aVZCT1J3MEtHZ29BQUFBTg=="  # arbitrary base64 payload (not a real PNG)


async def test_generate_with_image_sends_image_block_and_returns_text() -> None:
    adapter = _make_anthropic_adapter(_anthropic_response([_text_block("a mat-select")]))
    result = await adapter.generate_with_image("describe this form", _PNG_B64)
    assert result == "a mat-select"
    kwargs = adapter._client.messages.create.call_args.kwargs
    content = kwargs["messages"][0]["content"]
    image_blocks = [b for b in content if b.get("type") == "image"]
    text_blocks = [b for b in content if b.get("type") == "text"]
    assert len(image_blocks) == 1
    assert image_blocks[0]["source"] == {
        "type": "base64", "media_type": "image/png", "data": _PNG_B64,
    }
    assert text_blocks[0]["text"] == "describe this form"
    # Usage is recorded exactly like the text paths.
    assert adapter.token_usage["llm_calls"] == 1


async def test_generate_with_image_empty_content_returns_empty_string(caplog) -> None:
    adapter = _make_anthropic_adapter(_anthropic_response([]))
    with caplog.at_level("WARNING"):
        result = await adapter.generate_with_image("prompt", _PNG_B64)
    assert result == ""  # not IndexError
    assert any("no text block" in r.message for r in caplog.records)


# --- Google: vision (generate_with_image) ---


async def test_google_generate_with_image_sends_part_and_returns_text() -> None:
    response = SimpleNamespace(text="gemini sees a form", candidates=[], usage_metadata=None)
    adapter = _make_google_adapter(response)
    result = await adapter.generate_with_image("describe this form", _PNG_B64)
    assert result == "gemini sees a form"
    kwargs = adapter._client.aio.models.generate_content.call_args.kwargs
    contents = kwargs["contents"]
    # A text prompt plus one inline image part.
    assert isinstance(contents, list) and len(contents) == 2
    assert contents[0] == "describe this form"
    assert contents[1] is not None  # the inline image Part


async def test_google_generate_with_image_empty_returns_empty_string(caplog) -> None:
    response = SimpleNamespace(
        text=None, candidates=[SimpleNamespace(finish_reason="SAFETY")], usage_metadata=None)
    adapter = _make_google_adapter(response)
    with caplog.at_level("WARNING"):
        result = await adapter.generate_with_image("prompt", _PNG_B64)
    assert result == ""
    assert any("no text" in r.message for r in caplog.records)


async def test_google_generate_text_raises_returns_empty_string(caplog) -> None:
    # Some SDK versions raise on .text for a blocked response.
    class _Raising:
        candidates: list = []

        @property
        def text(self):
            raise ValueError("blocked")

    adapter = _make_google_adapter(_Raising())
    with caplog.at_level("WARNING"):
        result = await adapter.generate_with_system("sys", "user")
    assert result == ""
    assert any("text access failed" in r.message for r in caplog.records)


class TestAnthropicOmitsTemperature:
    """Regression: current models reject ``temperature`` ('deprecated for this model').
    The adapter must NOT forward it — the mocked-SDK tests missed the real 400."""

    @staticmethod
    def _adapter_with_fake_client() -> tuple[Any, Any]:
        client = MagicMock()
        resp = MagicMock()
        resp.content = [MagicMock(type="text", text="ok")]
        client.messages.create = AsyncMock(return_value=resp)
        adapter = AnthropicAdapter(api_key="k")  # noqa: S106
        adapter._client = client
        return adapter, client

    async def test_generate_does_not_send_temperature(self):
        adapter, client = self._adapter_with_fake_client()
        await adapter.generate("hi")
        assert "temperature" not in client.messages.create.call_args.kwargs

    async def test_generate_with_image_does_not_send_temperature(self):
        adapter, client = self._adapter_with_fake_client()
        await adapter.generate_with_image("describe", "ZmFrZQ==")
        assert "temperature" not in client.messages.create.call_args.kwargs
