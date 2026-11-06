"""AnthropicAdapter: cyber-safeguard refusal fallback, workspace-id header, config loaders."""

from __future__ import annotations

import asyncio
import sys
import types
from types import SimpleNamespace

import pytest

from isitsecure import config
from isitsecure.llm import adapters
from isitsecure.llm.adapters import CYBER_REFUSAL_FALLBACK_MODEL, AnthropicAdapter


def _msg(text: str, stop_reason: str = "end_turn"):
    content = [SimpleNamespace(text=text)] if text else []
    return SimpleNamespace(
        content=content,
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
    )


class FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


@pytest.fixture
def fake_sdk(monkeypatch):
    """Install a fake ``anthropic`` module; exposes constructor kwargs and the messages fake."""
    state = SimpleNamespace(init_kwargs=[], messages=FakeMessages([]))

    class FakeClient:
        def __init__(self, **kwargs):
            state.init_kwargs.append(kwargs)
            self.messages = state.messages

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(AsyncAnthropic=FakeClient))
    return state


def test_normal_response_single_call_no_fallback(fake_sdk):
    fake_sdk.messages.responses = [_msg("ok")]
    a = AnthropicAdapter("k", model="m1", fallback_model="m2")
    assert asyncio.run(a.generate("hi")) == "ok"
    assert [c["model"] for c in fake_sdk.messages.calls] == ["m1"]
    assert a.token_usage["llm_calls"] == 1


def test_refusal_retries_once_on_fallback(fake_sdk, caplog):
    fake_sdk.messages.responses = [_msg("", "refusal"), _msg("recovered")]
    a = AnthropicAdapter("k", model="m1", fallback_model="m2")
    with caplog.at_level("WARNING"):
        assert asyncio.run(a.generate_with_system("sys", "user")) == "recovered"
    calls = fake_sdk.messages.calls
    assert [c["model"] for c in calls] == ["m1", "m2"]
    assert calls[0]["system"] == calls[1]["system"] == "sys"
    assert a.token_usage["llm_calls"] == 2
    assert "m2" in caplog.text


def test_refusal_without_fallback_is_not_retried(fake_sdk):
    fake_sdk.messages.responses = [_msg("", "refusal")]
    a = AnthropicAdapter("k", model="m1")
    with pytest.raises(IndexError):  # empty content, as before the change
        asyncio.run(a.generate("hi"))
    assert len(fake_sdk.messages.calls) == 1


def test_fallback_equal_to_primary_is_disabled(fake_sdk):
    fake_sdk.messages.responses = [_msg("", "refusal")]
    a = AnthropicAdapter("k", model="m1", fallback_model="m1")
    with pytest.raises(IndexError):
        asyncio.run(a.generate("hi"))
    assert len(fake_sdk.messages.calls) == 1


def test_workspace_header_absent_when_unset(fake_sdk):
    AnthropicAdapter("k")
    assert fake_sdk.init_kwargs == [{"api_key": "k"}]


def test_workspace_header_sent_when_set(fake_sdk):
    AnthropicAdapter("k", workspace_id="wrkspc_1")
    assert fake_sdk.init_kwargs[0]["default_headers"] == {"anthropic-workspace-id": "wrkspc_1"}


def test_factory_wires_fallback_and_workspace(fake_sdk, monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_FALLBACK_MODEL", raising=False)
    monkeypatch.setenv("ANTHROPIC_WORKSPACE_ID", "wrkspc_9")
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "missing.toml")
    monkeypatch.chdir(tmp_path)
    a = adapters.create_llm_client("anthropic", "k")
    assert a._fallback_model == CYBER_REFUSAL_FALLBACK_MODEL
    assert fake_sdk.init_kwargs[0]["default_headers"] == {"anthropic-workspace-id": "wrkspc_9"}
    monkeypatch.setenv("ANTHROPIC_FALLBACK_MODEL", "custom-model")
    assert adapters.create_llm_client("anthropic", "k")._fallback_model == "custom-model"


def test_loader_precedence_env_then_dotenv_then_toml(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_WORKSPACE_ID", raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[llm]\nanthropic_workspace_id = "from_toml"\n')
    monkeypatch.setattr(config, "CONFIG_FILE", cfg)
    monkeypatch.chdir(tmp_path)
    assert config.load_workspace_id() == "from_toml"
    (tmp_path / ".env").write_text('ANTHROPIC_WORKSPACE_ID="from_dotenv"\n')
    assert config.load_workspace_id() == "from_dotenv"
    monkeypatch.setenv("ANTHROPIC_WORKSPACE_ID", "from_env")
    assert config.load_workspace_id() == "from_env"


def test_loaders_return_none_when_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_WORKSPACE_ID", raising=False)
    monkeypatch.delenv("ANTHROPIC_FALLBACK_MODEL", raising=False)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "missing.toml")
    monkeypatch.chdir(tmp_path)
    assert config.load_workspace_id() is None
    assert config.load_fallback_model() is None
