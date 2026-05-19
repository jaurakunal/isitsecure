"""Tests for BrowserLoginHelper and shared token extraction."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from isitsecure.engine.auth.browser_login_helper import (
    BrowserLoginHelper,
    extract_token_from_json,
    _clean_token,
)
from isitsecure.engine.constants import BrowserLoginConfig


class TestExtractTokenFromJson:
    """Tests for the extract_token_from_json module function."""

    def test_direct_access_token(self):
        raw = json.dumps({"access_token": "my-token"})
        assert extract_token_from_json(raw) == "my-token"

    def test_direct_token_key(self):
        raw = json.dumps({"token": "my-token"})
        assert extract_token_from_json(raw) == "my-token"

    def test_supabase_v2_current_session(self):
        raw = json.dumps({
            "currentSession": {
                "access_token": "nested-token",
                "refresh_token": "refresh",
            }
        })
        assert extract_token_from_json(raw) == "nested-token"

    def test_supabase_session_wrapper(self):
        raw = json.dumps({
            "session": {
                "access_token": "session-token",
            }
        })
        assert extract_token_from_json(raw) == "session-token"

    def test_returns_none_for_no_token(self):
        raw = json.dumps({"user": "test"})
        assert extract_token_from_json(raw) is None

    def test_returns_none_for_invalid_json(self):
        assert extract_token_from_json("not json") is None

    def test_returns_none_for_array(self):
        assert extract_token_from_json("[1, 2, 3]") is None

    def test_returns_none_for_empty_string(self):
        assert extract_token_from_json("") is None

    def test_prefers_access_token_over_token(self):
        raw = json.dumps({"access_token": "primary", "token": "secondary"})
        assert extract_token_from_json(raw) == "primary"


class TestCleanToken:
    """Tests for _clean_token."""

    def test_strips_double_quotes(self):
        assert _clean_token('"my-token"') == "my-token"

    def test_strips_single_quotes(self):
        assert _clean_token("'my-token'") == "my-token"

    def test_no_quotes(self):
        assert _clean_token("my-token") == "my-token"


class TestFillInput:
    """Tests for BrowserLoginHelper.fill_input."""

    @pytest.mark.asyncio
    async def test_fills_first_matching_selector(self):
        mock_element = AsyncMock()
        mock_page = AsyncMock()

        async def mock_qs(selector):
            if selector == 'input[type="email"]':
                return mock_element
            return None

        mock_page.query_selector = mock_qs

        result = await BrowserLoginHelper.fill_input(
            mock_page,
            BrowserLoginConfig.EMAIL_INPUT_SELECTORS,
            "test@example.com",
        )
        assert result is True
        mock_element.fill.assert_called_once_with("test@example.com")

    @pytest.mark.asyncio
    async def test_returns_false_when_no_selector_matches(self):
        mock_page = AsyncMock()
        mock_page.query_selector = AsyncMock(return_value=None)

        result = await BrowserLoginHelper.fill_input(
            mock_page,
            BrowserLoginConfig.EMAIL_INPUT_SELECTORS,
            "test@example.com",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_continues_on_exception(self):
        mock_page = AsyncMock()
        call_count = 0

        async def mock_qs(selector):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Element detached")
            el = AsyncMock()
            return el

        mock_page.query_selector = mock_qs

        result = await BrowserLoginHelper.fill_input(
            mock_page,
            ('selector-1', 'selector-2'),
            "value",
        )
        assert result is True
        assert call_count == 2


class TestClickSubmit:
    """Tests for BrowserLoginHelper.click_submit."""

    @pytest.mark.asyncio
    async def test_clicks_first_matching_button(self):
        mock_button = AsyncMock()
        mock_page = AsyncMock()

        async def mock_qs(selector):
            if "submit" in selector:
                return mock_button
            return None

        mock_page.query_selector = mock_qs

        result = await BrowserLoginHelper.click_submit(mock_page)
        assert result is True
        mock_button.click.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_false_when_no_button_found(self):
        mock_page = AsyncMock()
        mock_page.query_selector = AsyncMock(return_value=None)

        result = await BrowserLoginHelper.click_submit(mock_page)
        assert result is False


class TestExtractToken:
    """Tests for BrowserLoginHelper.extract_token."""

    @pytest.mark.asyncio
    async def test_extracts_from_local_storage(self):
        mock_page = AsyncMock()

        async def mock_evaluate(script):
            if "access_token" in script and "localStorage" in script:
                return "my-jwt-token"
            return None

        mock_page.evaluate = mock_evaluate

        token = await BrowserLoginHelper.extract_token(mock_page)
        assert token == "my-jwt-token"

    @pytest.mark.asyncio
    async def test_extracts_from_session_storage(self):
        mock_page = AsyncMock()
        call_count = 0

        async def mock_evaluate(script):
            nonlocal call_count
            call_count += 1
            if "sessionStorage" in script and "token" in script:
                return "session-token"
            if "localStorage" in script and "Object.keys" not in script:
                return None
            if "Object.keys" in script:
                return []
            return None

        mock_page.evaluate = mock_evaluate

        token = await BrowserLoginHelper.extract_token(mock_page)
        assert token == "session-token"

    @pytest.mark.asyncio
    async def test_returns_none_when_no_token_found(self):
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=None)

        token = await BrowserLoginHelper.extract_token(mock_page)
        assert token is None

    @pytest.mark.asyncio
    async def test_handles_evaluate_exception(self):
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(side_effect=Exception("Page crashed"))

        token = await BrowserLoginHelper.extract_token(mock_page)
        assert token is None
