"""Tests for build_llm_provider(): confirms each LLM_PROVIDER setting
wires up the correct provider class with the correct configuration,
including OpenAI-compatible third-party endpoints like Groq."""

from __future__ import annotations

import pytest

from config import LLMProviderName, settings
from engine import AnthropicProvider, LocalProvider, OpenAIProvider, build_llm_provider


@pytest.fixture(autouse=True)
def _reset_llm_settings():
    """Every test in this file mutates global settings — restore them
    afterward so other test files aren't affected by ordering."""
    original = (
        settings.llm_provider,
        settings.openai_api_key,
        settings.openai_base_url,
        settings.anthropic_api_key,
        settings.local_llm_base_url,
        settings.llm_model,
    )
    yield
    (
        settings.llm_provider,
        settings.openai_api_key,
        settings.openai_base_url,
        settings.anthropic_api_key,
        settings.local_llm_base_url,
        settings.llm_model,
    ) = original


class TestOpenAIProvider:
    def test_plain_openai_config(self) -> None:
        settings.llm_provider = LLMProviderName.OPENAI
        settings.openai_api_key = "sk-test-key"
        settings.openai_base_url = None
        settings.llm_model = "gpt-4o-mini"

        provider = build_llm_provider()
        assert isinstance(provider, OpenAIProvider)
        assert provider.api_key == "sk-test-key"
        assert provider.base_url is None
        assert provider.model == "gpt-4o-mini"

    def test_groq_via_base_url(self) -> None:
        """Groq (and any OpenAI-compatible provider) works by setting
        LLM_PROVIDER=openai with OPENAI_BASE_URL pointing at their
        endpoint — this is the free-tier path recommended for demos."""
        settings.llm_provider = LLMProviderName.OPENAI
        settings.openai_api_key = "gsk_fake_groq_key"
        settings.openai_base_url = "https://api.groq.com/openai/v1"
        settings.llm_model = "openai/gpt-oss-20b"  # current Groq free-tier default; see README

        provider = build_llm_provider()
        assert isinstance(provider, OpenAIProvider)
        assert provider.base_url == "https://api.groq.com/openai/v1"

        client = provider._get_client()
        assert str(client.base_url).rstrip("/") == "https://api.groq.com/openai/v1"

    def test_missing_key_with_no_base_url_raises(self) -> None:
        settings.llm_provider = LLMProviderName.OPENAI
        settings.openai_api_key = None
        settings.openai_base_url = None
        with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
            build_llm_provider()

    def test_missing_key_with_base_url_falls_back_to_placeholder(self) -> None:
        """A local no-auth OpenAI-compatible server (e.g. Ollama) doesn't
        need a real key — the client library still requires a non-empty
        string, so this must not raise."""
        settings.llm_provider = LLMProviderName.OPENAI
        settings.openai_api_key = None
        settings.openai_base_url = "http://localhost:11434/v1"

        provider = build_llm_provider()
        assert isinstance(provider, OpenAIProvider)
        assert provider.api_key  # non-empty placeholder, not None


class TestAnthropicProvider:
    def test_plain_anthropic_config(self) -> None:
        settings.llm_provider = LLMProviderName.ANTHROPIC
        settings.anthropic_api_key = "sk-ant-test-key"
        settings.llm_model = "claude-sonnet-4-6"

        provider = build_llm_provider()
        assert isinstance(provider, AnthropicProvider)
        assert provider.api_key == "sk-ant-test-key"

    def test_missing_key_raises(self) -> None:
        settings.llm_provider = LLMProviderName.ANTHROPIC
        settings.anthropic_api_key = None
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            build_llm_provider()


class TestLocalProvider:
    def test_plain_local_config(self) -> None:
        settings.llm_provider = LLMProviderName.LOCAL
        settings.local_llm_base_url = "http://localhost:11434/v1"

        provider = build_llm_provider()
        assert isinstance(provider, LocalProvider)
        assert provider.base_url == "http://localhost:11434/v1"

    def test_missing_base_url_raises(self) -> None:
        settings.llm_provider = LLMProviderName.LOCAL
        settings.local_llm_base_url = None
        with pytest.raises(RuntimeError, match="LOCAL_LLM_BASE_URL"):
            build_llm_provider()
