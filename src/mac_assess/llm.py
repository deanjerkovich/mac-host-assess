"""LLM provider configuration and factory.

Supports multiple LLM providers:
- Anthropic (Claude)
- OpenAI (GPT-4)
- Google (Gemini via Vertex AI or AI Studio)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from langchain_core.language_models.chat_models import BaseChatModel


class Provider(str, Enum):
    """Supported LLM providers."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    VERTEX = "vertex"  # Google Cloud Vertex AI


@dataclass
class LLMConfig:
    """Configuration for LLM provider."""

    provider: Provider
    model: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.0
    max_tokens: int = 4096

    # Google/Vertex specific
    project_id: Optional[str] = None
    location: Optional[str] = None

    def get_default_model(self) -> str:
        """Get the default model for the provider."""
        defaults = {
            Provider.ANTHROPIC: "claude-sonnet-4-20250514",
            Provider.OPENAI: "gpt-4o",
            Provider.GOOGLE: "gemini-2.0-flash",
            Provider.VERTEX: "gemini-2.0-flash",
        }
        return self.model or defaults[self.provider]


# Default configuration
_current_config: Optional[LLMConfig] = None


def configure(
    provider: str | Provider = Provider.ANTHROPIC,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    temperature: float = 0.0,
    max_tokens: int = 4096,
    project_id: Optional[str] = None,
    location: Optional[str] = "us-central1",
) -> LLMConfig:
    """Configure the LLM provider.

    Args:
        provider: The LLM provider to use.
        model: Model name (uses provider default if not specified).
        api_key: API key (falls back to environment variable).
        temperature: Sampling temperature.
        max_tokens: Maximum tokens in response.
        project_id: GCP project ID (for Vertex AI).
        location: GCP location (for Vertex AI).

    Returns:
        The LLM configuration.
    """
    global _current_config

    if isinstance(provider, str):
        provider = Provider(provider.lower())

    _current_config = LLMConfig(
        provider=provider,
        model=model,
        api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens,
        project_id=project_id,
        location=location,
    )

    return _current_config


def get_config() -> LLMConfig:
    """Get the current LLM configuration."""
    global _current_config
    if _current_config is None:
        _current_config = LLMConfig(provider=Provider.ANTHROPIC)
    return _current_config


def create_llm(config: Optional[LLMConfig] = None) -> BaseChatModel:
    """Create an LLM instance based on configuration.

    Args:
        config: LLM configuration. Uses global config if not provided.

    Returns:
        A LangChain chat model instance.

    Raises:
        ValueError: If the provider is not supported or dependencies are missing.
    """
    if config is None:
        config = get_config()

    model = config.get_default_model()

    if config.provider == Provider.ANTHROPIC:
        return _create_anthropic(config, model)
    elif config.provider == Provider.OPENAI:
        return _create_openai(config, model)
    elif config.provider == Provider.GOOGLE:
        return _create_google(config, model)
    elif config.provider == Provider.VERTEX:
        return _create_vertex(config, model)
    else:
        raise ValueError(f"Unsupported provider: {config.provider}")


def _create_anthropic(config: LLMConfig, model: str) -> BaseChatModel:
    """Create Anthropic Claude model."""
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError:
        raise ValueError(
            "langchain-anthropic not installed. Run: pip install langchain-anthropic"
        )

    api_key = config.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError(
            "Anthropic API key required. Set ANTHROPIC_API_KEY or pass api_key."
        )

    return ChatAnthropic(
        model=model,
        api_key=api_key,
        max_tokens=config.max_tokens,
        temperature=config.temperature,
    )


def _create_openai(config: LLMConfig, model: str) -> BaseChatModel:
    """Create OpenAI model."""
    try:
        from langchain_openai import ChatOpenAI
    except ImportError:
        raise ValueError(
            "langchain-openai not installed. Run: pip install langchain-openai"
        )

    api_key = config.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError(
            "OpenAI API key required. Set OPENAI_API_KEY or pass api_key."
        )

    return ChatOpenAI(
        model=model,
        api_key=api_key,
        max_tokens=config.max_tokens,
        temperature=config.temperature,
    )


def _create_google(config: LLMConfig, model: str) -> BaseChatModel:
    """Create Google Gemini model via AI Studio."""
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
    except ImportError:
        raise ValueError(
            "langchain-google-genai not installed. Run: pip install langchain-google-genai"
        )

    api_key = config.api_key or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError(
            "Google API key required. Set GOOGLE_API_KEY or pass api_key."
        )

    return ChatGoogleGenerativeAI(
        model=model,
        google_api_key=api_key,
        max_output_tokens=config.max_tokens,
        temperature=config.temperature,
    )


def _create_vertex(config: LLMConfig, model: str) -> BaseChatModel:
    """Create Google Gemini model via Vertex AI."""
    try:
        from langchain_google_vertexai import ChatVertexAI
    except ImportError:
        raise ValueError(
            "langchain-google-vertexai not installed. Run: pip install langchain-google-vertexai"
        )

    project_id = config.project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
    location = config.location or os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")

    return ChatVertexAI(
        model=model,
        project=project_id,
        location=location,
        max_output_tokens=config.max_tokens,
        temperature=config.temperature,
    )


def list_providers() -> list[dict[str, Any]]:
    """List available providers and their configuration."""
    return [
        {
            "name": Provider.ANTHROPIC.value,
            "description": "Anthropic Claude models",
            "env_var": "ANTHROPIC_API_KEY",
            "default_model": "claude-sonnet-4-20250514",
            "models": ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-3-5-20241022"],
        },
        {
            "name": Provider.OPENAI.value,
            "description": "OpenAI GPT models",
            "env_var": "OPENAI_API_KEY",
            "default_model": "gpt-4o",
            "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
        },
        {
            "name": Provider.GOOGLE.value,
            "description": "Google Gemini via AI Studio",
            "env_var": "GOOGLE_API_KEY",
            "default_model": "gemini-2.0-flash",
            "models": ["gemini-2.0-flash", "gemini-2.5-pro-preview-05-06"],
        },
        {
            "name": Provider.VERTEX.value,
            "description": "Google Gemini via Vertex AI (GCP)",
            "env_var": "GOOGLE_CLOUD_PROJECT",
            "default_model": "gemini-2.0-flash",
            "models": ["gemini-2.0-flash", "gemini-2.5-pro-preview-05-06"],
        },
    ]
