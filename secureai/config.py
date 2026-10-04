"""
SecureAI configuration module.

Single source of truth for every tunable value in the system: model file
locations, risk-scoring weights, policy thresholds, and LLM provider
selection. Nothing outside this module should read `os.environ` directly —
every other module imports `settings` from here.

All values are overridable via environment variables or a `.env` file in
the project root (see `.env.example`).
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RiskLevel(str, Enum):
    """Discrete risk bands the numeric risk score is mapped into."""

    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, Enum):
    """The three outcomes the policy engine can return for a scan."""

    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


class LLMProviderName(str, Enum):
    """Supported LLM backends. Add new members here when adding a provider."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


class Settings(BaseSettings):
    """
    Central configuration object, populated from environment variables
    (and a `.env` file if present). Import `settings` from this module —
    do not instantiate `Settings()` anywhere else.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    models_dir: Path = Field(
        default=Path("./models"),
        description="Root directory containing the locally downloaded model folders.",
    )
    audit_db_path: Path = Field(
        default=Path("./audit_log.db"),
        description="SQLite database file for the security audit log.",
    )

    prompt_injection_model_dir: str = "prompt-injection"
    pii_detection_model_dir: str = "pii-detection"
    output_safety_model_dir: str = "output-safety"
    toxicity_model_dir: str = "toxicity"

    max_input_tokens: int = Field(
        default=512,
        description="Truncation length passed to detector tokenizers.",
    )
    gitleaks_binary: str = Field(
        default="gitleaks",
        description="Name or path of the gitleaks executable on PATH.",
    )
    gitleaks_timeout_seconds: int = Field(
        default=10,
        description="Max time to wait for a gitleaks subprocess scan before failing safe.",
    )

    weight_secret: int = Field(default=45, ge=0, le=100)
    weight_pii: int = Field(default=25, ge=0, le=100)
    weight_injection: int = Field(default=40, ge=0, le=100)
    weight_toxicity: int = Field(default=15, ge=0, le=100)
    weight_output_safety: int = Field(default=40, ge=0, le=100)
    weight_injection_technique: int = Field(default=25, ge=0, le=100)
    weight_instruction_leakage: int = Field(default=35, ge=0, le=100)

    max_prompt_length: int = Field(default=8000, ge=100)
    weight_oversized_input: int = Field(default=100, ge=0, le=100)

    threshold_low: int = Field(default=20, ge=0, le=100)
    threshold_medium: int = Field(default=40, ge=0, le=100)
    threshold_high: int = Field(default=70, ge=0, le=100)
    threshold_critical: int = Field(default=90, ge=0, le=100)

    policy_safe: Decision = Decision.ALLOW
    policy_low: Decision = Decision.ALLOW
    policy_medium: Decision = Decision.SANITIZE
    policy_high: Decision = Decision.BLOCK
    policy_critical: Decision = Decision.BLOCK

    llm_provider: LLMProviderName = Field(default=LLMProviderName.ANTHROPIC)
    llm_model: str = Field(
        default="claude-sonnet-4-6",
        description="Model identifier passed to the selected provider's API.",
    )
    openai_api_key: str | None = Field(default=None)
    openai_base_url: str | None = Field(
        default=None,
        description=(
            "Optional override for the OpenAI-compatible endpoint. Leave "
            "unset to use OpenAI's own servers. Set this to use any "
            "OpenAI-API-compatible provider instead — e.g. Groq "
            "(https://api.groq.com/openai/v1) or OpenRouter "
            "(https://openrouter.ai/api/v1) — while keeping "
            "LLM_PROVIDER=openai."
        ),
    )
    anthropic_api_key: str | None = Field(default=None)
    local_llm_base_url: str | None = Field(
        default=None,
        description="Base URL for a local/self-hosted OpenAI-compatible endpoint.",
    )
    llm_request_timeout_seconds: int = Field(default=30, ge=1)

    app_title: str = "SecureAI"
    demo_mode_enabled: bool = Field(
        default=True,
        description="Whether the sidebar demo-scenario picker is shown.",
    )

    @field_validator("threshold_medium")
    @classmethod
    def _medium_above_low(cls, v: int, info) -> int:
        low = info.data.get("threshold_low", 0)
        if v <= low:
            raise ValueError("threshold_medium must be greater than threshold_low")
        return v

    @field_validator("threshold_high")
    @classmethod
    def _high_above_medium(cls, v: int, info) -> int:
        medium = info.data.get("threshold_medium", 0)
        if v <= medium:
            raise ValueError("threshold_high must be greater than threshold_medium")
        return v

    @field_validator("threshold_critical")
    @classmethod
    def _critical_above_high(cls, v: int, info) -> int:
        high = info.data.get("threshold_high", 0)
        if v <= high:
            raise ValueError("threshold_critical must be greater than threshold_high")
        return v

    def model_path(self, subfolder: str) -> str:
        """Resolve a configured model subfolder to a full path string."""
        return str(self.models_dir / subfolder)

    def risk_level_for_score(self, score: int) -> RiskLevel:
        """Map a 0-100 risk score to its RiskLevel band."""
        if score >= self.threshold_critical:
            return RiskLevel.CRITICAL
        if score >= self.threshold_high:
            return RiskLevel.HIGH
        if score >= self.threshold_medium:
            return RiskLevel.MEDIUM
        if score >= self.threshold_low:
            return RiskLevel.LOW
        return RiskLevel.SAFE

    def decision_for_level(self, level: RiskLevel) -> Decision:
        """Map a RiskLevel to the configured policy Decision."""
        mapping = {
            RiskLevel.SAFE: self.policy_safe,
            RiskLevel.LOW: self.policy_low,
            RiskLevel.MEDIUM: self.policy_medium,
            RiskLevel.HIGH: self.policy_high,
            RiskLevel.CRITICAL: self.policy_critical,
        }
        return mapping[level]


settings = Settings()
