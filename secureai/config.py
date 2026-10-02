"""
SecureAI configuration module.
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

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------
    models_dir: Path = Field(
        default=Path("./models"),
        description="Root directory containing the locally downloaded model folders.",
    )
    audit_db_path: Path = Field(
        default=Path("./audit_log.db"),
        description="SQLite database file for the security audit log.",
    )

    # ------------------------------------------------------------------
    # Model subfolder names (relative to models_dir)
    # ------------------------------------------------------------------
    prompt_injection_model_dir: str = "prompt-injection"
    pii_detection_model_dir: str = "pii-detection"
    output_safety_model_dir: str = "output-safety"
    toxicity_model_dir: str = "toxicity"

    # ------------------------------------------------------------------
    # Detector behavior
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Risk scoring weights
    # ------------------------------------------------------------------
    # Each weight is the maximum points a fully-confident finding in that
    # category contributes to the 0-100 risk score. Actual contribution is
    # weight * confidence, then combined across categories (see engine.py).
    weight_secret: int = Field(default=45, ge=0, le=100)
    weight_pii: int = Field(default=25, ge=0, le=100)
    weight_injection: int = Field(default=40, ge=0, le=100)
    weight_toxicity: int = Field(default=15, ge=0, le=100)
    weight_output_safety: int = Field(default=40, ge=0, le=100)
    # Weight for each distinct recognized attack SUB-TECHNIQUE (instruction
    # override, role hijack, system-prompt extraction, defense evasion,
    # data exfiltration, indirect injection) found within a prompt the
    # injection classifier has already flagged. Deliberately smaller than
    # weight_injection itself — this is corroborating evidence for an
    # already-flagged prompt, not an independent primary signal — but
    # large enough that combining several techniques (a real multi-stage
    # attack) meaningfully raises the score above a single simple attempt,
    # via the same diminishing-returns combination already used for every
    # other category (see SecurityEngine.compute_risk_score).
    weight_injection_technique: int = Field(default=25, ge=0, le=100)
    # Output-side: the model's OWN response disclosing system/developer
    # instructions (distinct from a user merely ASKING for them, which is
    # the input-side SYSTEM_PROMPT_EXTRACTION technique above). Weighted
    # close to weight_injection since actual disclosure, not just a
    # request for it, is a more concrete outcome.
    weight_instruction_leakage: int = Field(default=35, ge=0, le=100)

    # ------------------------------------------------------------------
    # Gateway hardening
    # ------------------------------------------------------------------
    # Character-length guard applied BEFORE any detector runs (gitleaks
    # subprocess, ML classifiers, regex matching) — distinct from
    # max_input_tokens above, which only bounds what a tokenizer sees
    # AFTER a classifier call has already started. This exists purely to
    # cheaply reject an oversized request (a denial-of-service vector
    # against the detectors themselves) without spending any real work
    # on it. 8000 characters is generous for ordinary chat use (roughly
    # 1500-2000 words).
    max_prompt_length: int = Field(default=8000, ge=100)
    # Weight for the OVERSIZED_INPUT finding (see scan_prompt/scan_response's
    # length guard). Maximal by default: exceeding a hard configured
    # length limit is a deterministic policy violation, not a
    # probabilistic judgment call, so it forces BLOCK regardless of
    # score via the same category-based hard-override pattern already
    # used for HIGH/CRITICAL prompt-injection findings (see
    # SecurityEngine._score_and_decide) — this weight mainly affects the
    # REPORTED score for audit/explainability purposes, not the decision.
    weight_oversized_input: int = Field(default=100, ge=0, le=100)
    # Weight for GUARD_* findings: categories the hosted Guard flagged on a
    # prompt that none of the local detectors has a counterpart for
    # (unsafe links, prohibited content, harmful content, "other"). Like
    # OVERSIZED_INPUT these are a deterministic rejection by the Guard, not
    # a probabilistic judgment, so the engine forces BLOCK for them (only
    # when the Guard backend is active) and this weight affects the
    # REPORTED score only. Never used with local models.
    weight_guard_policy: int = Field(default=100, ge=0, le=100)

    # ------------------------------------------------------------------
    # Risk band thresholds (inclusive lower bound of each band)
    # ------------------------------------------------------------------
    threshold_low: int = Field(default=20, ge=0, le=100)
    threshold_medium: int = Field(default=40, ge=0, le=100)
    threshold_high: int = Field(default=70, ge=0, le=100)
    threshold_critical: int = Field(default=90, ge=0, le=100)

    # ------------------------------------------------------------------
    # Policy: which decision each risk level maps to by default.
    # MEDIUM defaults to SANITIZE (user can review/redact-and-continue),
    # HIGH and CRITICAL default to BLOCK, per the spec's "default to
    # blocking on critical risk" requirement.
    # ------------------------------------------------------------------
    policy_safe: Decision = Decision.ALLOW
    policy_low: Decision = Decision.ALLOW
    policy_medium: Decision = Decision.SANITIZE
    policy_high: Decision = Decision.BLOCK
    policy_critical: Decision = Decision.BLOCK

    # ------------------------------------------------------------------
    # LLM provider
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Organizer-hosted services (all optional; see .env.example)
    # ------------------------------------------------------------------
    # Secrets: set via environment / .env only -- never hardcode.
    guard_url: str | None = Field(
        default=None,
        description="Base URL of the hosted Guard API. With GUARD_TOKEN, replaces the local detector models.",
    )
    guard_token: str | None = Field(default=None, description="Bearer token for the Guard API (sai_...).")
    guard_timeout_seconds: float = Field(default=10.0, gt=0)
    guard_fail_on_partial: bool = Field(
        default=True,
        description=(
            "If the Guard reports status=partial / a check with ran=false and "
            "nothing else was flagged, treat the scan as FAILED (fail closed) "
            "instead of as clean."
        ),
    )
    use_local_models: bool = Field(
        default=False,
        description="Force the local pretrained detectors even if GUARD_URL/GUARD_TOKEN are set.",
    )
    llm_api_key: str | None = Field(
        default=None,
        description="API key for the organizers' LLM. When set, takes precedence over LLM_PROVIDER's own key.",
    )
    llm_base_url: str | None = Field(
        default=None,
        description=(
            "Base URL of the organizers' LLM endpoint (from the organizers' documentation). "
            "Required when LLM_API_KEY is set; the key is only ever sent to this URL."
        ),
    )

    # ------------------------------------------------------------------
    # App / demo
    # ------------------------------------------------------------------
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

    def use_guard_backend(self) -> bool:
        """True when the detectors should run through the hosted Guard. Any
        Guard credential being set opts in (a half-configured Guard is then
        reported as an error by GuardClient rather than silently ignored);
        USE_LOCAL_MODELS=true forces the local models."""
        return (not self.use_local_models) and bool(self.guard_url or self.guard_token)

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
