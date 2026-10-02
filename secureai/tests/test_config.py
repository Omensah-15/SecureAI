"""Tests for config.py: risk band boundaries, policy mapping, and validation."""

from __future__ import annotations

import pytest

from config import Decision, RiskLevel, Settings, settings


class TestRiskLevelBoundaries:
    """The exact edges matter: an off-by-one here silently changes what
    gets blocked vs. allowed in production."""

    @pytest.mark.parametrize(
        "score,expected_level",
        [
            (0, RiskLevel.SAFE),
            (19, RiskLevel.SAFE),
            (20, RiskLevel.LOW),
            (39, RiskLevel.LOW),
            (40, RiskLevel.MEDIUM),
            (69, RiskLevel.MEDIUM),
            (70, RiskLevel.HIGH),
            (89, RiskLevel.HIGH),
            (90, RiskLevel.CRITICAL),
            (100, RiskLevel.CRITICAL),
        ],
    )
    def test_score_maps_to_expected_band(self, score: int, expected_level: RiskLevel) -> None:
        assert settings.risk_level_for_score(score) == expected_level


class TestPolicyMapping:
    def test_safe_and_low_allow(self) -> None:
        assert settings.decision_for_level(RiskLevel.SAFE) == Decision.ALLOW
        assert settings.decision_for_level(RiskLevel.LOW) == Decision.ALLOW

    def test_medium_sanitizes(self) -> None:
        assert settings.decision_for_level(RiskLevel.MEDIUM) == Decision.SANITIZE

    def test_high_and_critical_block(self) -> None:
        assert settings.decision_for_level(RiskLevel.HIGH) == Decision.BLOCK
        assert settings.decision_for_level(RiskLevel.CRITICAL) == Decision.BLOCK


class TestThresholdValidation:
    """Misconfigured thresholds must fail loudly at startup, not silently
    produce wrong security decisions later."""

    def test_rejects_medium_below_low(self) -> None:
        with pytest.raises(ValueError):
            Settings(threshold_low=20, threshold_medium=10)

    def test_rejects_high_below_medium(self) -> None:
        with pytest.raises(ValueError):
            Settings(threshold_medium=40, threshold_high=30)

    def test_rejects_critical_below_high(self) -> None:
        with pytest.raises(ValueError):
            Settings(threshold_high=70, threshold_critical=60)

    def test_accepts_valid_ordering(self) -> None:
        s = Settings(threshold_low=10, threshold_medium=30, threshold_high=60, threshold_critical=85)
        assert s.threshold_low < s.threshold_medium < s.threshold_high < s.threshold_critical
