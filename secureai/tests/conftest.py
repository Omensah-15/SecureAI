"""
Shared pytest fixtures for the SecureAI test suite.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from config import settings
from engine import SecurityEngine


@pytest.fixture
def isolated_audit_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Points settings.audit_db_path at a fresh temp file for the duration
    of one test, so AuditLog reads/writes never touch the real database."""
    db_path = tmp_path / "test_audit.db"
    monkeypatch.setattr(settings, "audit_db_path", db_path)
    return db_path


@pytest.fixture
def engine(isolated_audit_db: Path) -> SecurityEngine:
    """A SecurityEngine with no real model weights loaded. Each detector
    pipeline is a MagicMock the individual test configures with
    `.return_value = [...]` to simulate a specific classifier output.

    Default mock shapes/labels match the real confirmed outputs of the
    project's four models (see engine.py's _OUTPUT_SAFETY_LABEL_NAMES and
    _detect_toxicity docstring): prompt-injection uses SAFE/INJECTION,
    output-safety uses KoalaAI's OK/H/H2/etc. codes, and toxicity is
    multi-label with no safe label at all — a "clean" default means every
    one of its 6 categories scoring low, not a single "NOT_TOXIC" label.
    """
    eng = SecurityEngine(load_models=False)
    eng.injection_clf = MagicMock(return_value=[{"label": "SAFE", "score": 0.99}])
    eng.pii_clf = MagicMock(return_value=[])
    eng.output_safety_clf = MagicMock(return_value=[[{"label": "OK", "score": 0.99}]])
    eng.toxicity_clf = MagicMock(return_value=[[
        {"label": "toxic", "score": 0.02},
        {"label": "severe_toxic", "score": 0.01},
        {"label": "obscene", "score": 0.01},
        {"label": "threat", "score": 0.01},
        {"label": "insult", "score": 0.02},
        {"label": "identity_hate", "score": 0.01},
    ]])
    return eng
