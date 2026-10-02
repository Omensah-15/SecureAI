"""
Thin adapter between SecureAI's engine and the hosted Guard API.
"""

from __future__ import annotations

import contextvars
import logging
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

logger = logging.getLogger("secureai.guard")


class GuardError(RuntimeError):
    """The Guard could not produce a trustworthy verdict. Callers must
    treat this as 'security check did not complete', never as 'safe'."""


# ----------------------------------------------------------------------
# Pipeline stage (prompt vs response)
# ----------------------------------------------------------------------
# The engine's PII detector is shared by both pipeline stages but only
# receives text, while the Guard has a separate endpoint per stage.
# scan_prompt()/scan_response() record which stage they are running in a
# ContextVar (per-thread/per-task, so concurrent Streamlit sessions can't
# see each other's value).
_stage: contextvars.ContextVar[str] = contextvars.ContextVar("secureai_guard_stage", default="prompt")


def set_stage(stage: str) -> None:
    if stage not in ("prompt", "response"):
        raise ValueError(f"Unknown Guard stage: {stage!r}")
    _stage.set(stage)


def get_stage() -> str:
    return _stage.get()


# ----------------------------------------------------------------------
# Guard contract constants (from the organizers' Guard API documentation)
# ----------------------------------------------------------------------
# Documented categories. `flags` may also contain "other".
_KNOWN_CHECKS = ("injection", "harmful_content", "sensitive_data", "unsafe_links", "prohibited_content")

# Documented limit is "under 4,000 characters" per request. Longer text
# (an LLM answer easily exceeds this) is checked in overlapping chunks and
# the verdicts are OR-merged, so a long response is not rejected outright
# with HTTP 413 and an injection straddling a chunk boundary is still seen.
_CHUNK_CHARS = 3800
_CHUNK_OVERLAP = 200

_MAX_RETRY_AFTER_SECONDS = 10.0
_CACHE_MAX_ENTRIES = 64
_CACHE_TTL_SECONDS = 120.0

# The Guard documents `confidence` ("HIGH" in its example) but not the full
# set of values, and its policy is to block on ANY flag (allowed=false).
# Every flagged injection is therefore mapped to a score >= 0.70 so the
# engine's severity ladder yields HIGH/CRITICAL and its existing hard
# BLOCK override applies; unknown/missing confidence fails toward caution.
_INJECTION_CONFIDENCE_SCORE = {"HIGH": 0.99, "MEDIUM": 0.85, "LOW": 0.75}
_INJECTION_UNKNOWN_CONFIDENCE_SCORE = 0.95

_TOXICITY_LABELS = ("toxic", "severe_toxic", "obscene", "threat", "insult", "identity_hate")


# ----------------------------------------------------------------------
# HTTP client
# ----------------------------------------------------------------------

class GuardClient:
    """Calls the Guard and returns a validated, normalized verdict:

        {"flags": set[str],            # categories flagged (+ "other")
         "checks": {name: {"ran": bool, "flagged": bool,
                           "types": list[str], "confidence": str | None}},
         "status": "complete" | "partial" | ...,
         "request_ids": list[str]}

    Thread-safe (Streamlit shares one engine across sessions).
    """

    def __init__(
        self,
        base_url: str | None,
        token: str | None,
        timeout: float = 10.0,
        fail_on_partial: bool = True,
    ) -> None:
        if not base_url:
            raise GuardError("GUARD_URL is not set (the hosted Guard is configured but has no URL).")
        if not token:
            raise GuardError("GUARD_TOKEN is not set (the hosted Guard is configured but has no token).")
        parsed = urlparse(base_url.strip())
        # The bearer token must not travel in clear text to a remote host.
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")
        ):
            raise GuardError("GUARD_URL must be an https:// URL.")
        self._base_url = base_url.strip().rstrip("/")
        self._token = token.strip()
        self._timeout = timeout
        self._fail_on_partial = fail_on_partial

        import httpx  # lazy, matching the LLM providers' style in engine.py

        self._httpx = httpx
        self._http = httpx.Client(timeout=timeout)  # keep-alive: Guard calls are latency-sensitive

        self._cache: OrderedDict[tuple[str, str], tuple[float, dict[str, Any]]] = OrderedDict()
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, stage: str, text: str) -> dict[str, Any]:
        """Verdict for `text` at `stage` ("prompt" | "response"). One Guard
        request per distinct (stage, text) is shared by every adapter that
        needs it (results are cached briefly), so a scan costs one call, not
        one per detector. Raises GuardError on any failure."""
        if stage not in ("prompt", "response"):
            raise GuardError(f"Unknown Guard stage: {stage!r}")
        if not isinstance(text, str):
            raise GuardError("Guard input must be a string.")
        if not text.strip():
            return _empty_verdict()  # the Guard rejects empty text (400); there is nothing to check

        key = (stage, text)
        now = time.monotonic()
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < _CACHE_TTL_SECONDS:
                self._cache.move_to_end(key)
                return hit[1]

        verdicts = [self._check_one(stage, chunk) for chunk in _chunks(text)]
        verdict = verdicts[0] if len(verdicts) == 1 else _merge(verdicts)

        with self._cache_lock:
            self._cache[key] = (now, verdict)
            self._cache.move_to_end(key)
            while len(self._cache) > _CACHE_MAX_ENTRIES:
                self._cache.popitem(last=False)
        return verdict

    # ------------------------------------------------------------------
    # One request
    # ------------------------------------------------------------------

    def _check_one(self, stage: str, text: str) -> dict[str, Any]:
        url = f"{self._base_url}/v1/check/{stage}"
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}
        httpx = self._httpx

        for attempt in (1, 2):
            try:
                resp = self._http.post(url, json={"text": text}, headers=headers)
            except httpx.TimeoutException as exc:
                raise GuardError(f"Guard request timed out after {self._timeout:g}s.") from exc
            except httpx.HTTPError as exc:
                raise GuardError(f"Guard service unreachable ({type(exc).__name__}).") from exc

            status = resp.status_code
            if status == 200:
                return self._parse(resp)

            code = _error_code(resp)
            if status == 429 and code != "daily_quota_exceeded" and attempt == 1:
                wait = _retry_after(resp)
                logger.warning("Guard rate limited; retrying once after %.1fs.", wait)
                time.sleep(wait)
                continue
            if status in (502, 503) and attempt == 1:
                logger.warning("Guard temporarily unavailable (%s); retrying once.", status)
                time.sleep(1.0)
                continue
            raise GuardError(_describe_http_error(status, code))

        raise GuardError("Guard request failed.")  # unreachable; keeps type-checkers happy

    def _parse(self, resp: Any) -> dict[str, Any]:
        try:
            data = resp.json()
        except ValueError as exc:
            raise GuardError("Guard returned a non-JSON response.") from exc
        if not isinstance(data, dict) or not isinstance(data.get("allowed"), bool):
            raise GuardError("Guard returned an unexpected response (missing 'allowed').")
        raw_checks = data.get("checks")
        if not isinstance(raw_checks, dict):
            raise GuardError("Guard returned an unexpected response (missing 'checks').")
        raw_flags = data.get("flags", [])
        if not isinstance(raw_flags, list):
            raise GuardError("Guard returned an unexpected response (bad 'flags').")

        checks: dict[str, dict[str, Any]] = {}
        for name in _KNOWN_CHECKS:
            entry = raw_checks.get(name)
            if not isinstance(entry, dict):
                # A category we expect is absent: treat as "did not run".
                checks[name] = {"ran": False, "flagged": False, "types": [], "confidence": None}
                continue
            types = entry.get("types", [])
            checks[name] = {
                "ran": entry.get("ran") is True,
                "flagged": entry.get("flagged") is True,
                "types": [str(t) for t in types] if isinstance(types, list) else [],
                "confidence": str(entry["confidence"]).upper() if entry.get("confidence") else None,
            }

        flags = {name for name, c in checks.items() if c["flagged"]}
        flags |= {str(f) for f in raw_flags}
        if not data["allowed"] and not flags:
            flags.add("other")  # rejected for a reason we couldn't attribute: still a rejection

        status = str(data.get("status", "complete"))
        request_id = str(data.get("request_id", ""))
        partial = status != "complete" or any(not c["ran"] for c in checks.values())
        if partial and self._fail_on_partial and not flags:
            # Some checks never ran and nothing else was flagged: we cannot
            # claim the text is safe. (If something WAS flagged we return it;
            # the rejection stands regardless of the checks that didn't run.)
            raise GuardError(f"Guard returned a partial result (some checks did not run) [request_id={request_id}].")

        return {"flags": flags, "checks": checks, "status": status, "request_ids": [request_id]}


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _empty_verdict() -> dict[str, Any]:
    return {
        "flags": set(),
        "checks": {n: {"ran": True, "flagged": False, "types": [], "confidence": None} for n in _KNOWN_CHECKS},
        "status": "complete",
        "request_ids": [],
    }


def _chunks(text: str) -> list[str]:
    if len(text) <= _CHUNK_CHARS:
        return [text]
    out, step, i = [], _CHUNK_CHARS - _CHUNK_OVERLAP, 0
    while i < len(text):
        out.append(text[i : i + _CHUNK_CHARS])
        if i + _CHUNK_CHARS >= len(text):
            break
        i += step
    return out


def _merge(verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    """OR-merge per-chunk verdicts: anything flagged in any chunk is flagged."""
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}
    merged = _empty_verdict()
    merged["request_ids"] = []
    for v in verdicts:
        merged["flags"] |= v["flags"]
        merged["request_ids"] += v["request_ids"]
        if v["status"] != "complete":
            merged["status"] = v["status"]
        for name, c in v["checks"].items():
            m = merged["checks"][name]
            m["ran"] = m["ran"] and c["ran"]
            m["flagged"] = m["flagged"] or c["flagged"]
            m["types"] = sorted(set(m["types"]) | set(c["types"]))
            if order.get(c["confidence"], 0) > order.get(m["confidence"], 0):
                m["confidence"] = c["confidence"]
    return merged


def _error_code(resp: Any) -> str:
    try:
        body = resp.json()
        return str(body.get("error", "")) if isinstance(body, dict) else ""
    except ValueError:
        return ""


def _retry_after(resp: Any) -> float:
    try:
        return max(0.0, min(float(resp.headers.get("Retry-After", 1)), _MAX_RETRY_AFTER_SECONDS))
    except (TypeError, ValueError):
        return 1.0


def _describe_http_error(status: int, code: str) -> str:
    if status == 401:
        return "Guard authentication failed (check GUARD_TOKEN)."
    if status == 429 and code == "daily_quota_exceeded":
        return "Guard daily quota exhausted (resets at 00:00 UTC)."
    if status == 429:
        return "Guard rate limit exceeded (30 requests/minute by default); try again shortly."
    if status == 413:
        return "Guard rejected the text as too long."
    if status == 400:
        return f"Guard rejected the request ({code or 'bad request'})."
    if status in (502, 503):
        return f"Guard service unavailable (HTTP {status})."
    return f"Guard returned an unexpected HTTP {status}."


def _label(name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_") or "OTHER"


def unsafe_labels(verdict: dict[str, Any], exclude: tuple[str, ...] = ()) -> list[str]:
    """Readable category names for everything flagged in `verdict` except
    `exclude`. harmful_content expands to the Guard's own `types`."""
    out: list[str] = []
    for name in sorted(verdict["flags"], key=lambda n: (n != "prohibited_content", n != "harmful_content", n)):
        if name in exclude:
            continue
        if name == "harmful_content":
            out += [_label(t) for t in verdict["checks"]["harmful_content"]["types"]] or ["HARMFUL_CONTENT"]
        else:
            out.append(_label(name))
    return out


# ----------------------------------------------------------------------
# The four drop-in replacements for the local HF pipelines
# ----------------------------------------------------------------------

@dataclass
class GuardClassifiers:
    injection: Callable[[str], list]
    pii: Callable[[str], list]
    output_safety: Callable[[str], list]
    toxicity: Callable[[str], list]


def build_guard_classifiers(client: GuardClient) -> GuardClassifiers:
    """Each callable mirrors the output shape of the local pipeline it
    replaces, so the engine's detectors consume it unchanged."""

    def injection(text: str) -> list[dict[str, Any]]:
        # Local shape: [{"label": "INJECTION" | "SAFE", "score": float}]
        v = client.check("prompt", text)
        if "injection" in v["flags"]:
            conf = v["checks"]["injection"]["confidence"]
            return [{"label": "INJECTION", "score": _INJECTION_CONFIDENCE_SCORE.get(conf, _INJECTION_UNKNOWN_CONFIDENCE_SCORE)}]
        return [{"label": "SAFE", "score": 0.99}]

    def pii(text: str) -> list[dict[str, Any]]:
        # Local shape: [{"entity_group", "score", "word", "start", "end"}].
        # The Guard reports "sensitive_data" as a yes/no with NO character
        # offsets, so the entity is span-less; the engine blocks (rather than
        # sanitizes) span-less sensitive-data findings, since there is
        # nothing it could redact.
        v = client.check(get_stage(), text)
        if "sensitive_data" in v["flags"]:
            return [{"entity_group": "SENSITIVE_DATA", "score": 0.99, "word": None, "start": None, "end": None}]
        return []

    def output_safety(text: str) -> list[list[dict[str, Any]]]:
        # Local shape: [[{"label", "score"}, ...]] with an "OK" class; the
        # engine flags when 1 - P(OK) >= 0.5 and names the top non-OK label.
        # sensitive_data is reported through the PII path above, not here.
        v = client.check("response", text)
        labels = unsafe_labels(v, exclude=("sensitive_data",))
        if not labels:
            return [[{"label": "OK", "score": 0.99}]]
        scores = [{"label": "OK", "score": 0.01}]
        scores += [{"label": lab, "score": 0.99 - 0.01 * i} for i, lab in enumerate(labels)]
        return [scores]

    def toxicity(text: str) -> list[list[dict[str, Any]]]:
        # The Guard's single harmful_content check is already surfaced via
        # output_safety above; reporting it here as well would double-count
        # the same signal, so this detector reports "nothing" without a call.
        return [[{"label": lab, "score": 0.0} for lab in _TOXICITY_LABELS]]

    return GuardClassifiers(injection=injection, pii=pii, output_safety=output_safety, toxicity=toxicity)
