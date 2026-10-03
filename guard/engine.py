"""
engine.py - secured chat engine for the SecureAI hackathon.

Every user message is checked by the organizer's Guard API before it reaches
the LLM, and every LLM reply is checked by the Guard API before it reaches
the user. If the Guard cannot give a clear verdict, the message or reply is
withheld (fail closed).

Configuration comes only from `.env`:

    GUARD_URL     base URL of the Guard API (required)
    GUARD_TOKEN   team token for the Guard API (required)
    LLM_API_KEY   organizer LLM key (required)

Optional (the provider is detected from the key prefix when not set):

    LLM_PROVIDER  openai | anthropic | groq | gemini | openrouter | custom
    LLM_BASE_URL  OpenAI-compatible base URL (required for "custom")
    LLM_MODEL     model name

Run `python engine.py --check` to verify the whole chain from the terminal.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

ENV_PATH = Path(__file__).resolve().parent / ".env"

MAX_GUARD_TEXT = 4000          # Guard maximum text length
MAX_RESPONSE_CHUNKS = 4        # longest reply we will verify (4 x 4000 chars)
GUARD_REQUESTS_PER_MINUTE = 25 # stay under the organizer limit of ~30/min
CONNECT_TIMEOUT = 10
GUARD_READ_TIMEOUT = 45
LLM_READ_TIMEOUT = 90

MAX_HISTORY_MESSAGES = 20      # messages of context sent to the LLM
MAX_HISTORY_CHARS = 12000
LLM_MAX_TOKENS = 1200

SYSTEM_PROMPT = (
    "You are a helpful, accurate and concise assistant. Answer clearly. "
    "Keep answers under about 600 words unless the user asks for more."
)

PROVIDERS: Dict[str, Dict[str, str]] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "model": "claude-haiku-4-5-20251001",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.0-flash",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "model": "openai/gpt-4o-mini",
    },
}

BLOCKED_PROMPT_MESSAGE = (
    "Your message was blocked by the security check and was not sent to the AI."
)
BLOCKED_RESPONSE_MESSAGE = (
    "The AI's reply was withheld because it failed the security check."
)


class ConfigError(Exception):
    """Configuration is missing or still a placeholder."""


# --------------------------------------------------------------------------- #
# Configuration and credential safety
# --------------------------------------------------------------------------- #


def _clean(value: Optional[str]) -> str:
    return (value or "").strip().strip('"').strip("'").strip()


def _is_placeholder(value: str) -> bool:
    return (not value) or ("<" in value and ">" in value)


@dataclass
class Config:
    guard_url: str
    guard_token: str
    llm_key: str
    provider: str
    llm_base_url: str
    llm_model: str


def detect_provider(key: str) -> str:
    if key.startswith("sk-ant-"):
        return "anthropic"
    if key.startswith("gsk_"):
        return "groq"
    if key.startswith("AIza"):
        return "gemini"
    if key.startswith("sk-or-"):
        return "openrouter"
    return "openai"


def load_config() -> Config:
    """Read .env on every call so edits apply without restarting."""
    load_dotenv(ENV_PATH, override=True)
    guard_url = _clean(os.getenv("GUARD_URL"))
    guard_token = _clean(os.getenv("GUARD_TOKEN"))
    llm_key = _clean(os.getenv("LLM_API_KEY"))

    missing = [
        name
        for name, value in (
            ("GUARD_URL", guard_url),
            ("GUARD_TOKEN", guard_token),
            ("LLM_API_KEY", llm_key),
        )
        if _is_placeholder(value)
    ]
    if missing:
        raise ConfigError(
            "Missing or placeholder values in .env: " + ", ".join(missing)
        )
    if not re.match(r"^https?://[^\s/]+", guard_url):
        raise ConfigError("GUARD_URL must start with http:// or https://")

    provider = _clean(os.getenv("LLM_PROVIDER")).lower() or detect_provider(llm_key)
    if provider != "custom" and provider not in PROVIDERS:
        raise ConfigError(
            "LLM_PROVIDER must be one of: " + ", ".join(list(PROVIDERS) + ["custom"])
        )
    defaults = PROVIDERS.get(provider, {})
    base_url = _clean(os.getenv("LLM_BASE_URL")) or defaults.get("base_url", "")
    model = _clean(os.getenv("LLM_MODEL")) or defaults.get("model", "")
    if not base_url or not re.match(r"^https?://[^\s/]+", base_url):
        raise ConfigError("LLM_BASE_URL is required and must start with http(s)://")
    if not model:
        raise ConfigError("LLM_MODEL is required for a custom provider")

    return Config(
        guard_url=guard_url.rstrip("/"),
        guard_token=guard_token,
        llm_key=llm_key,
        provider=provider,
        llm_base_url=base_url.rstrip("/"),
        llm_model=model,
    )


def scrub(text: Any, cfg: Optional[Config] = None) -> str:
    """Remove credential values and bearer tokens from any string."""
    text = str(text)
    if cfg is not None:
        for secret in (cfg.guard_token, cfg.llm_key):
            if len(secret) >= 4:
                text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._\-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)(x-api-key|api[_-]?key)(\W{1,4})[A-Za-z0-9._\-]{8,}",
                  r"\1\2[REDACTED]", text)
    return text


# --------------------------------------------------------------------------- #
# Rate limiting (rolling window, only waits when the limit is close)
# --------------------------------------------------------------------------- #

_rate_lock = threading.Lock()
_recent: deque = deque()


def _rate_limit() -> None:
    with _rate_lock:
        while True:
            now = time.monotonic()
            while _recent and now - _recent[0] >= 60.0:
                _recent.popleft()
            if len(_recent) < GUARD_REQUESTS_PER_MINUTE:
                _recent.append(now)
                return
            time.sleep(max(_recent[0] + 60.0 - now, 0.05))


# --------------------------------------------------------------------------- #
# Guard API
# --------------------------------------------------------------------------- #


@dataclass
class GuardVerdict:
    allowed: bool
    flags: List[str] = field(default_factory=list)
    reason: str = ""            # user-safe explanation when not allowed
    request_id: Optional[str] = None
    error: bool = False         # True when no clear verdict could be obtained


def _flagged_check_names(checks: Any) -> List[str]:
    names: List[str] = []
    if isinstance(checks, dict):
        for name, info in checks.items():
            if isinstance(info, dict) and info.get("flagged"):
                names.append(str(name))
    return names


def _humanize(names: List[str]) -> str:
    cleaned = [n.replace("_", " ").replace("-", " ") for n in names if n]
    seen: List[str] = []
    for item in cleaned:
        if item not in seen:
            seen.append(item)
    return ", ".join(seen)


def _guard_once(cfg: Config, endpoint: str, text: str) -> GuardVerdict:
    url = cfg.guard_url + endpoint
    headers = {
        "Authorization": f"Bearer {cfg.guard_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    _rate_limit()
    try:
        resp = requests.post(
            url,
            headers=headers,
            json={"text": text},
            timeout=(CONNECT_TIMEOUT, GUARD_READ_TIMEOUT),
            allow_redirects=False,
        )
    except requests.exceptions.Timeout:
        return GuardVerdict(False, reason="The security service timed out.", error=True)
    except requests.exceptions.RequestException:
        return GuardVerdict(False, reason="The security service is unreachable.", error=True)

    if resp.status_code == 429:
        return GuardVerdict(
            False,
            reason="The security service is rate limited. Please wait a moment and try again.",
            error=True,
        )
    if resp.status_code in (401, 403):
        return GuardVerdict(
            False,
            reason="The security service rejected the token. Check GUARD_TOKEN in .env.",
            error=True,
        )
    if resp.status_code >= 300:
        return GuardVerdict(
            False,
            reason=f"The security service returned HTTP {resp.status_code}.",
            error=True,
        )

    try:
        data = resp.json()
    except ValueError:
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("allowed"), bool):
        return GuardVerdict(False, reason="The security service gave an unreadable verdict.", error=True)

    status = data.get("status")
    checks = data.get("checks")
    flags = [str(f) for f in data.get("flags") or []] if isinstance(data.get("flags"), list) else []
    request_id = data.get("request_id")
    request_id = str(request_id) if request_id is not None else None

    if isinstance(status, str) and status.strip().lower() != "complete":
        return GuardVerdict(
            False, flags=flags, request_id=request_id, error=True,
            reason="The security check did not complete.",
        )
    if isinstance(checks, dict):
        not_run = [n for n, i in checks.items() if isinstance(i, dict) and i.get("ran") is False]
        if not_run:
            return GuardVerdict(
                False, flags=flags, request_id=request_id, error=True,
                reason="The security check did not complete.",
            )

    if data["allowed"]:
        return GuardVerdict(True, flags=flags, request_id=request_id)

    names = flags or _flagged_check_names(checks)
    reason = _humanize(names)
    return GuardVerdict(False, flags=flags, request_id=request_id, reason=reason)


def check_prompt(cfg: Config, text: str) -> GuardVerdict:
    """Guard check for a user message. Fails closed."""
    if not isinstance(text, str) or not text.strip():
        return GuardVerdict(False, reason="The message is empty.", error=True)
    if len(text) > MAX_GUARD_TEXT:
        return GuardVerdict(
            False,
            reason=f"The message is too long. The limit is {MAX_GUARD_TEXT} characters.",
            error=True,
        )
    return _guard_once(cfg, "/v1/check/prompt", text)


def split_for_guard(text: str, size: int = MAX_GUARD_TEXT) -> List[str]:
    """Split text into pieces of at most `size` characters, preferring line breaks."""
    chunks: List[str] = []
    rest = text
    while len(rest) > size:
        cut = rest.rfind("\n", int(size * 0.5), size)
        if cut == -1:
            cut = rest.rfind(" ", int(size * 0.5), size)
        if cut == -1:
            cut = size
        chunks.append(rest[:cut])
        rest = rest[cut:]
    if rest.strip():
        chunks.append(rest)
    return chunks


def check_response(cfg: Config, text: str) -> GuardVerdict:
    """Guard check for an LLM reply. Long replies are checked piece by piece."""
    if not isinstance(text, str) or not text.strip():
        return GuardVerdict(False, reason="The AI returned an empty reply.", error=True)
    chunks = split_for_guard(text)
    if len(chunks) > MAX_RESPONSE_CHUNKS:
        return GuardVerdict(
            False,
            reason="The reply is too long to be verified.",
            error=True,
        )
    all_flags: List[str] = []
    for chunk in chunks:
        verdict = _guard_once(cfg, "/v1/check/response", chunk)
        if not verdict.allowed:
            return verdict
        all_flags.extend(verdict.flags)
    return GuardVerdict(True, flags=all_flags)


# --------------------------------------------------------------------------- #
# LLM
# --------------------------------------------------------------------------- #


class LLMError(Exception):
    """Raised with a user-safe message when the LLM call fails."""


def trim_history(messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Keep the most recent messages within the count and size budgets,
    always starting on a user message."""
    kept: List[Dict[str, str]] = []
    total = 0
    for msg in reversed(messages):
        total += len(msg["content"])
        if len(kept) >= MAX_HISTORY_MESSAGES or (kept and total > MAX_HISTORY_CHARS):
            break
        kept.append(msg)
    kept.reverse()
    while kept and kept[0]["role"] != "user":
        kept.pop(0)
    return kept


def _llm_error_message(cfg: Config, resp: requests.Response) -> str:
    detail = ""
    try:
        data = resp.json()
        err = data.get("error", data) if isinstance(data, dict) else data
        if isinstance(err, dict):
            detail = str(err.get("message") or err.get("detail") or "")
        else:
            detail = str(err)
    except ValueError:
        detail = (resp.text or "")[:200]
    detail = scrub(detail, cfg).strip()[:240]
    base = {
        401: "The LLM rejected the API key. Check LLM_API_KEY in .env.",
        403: "The LLM refused access with this API key.",
        404: "The LLM endpoint or model was not found. Check LLM_BASE_URL and LLM_MODEL in .env.",
        429: "The LLM is rate limited. Please wait a moment and try again.",
    }.get(resp.status_code, f"The LLM returned HTTP {resp.status_code}.")
    return f"{base} {detail}".strip()


def _extract_openai_text(data: Any) -> str:
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def _extract_anthropic_text(data: Any) -> str:
    try:
        blocks = data["content"]
    except (KeyError, TypeError):
        return ""
    if not isinstance(blocks, list):
        return ""
    return "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")


def call_llm(cfg: Config, messages: List[Dict[str, str]]) -> str:
    """Send the conversation to the LLM and return the reply text."""
    history = trim_history(messages)
    if not history:
        raise LLMError("There is nothing to send to the AI.")

    if cfg.provider == "anthropic":
        url = cfg.llm_base_url + "/messages"
        headers = {
            "x-api-key": cfg.llm_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": cfg.llm_model,
            "max_tokens": LLM_MAX_TOKENS,
            "system": SYSTEM_PROMPT,
            "messages": history,
        }
    else:
        url = cfg.llm_base_url + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {cfg.llm_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": cfg.llm_model,
            "max_tokens": LLM_MAX_TOKENS,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + history,
        }

    try:
        resp = requests.post(
            url,
            headers=headers,
            json=body,
            timeout=(CONNECT_TIMEOUT, LLM_READ_TIMEOUT),
            allow_redirects=False,
        )
    except requests.exceptions.Timeout:
        raise LLMError("The AI took too long to answer. Please try again.") from None
    except requests.exceptions.RequestException:
        raise LLMError("The AI service is unreachable. Check your connection and LLM_BASE_URL.") from None

    if resp.status_code >= 300:
        raise LLMError(_llm_error_message(cfg, resp))

    try:
        data = resp.json()
    except ValueError:
        raise LLMError("The AI returned an unreadable response.") from None

    text = _extract_anthropic_text(data) if cfg.provider == "anthropic" else _extract_openai_text(data)
    if not text.strip():
        raise LLMError("The AI returned an empty reply. Please try again.")
    return text.strip()


# --------------------------------------------------------------------------- #
# One secured chat turn
# --------------------------------------------------------------------------- #


@dataclass
class TurnResult:
    status: str                 # "ok" | "blocked_prompt" | "blocked_response" | "error"
    reply: str                  # text safe to show to the user
    detail: str = ""            # short reason, safe to show


def secure_turn(cfg: Config, history: List[Dict[str, str]], user_text: str) -> TurnResult:
    """
    history: earlier, already-approved messages as [{"role", "content"}].
    Runs: Guard(prompt) -> LLM -> Guard(response). Nothing unchecked is returned.
    """
    prompt_verdict = check_prompt(cfg, user_text)
    if not prompt_verdict.allowed:
        if prompt_verdict.error:
            return TurnResult("error", "", prompt_verdict.reason)
        return TurnResult("blocked_prompt", BLOCKED_PROMPT_MESSAGE, prompt_verdict.reason)

    try:
        reply = call_llm(cfg, history + [{"role": "user", "content": user_text}])
    except LLMError as exc:
        return TurnResult("error", "", str(exc))

    response_verdict = check_response(cfg, reply)
    if not response_verdict.allowed:
        if response_verdict.error:
            return TurnResult("error", "", response_verdict.reason + " The reply was withheld.")
        return TurnResult("blocked_response", BLOCKED_RESPONSE_MESSAGE, response_verdict.reason)

    return TurnResult("ok", reply)


# --------------------------------------------------------------------------- #
# Terminal self-check:  python engine.py --check
# --------------------------------------------------------------------------- #


def self_check() -> int:
    try:
        cfg = load_config()
    except ConfigError as exc:
        print(f"CONFIG  FAIL  {exc}")
        return 1
    print(f"CONFIG  ok    guard={cfg.guard_url}  llm={cfg.provider} / {cfg.llm_model}")

    ok = True
    v = check_prompt(cfg, "What is the capital of Ghana?")
    print(f"GUARD prompt   {'ok' if v.allowed else 'FAIL'}  {v.reason}")
    ok &= v.allowed
    v = check_response(cfg, "The capital of Ghana is Accra.")
    print(f"GUARD response {'ok' if v.allowed else 'FAIL'}  {v.reason}")
    ok &= v.allowed
    try:
        reply = call_llm(cfg, [{"role": "user", "content": "Reply with the single word: ready"}])
        print(f"LLM            ok    {reply[:60]!r}")
    except LLMError as exc:
        print(f"LLM            FAIL  {exc}")
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(self_check())
    print("Run the app with: streamlit run app.py   (or verify setup with: python engine.py --check)")
