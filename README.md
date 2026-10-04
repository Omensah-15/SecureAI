# SecureAI

A security gateway that sits between a user and an LLM. Every prompt is
scanned for secrets, PII, and prompt-injection attempts before it reaches
the model; every response is scanned again before it reaches the user.
The security decision (ALLOW / SANITIZE / BLOCK) is made by a
deterministic policy engine, never by an LLM.

## Project layout

```
secureai/
├── config.py          # env-driven settings, risk thresholds, policy mapping
├── engine.py           # detectors, risk scoring, sanitization, LLM abstraction, audit log
├── app.py               # Streamlit frontend
├── verify_models.py      # pre-demo sanity check against your real downloaded models
├── diagnose_injection_fp.py  # bisection tool for injection-classifier false positives
├── requirements.txt
├── .env.example
├── models/               # your downloaded model folders go here (not in version control)
│   ├── prompt-injection/
│   ├── pii-detection/
│   ├── output-safety/
│   └── toxicity/
├── tests/
│   ├── conftest.py         # shared fixtures (mocked engine, isolated audit DB)
│   ├── test_config.py       # risk band boundaries, policy mapping, validation
│   ├── test_engine.py        # risk scoring, sanitization, gitleaks, full pipeline, audit log
│   └── test_eval_metrics.py  # eval harness metric math + orchestration
└── eval/
    ├── dataset.json           # 29 labeled prompts across 8 categories
    ├── run_eval.py             # runs the dataset through the real engine, reports metrics
    └── results.json             # written by run_eval.py (generated, not checked in)
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env — set ANTHROPIC_API_KEY (or OPENAI_API_KEY / LOCAL_LLM_BASE_URL
# depending on which LLM_PROVIDER you choose)
```

### Using a free LLM instead of a paid API (recommended for demos)

The LLM provider abstraction in `engine.py` supports any OpenAI-API-compatible
backend, not just OpenAI itself — this includes free providers like Groq.
To use Groq:

1. Get a free key at https://console.groq.com/keys (no card required)
2. In `.env`, set:
   ```
   LLM_PROVIDER=openai
   LLM_MODEL=openai/gpt-oss-20b
   OPENAI_API_KEY=gsk_your_key_here
   OPENAI_BASE_URL=https://api.groq.com/openai/v1
   ```

That's it — `OpenAIProvider` connects to Groq's servers instead of
OpenAI's, with no other code changes. Groq's free tier is fast (their
main selling point) and has no billing risk, which is why it's the
recommended choice for a hackathon demo over a paid API like Anthropic's
or OpenAI's own. (Groq retired the older `llama-3.1-8b-instant` /
`llama-3.3-70b-versatile` free-tier models on 2026-08-16 in favor of the
`gpt-oss` line — if a Groq model you're using elsewhere starts 404ing
with `model_not_found`, check https://console.groq.com/docs/deprecations
for the current recommended replacement.)

For a fully offline option with zero dependency on internet access during
your demo, run a local model via Ollama instead:
```
LLM_PROVIDER=local
LOCAL_LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama3.1
```
(requires `ollama pull llama3.1` and `ollama serve` running locally first)

Install gitleaks (secret scanner — a separate Go binary, not a Python package):

```bash
curl -sL -o /tmp/gitleaks.tar.gz \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C /tmp
chmod +x /tmp/gitleaks
mv /tmp/gitleaks ~/.local/bin/
gitleaks version   # confirm it's on PATH
```

Download the four detection models into `models/` (see project chat history
for the exact `hf download` commands per model) — each model needs its own
subfolder matching the names in `.env.example`'s defaults.

## Before your first real run: verify the models

```bash
python3 verify_models.py
```

**Run this once, right after downloading your models, before you rely on
the system for anything.** Every model vendor phrases "flagged" vs "not
flagged" differently — SAFE/INJECTION, LABEL_0/LABEL_1, toxic/non_toxic,
short codes like "H2" — and `engine.py` has to correctly interpret
whichever convention your specific downloaded models actually use. This
script loads your real models, runs a battery of known clean/malicious
test strings through each one, prints the raw label and score, and tells
you plainly (PASS/WARN/FAIL) whether the interpretation logic understood
it correctly. If it reports an `AMBIGUOUS` label, the fix is one line:
add that exact label string to `_NEGATIVE_LABEL_HINTS` or
`_POSITIVE_LABEL_HINTS` near the top of `engine.py`, then re-run.

Exits with code 0 only if every check passes — safe to use as a CI gate
or a pre-demo checklist.

If you ever see an unexpected `PROMPT_INJECTION` finding on text that has
no imperative/override language in it, `diagnose_injection_fp.py` runs
your real injection classifier directly against a bisected series of text
variants to help isolate what's actually triggering it — see its module
docstring for background on the one real case this came up for during
development, and how `scan_prompt()`'s override-language corroboration
check (`_has_override_language` in `engine.py`) resolved it.

## Running the app

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`. First load is slower — all four models
load into memory once, then stay cached for the life of the server process.

## Running the tests

```bash
pytest tests/ -v
```
```

