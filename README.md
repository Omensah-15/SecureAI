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
```

