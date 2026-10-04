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
├── models/               # your downloaded model folders go here
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

# SecureAI — Getting Started

## 1. Enter the project

```bash
cd secureai
```

## 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

## 4. Install Gitleaks (secret scanner)

```bash
curl -sL -o /tmp/gitleaks.tar.gz \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C /tmp
chmod +x /tmp/gitleaks
mkdir -p ~/.local/bin
mv /tmp/gitleaks ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"   # add this line to ~/.bashrc too
gitleaks version
```

## 5. Download the four models

```bash
pip install huggingface_hub
hf auth login   # paste a free token from https://huggingface.co/settings/tokens

hf download ProtectAI/deberta-v3-small-prompt-injection-v2 \
  --local-dir ./models/prompt-injection

hf download iiiorg/piiranha-v1-detect-personal-information \
  --local-dir ./models/pii-detection

hf download KoalaAI/Text-Moderation \
  --local-dir ./models/output-safety

hf download unitary/toxic-bert \
  --local-dir ./models/toxicity
```

## 6. Set up your `.env` file

```bash
cat > .env << 'EOF'
LLM_PROVIDER=openai
LLM_MODEL=llama-3.1-8b-instant
OPENAI_API_KEY=gsk_your_key_here
OPENAI_BASE_URL=https://api.groq.com/openai/v1
EOF
```

Get a free Groq key (no card needed) at https://console.groq.com/keys

## 7. Run the tests

```bash
pytest tests/ -v
```

Should end with all tests passed — no models needed for this step.

## 8. Verify your real models work

```bash
python3 verify_models.py
```

Loads your real downloaded models and checks each one. Should end with all `PASS`.

## 9. Run the app

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`. First load is slower while models load into memory.

## 10. (Optional) Run the accuracy evaluation

```bash
python -m eval.run_eval
```

---

## Every time you come back later

```bash
cd secureai
source venv/bin/activate
export PATH="$HOME/.local/bin:$PATH"
streamlit run app.py
```
