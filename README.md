# SecureAI

A security gateway that sits between a user and an LLM. Every prompt is
scanned for secrets, PII, and prompt-injection attempts before it reaches
the model; every response is scanned again before it reaches the user.
The security decision (ALLOW / SANITIZE / BLOCK) is made by a
deterministic policy engine, never by an LLM.

Built for the **SecureAI Hackathon — Challenge 3**.

## Problem

Challenge 3 provided a SecureAI Guard and an LLM, and asked teams to add
an additional security layer around them.

We tested the Guard by sending the same prompt-injection intent in
different representations. We found that the Guard's decision can change
depending on how the malicious instruction is represented, not just on
whether it is malicious.

For example:

- A direct prompt injection (plain text, imperative instruction) was
  blocked by the Guard.
- A semantically equivalent injection embedded inside structured data,
  such as JSON or CSV, was allowed by the Guard.

An allowed request then continues on to the LLM.

This is a **Guard detection gap**, not confirmation that the LLM itself
can be jailbroken. The downstream LLM may still refuse the request on its
own. The gap is that the Guard's decision depends on format, when it
should depend on intent.

## Our Solution

SecureAI does not replace the existing Guard. It adds a second,
independent security layer behind it.

- The system scans both incoming prompts and outgoing LLM responses.
- It uses four specialized pretrained detectors:
  1. Prompt Injection
  2. PII Detection
  3. Toxicity
  4. Output Safety
- The detectors identify potential security risks in the text.
- A deterministic security policy engine evaluates the findings from all
  detectors and makes the final `ALLOW`, `SANITIZE`, or `BLOCK` decision.
  The decision is never made by an LLM.
- The system looks for malicious instructions even when they are
  embedded inside structured data such as JSON, CSV, or other content,
  not only in plain imperative text.
- It distinguishes between an instruction that is trying to control the
  AI and an instruction that is simply present as content to be
  analyzed. Legitimate security analysis of untrusted text should not be
  blocked just because that text contains injection-like phrasing.

## Before and After

```text
Before:

User
 ↓
SecureAI Guard
 ↓
ALLOW
 ↓
LLM


After:

User
 ↓
SecureAI Guard
 ↓
SecureAI Security Engine
 ↓
Detection + Security Policies
 ↓
ALLOW / SANITIZE / BLOCK
 ↓
LLM
 ↓
Response Security Check
 ↓
User
```

## What We Found

We used a harmless marker, `CANARY-7731`, to demonstrate the detection
gap without using a real secret or a real attack payload.

```text
Direct injection → Guard BLOCK

Equivalent injection embedded in JSON/CSV
→ Guard ALLOW
→ SecureAI detects it
→ SecureAI BLOCK
→ LLM is never reached
```

`CANARY-7731` is not a real secret, and this does not demonstrate that
the LLM was jailbroken. It only shows that an injection payload can
reach the Guard in a format the Guard allows, and that SecureAI catches
it before the LLM is reached.

## Why This Matters

Real applications process untrusted content from many sources: uploaded
documents, customer records, API responses, CSV exports, JSON payloads,
file metadata, and more. Security should not depend on how an
instruction happens to be formatted. A layer that only checks plain-text
prompts misses malicious content carried inside the data the model is
asked to process.

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


## Getting Started

### 1. Enter the project

```bash
cd secureai
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Gitleaks (secret scanner)

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

### 5. Download the four models

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

### 6. Set up your `.env` file

```bash
cat > .env << 'EOF'
LLM_PROVIDER=openai
LLM_MODEL=llama-3.1-8b-instant
OPENAI_API_KEY=gsk_your_key_here
OPENAI_BASE_URL=https://api.groq.com/openai/v1
EOF
```

Get a free Groq key (no card needed) at https://console.groq.com/keys

### 7. Run the tests

```bash
pytest tests/ -v
```

Should end with all tests passed — no models needed for this step.

### 8. Verify your real models work

```bash
python3 verify_models.py
```

Loads your real downloaded models and checks each one. Should end with all `PASS`.

### 9. Run the app

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`. First load is slower while models load into memory.

### 10. (Optional) Run the accuracy evaluation

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
streamlit run app.py
```
