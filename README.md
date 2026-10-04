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

111 tests, covering:
- Exact risk-band boundaries and policy mapping (`test_config.py`)
- Risk scoring, sanitization (both prompt- and response-side), real
  Gitleaks subprocess integration, the full `scan_prompt`/`scan_response`
  pipeline including the hard BLOCK-override for prompt injection, the
  injection-classifier override-language corroboration gate, detector-
  level fail-safety (a crashing classifier can't take down the others),
  and audit log aggregation (`test_engine.py`)
- Real observed label conventions from each of the four downloaded
  models — prompt-injection, PII taxonomy, output-safety, toxicity —
  confirmed against actual model `config.json`/output rather than
  assumed (`test_real_model_labels.py`)
- Label-interpretation fallback logic for models with unfamiliar label
  conventions (`test_label_interpreter.py`)
- LLM provider construction for all three backends, including the Groq-
  via-OpenAI-compatible-endpoint path (`test_llm_provider.py`)
- The evaluation harness's precision/recall/F1/FPR/FNR math, verified
  against hand-calculated values, plus end-to-end orchestration
  (`test_eval_metrics.py`)

None of these tests require your downloaded model weights — the four ML
classifiers are mocked in `conftest.py` so the suite runs in seconds and
in CI. The Gitleaks tests use the real binary and are skipped
automatically if it isn't found on `PATH`.

## Running the evaluation

```bash
python -m eval.run_eval
```

Runs all 29 labeled examples in `eval/dataset.json` through the **real**
SecurityEngine (this does need your downloaded models and gitleaks
installed) and prints a report: overall accuracy, per-label precision/
recall/F1, false-positive rate, false-negative rate, and latency. Full
results are also written to `eval/results.json`. Use `--dataset` and
`--output` to point at different files.

## Known design decisions worth being able to explain to a judge

- **Risk scoring is a pure function** (`SecurityEngine.compute_risk_score`)
  with no model or network calls inside it — testable in isolation, and
  the one place the final decision is made.
- **Prompt-injection findings can never resolve to SANITIZE.** Redaction
  only touches SECRET/PII spans; an injection payload isn't something
  that can be "safely removed" the way a leaked key can, so any HIGH/
  CRITICAL injection finding forces BLOCK regardless of the aggregate
  score. This was a real bug caught by the test suite during development
  (see `test_injection_plus_secret_forces_block_not_sanitize` and
  `test_injection_alone_blocks`) — a corroborating finding at first
  masked a lone high-confidence injection just under the SANITIZE
  threshold.
- **Detection and policy are separate for embedded injections.** The
  detectors always flag an injection, even inside quoted/JSON/XML/code
  content, and the finding, severity and risk score are never lowered.
  Only the final decision looks at intent
  (`SecurityEngine._is_analysis_of_embedded_injection`): the BLOCK above
  is relaxed to ALLOW — shown as "ANALYSIS OF DETECTED INJECTION" — only
  when the user's own instruction (the prompt with the embedded content cut
  out) positively asks to analyze it, contains no execution cue ("then
  follow it", "instead of your system instructions", ...) or override
  vocabulary, and the injection classifier — re-run on that outer
  instruction alone — does not flag it. Every doubt, including a classifier
  failure, keeps the BLOCK. The embedded content is sent to the LLM wrapped
  in `<untrusted_content>` tags (`frame_untrusted_analysis`) and the
  response still goes through the unchanged output scan. This is a
  deny-list of phrasings plus a classifier check, not a proof: see
  `TestContextAwareInjectionPolicy` for what is and isn't covered.
- **Gitleaks spans are derived from `StartColumn` + `len(secret)`, not
  `EndColumn`.** Gitleaks' `EndColumn` isn't reliably the exact end of
  the secret text (it can include trailing match characters like a
  closing quote), which produced off-by-one redactions during testing.
  See `test_span_exactly_matches_secret_text` for the regression test.
- **The audit log stores categories and scores only, never raw matched
  text** — see `test_never_persists_raw_secret_text`.
- **PII risk weighting was calibrated against Piiranha's real entity
  taxonomy**, confirmed by reading the actual downloaded model's
  `config.json`. High-sensitivity entity types (`PASSWORD`,
  `CREDITCARDNUMBER`, `SOCIALNUM`, `TAXNUM`, `ACCOUNTNUM`,
  `DRIVERLICENSENUM`, `IDCARDNUM`) score at SECRET-level weight, not the
  generic PII weight — a leaked password found via the PII detector is
  functionally a secret, not a low-stakes contact detail like a city or
  name. See `TestPiiRealTaxonomy` in `tests/test_real_model_labels.py`.
- **The toxicity detector is multi-label, not single-label.** toxic-bert's
  real label set (`toxic`, `severe_toxic`, `obscene`, `threat`, `insult`,
  `identity_hate`) has no safe/negative label at all — every category is
  independently thresholded rather than picking one top-1 label, which
  would otherwise risk a softmax-normalization artifact flagging clean
  text. See `TestToxicityRealMultiLabel`.
- **The output-safety detector uses an explicit label map for KoalaAI's
  short codes** (`H`, `H2`, `HR`, `OK`, `S`, `S3`, `SH`, `V`, `V2`),
  confirmed against the real model's `config.json`, with a generic
  fallback for any other output-safety model. See
  `TestOutputSafetyRealKoalaLabels`.
- **`sanitize()`'s fallback redaction path only applies to findings
  without a span**, not to every finding with `matched_text` — applying
  it unconditionally risked a double redaction (and visible corruption)
  if a span were ever wrong. See
  `test_fallback_does_not_double_redact_a_finding_that_already_has_a_span`.
- **Responses are sanitized the same way prompts are, not just scored.**
  `scan_response()` populates `sanitized_text`/`redactions` on a SANITIZE
  decision exactly like `scan_prompt()` does. This matters because a
  single CRITICAL secret/PII finding in a response lands at ~44/100 —
  SANITIZE band (40-69), not BLOCK (70+) — so without this, the model
  echoing back something sensitive at that risk level would have reached
  the UI completely unredacted even though the detector caught it. The
  frontend (`app.py`) shows and persists only the redacted text on this
  path; the raw response is never referenced again once a SANITIZE
  decision is made, including in session history (Streamlit re-renders
  every stored message on every rerun, so this had to be fixed at the
  storage layer, not just the initial display).
- **A masked secret/PII mention can still trigger a false-positive
  PROMPT_INJECTION classification on its own**, confirmed against the
  real deployed classifier: a redacted, punctuation-free version of "My
  stripe key is REDACTED, please review it" still scored
  `PROMPT_INJECTION(1.00)`. Since genuine injection, by definition,
  instructs the model to deviate from its behavior, `scan_prompt()` now
  requires override/imperative language (`ignore`, `disregard`, `reveal
  your system prompt`, etc. — `_has_override_language`) to corroborate an
  injection finding whenever it co-occurs with a masked secret/PII span.
  This is deliberately narrow: prompts with no secret/PII in them still
  trust the classifier's raw score unchanged, so general injection
  detection is unaffected. The explicit trade-off: a genuinely novel
  attack that both leaks a secret and uses no recognizable override
  language would resolve to SANITIZE instead of BLOCK — judged acceptable
  against a 100% false-positive rate on ordinary credential-review
  requests, since the SECRET finding alone still forces at least
  SANITIZE, never a silent ALLOW. See
  `test_credential_mention_without_override_language_is_sanitized_not_blocked`
  and its sibling `test_injection_plus_secret_forces_block_not_sanitize`
  (same setup, but with real override language present, which still
  correctly BLOCKs).
- **Individual detector crashes fail safe; the whole pipeline fails
  closed.** Every ML classifier call goes through
  `_run_classifier_safely`, which catches any exception, logs it, and
  treats it as "no findings from this detector" — matching
  `GitleaksScanner`'s already-established pattern, so one broken model
  can't silently take the others down. But `app.py` wraps the entire
  `scan_prompt()`/`scan_response()` call in its own `try/except`: if the
  whole pipeline breaks (not just one detector), the content is withheld
  with a clear error rather than shown unscanned. See
  `TestDetectorFailSafety` for the four detector-crash regression tests.
- **`verify_models.py` calls the real `_detect_*` methods directly**
  rather than re-implementing their interpretation logic — an earlier
  version duplicated that logic and drifted out of sync with the real
  detectors after the KoalaAI/toxicity fixes above; calling the actual
  methods makes that class of bug structurally impossible going forward.
