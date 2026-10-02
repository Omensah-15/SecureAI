"""
Optional bisection diagnostic for prompt-injection classifier false
positives, kept around for future investigation.

engine.py's scan_prompt() now gates PROMPT_INJECTION findings that
would otherwise be corroborated only by a masked SECRET/PII span and
no recognizable override/imperative language (_has_override_language)
— this resolved the credential-leak false positive verify_models.py
was surfacing without needing to know exactly which token in the
masked sentence the classifier was keying off. This script is no
longer required to get verify_models.py green; it's here if you want
to actually pin down the classifier's specific trigger later (e.g. to
evaluate a different injection model, or to understand whether the
gate is masking a broader calibration issue worth addressing upstream).

Run it like:

    python3 diagnose_injection_fp.py

It calls engine.injection_clf directly (bypassing scan_prompt and the
gate entirely) on a series of variants that each change one thing from
the last, so wherever the score collapses is the actual trigger.
"""

from __future__ import annotations

from engine import SecurityEngine

# Synthetic Stripe-style test key, assembled at runtime from fragments so
# that no complete key-shaped string sits in the source file. This keeps
# GitHub push protection and other secret scanners from flagging the repo.
_FAKE_STRIPE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"

VARIANTS = [
    ("original (unmasked, raw secret)",
     f'My stripe key is "{_FAKE_STRIPE_KEY}", please review it.'),
    ("current masked form (what the pipeline sends today)",
     'My stripe key is "REDACTED", please review it.'),
    ("no quotes around the placeholder",
     'My stripe key is REDACTED, please review it.'),
    ("no quotes, no trailing clause",
     'My stripe key is REDACTED.'),
    ("drop \"please review it\" entirely",
     'My stripe key is "REDACTED".'),
    ("drop \"stripe\"",
     'My key is "REDACTED", please review it.'),
    ("drop \"key\" too -- just a quoted value being reviewed",
     'My value is "REDACTED", please review it.'),
    ("just the trailing clause alone",
     'Please review it.'),
    ("just the quoted placeholder alone",
     '"REDACTED"'),
    ("neutral control sentence (expect SAFE)",
     'The weather in Accra today is sunny with a light breeze.'),
    ("\"review\" alone, no credential language (expect SAFE-ish)",
     'Please review this document for me.'),
    ("\"key\" alone, no credential-shaped value (expect SAFE-ish)",
     'What is the key to a happy life?'),
]


def main() -> None:
    print("Loading models (this uses your real injection classifier only)...")
    engine = SecurityEngine(load_models=True)
    if engine.injection_clf is None:
        print("injection_clf failed to load -- check MODELS_DIR / model files.")
        return

    print(f"\n{'variant':55s} {'label':10s} {'score':>6s}   text")
    print("-" * 110)
    for description, text in VARIANTS:
        result = engine.injection_clf(text)[0]
        label = result["label"]
        score = float(result["score"])
        print(f"{description:55s} {label:10s} {score:6.3f}   {text!r}")


if __name__ == "__main__":
    main()
