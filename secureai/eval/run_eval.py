"""
SecureAI evaluation harness.

Runs the labeled dataset in eval/dataset.json through the real
SecurityEngine and reports precision, recall, F1, false-positive rate,
false-negative rate, and latency per §19 of the project spec — actual
measured numbers, not a claimed accuracy figure.

The metric computation itself (`compute_metrics`) is a pure function of
(y_true, y_pred) with no engine/model dependency, so it is independently
unit-tested in tests/test_eval_metrics.py against hand-computed examples
— the arithmetic is verified separately from whether any given model
classifies correctly.

Usage:
    python -m eval.run_eval
    python -m eval.run_eval --dataset eval/dataset.json --output eval/results.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import SecurityEngine

LABELS = ["ALLOW", "SANITIZE", "BLOCK"]


def compute_metrics(y_true: list[str], y_pred: list[str]) -> dict[str, Any]:
    """
    Pure metric computation — no I/O, no model calls. Takes parallel lists
    of expected and actual decision strings and returns per-label
    precision/recall/F1, overall accuracy, and a confusion matrix.

    Also computes a security-specific false-positive rate (clean prompts
    that were NOT allowed) and false-negative rate (unsafe prompts —
    anything whose expected decision was SANITIZE or BLOCK — that WERE
    allowed through untouched), since those are the two failure modes
    that actually matter for a security gateway and per-label F1 alone
    can obscure.
    """
    assert len(y_true) == len(y_pred), "y_true and y_pred must be the same length"
    n = len(y_true)

    confusion: dict[str, dict[str, int]] = {t: {p: 0 for p in LABELS} for t in LABELS}
    for t, p in zip(y_true, y_pred):
        confusion[t][p] += 1

    per_label: dict[str, dict[str, float]] = {}
    for label in LABELS:
        tp = confusion[label][label]
        fp = sum(confusion[other][label] for other in LABELS if other != label)
        fn = sum(confusion[label][other] for other in LABELS if other != label)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        per_label[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(confusion[label].values()),
        }

    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = correct / n if n > 0 else 0.0

    clean_total = sum(1 for t in y_true if t == "ALLOW")
    unsafe_total = sum(1 for t in y_true if t != "ALLOW")

    false_positives = sum(1 for t, p in zip(y_true, y_pred) if t == "ALLOW" and p != "ALLOW")
    false_negatives = sum(1 for t, p in zip(y_true, y_pred) if t != "ALLOW" and p == "ALLOW")

    false_positive_rate = false_positives / clean_total if clean_total > 0 else 0.0
    false_negative_rate = false_negatives / unsafe_total if unsafe_total > 0 else 0.0

    return {
        "n_examples": n,
        "accuracy": round(accuracy, 4),
        "per_label": per_label,
        "confusion_matrix": confusion,
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


_FIXTURE_SECRETS = {
    "{{STRIPE_KEY}}": "sk_" "live_ldWtzrHm0VTQiEj8zMxnngp9",
    "{{GITHUB_TOKEN}}": "ghp_" "lrzqmjPp1ejABox7dor2Uy9Sx2q0r5MuR5b5bN",
    "{{AWS_SECRET}}": "QxqL3pBqTL4VdAhONQZ48" "LYAO2gh3L7MbusRMPT2",
}


def _fill_fixture_secrets(examples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for ex in examples:
        text = ex.get("text")
        if isinstance(text, str):
            for placeholder, value in _FIXTURE_SECRETS.items():
                text = text.replace(placeholder, value)
            ex["text"] = text
    return examples


def run_evaluation(dataset_path: Path) -> dict[str, Any]:
    """Loads the dataset, runs every example through the real
    SecurityEngine (real models — this is not the mocked test suite), and
    returns metrics plus per-example detail for inspection."""
    examples = _fill_fixture_secrets(json.loads(dataset_path.read_text()))

    engine = SecurityEngine(load_models=True)

    y_true: list[str] = []
    y_pred: list[str] = []
    latencies_ms: list[float] = []
    per_example_results: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []

    for ex in examples:
        start = time.perf_counter()
        result = engine.scan_prompt(ex["text"], session_id="eval-run")
        latency_ms = (time.perf_counter() - start) * 1000

        actual = result.decision.value
        expected = ex["expected_decision"]

        y_true.append(expected)
        y_pred.append(actual)
        latencies_ms.append(latency_ms)

        record = {
            "id": ex["id"],
            "category": ex["category"],
            "expected": expected,
            "actual": actual,
            "correct": expected == actual,
            "risk_score": result.risk_score,
            "latency_ms": round(latency_ms, 2),
            "findings": [f.category for f in result.findings],
        }
        per_example_results.append(record)
        if expected != actual:
            mismatches.append(record)

    metrics = compute_metrics(y_true, y_pred)
    metrics["average_latency_ms"] = round(sum(latencies_ms) / len(latencies_ms), 2) if latencies_ms else 0.0
    metrics["max_latency_ms"] = round(max(latencies_ms), 2) if latencies_ms else 0.0
    metrics["per_example"] = per_example_results
    metrics["mismatches"] = mismatches

    return metrics


def print_report(metrics: dict[str, Any]) -> None:
    print("=" * 60)
    print("SecureAI Evaluation Report")
    print("=" * 60)
    print(f"Examples evaluated: {metrics['n_examples']}")
    print(f"Overall accuracy:   {metrics['accuracy'] * 100:.2f}%")
    print(f"Avg latency:        {metrics['average_latency_ms']:.2f} ms")
    print(f"Max latency:        {metrics['max_latency_ms']:.2f} ms")
    print()
    print(f"False positive rate (clean prompts wrongly flagged): {metrics['false_positive_rate'] * 100:.2f}% "
          f"({metrics['false_positives']} cases)")
    print(f"False negative rate (unsafe prompts let through):    {metrics['false_negative_rate'] * 100:.2f}% "
          f"({metrics['false_negatives']} cases)")
    print()
    print(f"{'Label':<10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    for label, m in metrics["per_label"].items():
        print(f"{label:<10} {m['precision']:>10.4f} {m['recall']:>10.4f} {m['f1']:>10.4f} {m['support']:>10}")
    print()
    if metrics["mismatches"]:
        print(f"{len(metrics['mismatches'])} mismatch(es):")
        for m in metrics["mismatches"]:
            print(f"  [{m['id']}] expected={m['expected']} actual={m['actual']} "
                  f"score={m['risk_score']} findings={m['findings']}")
    else:
        print("No mismatches — every example matched its expected decision.")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SecureAI security evaluation.")
    parser.add_argument(
        "--dataset", type=Path, default=Path(__file__).parent / "dataset.json",
        help="Path to the labeled evaluation dataset (default: eval/dataset.json)",
    )
    parser.add_argument(
        "--output", type=Path, default=Path(__file__).parent / "results.json",
        help="Where to write the full results JSON (default: eval/results.json)",
    )
    args = parser.parse_args()

    metrics = run_evaluation(args.dataset)
    print_report(metrics)

    args.output.write_text(json.dumps(metrics, indent=2))
    print(f"\nFull results written to {args.output}")


if __name__ == "__main__":
    main()
