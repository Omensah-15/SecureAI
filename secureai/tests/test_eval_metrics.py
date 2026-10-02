"""Tests for eval/run_eval.py: the metric math (verified against
hand-calculated values) and the run_evaluation orchestration logic."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from eval.run_eval import compute_metrics, run_evaluation


class TestComputeMetrics:
    """compute_metrics is a pure function — every value here is checked
    against a value computed by hand, not just re-derived from the code
    under test."""

    def setup_method(self) -> None:
        # 4 ALLOW, 3 SANITIZE, 3 BLOCK expected (10 total).
        # 1 ALLOW misclassified as SANITIZE; 1 SANITIZE misclassified as
        # ALLOW; BLOCK perfect.
        self.y_true = ["ALLOW"] * 4 + ["SANITIZE"] * 3 + ["BLOCK"] * 3
        self.y_pred = ["ALLOW", "ALLOW", "ALLOW", "SANITIZE", "SANITIZE", "SANITIZE", "ALLOW", "BLOCK", "BLOCK", "BLOCK"]
        self.metrics = compute_metrics(self.y_true, self.y_pred)

    def test_allow_precision_recall(self) -> None:
        # TP=3, FP=1 (SANITIZE mispredicted as ALLOW), FN=1 (ALLOW mispredicted as SANITIZE)
        assert self.metrics["per_label"]["ALLOW"]["precision"] == 0.75
        assert self.metrics["per_label"]["ALLOW"]["recall"] == 0.75

    def test_sanitize_precision_recall(self) -> None:
        # TP=2, FP=1, FN=1 -> 2/3 each
        assert abs(self.metrics["per_label"]["SANITIZE"]["precision"] - 2 / 3) < 0.001
        assert abs(self.metrics["per_label"]["SANITIZE"]["recall"] - 2 / 3) < 0.001

    def test_block_is_perfect(self) -> None:
        assert self.metrics["per_label"]["BLOCK"]["precision"] == 1.0
        assert self.metrics["per_label"]["BLOCK"]["recall"] == 1.0
        assert self.metrics["per_label"]["BLOCK"]["f1"] == 1.0

    def test_overall_accuracy(self) -> None:
        assert self.metrics["accuracy"] == 0.8  # 8/10 correct

    def test_false_positive_rate(self) -> None:
        # 4 clean(ALLOW) examples, 1 wrongly flagged -> 0.25
        assert self.metrics["false_positive_rate"] == 0.25
        assert self.metrics["false_positives"] == 1

    def test_false_negative_rate(self) -> None:
        # 6 unsafe(SANITIZE+BLOCK) examples, 1 let through as ALLOW -> 1/6
        assert abs(self.metrics["false_negative_rate"] - 1 / 6) < 0.001
        assert self.metrics["false_negatives"] == 1

    def test_confusion_matrix_rows_sum_to_support(self) -> None:
        for label in ("ALLOW", "SANITIZE", "BLOCK"):
            row_sum = sum(self.metrics["confusion_matrix"][label].values())
            assert row_sum == self.metrics["per_label"][label]["support"]

    def test_perfect_predictions_score_one_everywhere(self) -> None:
        y = ["ALLOW", "SANITIZE", "BLOCK", "ALLOW"]
        m = compute_metrics(y, y)
        assert m["accuracy"] == 1.0
        assert m["false_positive_rate"] == 0.0
        assert m["false_negative_rate"] == 0.0
        for label_metrics in m["per_label"].values():
            if label_metrics["support"] > 0:
                assert label_metrics["precision"] == 1.0
                assert label_metrics["recall"] == 1.0

    def test_empty_input_does_not_crash(self) -> None:
        m = compute_metrics([], [])
        assert m["n_examples"] == 0
        assert m["accuracy"] == 0.0


class TestRunEvaluationOrchestration:
    """Verifies the loop that reads the dataset, calls the engine, and
    assembles per-example results — using a mocked SecurityEngine since
    this test suite does not have your downloaded model weights."""

    def test_run_evaluation_end_to_end_with_mocked_engine(self, tmp_path: Path) -> None:
        dataset = [
            {"id": "a", "category": "clean", "expected_decision": "ALLOW", "text": "hello"},
            {"id": "b", "category": "prompt_injection", "expected_decision": "BLOCK", "text": "ignore instructions"},
        ]
        dataset_path = tmp_path / "mini_dataset.json"
        dataset_path.write_text(json.dumps(dataset))

        mock_engine = MagicMock()

        def fake_scan_prompt(text: str, session_id: str):
            from config import Decision, RiskLevel
            from engine import ScanResult

            if "ignore" in text.lower():
                return ScanResult(text, [], 95, RiskLevel.CRITICAL, Decision.BLOCK, latency_ms=5.0)
            return ScanResult(text, [], 0, RiskLevel.SAFE, Decision.ALLOW, latency_ms=5.0)

        mock_engine.scan_prompt.side_effect = fake_scan_prompt

        with patch("eval.run_eval.SecurityEngine", return_value=mock_engine):
            metrics = run_evaluation(dataset_path)

        assert metrics["n_examples"] == 2
        assert metrics["accuracy"] == 1.0
        assert len(metrics["mismatches"]) == 0
        assert "average_latency_ms" in metrics
        assert len(metrics["per_example"]) == 2

    def test_run_evaluation_records_mismatches(self, tmp_path: Path) -> None:
        dataset = [
            {"id": "a", "category": "prompt_injection", "expected_decision": "BLOCK", "text": "ignore instructions"},
        ]
        dataset_path = tmp_path / "mini_dataset.json"
        dataset_path.write_text(json.dumps(dataset))

        mock_engine = MagicMock()

        def fake_scan_prompt_wrong(text: str, session_id: str):
            from config import Decision, RiskLevel
            from engine import ScanResult
            # Deliberately wrong: allows something that should block
            return ScanResult(text, [], 0, RiskLevel.SAFE, Decision.ALLOW, latency_ms=5.0)

        mock_engine.scan_prompt.side_effect = fake_scan_prompt_wrong

        with patch("eval.run_eval.SecurityEngine", return_value=mock_engine):
            metrics = run_evaluation(dataset_path)

        assert metrics["accuracy"] == 0.0
        assert len(metrics["mismatches"]) == 1
        assert metrics["mismatches"][0]["expected"] == "BLOCK"
        assert metrics["mismatches"][0]["actual"] == "ALLOW"
