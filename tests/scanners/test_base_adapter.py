"""Tests for ScannerAdapter's shared execution/error-handling contract.

Uses FakeScannerAdapter (tests/scanners/fakes.py) so these tests are fast,
deterministic, and independent of any real scanner being installed.
"""

from __future__ import annotations

import json
from pathlib import Path

from terraveritas.models.finding import FindingOutcome, ScanStatus

from .fakes import FakeScannerAdapter


def test_success_with_findings(tmp_path: Path) -> None:
    findings_json = json.dumps(
        [
            {
                "rule_id": "FAKE_1",
                "outcome": "failed",
                "file_path": "main.tf",
                "description": "example finding",
                "resource_id": "aws_s3_bucket.data",
            }
        ]
    )
    adapter = FakeScannerAdapter("fake", f"import sys; print({findings_json!r})")

    result = adapter.scan(tmp_path)

    assert result.status == ScanStatus.SUCCESS
    assert len(result.findings) == 1
    assert result.findings[0].outcome == FindingOutcome.FAILED
    assert result.findings[0].rule_id == "FAKE_1"
    assert result.exit_code == 0


def test_success_with_no_findings(tmp_path: Path) -> None:
    adapter = FakeScannerAdapter("fake", "print('[]')")

    result = adapter.scan(tmp_path)

    assert result.status == ScanStatus.SUCCESS
    assert result.findings == []


def test_invalid_target_directory(tmp_path: Path) -> None:
    adapter = FakeScannerAdapter("fake", "print('[]')")

    result = adapter.scan(tmp_path / "does_not_exist")

    assert result.status == ScanStatus.INVALID_TARGET
    assert result.findings == []


def test_scanner_not_found(tmp_path: Path) -> None:
    adapter = FakeScannerAdapter(
        "fake", "print('[]')", executable="terraveritas-nonexistent-binary-xyz"
    )

    result = adapter.scan(tmp_path)

    assert result.status == ScanStatus.SCANNER_NOT_FOUND
    assert result.findings == []


def test_timeout(tmp_path: Path) -> None:
    adapter = FakeScannerAdapter("fake", "import time; time.sleep(5)")

    result = adapter.scan(tmp_path, timeout_seconds=0.2)

    assert result.status == ScanStatus.TIMEOUT
    assert result.findings == []
    assert result.error_message is not None


def test_execution_error_on_unexpected_nonzero_exit(tmp_path: Path) -> None:
    adapter = FakeScannerAdapter("fake", "import sys; sys.exit(2)")

    result = adapter.scan(tmp_path)

    assert result.status == ScanStatus.EXECUTION_ERROR
    assert result.exit_code == 2
    assert result.findings == []


def test_nonzero_exit_treated_as_success_when_expected(tmp_path: Path) -> None:
    """Many real scanners exit non-zero when findings exist — that's not a failure."""
    adapter = FakeScannerAdapter(
        "fake",
        "import sys; print('[]'); sys.exit(1)",
        success_exit_codes=frozenset({0, 1}),
    )

    result = adapter.scan(tmp_path)

    assert result.status == ScanStatus.SUCCESS
    assert result.exit_code == 1


def test_output_parse_error(tmp_path: Path) -> None:
    adapter = FakeScannerAdapter("fake", "print('not valid json {{{')")

    result = adapter.scan(tmp_path)

    assert result.status == ScanStatus.OUTPUT_PARSE_ERROR
    assert result.findings == []
    assert result.error_message is not None


def test_empty_output_parses_to_no_findings(tmp_path: Path) -> None:
    adapter = FakeScannerAdapter("fake", "print('[]')")

    result = adapter.scan(tmp_path)

    assert result.status == ScanStatus.SUCCESS
    assert result.findings == []


def test_target_unparseable_is_distinct_from_clean_success(tmp_path: Path) -> None:
    """All files failing to parse must never look identical to a clean scan."""
    payload = json.dumps({"findings": [], "unparseable_files": ["main.tf"]})
    adapter = FakeScannerAdapter("fake", f"print({payload!r})")

    result = adapter.scan(tmp_path)

    assert result.status == ScanStatus.TARGET_UNPARSEABLE
    assert result.findings == []
    assert result.unparseable_files == ["main.tf"]


def test_scanners_are_allowed_to_disagree(tmp_path: Path) -> None:
    """Two scanners against the same target can produce contradictory findings;
    nothing in the adapter layer reconciles them into a false consensus."""
    passes = json.dumps(
        [{"rule_id": "R1", "outcome": "passed", "file_path": "main.tf", "description": "ok"}]
    )
    fails = json.dumps(
        [{"rule_id": "R1", "outcome": "failed", "file_path": "main.tf", "description": "bad"}]
    )
    optimist = FakeScannerAdapter("optimist", f"print({passes!r})")
    pessimist = FakeScannerAdapter("pessimist", f"print({fails!r})")

    optimist_result = optimist.scan(tmp_path)
    pessimist_result = pessimist.scan(tmp_path)

    assert optimist_result.findings[0].outcome == FindingOutcome.PASSED
    assert pessimist_result.findings[0].outcome == FindingOutcome.FAILED
    # Each ScanResult stands on its own — no merged/reconciled third result exists.
