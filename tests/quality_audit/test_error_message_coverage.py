"""QA audit: systematic check that every non-SUCCESS ScanStatus produced by
the real adapter machinery carries a populated error_message.

Existing tests assert this ad hoc on some failure paths (timeout, parse
error) but not systematically on all of them (invalid target, scanner not
found, execution error) — this closes that gap in one place so a future
regression on any path is caught.
"""

from __future__ import annotations

from pathlib import Path

from terraveritas.models.finding import ScanStatus

from ..scanners.fakes import FakeScannerAdapter


def test_every_non_success_status_has_a_populated_error_message(tmp_path: Path) -> None:
    cases: dict[ScanStatus, FakeScannerAdapter] = {
        ScanStatus.INVALID_TARGET: FakeScannerAdapter("fake", "print('[]')"),
        ScanStatus.SCANNER_NOT_FOUND: FakeScannerAdapter(
            "fake", "print('[]')", executable="terraveritas-nonexistent-xyz"
        ),
        ScanStatus.TIMEOUT: FakeScannerAdapter("fake", "import time; time.sleep(5)"),
        ScanStatus.EXECUTION_ERROR: FakeScannerAdapter("fake", "import sys; sys.exit(2)"),
        ScanStatus.OUTPUT_PARSE_ERROR: FakeScannerAdapter("fake", "print('not json {{{')"),
    }

    for expected_status, adapter in cases.items():
        target = tmp_path if expected_status != ScanStatus.INVALID_TARGET else tmp_path / "gone"
        result = adapter.scan(target, timeout_seconds=0.5)

        assert result.status == expected_status, f"unexpected status for {expected_status}"
        assert result.error_message, f"{expected_status} produced no error_message"
        assert result.error_message.strip() != "", f"{expected_status} error_message is blank"
