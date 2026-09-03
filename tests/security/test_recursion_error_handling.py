"""Regression test: pathologically deep scanner output must be classified
as OUTPUT_PARSE_ERROR, not crash the whole scan call with an uncaught
RecursionError. RecursionError is a RuntimeError subclass, not a
ValueError, so the original exception handling silently missed it."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from terraveritas.models.finding import ParsedScanOutput, ScanStatus
from terraveritas.scanners.base import ScannerAdapter


class _RecursionErrorAdapter(ScannerAdapter):
    name = "recursion-probe"
    executable = "python3"

    def _get_version(self) -> str:
        return "test"

    def _build_command(self, target_dir: Path) -> list[str]:
        return ["python3", "-c", "print('anything')"]

    def _is_success_exit_code(self, returncode: int) -> bool:
        return returncode == 0

    def _parse_output(self, stdout: str, *, scan_timestamp: datetime) -> ParsedScanOutput:
        raise RecursionError("simulated: maximum recursion depth exceeded while parsing")


def test_recursion_error_during_parsing_is_classified_not_raised(tmp_path: Path) -> None:
    adapter = _RecursionErrorAdapter()

    result = adapter.scan(tmp_path, timeout_seconds=10)

    assert result.status == ScanStatus.OUTPUT_PARSE_ERROR
    assert result.error_message is not None
    assert "recursion" in result.error_message.lower()
