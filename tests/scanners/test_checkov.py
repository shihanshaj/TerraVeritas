"""Integration tests for CheckovAdapter against a real, installed Checkov binary.

These exercise the actual subprocess + real JSON output, not a mock, per the
project's "no fake completion" rule. Behaviors asserted here were manually
verified against checkov==3.3.16 before being encoded (see checkov.py's
module docstring) — these tests pin that verified behavior against
regressions in future Checkov versions.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from terraveritas.models.finding import FindingOutcome, ScanStatus
from terraveritas.scanners.checkov import CheckovAdapter

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "terraform"


def _rule_ids(findings, outcome: FindingOutcome) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.rule_id for f in findings if f.outcome == outcome}


def test_vulnerable_fixture_flags_public_access_rules() -> None:
    adapter = CheckovAdapter()

    result = adapter.scan(FIXTURES / "s3_vulnerable", timeout_seconds=60)

    assert result.status == ScanStatus.SUCCESS
    failed = _rule_ids(result.findings, FindingOutcome.FAILED)
    # CKV_AWS_20: public-read ACL. CKV2_AWS_6: missing Block Public Access.
    # Both are Candidate 1 (S3 Public Access Exposure) from the frozen scope.
    assert "CKV_AWS_20" in failed
    assert "CKV2_AWS_6" in failed


def test_secure_fixture_does_not_flag_public_access_rules() -> None:
    """The secure fixture still fails unrelated checks (logging, versioning,
    etc.) — only the public-access-specific rules must be clear. Asserting
    zero total failures would be testing Checkov's opinion of best practice,
    not the property this fixture was built to satisfy."""
    adapter = CheckovAdapter()

    result = adapter.scan(FIXTURES / "s3_secure", timeout_seconds=60)

    assert result.status == ScanStatus.SUCCESS
    failed = _rule_ids(result.findings, FindingOutcome.FAILED)
    assert "CKV_AWS_20" not in failed
    assert "CKV2_AWS_6" not in failed
    passed = _rule_ids(result.findings, FindingOutcome.PASSED)
    assert "CKV_AWS_20" in passed
    assert "CKV2_AWS_6" in passed


def test_invalid_hcl_is_target_unparseable_not_a_clean_scan() -> None:
    """Regression guard for the exact trap found during adapter verification:
    Checkov exits 0 and reports zero findings on broken HCL. Without explicit
    handling this looks identical to a genuinely clean scan."""
    adapter = CheckovAdapter()

    result = adapter.scan(FIXTURES / "invalid_hcl", timeout_seconds=60)

    assert result.status == ScanStatus.TARGET_UNPARSEABLE
    assert result.findings == []
    assert len(result.unparseable_files) == 1
    assert result.unparseable_files[0].endswith("main.tf")


def test_empty_directory_is_success_not_unparseable() -> None:
    """Zero .tf files is a legitimate empty scan, distinct from a parse
    failure — Checkov's JSON shape for this case has no "results" key."""
    adapter = CheckovAdapter()

    result = adapter.scan(FIXTURES / "empty_dir", timeout_seconds=60)

    assert result.status == ScanStatus.SUCCESS
    assert result.findings == []
    assert result.unparseable_files == []


def test_scanner_binary_not_found() -> None:
    adapter = CheckovAdapter()
    adapter.executable = "checkov-does-not-exist-xyz"

    result = adapter.scan(FIXTURES / "s3_vulnerable")

    assert result.status == ScanStatus.SCANNER_NOT_FOUND
    assert result.findings == []


def test_scanner_timeout() -> None:
    adapter = CheckovAdapter()

    result = adapter.scan(FIXTURES / "s3_vulnerable", timeout_seconds=0.01)

    assert result.status == ScanStatus.TIMEOUT
    assert result.findings == []


def test_version_is_captured() -> None:
    adapter = CheckovAdapter()

    result = adapter.scan(FIXTURES / "empty_dir", timeout_seconds=60)

    assert result.scanner_version == "3.3.16"


@pytest.mark.parametrize("fixture_name", ["s3_vulnerable", "s3_secure"])
def test_raw_evidence_is_preserved_verbatim(fixture_name: str) -> None:
    """Normalization must never destroy the original scanner fragment."""
    adapter = CheckovAdapter()

    result = adapter.scan(FIXTURES / fixture_name, timeout_seconds=60)

    assert len(result.findings) > 0
    for finding in result.findings:
        assert "check_id" in finding.raw_evidence
        assert finding.raw_evidence["check_id"] == finding.rule_id
