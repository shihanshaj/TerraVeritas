"""End-to-end differential engine tests against real Checkov output.

Unit tests in test_scanner_diff.py control the matching edge cases with
synthetic Finding objects; these prove the same algorithm behaves correctly
on genuine scanner evidence, not just on evidence shaped by my own
assumptions about what Checkov returns.
"""

from __future__ import annotations

from pathlib import Path

from terraveritas.differential.scanner_diff import compare_scan_results
from terraveritas.models.finding import FindingOutcome
from terraveritas.scanners.checkov import CheckovAdapter

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "terraform"


def test_real_fix_shows_public_access_rules_as_removed() -> None:
    adapter = CheckovAdapter()
    before = adapter.scan(FIXTURES / "s3_vulnerable", timeout_seconds=60)
    after = adapter.scan(FIXTURES / "s3_secure", timeout_seconds=60)

    result = compare_scan_results(before, after)

    removed_rule_ids = {r.before.rule_id for r in result.removed}
    assert "CKV_AWS_20" in removed_rule_ids
    assert "CKV2_AWS_6" in removed_rule_ids
    for r in result.removed:
        if r.before.rule_id in {"CKV_AWS_20", "CKV2_AWS_6"}:
            # Same resource label ("data") in both fixtures, so this is a
            # same-identity pass, not a resource that vanished.
            assert r.resource_still_present_in_after is True
            assert r.same_identity_now_passes is True
    # Unrelated checks (logging, versioning, etc.) still fail in both —
    # they must show up as persistent, not get swept into "removed".
    assert len(result.persistent) > 0


def test_renamed_but_still_vulnerable_is_relocated_on_real_evidence() -> None:
    adapter = CheckovAdapter()
    before = adapter.scan(FIXTURES / "s3_vulnerable", timeout_seconds=60)
    after = adapter.scan(FIXTURES / "s3_vulnerable_renamed", timeout_seconds=60)

    result = compare_scan_results(before, after)

    relocated_rule_ids = {r.before.rule_id for r in result.relocated}
    assert "CKV_AWS_20" in relocated_rule_ids
    assert "CKV2_AWS_6" in relocated_rule_ids
    for r in result.relocated:
        if r.before.rule_id in {"CKV_AWS_20", "CKV2_AWS_6"}:
            assert r.before.resource_id == "aws_s3_bucket.data"
            assert r.after.resource_id == "aws_s3_bucket.archive"
            assert r.after.outcome == FindingOutcome.FAILED
    # The vulnerability was never actually fixed, just relocated — it must
    # not show up as a clean removal.
    removed_rule_ids = {r.before.rule_id for r in result.removed}
    assert "CKV_AWS_20" not in removed_rule_ids
    assert "CKV2_AWS_6" not in removed_rule_ids
