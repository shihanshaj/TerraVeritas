"""Unit tests for the BEFORE/AFTER scanner-evidence comparator.

Written before the implementation, per the project's small-steps workflow.
Uses synthetic Finding objects (tests/differential/helpers.py) for precise
control over the matching edge cases; real Checkov output is exercised
separately in test_scanner_diff_checkov_integration.py.
"""

from __future__ import annotations

import pytest

from terraveritas.differential.scanner_diff import compare_scan_results
from terraveritas.models.finding import FindingOutcome, ScanStatus

from .helpers import finding, scan_result


def test_identical_before_and_after_is_all_persistent() -> None:
    before = scan_result([finding("CKV_AWS_20", "aws_s3_bucket.data")])
    after = scan_result([finding("CKV_AWS_20", "aws_s3_bucket.data")])

    result = compare_scan_results(before, after)

    assert len(result.persistent) == 1
    assert result.removed == []
    assert result.new == []
    assert result.relocated == []


def test_finding_removed_when_same_resource_now_passes() -> None:
    before = scan_result([finding("CKV_AWS_20", "aws_s3_bucket.data", FindingOutcome.FAILED)])
    after = scan_result([finding("CKV_AWS_20", "aws_s3_bucket.data", FindingOutcome.PASSED)])

    result = compare_scan_results(before, after)

    assert len(result.removed) == 1
    removed = result.removed[0]
    assert removed.resource_still_present_in_after is True
    assert removed.same_identity_now_passes is True
    assert result.persistent == []


def test_finding_removed_when_resource_deleted_entirely() -> None:
    before = scan_result([finding("CKV_AWS_20", "aws_s3_bucket.data")])
    after = scan_result([])

    result = compare_scan_results(before, after)

    assert len(result.removed) == 1
    removed = result.removed[0]
    assert removed.resource_still_present_in_after is False
    assert removed.same_identity_now_passes is False


def test_new_finding_on_genuinely_new_resource() -> None:
    before = scan_result([])
    after = scan_result([finding("CKV_AWS_20", "aws_s3_bucket.other")])

    result = compare_scan_results(before, after)

    assert len(result.new) == 1
    assert result.new[0].after.resource_id == "aws_s3_bucket.other"
    assert result.removed == []
    assert result.relocated == []


def test_persistent_finding_unaffected_by_unrelated_field_changes() -> None:
    """Matching keys on (rule_id, resource_id) only — a scanner description
    wording change between versions must not break the match."""
    before = scan_result(
        [finding("CKV_AWS_20", "aws_s3_bucket.data", description="old wording")]
    )
    after = scan_result(
        [finding("CKV_AWS_20", "aws_s3_bucket.data", description="new wording, same rule")]
    )

    result = compare_scan_results(before, after)

    assert len(result.persistent) == 1
    assert result.removed == []
    assert result.new == []


def test_resource_rename_is_relocated_not_removed_plus_new() -> None:
    """The core adversarial-restructuring case: same rule, same resource
    type, different address, unambiguous 1:1 -> a relocation candidate,
    not a false REMOVED+NEW pair."""
    before = scan_result([finding("CKV_AWS_20", "aws_s3_bucket.data")])
    after = scan_result([finding("CKV_AWS_20", "aws_s3_bucket.storage_bucket")])

    result = compare_scan_results(before, after)

    assert result.removed == []
    assert result.new == []
    assert len(result.relocated) == 1
    relocated = result.relocated[0]
    assert relocated.before.resource_id == "aws_s3_bucket.data"
    assert relocated.after.resource_id == "aws_s3_bucket.storage_bucket"


def test_ambiguous_relocation_candidates_are_not_falsely_paired() -> None:
    """False-matching test: two removed and two new candidates share the
    same (rule_id, resource_type) key. There is no principled way to say
    which maps to which, so none of them should be silently paired."""
    before = scan_result(
        [
            finding("CKV_AWS_20", "aws_s3_bucket.bucket_a"),
            finding("CKV_AWS_20", "aws_s3_bucket.bucket_b"),
        ]
    )
    after = scan_result(
        [
            finding("CKV_AWS_20", "aws_s3_bucket.bucket_c"),
            finding("CKV_AWS_20", "aws_s3_bucket.bucket_d"),
        ]
    )

    result = compare_scan_results(before, after)

    assert result.relocated == []
    assert len(result.removed) == 2
    assert len(result.new) == 2


def test_resource_splitting_across_types_is_not_resolved() -> None:
    """Documents a known, disclosed Phase 1 limitation: when a repair splits
    one resource into a different resource type (and typically a different
    rule_id), there is no shared key for the relocation heuristic to use.
    This is expected REMOVED + NEW, not a bug — resolving it needs
    plan/state-based identity (Prompt 5), not more string heuristics."""
    before = scan_result(
        [finding("CKV_AWS_24", "aws_security_group.web", resource_type="aws_security_group")]
    )
    after = scan_result(
        [
            finding(
                "CKV_AWS_260",
                "aws_security_group_rule.web_ssh",
                resource_type="aws_security_group_rule",
            )
        ]
    )

    result = compare_scan_results(before, after)

    assert result.relocated == []
    assert len(result.removed) == 1
    assert len(result.new) == 1


def test_duplicate_identical_findings_are_multiset_matched() -> None:
    """Two identical (rule_id, resource_id) findings in BEFORE, one in AFTER:
    one pair persists, one leftover is removed — never silently collapsed
    to a single 1:1 match that drops evidence."""
    before = scan_result(
        [
            finding("CKV_AWS_20", "aws_s3_bucket.data"),
            finding("CKV_AWS_20", "aws_s3_bucket.data"),
        ]
    )
    after = scan_result([finding("CKV_AWS_20", "aws_s3_bucket.data")])

    result = compare_scan_results(before, after)

    assert len(result.persistent) == 1
    assert len(result.removed) == 1


def test_only_failed_outcomes_participate_in_diff_categories() -> None:
    """PASSED/SKIPPED findings are context, not diffable "findings" in the
    vulnerability sense — but they still feed the removed-finding evidence
    flags (see test_finding_removed_when_same_resource_now_passes)."""
    before = scan_result(
        [
            finding("CKV_AWS_20", "aws_s3_bucket.data", FindingOutcome.FAILED),
            finding("CKV_AWS_93", "aws_s3_bucket.data", FindingOutcome.PASSED),
        ]
    )
    after = scan_result(
        [
            finding("CKV_AWS_20", "aws_s3_bucket.data", FindingOutcome.FAILED),
            finding("CKV_AWS_93", "aws_s3_bucket.data", FindingOutcome.PASSED),
        ]
    )

    result = compare_scan_results(before, after)

    assert len(result.persistent) == 1
    assert result.persistent[0].before.rule_id == "CKV_AWS_20"


def test_raises_when_before_scan_did_not_succeed() -> None:
    before = scan_result([], status=ScanStatus.TIMEOUT)
    after = scan_result([])

    with pytest.raises(ValueError, match="before"):
        compare_scan_results(before, after)


def test_raises_when_after_scan_did_not_succeed() -> None:
    before = scan_result([])
    after = scan_result([], status=ScanStatus.TARGET_UNPARSEABLE)

    with pytest.raises(ValueError, match="after"):
        compare_scan_results(before, after)


def test_raises_when_scanner_names_differ() -> None:
    before = scan_result([], scanner_name="checkov")
    after = scan_result([], scanner_name="trivy")

    with pytest.raises(ValueError, match="scanner"):
        compare_scan_results(before, after)


def test_findings_with_no_resource_id_use_none_as_identity() -> None:
    """Some checks (provider/file-level) have no resource attached at all —
    None must be a valid, stable identity component, not a crash."""
    before = scan_result([finding("CKV_AWS_1", None)])
    after = scan_result([finding("CKV_AWS_1", None)])

    result = compare_scan_results(before, after)

    assert len(result.persistent) == 1
