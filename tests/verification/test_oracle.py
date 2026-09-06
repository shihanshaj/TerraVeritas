"""Tests for the security-intent oracle's decision process.

Organized to mirror the decision table from the design pass: known cases,
deceptive cases, incomplete evidence, and contradictory evidence, plus
explicit tests for the two safety properties the oracle is supposed to
guarantee by construction (scanner evidence never upgrades to TRUE_FIX;
UNKNOWN never becomes a positive verdict).
"""

from __future__ import annotations

import pytest

from terraveritas.models.diff import DifferentialResult, PersistentFinding, RemovedFinding
from terraveritas.models.invariant import InvariantStatus
from terraveritas.models.oracle import Classification, Confidence
from terraveritas.models.plan import PlanStatus
from terraveritas.verification.oracle import classify_repair

from .helpers import (
    differential_with_new,
    differential_with_persistent,
    differential_with_relocated,
    differential_with_removed,
    finding,
    invariant_result,
)

PASS = InvariantStatus.PASS
FAIL = InvariantStatus.FAIL
UNKNOWN = InvariantStatus.UNKNOWN
SUCCESS = PlanStatus.PLAN_SUCCESS


# --- Known cases ---


def test_true_fix_with_corroborating_scanner_evidence() -> None:
    verdict = classify_repair(
        invariant_result(FAIL, reason="ACL grants public access"),
        invariant_result(PASS, reason="no public grant found"),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[differential_with_removed("aws_s3_bucket.data")],
    )

    assert verdict.classification == Classification.TRUE_FIX
    assert verdict.confidence == Confidence.HIGH
    assert verdict.remaining_uncertainty == []


def test_true_fix_without_differential_evidence_is_medium_confidence() -> None:
    verdict = classify_repair(
        invariant_result(FAIL),
        invariant_result(PASS),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
    )

    assert verdict.classification == Classification.TRUE_FIX
    assert verdict.confidence == Confidence.MEDIUM


def test_inconclusive_when_invariant_already_passed_before() -> None:
    """The premise "original violates the invariant" doesn't hold — there
    was nothing for THIS invariant to fix."""
    verdict = classify_repair(
        invariant_result(PASS),
        invariant_result(PASS),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
    )

    assert verdict.classification == Classification.INCONCLUSIVE
    assert verdict.confidence == Confidence.LOW


# --- Deceptive cases ---


def test_deceptive_fix_when_scanner_clears_but_invariant_still_fails() -> None:
    verdict = classify_repair(
        invariant_result(FAIL, violated_conditions=["acl_grants_public", "policy_grants_public"]),
        invariant_result(
            FAIL, violated_conditions=["policy_grants_public"], reason="policy still public"
        ),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[differential_with_removed("aws_s3_bucket.data")],
    )

    # Even though the invariant narrowed (ACL fixed), the scanner-visible
    # "looks fixed" signal takes priority — this is the headline case.
    assert verdict.classification == Classification.DECEPTIVE_FIX
    assert verdict.confidence == Confidence.HIGH


def test_scanner_evidence_alone_can_never_produce_true_fix() -> None:
    """Safety property: even overwhelming scanner-visible "looks fixed"
    evidence must never upgrade a verdict to TRUE_FIX without the invariant
    itself resolving to PASS."""
    verdict = classify_repair(
        invariant_result(FAIL),
        invariant_result(FAIL),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[
            differential_with_removed("aws_s3_bucket.data"),
            differential_with_removed("aws_s3_bucket.data", scanner_name="trivy"),
        ],
    )

    assert verdict.classification != Classification.TRUE_FIX
    assert verdict.classification == Classification.DECEPTIVE_FIX


# --- Partial fix ---


def test_partial_fix_with_narrowing() -> None:
    verdict = classify_repair(
        invariant_result(FAIL, violated_conditions=["acl_grants_public", "policy_grants_public"]),
        invariant_result(FAIL, violated_conditions=["policy_grants_public"]),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
    )

    assert verdict.classification == Classification.PARTIAL_FIX
    assert any("narrowing" in r for r in verdict.reasons)


def test_partial_fix_with_no_narrowing_is_disclosed_as_weak_fit() -> None:
    """Nothing changed at all — the six-label taxonomy has no distinct
    "no-op" class, so this is documented explicitly as the weakest-fit use
    of PARTIAL_FIX rather than silently presented as equivalent to genuine
    narrowing."""
    verdict = classify_repair(
        invariant_result(FAIL, violated_conditions=["acl_grants_public"]),
        invariant_result(FAIL, violated_conditions=["acl_grants_public"]),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
    )

    assert verdict.classification == Classification.PARTIAL_FIX
    assert any("no measurable narrowing" in r for r in verdict.reasons)


# --- Regression ---


def test_regression_from_new_findings() -> None:
    verdict = classify_repair(
        invariant_result(FAIL),
        invariant_result(PASS),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[differential_with_new("aws_security_group.web")],
    )

    assert verdict.classification == Classification.REGRESSION
    assert verdict.confidence == Confidence.HIGH


def test_regression_takes_priority_over_true_fix() -> None:
    """Even a clean TRUE_FIX-shaped invariant transition must be reported
    as REGRESSION if the repair introduced an unrelated new problem —
    REGRESSION is checked first, not folded silently into TRUE_FIX."""
    verdict = classify_repair(
        invariant_result(FAIL),
        invariant_result(PASS),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[
            differential_with_removed("aws_s3_bucket.data"),
            differential_with_new("aws_iam_role_policy.overly_broad"),
        ],
    )

    assert verdict.classification == Classification.REGRESSION


def test_regression_from_invariant_itself_regressing() -> None:
    verdict = classify_repair(
        invariant_result(PASS),
        invariant_result(FAIL),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
    )

    assert verdict.classification == Classification.REGRESSION
    # No differential evidence corroborates this — confidence reflects that.
    assert verdict.confidence == Confidence.LOW


# --- Invalid configuration ---


def test_invalid_configuration_short_circuits_everything_else() -> None:
    verdict = classify_repair(
        invariant_result(FAIL),
        invariant_result(UNKNOWN, reason="plan did not succeed"),
        before_plan_status=SUCCESS,
        after_plan_status=PlanStatus.PLAN_INVALID_CONFIGURATION,
        differential_results=[differential_with_new("aws_s3_bucket.data")],
    )

    assert verdict.classification == Classification.INVALID_CONFIGURATION
    assert verdict.confidence == Confidence.HIGH


# --- Incomplete evidence ---


def test_inconclusive_when_after_invariant_unknown() -> None:
    verdict = classify_repair(
        invariant_result(FAIL),
        invariant_result(UNKNOWN, reason="bucket not found in plan"),
        before_plan_status=SUCCESS,
        after_plan_status=PlanStatus.PLAN_PROVIDER_FAILURE,
    )

    assert verdict.classification == Classification.INCONCLUSIVE
    assert verdict.confidence == Confidence.LOW
    assert any("bucket not found" in r for r in verdict.reasons)


def test_inconclusive_when_before_invariant_unknown() -> None:
    verdict = classify_repair(
        invariant_result(UNKNOWN, reason="policy redacted"),
        invariant_result(PASS),
        before_plan_status=PlanStatus.PLAN_TIMEOUT,
        after_plan_status=SUCCESS,
    )

    assert verdict.classification == Classification.INCONCLUSIVE


def test_unknown_never_becomes_a_positive_verdict() -> None:
    """Safety property, stated directly: no combination involving an
    UNKNOWN invariant status can produce TRUE_FIX."""
    for before_status in (PASS, FAIL, UNKNOWN):
        verdict = classify_repair(
            invariant_result(before_status),
            invariant_result(UNKNOWN),
            before_plan_status=SUCCESS,
            after_plan_status=SUCCESS,
        )
        assert verdict.classification != Classification.TRUE_FIX


# --- Contradictory evidence ---


def test_contradicting_scanner_suppresses_deceptive_fix_signal() -> None:
    """One scanner shows the finding removed, another still flags it for
    the same resource — the "looks improved" signal must not fire on a
    single supporting scanner when another contradicts it."""
    verdict = classify_repair(
        invariant_result(FAIL),
        invariant_result(FAIL),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[
            differential_with_removed("aws_s3_bucket.data"),
            differential_with_persistent("aws_s3_bucket.data", scanner_name="trivy"),
        ],
    )

    assert verdict.classification == Classification.PARTIAL_FIX
    assert any("still flags" in n for n in verdict.remaining_uncertainty)


def test_relocated_finding_is_not_treated_as_improvement() -> None:
    """A RELOCATED finding (Prompt 4) means the vulnerability persisted
    under a new resource address, not that it was fixed — must not count
    toward the "looks improved" signal."""
    verdict = classify_repair(
        invariant_result(FAIL, resource_address="aws_s3_bucket.data"),
        invariant_result(FAIL, resource_address="aws_s3_bucket.archive"),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[
            differential_with_relocated("aws_s3_bucket.data", "aws_s3_bucket.archive")
        ],
    )

    assert verdict.classification == Classification.PARTIAL_FIX


def test_mismatched_invariant_ids_raise() -> None:
    with pytest.raises(ValueError, match="same invariant"):
        classify_repair(
            invariant_result(FAIL, invariant_id="S3_PUBLIC_ACCESS_EXPOSURE"),
            invariant_result(PASS, invariant_id="SG_INGRESS_EXPOSURE"),
            before_plan_status=SUCCESS,
            after_plan_status=SUCCESS,
        )


def test_empty_differential_list_treated_same_as_none() -> None:
    verdict = classify_repair(
        invariant_result(FAIL),
        invariant_result(PASS),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[],
    )

    assert verdict.classification == Classification.TRUE_FIX
    assert verdict.confidence == Confidence.MEDIUM


def test_verdict_always_carries_nonempty_reasons() -> None:
    for before_status in (PASS, FAIL, UNKNOWN):
        for after_status in (PASS, FAIL, UNKNOWN):
            verdict = classify_repair(
                invariant_result(before_status),
                invariant_result(after_status),
                before_plan_status=SUCCESS,
                after_plan_status=SUCCESS,
            )
            msg = f"empty reasons for before={before_status}, after={after_status}"
            assert verdict.reasons, msg


# --- Scanner-improvement scoping: sibling-resource attribution ---
# Root cause: Checkov attributes a bucket-policy finding (e.g. CKV_AWS_70)
# to the separate aws_s3_bucket_policy resource's own address, not the
# bucket's -- confirmed against a real scan (phase2_case_c_deceptive_
# attempt's stored differential: CKV_AWS_70 removed with resource_id
# "aws_s3_bucket_policy.data", while the invariant's own identity is
# "aws_s3_bucket.data"). The oracle previously compared scanner evidence
# against only the bare invariant.resource_address, so a real, relevant,
# cleared finding on a sibling resource was structurally invisible to
# DECEPTIVE_FIX detection regardless of repair quality. Investigated and
# rejected: matching by rule_id alone (any resource, anywhere) -- too
# broad, would let an unrelated bucket's cleared finding count as
# improvement here; matching across the full Terraform dependency graph --
# unbounded, no natural stopping point, would also make regression
# detection wildly over-broad. Fixed by scoping to exactly the resource
# set an invariant reports it examined (InvariantResult.
# related_resource_addresses) -- as wide as the invariant's own definition
# of "what determines this security property," no wider. See
# docs/deceptive_fix_scoping.md.


def test_deceptive_fix_detected_when_cleared_finding_is_on_a_sibling_resource() -> None:
    """The headline case this fix exists for: the scanner-cleared finding
    is on the POLICY resource, not the bucket, and the invariant reports
    both as part of the same judgment via related_resource_addresses."""
    related = ["aws_s3_bucket.data", "aws_s3_bucket_policy.data"]
    verdict = classify_repair(
        invariant_result(
            FAIL,
            violated_conditions=["policy_grants_public"],
            related_resource_addresses=related,
        ),
        invariant_result(
            FAIL,
            violated_conditions=["policy_grants_public"],
            reason="policy still public",
            related_resource_addresses=related,
        ),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[differential_with_removed("aws_s3_bucket_policy.data")],
    )

    assert verdict.classification == Classification.DECEPTIVE_FIX


def test_unrelated_resources_finding_cleared_does_not_count_as_improvement() -> None:
    """Safety-preserving companion: a finding cleared on a resource that is
    NOT part of this invariant's related set (e.g. an entirely different
    bucket's policy, or an unrelated resource type) must not count as
    improvement -- the fix widens the scope to what the invariant actually
    examined, not to the whole scan."""
    related = ["aws_s3_bucket.data", "aws_s3_bucket_policy.data"]
    verdict = classify_repair(
        invariant_result(
            FAIL,
            violated_conditions=["policy_grants_public"],
            related_resource_addresses=related,
        ),
        invariant_result(
            FAIL,
            violated_conditions=["policy_grants_public"],
            reason="policy still public",
            related_resource_addresses=related,
        ),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[differential_with_removed("aws_s3_bucket_lifecycle_configuration.data")],
    )

    assert verdict.classification == Classification.PARTIAL_FIX


def test_scanner_scoping_falls_back_to_bare_address_when_not_populated() -> None:
    """Backward-compatibility: an InvariantResult that doesn't populate
    related_resource_addresses (the field is additive/optional) must fall
    back to exactly the old, single-address behavior, not match everything
    or nothing."""
    verdict = classify_repair(
        invariant_result(FAIL, violated_conditions=["acl_grants_public", "policy_grants_public"]),
        invariant_result(
            FAIL, violated_conditions=["policy_grants_public"], reason="policy still public"
        ),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        # Finding cleared on a DIFFERENT resource than the bare
        # resource_address ("aws_s3_bucket.data") -- must not count.
        differential_results=[differential_with_removed("aws_s3_bucket_policy.data")],
    )

    assert verdict.classification == Classification.PARTIAL_FIX


def test_real_differential_still_correctly_withholds_deceptive_fix_on_genuine_contradiction() -> (
    None
):
    """Real data from phase2_case_c_deceptive_attempt's stored differential:
    CKV_AWS_70 was removed on the policy resource (now in scope), but
    CKV2_AWS_6 ("no Block Public Access resource") persists on the BUCKET
    ITSELF -- a genuine, real contradiction, not an artifact of narrow
    scoping. The fix must not blindly flip every sibling-resource case to
    DECEPTIVE_FIX; a real, independent contradiction on an in-scope
    resource must still withhold the signal. (CKV_AWS_300 and CKV_AWS_26,
    also persistent in the real data on the lifecycle-configuration and SNS
    topic resources respectively, are correctly OUT of scope and must not
    contribute to the contradiction -- confirmed by this test using the
    exact real resource_ids, not a simplified stand-in.)"""
    related = [
        "aws_s3_bucket.data",
        "aws_s3_bucket_policy.data",
    ]
    differential = DifferentialResult(
        scanner_name="checkov",
        removed=[
            RemovedFinding(
                before=finding("CKV_AWS_70", "aws_s3_bucket_policy.data"),
                resource_still_present_in_after=True,
                same_identity_now_passes=True,
            )
        ],
        persistent=[
            PersistentFinding(
                before=finding("CKV2_AWS_6", "aws_s3_bucket.data"),
                after=finding("CKV2_AWS_6", "aws_s3_bucket.data"),
            ),
            PersistentFinding(
                before=finding("CKV_AWS_300", "aws_s3_bucket_lifecycle_configuration.data"),
                after=finding("CKV_AWS_300", "aws_s3_bucket_lifecycle_configuration.data"),
            ),
            PersistentFinding(
                before=finding("CKV_AWS_26", "aws_sns_topic.notifications"),
                after=finding("CKV_AWS_26", "aws_sns_topic.notifications"),
            ),
        ],
        new=[],
        relocated=[],
    )

    verdict = classify_repair(
        invariant_result(
            FAIL, violated_conditions=["policy_grants_public"], related_resource_addresses=related
        ),
        invariant_result(
            FAIL,
            violated_conditions=["policy_grants_public"],
            reason="policy still public",
            related_resource_addresses=related,
        ),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=[differential],
    )

    assert verdict.classification == Classification.PARTIAL_FIX
    assert any("still flags" in n for n in verdict.remaining_uncertainty)
