"""Tests for the security-intent oracle's decision process.

Organized to mirror the decision table from the design pass: known cases,
deceptive cases, incomplete evidence, and contradictory evidence, plus
explicit tests for the two safety properties the oracle is supposed to
guarantee by construction (scanner evidence never upgrades to TRUE_FIX;
UNKNOWN never becomes a positive verdict).
"""

from __future__ import annotations

import pytest

from terraveritas.models.invariant import InvariantStatus
from terraveritas.models.oracle import Classification, Confidence
from terraveritas.models.plan import PlanStatus
from terraveritas.verification.oracle import classify_repair

from .helpers import (
    differential_with_new,
    differential_with_persistent,
    differential_with_relocated,
    differential_with_removed,
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
