"""Demonstrates the requested error-analysis workflow end-to-end against the
REAL oracle (verification/oracle.py) from Prompt 7.

This is NOT a validation result — no accessible human-adjudicated ground
truth exists for this task (see the verification pass for Prompt 8). The
"human" labels here are illustrative stand-ins I assigned by hand to prove
the harness correctly surfaces a disagreement with full context (original
case, repaired case, human decision, oracle decision, and why they
differ), exactly as requested. Treat this as a test of the machinery, not
a performance claim.
"""

from __future__ import annotations

from terraveritas.evaluation.metrics import LabeledCase, evaluate, find_disagreements
from terraveritas.models.oracle import Classification
from terraveritas.models.plan import PlanStatus
from terraveritas.verification.oracle import classify_repair

from ..verification.helpers import differential_with_removed, invariant_result

SUCCESS = PlanStatus.PLAN_SUCCESS


def _predict(before_status, after_status, violated_before, violated_after, *, corroborate):
    differentials = [differential_with_removed("aws_s3_bucket.data")] if corroborate else []
    verdict = classify_repair(
        invariant_result(before_status, violated_conditions=violated_before),
        invariant_result(after_status, violated_conditions=violated_after),
        before_plan_status=SUCCESS,
        after_plan_status=SUCCESS,
        differential_results=differentials,
    )
    return verdict


def test_error_analysis_demo_surfaces_a_disagreement_with_full_context() -> None:
    from terraveritas.models.invariant import InvariantStatus

    FAIL, PASS = InvariantStatus.FAIL, InvariantStatus.PASS

    cases: list[LabeledCase] = []

    # Case A: genuine fix, scanner corroborates. Oracle and a human reviewer agree.
    verdict_a = _predict(FAIL, PASS, ["acl_grants_public"], [], corroborate=True)
    cases.append(
        LabeledCase(
            case_id="A",
            predicted=verdict_a.classification,
            actual=Classification.TRUE_FIX,
            original_summary="aws_s3_bucket.data: public-read ACL, no Block Public Access",
            repaired_summary="aws_s3_bucket.data: private ACL, full Block Public Access enabled",
            oracle_reasons=verdict_a.reasons,
        )
    )

    # Case B: illustrative disagreement. The invariant still fails (policy
    # exposure remains) but scanner evidence looks improved -> oracle says
    # DECEPTIVE_FIX. A human reviewer, in this illustrative label, judged it
    # PARTIAL_FIX instead (e.g. they weighted the ACL narrowing more heavily
    # than the oracle's conservative "any remaining exposure -> not fixed"
    # stance) -- a genuine, plausible source of oracle/human disagreement
    # worth surfacing, not a bug in either judgment.
    verdict_b = _predict(
        FAIL,
        FAIL,
        ["acl_grants_public", "policy_grants_public"],
        ["policy_grants_public"],
        corroborate=True,
    )
    cases.append(
        LabeledCase(
            case_id="B",
            predicted=verdict_b.classification,
            actual=Classification.PARTIAL_FIX,
            original_summary="aws_s3_bucket.data: public ACL AND public policy statement",
            repaired_summary="aws_s3_bucket.data: ACL fixed, policy statement still public",
            oracle_reasons=verdict_b.reasons,
        )
    )

    report = evaluate(cases)
    disagreements = find_disagreements(cases)

    assert report.n == 2
    assert len(disagreements) == 1

    d = disagreements[0]
    assert d.case_id == "B"
    assert d.predicted == Classification.DECEPTIVE_FIX
    assert d.actual == Classification.PARTIAL_FIX
    # The disagreement carries everything Prompt 8 asked to be shown for it:
    assert d.original_summary
    assert d.repaired_summary
    assert d.oracle_reasons  # the oracle's own stated reasons, for "why they differ"
