"""Adversarial test suite: genuine attempts to defeat TerraVeritas.

Every test documents, per the instructions: the attack, why a naive
verifier (one that just reruns the original scanner) would fail, the
EXPECTED TerraVeritas result predicted BEFORE running, and the security
property involved. Predictions were made after real empirical probing
(see the conversation record) — two hypothesized scanner blind spots
(legacy inline ACL, all-false Block Public Access flags) turned out to be
WRONG on real Checkov and are reported as such, not quietly dropped.

Where a synthetic PlanResult is used instead of a real Terraform plan,
that's the same disclosed sandbox constraint as every prior prompt (no
AWS provider registry access) — not a choice to avoid a harder test.
"""

from __future__ import annotations

import json

from terraveritas.invariants.s3_public_access import evaluate_s3_public_access_exposure
from terraveritas.models.invariant import InvariantStatus
from terraveritas.models.oracle import Classification, Confidence
from terraveritas.models.plan import PlanStatus
from terraveritas.scanners.checkov import CheckovAdapter
from terraveritas.verification.oracle import classify_repair

from ..differential.helpers import finding as diff_finding
from ..differential.helpers import scan_result
from ..invariants.helpers import plan_with, resource
from ..verification.helpers import invariant_result

BUCKET = "aws_s3_bucket.data"


def _fixtures_dir():
    from pathlib import Path

    return Path(__file__).resolve().parents[2] / "fixtures" / "terraform"


# ---------------------------------------------------------------------------
# Attack 1 — remove the scanner's syntax trigger while preserving the
# vulnerability, against THIS PROJECT'S INVARIANT (not the scanner, which
# real Checkov correctly still catches — see docstring).
#
# ATTACK: express the public grant via the legacy pre-v4 AWS-provider
# inline `acl` attribute on aws_s3_bucket, instead of a separate
# aws_s3_bucket_acl resource.
# WHY A NAIVE VERIFIER FAILS: a verifier that only knows the modern
# resource shape (aws_s3_bucket_acl) never looks at aws_s3_bucket.acl at
# all, and reports no grant found.
# EXPECTED: real Checkov still flags CKV_AWS_20 (verified empirically —
# my original hypothesis that this was a scanner blind spot was WRONG).
# TerraVeritas's own invariant, however, is exactly that naive verifier:
# it only reads aws_s3_bucket_acl, so it incorrectly returns PASS. This
# is a disclosed, known gap (Prompt 6), confirmed here by direct test
# rather than by inspection alone.
# SECURITY PROPERTY: no unauthenticated ACL grant to AllUsers/AuthenticatedUsers.
# ---------------------------------------------------------------------------


def test_attack_1_legacy_inline_acl_defeats_the_invariant_not_the_scanner() -> None:
    plan = plan_with(
        [resource(BUCKET, "aws_s3_bucket", {"id": "b", "bucket": "b", "acl": "public-read"})]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    # This IS the predicted miss, not a surprise — confirming the disclosed gap.
    assert result.status == InvariantStatus.PASS


def test_attack_1_real_checkov_is_not_fooled_by_the_same_attack() -> None:
    adapter = CheckovAdapter()
    scan = adapter.scan(_fixtures_dir() / "adversarial_legacy_acl", timeout_seconds=60)
    failed_ids = {f.rule_id for f in scan.findings if f.outcome.value == "failed"}
    assert "CKV_AWS_20" in failed_ids


# ---------------------------------------------------------------------------
# Attack 2 — move the insecure configuration to a resource type the
# invariant never looks at.
#
# ATTACK: lock down the bucket ACL/policy/BPA completely, then expose the
# same data via an S3 Access Point with its own public access-point policy
# (a distinct Terraform resource, aws_s3_access_point / aws_s3control_
# access_point_policy, with its OWN "meaning of public" rules per AWS's
# docs — different from bucket policy evaluation).
# WHY A NAIVE VERIFIER FAILS: it checks only the bucket-level mechanisms
# and concludes "no grant found" without knowing access points exist.
# EXPECTED: MISS. This is the one gap in S3_PUBLIC_ACCESS_EXPOSURE
# explicitly flagged in the Prompt 6 design review as NOT safe-direction-
# only — a genuine false PASS, not a defensible limitation.
# SECURITY PROPERTY: same as attack 1, via a different AWS mechanism the
# invariant was never scoped to cover (Prompt 2's frozen resource list).
# ---------------------------------------------------------------------------


def test_attack_2_access_point_exposure_is_an_undetected_false_pass() -> None:
    # A fully locked-down bucket per everything the invariant DOES check:
    plan = plan_with(
        [
            resource(BUCKET, "aws_s3_bucket", {"id": "b", "bucket": "b"}),
            resource(
                "aws_s3_bucket_public_access_block.data",
                "aws_s3_bucket_public_access_block",
                {
                    "bucket": "b",
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                },
            ),
            # The actual exposure lives here — a resource type this
            # invariant has never heard of:
            resource(
                "aws_s3control_access_point_policy.data",
                "aws_s3control_access_point_policy",
                {
                    "access_point_arn": "arn:aws:s3:us-east-1:123456789012:accesspoint/public-ap",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
                            ]
                        }
                    ),
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    # Predicted and confirmed false PASS — the disclosed non-safe-direction gap.
    assert result.status == InvariantStatus.PASS


# ---------------------------------------------------------------------------
# Attack 3 — replace one insecure mechanism with another, exploiting a
# parser edge case in principal matching.
#
# ATTACK: a bucket policy statement whose Principal.AWS is a MULTI-ELEMENT
# array containing "*" alongside a named account, e.g.
# {"AWS": ["arn:aws:iam::123456789012:root", "*"]} — grants to literally
# everyone (the "*" entry alone is sufficient under IAM's OR semantics
# for array-valued principals) but isn't the single-element ["*"] shape.
# WHY A NAIVE VERIFIER FAILS: exact-equality principal checks
# (`aws_val == ["*"]`) miss any array containing "*" alongside other entries.
# EXPECTED (before fix): MISS — genuine implementation bug, confirmed by
# reading the code before running this test, not discovered by surprise.
# SECURITY PROPERTY: no bucket-policy statement grants to an unauthenticated
# principal, regardless of how the wildcard is embedded in the Principal value.
# ---------------------------------------------------------------------------


def test_attack_3_multi_element_principal_array_with_wildcard() -> None:
    plan = plan_with(
        [
            resource(BUCKET, "aws_s3_bucket", {"id": "b", "bucket": "b"}),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "b",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": ["arn:aws:iam::123456789012:root", "*"]
                                    },
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            ]
                        }
                    ),
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.FAIL
    assert "policy_grants_public" in result.violated_conditions


# ---------------------------------------------------------------------------
# Attack 4 — split the resource across a type boundary the differential
# engine cannot bridge, and show the SYSTEM-LEVEL (not component-level)
# consequence: each component behaves "correctly" against the evidence
# it's given, yet the overall pipeline can still be fooled if a caller
# doesn't know to re-target the invariant evaluation.
#
# ATTACK: the original bucket's ACL exposure is removed entirely, and the
# SAME data is re-exposed via a brand-new, differently-typed, differently-
# addressed resource (a second bucket policy on a *different* bucket that
# receives the same objects via replication — modeled here simply as an
# unrelated new resource address).
# WHY A NAIVE VERIFIER FAILS: it re-scans only the original bucket address
# and sees a clean result.
# EXPECTED: the DIFFERENTIAL engine correctly reports REMOVED (for the
# original bucket) + NEW (for the unrelated one) rather than falsely
# claiming they're the same resource (already tested in Prompt 4) — that
# part is DETECTED correctly. But if an orchestration layer only re-runs
# the invariant against the ORIGINAL bucket address (the natural thing to
# do, since nothing links the two addresses), the oracle sees FAIL->PASS
# on that one address and calls it TRUE_FIX while missing that a NEW
# public bucket now exists. This is a discovered SYSTEM-LEVEL gap:
# individually-correct components composing into a wrong end-to-end
# result, because "which resource address to re-evaluate" is a caller
# responsibility no component here owns.
# SECURITY PROPERTY: same property, now on a second resource the oracle
# was never asked about.
# ---------------------------------------------------------------------------


def test_attack_4_split_across_resources_fools_naive_orchestration() -> None:
    before_plan = plan_with(
        [
            resource(BUCKET, "aws_s3_bucket", {"id": "b1", "bucket": "b1"}),
            resource(
                "aws_s3_bucket_acl.data",
                "aws_s3_bucket_acl",
                {"bucket": "b1", "acl": "public-read"},
            ),
        ]
    )
    # The repair removes the original grant AND introduces a new public
    # bucket entirely, but a caller only re-targets the original address:
    after_plan = plan_with(
        [resource(BUCKET, "aws_s3_bucket", {"id": "b1", "bucket": "b1"})]
    )
    new_bucket_plan = plan_with(
        [
            resource("aws_s3_bucket.replica", "aws_s3_bucket", {"id": "b2", "bucket": "b2"}),
            resource(
                "aws_s3_bucket_acl.replica",
                "aws_s3_bucket_acl",
                {"bucket": "b2", "acl": "public-read"},
            ),
        ]
    )

    before_invariant = evaluate_s3_public_access_exposure(before_plan, BUCKET)
    after_invariant_naive = evaluate_s3_public_access_exposure(after_plan, BUCKET)  # wrong target
    new_resource_invariant = evaluate_s3_public_access_exposure(
        new_bucket_plan, "aws_s3_bucket.replica"
    )

    # Each individual evaluation is correct against what it was asked:
    assert before_invariant.status == InvariantStatus.FAIL
    assert after_invariant_naive.status == InvariantStatus.PASS  # correct for THIS address
    assert new_resource_invariant.status == InvariantStatus.FAIL  # correct for THAT address

    # But an oracle fed only the naively-retargeted pair reaches a false
    # TRUE_FIX, oblivious to the second resource nobody asked it about:
    verdict = classify_repair(
        before_invariant,
        after_invariant_naive,
        before_plan_status=PlanStatus.PLAN_SUCCESS,
        after_plan_status=PlanStatus.PLAN_SUCCESS,
    )
    assert verdict.classification == Classification.TRUE_FIX  # the false positive, demonstrated


# ---------------------------------------------------------------------------
# Attack 5 — indirect exposure via a mechanism entirely outside the
# invariant's declared scope.
#
# ATTACK: lock the bucket down completely (private ACL, full BPA, no
# policy), but grant a public IAM role (AssumeRolePolicyDocument with
# Principal: "*") broad S3 permissions — anyone can assume the role and
# read the bucket, without the bucket's own configuration ever looking
# unsafe.
# WHY A NAIVE VERIFIER FAILS: same reason a sophisticated one does here —
# this is genuinely an IAM-authorization question (Candidate 5's territory
# from Prompt 2), never in S3_PUBLIC_ACCESS_EXPOSURE's scope.
# EXPECTED: MISS, and correctly so — this isn't a limitation to fix, it's
# a different security property (IAM over-permission) that a DIFFERENT,
# not-yet-implemented invariant would need to cover.
# SECURITY PROPERTY: technically a different one — public role assumption,
# not bucket-resource-policy exposure.
# ---------------------------------------------------------------------------


def test_attack_5_indirect_iam_exposure_is_out_of_scope() -> None:
    plan = plan_with(
        [
            resource(BUCKET, "aws_s3_bucket", {"id": "b", "bucket": "b"}),
            resource(
                "aws_s3_bucket_public_access_block.data",
                "aws_s3_bucket_public_access_block",
                {"bucket": "b", "ignore_public_acls": True, "restrict_public_buckets": True},
            ),
            # A public IAM role is simply a resource type this invariant
            # never reads — not even joined by the `bucket` attribute:
            resource(
                "aws_iam_role.public_reader",
                "aws_iam_role",
                {
                    "assume_role_policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "sts:AssumeRole",
                                }
                            ]
                        }
                    )
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    # Correctly PASS for what this invariant actually checks — the miss
    # here is a scope boundary, not a defect.
    assert result.status == InvariantStatus.PASS


# ---------------------------------------------------------------------------
# Attack 6 — exploit a REAL, empirically-verified Checkov blind spot.
#
# ATTACK: a bucket policy statement with Principal:"*" conditioned on a
# WILDCARDED aws:SourceVpc value ("vpc-*") — per AWS's own documented
# "meaning of public" (verified in the Prompt 6 design pass), this is
# still public: only a FIXED condition value narrows it. Real Checkov was
# tested against exactly this policy and its public-policy checks
# (CKV_AWS_70, CKV_AWS_93) both PASS — Checkov treats "a Condition is
# present" as sufficient, not "the condition value is actually fixed".
# WHY A NAIVE VERIFIER FAILS: this is the naive verifier — Checkov itself.
# EXPECTED: DETECTED. TerraVeritas's invariant implements AWS's exact
# disqualification algorithm (Prompt 6), so it correctly still fails this.
# SECURITY PROPERTY: bucket policy is not public per AWS's own evaluation
# semantics, which "any Condition present" does not establish.
# ---------------------------------------------------------------------------


def test_attack_6_wildcarded_condition_defeats_real_checkov_but_not_the_invariant() -> None:
    # Real Checkov's behavior on this exact policy (CKV_AWS_70/93 both
    # PASS) was verified manually against a live scan during the design
    # pass for this attack — not re-run here, since it needs no fixture
    # beyond what's already recorded. This test covers the invariant side.
    plan = plan_with(
        [
            resource(BUCKET, "aws_s3_bucket", {"id": "b", "bucket": "b"}),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "b",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                    "Condition": {"StringLike": {"aws:SourceVpc": "vpc-*"}},
                                }
                            ]
                        }
                    ),
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.FAIL


# ---------------------------------------------------------------------------
# Attack 7 — exploit incomplete plan information: a policy value Terraform
# could not resolve at plan time.
#
# ATTACK: the policy attribute is marked unknown in the plan
# (after_unknown_keys contains "policy"), but happens to still carry SOME
# string in `after` (Terraform's actual behavior for unknown string values
# was not independently re-verified in this sandbox — see disclosure
# below). A verifier that only checks whether `after["policy"]` parses as
# JSON, without consulting after_unknown_keys at all, could be fooled into
# treating a not-yet-known value as resolved.
# WHY A NAIVE VERIFIER FAILS: it never looks at after_unknown_keys at all
# — confirmed true of THIS invariant's code before this test was written.
# EXPECTED (before fix): a false PASS is possible if the placeholder in
# `after` happens to parse as valid, non-public JSON. Genuine bug —
# after_unknown_keys exists on PlannedResourceChange specifically to
# prevent this and was never consulted.
# DISCLOSED UNCERTAINTY: whether real Terraform ever actually populates
# `after` with a parseable placeholder for a genuinely unknown value
# (versus `null`) was not verified against a live plan in this sandbox
# (the same AWS-provider constraint as every prior prompt). The fix is
# applied regardless, since checking after_unknown_keys is strictly safer
# and costs nothing when it's empty.
# SECURITY PROPERTY: never treat an unresolved value as evidence of safety.
# ---------------------------------------------------------------------------


def test_attack_7_unknown_policy_value_not_guarded_by_after_unknown_keys() -> None:
    bucket = resource(BUCKET, "aws_s3_bucket", {"id": "b", "bucket": "b"})
    policy_resource = resource(
        "aws_s3_bucket_policy.data",
        "aws_s3_bucket_policy",
        {"bucket": "b", "policy": "{}"},  # resolves to "no statements" if read naively
    )
    # Mark it unknown, exactly as a real plan would for a not-yet-computed value:
    from dataclasses import replace

    policy_resource = replace(policy_resource, after_unknown_keys=["policy"])
    plan = plan_with([bucket, policy_resource])

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    # After the fix: must be UNKNOWN, never a confident PASS on an
    # unresolved value.
    assert result.status == InvariantStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Attack 8 — make a repair look secure under partial (single-source)
# evidence: an invariant PASS with zero corroborating scanner evidence.
#
# ATTACK: nothing adversarial in the Terraform itself — the attack is on
# the REPORTING layer. If confidence looked the same (HIGH) whether or
# not any scanner ran at all, a downstream consumer could mistake "the
# invariant resolved" for "this was thoroughly checked."
# WHY A NAIVE VERIFIER FAILS: a verifier that reports "PASS" without a
# distinct confidence signal gives the same output whether one or zero
# evidence sources were consulted.
# EXPECTED: DETECTED by design — Prompt 7's Confidence model requires
# differential evidence for HIGH; TRUE_FIX with zero scanner corroboration
# must be MEDIUM, not HIGH. Verified here as an adversarial check, not
# just a unit test of the happy path.
# SECURITY PROPERTY: confidence must reflect evidence completeness, not
# just whether *a* verdict was reached.
# ---------------------------------------------------------------------------


def test_attack_8_true_fix_with_no_corroboration_is_not_reported_as_high_confidence() -> None:
    verdict = classify_repair(
        invariant_result(InvariantStatus.FAIL),
        invariant_result(InvariantStatus.PASS),
        before_plan_status=PlanStatus.PLAN_SUCCESS,
        after_plan_status=PlanStatus.PLAN_SUCCESS,
        differential_results=[],
    )

    assert verdict.classification == Classification.TRUE_FIX
    assert verdict.confidence != Confidence.HIGH
    assert verdict.confidence == Confidence.MEDIUM


# ---------------------------------------------------------------------------
# Attack 9 — parser edge case: case variation in the IAM action string.
#
# ATTACK: "Action": "S3:GetObject" (capital S3) instead of the
# conventional lowercase "s3:GetObject".
# WHY A NAIVE VERIFIER FAILS: a case-sensitive prefix match
# (`.startswith("s3:GetObject")`) silently misses this, since Python
# string comparison is case-sensitive by default — confirmed true of this
# invariant's code before this test was written.
# EXPECTED (before fix): MISS. DISCLOSED UNCERTAINTY: whether AWS's own
# policy evaluation engine treats action names as case-insensitive at
# attach/evaluation time was not independently verified here — the fix
# (case-insensitive comparison) is applied as defensive hardening
# regardless, since it can only reduce false PASSes, never cause one.
# SECURITY PROPERTY: a sensitive action must be recognized regardless of
# incidental casing.
# ---------------------------------------------------------------------------


def test_attack_9_action_case_variation() -> None:
    plan = plan_with(
        [
            resource(BUCKET, "aws_s3_bucket", {"id": "b", "bucket": "b"}),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "b",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "S3:GetObject",
                                    "Resource": "*",
                                }
                            ]
                        }
                    ),
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.FAIL


# ---------------------------------------------------------------------------
# Attack 10 — produce contradictory scanner results and confirm the
# oracle's conservative handling holds with REAL evidence from one
# scanner, not just synthetic evidence on both sides.
#
# ATTACK: real Checkov (via a real scan of s3_secure, a genuine fix) shows
# the finding REMOVED. A second, synthetic scanner (standing in for a
# scanner this project hasn't implemented, e.g. Trivy) is fabricated to
# show the same rule as PERSISTENT — a genuine disagreement between
# sources.
# WHY A NAIVE VERIFIER FAILS: one that trusts a single scanner (or the
# first one it queries) would call this TRUE_FIX or DECEPTIVE_FIX based on
# whichever source it happened to check.
# EXPECTED: DETECTED-as-uncertain — the oracle must not resolve the
# contradiction by picking a side; the "looks improved" signal must be
# withheld (already the design from Prompt 7, confirmed here against one
# genuinely real evidence source).
# SECURITY PROPERTY: never trust a single scanner (Prompt 7's explicit
# requirement), even when the other scanner is real and the fix is genuine.
# ---------------------------------------------------------------------------


def test_attack_10_real_and_synthetic_scanner_disagreement_is_not_resolved_by_picking_a_side(
    tmp_path,
) -> None:
    adapter = CheckovAdapter()
    fixtures = _fixtures_dir()
    before_scan = adapter.scan(fixtures / "s3_vulnerable", timeout_seconds=60)
    after_scan = adapter.scan(fixtures / "s3_secure", timeout_seconds=60)

    from terraveritas.differential.scanner_diff import compare_scan_results

    real_differential = compare_scan_results(before_scan, after_scan)
    assert any(r.before.rule_id == "CKV_AWS_20" for r in real_differential.removed)  # sanity check

    # A synthetic second scanner (disclosed stand-in for an unimplemented
    # one, e.g. Trivy) that still flags the same finding after the repair:
    stub_before = scan_result(
        [diff_finding("CKV_AWS_20", "aws_s3_bucket.data")], scanner_name="synthetic-trivy-stub"
    )
    stub_after = scan_result(
        [diff_finding("CKV_AWS_20", "aws_s3_bucket.data")], scanner_name="synthetic-trivy-stub"
    )
    contradicting = compare_scan_results(stub_before, stub_after)

    verdict = classify_repair(
        invariant_result(InvariantStatus.FAIL),
        invariant_result(InvariantStatus.FAIL),  # invariant still fails regardless
        before_plan_status=PlanStatus.PLAN_SUCCESS,
        after_plan_status=PlanStatus.PLAN_SUCCESS,
        differential_results=[real_differential, contradicting],
    )

    assert verdict.classification != Classification.DECEPTIVE_FIX
    assert any("still flags" in n for n in verdict.remaining_uncertainty)
