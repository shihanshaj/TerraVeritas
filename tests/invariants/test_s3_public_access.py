"""Tests for the S3_PUBLIC_ACCESS_EXPOSURE invariant.

Uses synthetic PlanResult objects (see helpers.py for why — this sandbox
cannot reliably produce a real AWS-provider plan). Several test cases here
are taken directly from AWS's own documented "meaning of public" examples
(fetched during the design pass), not invented — see the
wildcarded-vs-fixed-SourceVpc pair below in particular.
"""

from __future__ import annotations

import json

from terraveritas.invariants.s3_public_access import (
    _action_is_sensitive,
    evaluate_s3_public_access_exposure,
)
from terraveritas.models.invariant import InvariantStatus
from terraveritas.models.plan import PlanResult, PlanStatus

from .helpers import plan_with, resource, resource_with_unknown

BUCKET = "aws_s3_bucket.data"


def bucket_resource(bucket_id: str = "my-bucket") -> object:
    return resource(BUCKET, "aws_s3_bucket", {"id": bucket_id, "bucket": bucket_id})


def test_fully_open_bucket_fails_on_both_mechanisms() -> None:
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_acl.data",
                "aws_s3_bucket_acl",
                {"bucket": "my-bucket", "acl": "public-read"},
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.FAIL
    assert "acl_grants_public" in result.violated_conditions


def test_public_acl_via_explicit_grant_block() -> None:
    """The canned `acl` attribute is "private", but an explicit grant to
    AllUsers still makes the bucket public — the invariant must check both
    representations, not just the canned string."""
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_acl.data",
                "aws_s3_bucket_acl",
                {
                    "bucket": "my-bucket",
                    "acl": "private",
                    "access_control_policy": [
                        {
                            "grant": [
                                {
                                    "permission": "READ",
                                    "grantee": [
                                        {
                                            "type": "Group",
                                            "uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.FAIL
    assert "acl_grants_public" in result.violated_conditions


def test_full_block_public_access_neutralizes_public_acl_and_policy() -> None:
    """BPA is an independent, strong guarantee — it neutralizes ACL/policy
    exposure regardless of their content."""
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_acl.data",
                "aws_s3_bucket_acl",
                {"bucket": "my-bucket", "acl": "public-read"},
            ),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            ]
                        }
                    ),
                },
            ),
            resource(
                "aws_s3_bucket_public_access_block.data",
                "aws_s3_bucket_public_access_block",
                {
                    "bucket": "my-bucket",
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": True,
                    "restrict_public_buckets": True,
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []


def test_bucket_owner_enforced_neutralizes_acl_but_not_policy() -> None:
    """Object Ownership = BucketOwnerEnforced disables ACLs entirely, but
    has no effect on bucket-policy-based exposure — the invariant must not
    conflate the two mechanisms."""
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_acl.data",
                "aws_s3_bucket_acl",
                {"bucket": "my-bucket", "acl": "public-read"},
            ),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            ]
                        }
                    ),
                },
            ),
            resource(
                "aws_s3_bucket_ownership_controls.data",
                "aws_s3_bucket_ownership_controls",
                {"bucket": "my-bucket", "rule": [{"object_ownership": "BucketOwnerEnforced"}]},
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.FAIL
    assert result.violated_conditions == ["policy_grants_public"]


def test_policy_conditioned_on_fixed_source_vpc_is_not_public() -> None:
    """Taken directly from AWS's own documented example: a Principal:* Allow
    statement conditioned on a FIXED aws:SourceVpc value is not public."""
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Principal": "*",
                                    "Resource": "*",
                                    "Action": "s3:PutObject",
                                    "Effect": "Allow",
                                    "Condition": {
                                        "StringEquals": {"aws:SourceVpc": "vpc-91237329"}
                                    },
                                }
                            ]
                        }
                    ),
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.PASS


def test_policy_conditioned_on_wildcarded_source_vpc_is_still_public() -> None:
    """Also taken directly from AWS's documented example: the *wildcarded*
    version of the same condition ("vpc-*") is explicitly still public.
    This is exactly the AWS-semantics precision a naive "any Condition
    present -> safe" scanner-style rule would get wrong."""
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Principal": "*",
                                    "Resource": "*",
                                    "Action": "s3:PutObject",
                                    "Effect": "Allow",
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
    assert result.violated_conditions == ["policy_grants_public"]


def test_unrecognized_condition_key_is_unknown_not_a_guess() -> None:
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                    "Condition": {
                                        "StringEquals": {"some:UnrecognizedKey": "value"}
                                    },
                                }
                            ]
                        }
                    ),
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.UNKNOWN


def test_not_principal_is_never_treated_as_public() -> None:
    """A Deny + NotPrincipal allowlist pattern contains the literal string
    "*" but is the opposite of public exposure."""
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Deny",
                                    "NotPrincipal": {
                                        "AWS": "arn:aws:iam::123456789012:role/allowed"
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

    assert result.status == InvariantStatus.PASS


def test_specific_account_principal_is_not_public() -> None:
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
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

    assert result.status == InvariantStatus.PASS


def test_one_public_statement_among_several_still_fails() -> None:
    """Union semantics, matching AWS's own documented multi-statement
    evaluation: one public statement is enough regardless of others."""
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                },
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                },
                            ]
                        }
                    ),
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.FAIL


def test_bare_bucket_passes_based_on_declared_config_not_verified_aws_default() -> None:
    """No ACL/policy/BPA/ownership resource declared at all: nothing this
    invariant reads has granted public access, so it reports PASS based on
    what's declared — this is NOT a verified claim about AWS's own implicit
    default BPA behavior for a bare bucket. Two independent attempts to
    confirm the real default against AWS's own documentation (see module
    docstring's "Disclosed scope gaps") both failed to find a crisp
    confirmation. Unlike most of this invariant's other disclosed gaps,
    this one is not known to be safe-direction-only — do not read a passing
    test here as "verified safe for a bare bucket in reality"."""
    plan = plan_with([bucket_resource()])

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.PASS


def test_unknown_when_plan_did_not_succeed() -> None:
    from terraveritas.models.plan import PlanResult

    plan = PlanResult(target_path="/x", status=PlanStatus.PLAN_PROVIDER_FAILURE)

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.UNKNOWN


def test_unknown_when_bucket_not_in_plan() -> None:
    plan = plan_with([])

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.UNKNOWN


def test_unknown_when_policy_value_is_redacted() -> None:
    """A sensitive-redacted policy value would appear as a non-string
    (Terraform replaces it with a boolean marker in after_sensitive, and
    `after` itself may omit or null the real value) — must never be treated
    as "no policy" (a false PASS)."""
    plan = plan_with(
        [
            bucket_resource(),
            resource(
                "aws_s3_bucket_policy.data", "aws_s3_bucket_policy", {"bucket": "my-bucket"}
            ),
        ]
    )
    # Simulate a redacted/non-string policy value directly (policy present,
    # but its content isn't a plain string):
    plan.resource_changes[1].after["policy"] = True

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.UNKNOWN


def test_known_gap_legacy_inline_acl_attribute_is_not_detected() -> None:
    """Documents a disclosed limitation, not a correctness claim: exposure
    declared via the legacy pre-v4-provider inline `aws_s3_bucket.acl`
    attribute (rather than a separate aws_s3_bucket_acl resource) is
    invisible to this invariant and incorrectly evaluates as PASS."""
    plan = plan_with(
        [
            resource(
                BUCKET,
                "aws_s3_bucket",
                {"id": "my-bucket", "bucket": "my-bucket", "acl": "public-read"},
            )
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    # This SHOULD be FAIL in reality — asserting PASS here documents the gap.
    assert result.status == InvariantStatus.PASS


# --- Regression tests: real terraform plan data (not synthetic) ---
# fixtures/real_plans/*.json were captured from an ACTUAL `terraform plan`
# + `terraform show -json` run against the AWS provider (see
# scripts/run_real_e2e_pipeline.py and scripts/build_provider_mirror.py) —
# the first time this project ever achieved a real PLAN_SUCCESS. Running
# the invariant against this real data immediately surfaced a genuine bug
# no synthetic test had ever caught: for a `create`-action plan (the only
# kind this project produces, since `apply` is never run), a computed
# cross-reference like `bucket = aws_s3_bucket.data.id` is entirely
# UNKNOWN in `after` — omitted, not resolved — so the old resolved-value-
# only join in _find_by_bucket silently failed to correlate the ACL
# resource to its bucket, and the invariant reported PASS on a bucket with
# a literal `acl = "public-read"`. Fixed by adding a static-reference-graph
# join (configuration.root_module.resources[].expressions) as the primary
# strategy. These tests load the real captured plan JSON through the
# project's own real parsing path (_extract_resource_changes), not a
# hand-rolled re-parse, so they exercise exactly the code a live run does.


def _load_real_plan(fixture_name: str) -> PlanResult:
    import json as _json
    from pathlib import Path

    from terraveritas.terraform.plan import _extract_resource_changes

    fixture_path = (
        Path(__file__).resolve().parents[2] / "fixtures" / "real_plans" / fixture_name
    )
    raw = _json.loads(fixture_path.read_text())
    return PlanResult(
        target_path=str(fixture_path),
        status=PlanStatus.PLAN_SUCCESS,
        terraform_version=raw.get("terraform_version"),
        resource_changes=_extract_resource_changes(raw),
        raw_plan_json=raw,
    )


def test_real_plan_vulnerable_bucket_correctly_fails() -> None:
    """Regression test for the join bug found via real data: before the
    fix, this returned PASS despite a literal `acl = "public-read"` in the
    real captured plan."""
    plan = _load_real_plan("s3_vulnerable_create_plan.json")

    result = evaluate_s3_public_access_exposure(plan, "aws_s3_bucket.data")

    assert result.status == InvariantStatus.FAIL
    assert "acl_grants_public" in result.violated_conditions


def test_real_plan_secure_bucket_correctly_passes() -> None:
    """Companion real-data case: private ACL + full Block Public Access,
    captured from the same real terraform run, correctly passes."""
    plan = _load_real_plan("s3_secure_create_plan.json")

    result = evaluate_s3_public_access_exposure(plan, "aws_s3_bucket.data")

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []


# --- Regression tests: incomplete sensitive-action matching (confirmed gap) ---
# Root cause: the matcher was an allow-list of four literal action strings
# (GetObject/PutObject/ListBucket/s3:*), not grounded in the invariant's own
# stated threat model (read/write/delete/list against the bucket's objects
# OR its own ACL/policy — see module docstring). Any action outside those
# four literal strings, including ones with genuine severe impact like
# DeleteObject or PutBucketPolicy, silently evaded detection entirely.


def test_delete_object_is_sensitive() -> None:
    assert _action_is_sensitive("s3:DeleteObject") is True


def test_get_bucket_acl_is_sensitive() -> None:
    """A public grant to read the bucket's own ACL is itself an exposure of
    the bucket's security configuration, not just its data."""
    assert _action_is_sensitive("s3:GetBucketAcl") is True


def test_put_bucket_policy_is_sensitive() -> None:
    """A public grant to REWRITE the bucket's own policy is a privilege-
    escalation vector — an anonymous principal could grant itself anything
    else. Arguably the most severe single action this invariant can name."""
    assert _action_is_sensitive("s3:PutBucketPolicy") is True


def test_bare_universal_wildcard_is_sensitive() -> None:
    """"Action": "*" (not "s3:*") grants every action on every AWS service —
    a second, related gap found during this fix: the old matcher only
    recognized the s3:*-scoped wildcard, not the fully universal one."""
    assert _action_is_sensitive("*") is True


def test_future_action_category_is_covered_by_verb_not_enumeration() -> None:
    """Not a real AWS action — stands in for "whatever S3 read/write/delete/
    list action AWS adds next". The matcher must cover it via the verb
    prefix, not require enumerating it by name (the issue's own explicit
    ask: 'future action categories where possible')."""
    assert _action_is_sensitive("s3:GetObjectRetention") is True
    assert _action_is_sensitive("s3:DeleteObjectTagging") is True


def test_multiple_actions_any_sensitive_one_triggers() -> None:
    assert _action_is_sensitive(["s3:GetBucketTagging", "s3:DeleteObject"]) is True


def test_non_sensitive_action_alone_is_not_flagged() -> None:
    """A read-only, non-exposure-relevant action must not be over-flagged —
    the matcher is verb-scoped (get/put/delete/list), not "any s3: action"."""
    assert _action_is_sensitive("s3:CreateBucket") is False


def test_end_to_end_policy_with_delete_object_only_is_still_detected() -> None:
    """Full invariant path, not just the helper — a policy granting ONLY
    s3:DeleteObject publicly (no GetObject/PutObject/ListBucket at all)
    must still fail the invariant. Before this fix it would have silently
    passed since DeleteObject matched none of the four literal prefixes."""
    plan = plan_with(
        [
            resource(BUCKET, "aws_s3_bucket", {"id": "my-bucket", "bucket": "my-bucket"}),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "s3:DeleteObject",
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
    assert result.violated_conditions == ["policy_grants_public"]


# --- Regression tests: policy-unresolved partial evaluation ---
# Root cause: a bucket policy that interpolates the bucket's own computed
# `.arn` (e.g. Resource = "${aws_s3_bucket.data.arn}/*") is entirely unknown
# at plan time in a create-action plan. The invariant previously returned a
# blanket UNKNOWN for the whole bucket the moment this happened, discarding
# a fully-resolved, independently-conclusive ACL on the SAME resource. This
# was a real, observed failure: three genuine AI-generated repairs in
# datasets/experiments/2026-09-03-real-ai-pilot-s3exposure/ all classified
# INCONCLUSIVE for exactly this reason, including case3_acl_and_policy,
# whose before-state had a literal, fully-resolved `acl = "public-read"`
# sitting right next to the unresolved policy. Investigated and rejected:
# reconstructing Principal/Effect/Action independently of Resource from
# Terraform's static configuration graph — a real captured plan (see the
# fixtures loaded below, extracted verbatim from that same experiment
# record) confirms `configuration...expressions.policy` for a
# `jsonencode(...)`-built policy collapses to a flat `references` list with
# no sub-key structure to recover. What IS implemented: independent
# evaluation of the ACL and policy sides, where an unresolved side can
# contribute a FAIL (it can only make an already-exposed bucket MORE
# exposed) but is NEVER treated as evidence toward PASS.


def test_real_plan_acl_public_policy_unresolved_now_correctly_fails() -> None:
    """The exact real scenario that was previously stuck at UNKNOWN: ACL is
    a literal, resolved `public-read`; the bucket policy is unresolved
    (references the bucket's own .arn). The known-public ACL alone must be
    sufficient to reach FAIL, without needing the policy to be resolved."""
    plan = _load_real_plan("s3_acl_public_policy_unresolved_before_plan.json")

    result = evaluate_s3_public_access_exposure(plan, "aws_s3_bucket.data")

    assert result.status == InvariantStatus.FAIL
    assert result.violated_conditions == ["acl_grants_public"]
    assert "policy" in result.reason.lower()
    assert result.evidence["policy_unresolved_at_plan_time"] is True


def test_real_plan_acl_private_policy_unresolved_stays_unknown_never_pass() -> None:
    """Critical safety case, using real data from the SAME experiment's
    after-state: the AI's repair made the ACL private (known, safe) but left
    the bucket policy resource in place, still unresolved. The invariant
    must NOT report PASS just because the resolvable side looks safe — the
    unresolved policy could still be granting public access, and there is no
    independent evidence it isn't. This must stay UNKNOWN."""
    plan = _load_real_plan("s3_acl_private_policy_unresolved_after_plan.json")

    result = evaluate_s3_public_access_exposure(plan, "aws_s3_bucket.data")

    assert result.status == InvariantStatus.UNKNOWN
    assert result.violated_conditions == []


def test_policy_known_public_acl_unresolved_still_fails() -> None:
    """Symmetric direction (synthetic — no real captured plan exercises this
    shape yet): a fully resolved, public bucket policy must independently
    prove FAIL even when the ACL resource's own content happens to be
    unresolved at plan time."""
    from terraveritas.models.plan import PlannedResourceChange

    plan = plan_with(
        [
            bucket_resource(),
            PlannedResourceChange(
                address="aws_s3_bucket_acl.data",
                resource_type="aws_s3_bucket_acl",
                resource_name="data",
                provider_name="registry.terraform.io/hashicorp/aws",
                actions=["create"],
                after={"bucket": "my-bucket"},
                after_unknown_keys=["acl"],
            ),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::my-bucket/*",
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
    assert result.violated_conditions == ["policy_grants_public"]
    assert result.evidence["acl_unresolved_at_plan_time"] is True


def test_policy_known_safe_acl_unresolved_stays_unknown_never_pass() -> None:
    """Symmetric safety case (synthetic): the policy is resolved and safe,
    but the ACL is unresolved. Must stay UNKNOWN, not PASS — the unresolved
    ACL could still be granting public access via a canned string or an
    explicit grant block that simply wasn't known at plan time."""
    from terraveritas.models.plan import PlannedResourceChange

    plan = plan_with(
        [
            bucket_resource(),
            PlannedResourceChange(
                address="aws_s3_bucket_acl.data",
                resource_type="aws_s3_bucket_acl",
                resource_name="data",
                provider_name="registry.terraform.io/hashicorp/aws",
                actions=["create"],
                after={"bucket": "my-bucket"},
                after_unknown_keys=["acl"],
            ),
            resource(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                {
                    "bucket": "my-bucket",
                    "policy": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::my-bucket/*",
                                }
                            ]
                        }
                    ),
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.UNKNOWN
    assert result.violated_conditions == []


def test_both_acl_and_policy_unresolved_stays_unknown() -> None:
    """Baseline unaffected by this fix: with no independently-resolved side
    at all, the result must remain UNKNOWN exactly as before."""
    from terraveritas.models.plan import PlannedResourceChange

    plan = plan_with(
        [
            bucket_resource(),
            PlannedResourceChange(
                address="aws_s3_bucket_acl.data",
                resource_type="aws_s3_bucket_acl",
                resource_name="data",
                provider_name="registry.terraform.io/hashicorp/aws",
                actions=["create"],
                after={"bucket": "my-bucket"},
                after_unknown_keys=["acl"],
            ),
            PlannedResourceChange(
                address="aws_s3_bucket_policy.data",
                resource_type="aws_s3_bucket_policy",
                resource_name="data",
                provider_name="registry.terraform.io/hashicorp/aws",
                actions=["create"],
                after={"bucket": "my-bucket"},
                after_unknown_keys=["policy"],
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.UNKNOWN
    assert result.violated_conditions == []


# --- Regression tests: BPA rescue must apply even when content is unresolved ---
# Root cause: the ACL and policy branches only consult their independent
# Block Public Access / Object Ownership rescue (ignore_public_acls,
# BucketOwnerEnforced, restrict_public_buckets) INSIDE the "content is
# resolved" branch. When content is unresolved, the function short-circuits
# straight to *_neutralized = None before ever checking whether an
# independent, content-blind protective flag was already declared and
# known -- even though restrict_public_buckets=True (or
# ignore_public_acls=True / BucketOwnerEnforced) neutralizes the relevant
# vector at the AWS enforcement layer regardless of what the ACL/policy
# document actually says. Found via two real, independently-generated AI
# repairs (phase2_case_d_regression_attempt, phase3_case_d_regression_
# attempt) that added a real aws_s3_bucket_policy referencing an unresolved
# value on top of an already-BPA-locked-down bucket -- both were very
# likely genuinely safe repairs that TerraVeritas could not confirm,
# reported as INCONCLUSIVE for a reason that turned out to be fixable.


def test_real_plan_restrict_public_buckets_rescues_unresolved_policy() -> None:
    """Real captured plan from phase2_case_d_regression_attempt's after-state:
    aws_s3_bucket_public_access_block declares restrict_public_buckets=true
    (fully resolved), while the new aws_s3_bucket_policy's content is
    unresolved (built from a data source referencing the bucket's own
    .arn). Before this fix: UNKNOWN. The BPA flag alone is sufficient
    evidence to neutralize the policy vector regardless of its content."""
    plan = _load_real_plan("s3_bpa_restrict_public_buckets_policy_unresolved_plan.json")

    result = evaluate_s3_public_access_exposure(plan, "aws_s3_bucket.data")

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []


def test_ignore_public_acls_rescues_unresolved_acl() -> None:
    """Symmetric direction (synthetic -- no real captured plan exercises
    this shape yet): ignore_public_acls=true is fully resolved and
    independently neutralizes the ACL vector regardless of the ACL's own
    content, which is unresolved here. Must be PASS, not UNKNOWN, given a
    policy side that is also independently safe (none declared)."""
    plan = plan_with(
        [
            bucket_resource(),
            resource_with_unknown(
                "aws_s3_bucket_acl.data",
                "aws_s3_bucket_acl",
                after={"bucket": "my-bucket"},
                unknown_keys=["acl"],
            ),
            resource(
                "aws_s3_bucket_public_access_block.data",
                "aws_s3_bucket_public_access_block",
                {
                    "bucket": "my-bucket",
                    "ignore_public_acls": True,
                    "restrict_public_buckets": False,
                },
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []


def test_bucket_owner_enforced_rescues_unresolved_acl() -> None:
    """Same rescue, via Object Ownership rather than the BPA flag."""
    plan = plan_with(
        [
            bucket_resource(),
            resource_with_unknown(
                "aws_s3_bucket_acl.data",
                "aws_s3_bucket_acl",
                after={"bucket": "my-bucket"},
                unknown_keys=["acl"],
            ),
            resource(
                "aws_s3_bucket_ownership_controls.data",
                "aws_s3_bucket_ownership_controls",
                {"bucket": "my-bucket", "rule": [{"object_ownership": "BucketOwnerEnforced"}]},
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []


def test_unresolved_policy_without_restrict_public_buckets_still_unknown() -> None:
    """Safety-preserving companion: the rescue must be conditional on the
    flag actually being True. No BPA resource at all (so
    restrict_public_buckets is simply absent, not True) alongside an
    unresolved policy must stay UNKNOWN, not silently become PASS --
    confirms the fix didn't widen the rescue beyond what's actually
    declared and known."""
    plan = plan_with(
        [
            bucket_resource(),
            resource_with_unknown(
                "aws_s3_bucket_policy.data",
                "aws_s3_bucket_policy",
                after={"bucket": "my-bucket"},
                unknown_keys=["policy"],
            ),
        ]
    )

    result = evaluate_s3_public_access_exposure(plan, BUCKET)

    assert result.status == InvariantStatus.UNKNOWN
    assert result.violated_conditions == []
