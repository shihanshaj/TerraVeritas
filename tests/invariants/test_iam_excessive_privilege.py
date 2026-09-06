"""Tests for the IAM_EXCESSIVE_PRIVILEGE_EXPOSURE invariant.

The admin-access test cases (bare Effect=Allow/Action="*"/Resource="*" vs.
a service-scoped wildcard) are taken directly from AWS Config's own
documented NON_COMPLIANT/COMPLIANT examples for
IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS (fetched during design), not
invented.
"""

from __future__ import annotations

import json

from terraveritas.invariants.iam_excessive_privilege import (
    evaluate_iam_excessive_privilege_exposure,
)
from terraveritas.models.invariant import InvariantStatus
from terraveritas.models.plan import PlanResult, PlanStatus

from .helpers import load_real_plan, plan_with, resource, resource_with_unknown

ROLE = "aws_iam_role.data"


def role_resource(role_id: str = "my-role") -> object:
    return resource(ROLE, "aws_iam_role", {"id": role_id, "name": role_id})


def policy_json(statements: list[dict[str, object]]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def test_no_inline_policy_passes() -> None:
    plan = plan_with([role_resource()])

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []


def test_bare_wildcard_action_and_resource_is_admin_access() -> None:
    """AWS Config's own cited NON_COMPLIANT example: Effect=Allow,
    Action="*", Resource="*"."""
    plan = plan_with(
        [
            role_resource(),
            resource(
                "aws_iam_role_policy.data",
                "aws_iam_role_policy",
                {
                    "role": "my-role",
                    "policy": policy_json(
                        [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                    ),
                },
            ),
        ]
    )

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.FAIL
    assert result.violated_conditions == ["admin_access_via:aws_iam_role_policy.data"]


def test_service_scoped_wildcard_is_not_admin_access() -> None:
    """AWS Config's own cited COMPLIANT example: Action="service:*" over
    Resource="*" is NOT admin access — only the bare "*" action counts."""
    plan = plan_with(
        [
            role_resource(),
            resource(
                "aws_iam_role_policy.data",
                "aws_iam_role_policy",
                {
                    "role": "my-role",
                    "policy": policy_json(
                        [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
                    ),
                },
            ),
        ]
    )

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []


def test_bare_wildcard_action_but_specific_resource_is_not_admin_access() -> None:
    """Both Action AND Resource must be the bare wildcard — a "*" action
    scoped to one specific resource ARN is a different (real, but
    different) risk this invariant doesn't claim to cover."""
    plan = plan_with(
        [
            role_resource(),
            resource(
                "aws_iam_role_policy.data",
                "aws_iam_role_policy",
                {
                    "role": "my-role",
                    "policy": policy_json(
                        [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "arn:aws:s3:::specific-bucket",
                            }
                        ]
                    ),
                },
            ),
        ]
    )

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.PASS


def test_deny_statement_is_never_admin_access() -> None:
    plan = plan_with(
        [
            role_resource(),
            resource(
                "aws_iam_role_policy.data",
                "aws_iam_role_policy",
                {
                    "role": "my-role",
                    "policy": policy_json(
                        [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
                    ),
                },
            ),
        ]
    )

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.PASS


def test_not_action_statement_is_not_confidently_classified() -> None:
    """Disclosed scope gap: NotAction inverts the normal match and this
    invariant does not implement that logic — must not guess either way."""
    plan = plan_with(
        [
            role_resource(),
            resource(
                "aws_iam_role_policy.data",
                "aws_iam_role_policy",
                {
                    "role": "my-role",
                    "policy": policy_json(
                        [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]
                    ),
                },
            ),
        ]
    )

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    # Excluded from the check entirely -- neither flagged as violating nor
    # treated as proof of safety by itself, so with nothing else to go on
    # this resolves to PASS (no *confirmed* violation), not a guess either way.
    assert result.status == InvariantStatus.PASS


def test_one_admin_statement_among_several_still_fails() -> None:
    plan = plan_with(
        [
            role_resource(),
            resource(
                "aws_iam_role_policy.data",
                "aws_iam_role_policy",
                {
                    "role": "my-role",
                    "policy": policy_json(
                        [
                            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                            {"Effect": "Allow", "Action": "*", "Resource": "*"},
                        ]
                    ),
                },
            ),
        ]
    )

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.FAIL


def test_multiple_inline_policies_each_evaluated() -> None:
    plan = plan_with(
        [
            role_resource(),
            resource(
                "aws_iam_role_policy.safe",
                "aws_iam_role_policy",
                {
                    "role": "my-role",
                    "policy": policy_json(
                        [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
                    ),
                },
            ),
            resource(
                "aws_iam_role_policy.dangerous",
                "aws_iam_role_policy",
                {
                    "role": "my-role",
                    "policy": policy_json([{"Effect": "Allow", "Action": "*", "Resource": "*"}]),
                },
            ),
        ]
    )

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.FAIL
    assert result.violated_conditions == ["admin_access_via:aws_iam_role_policy.dangerous"]
    assert result.evidence["inline_policy_count"] == 2


def test_unresolved_policy_content_stays_unknown_never_pass() -> None:
    plan = plan_with(
        [
            role_resource(),
            resource_with_unknown(
                "aws_iam_role_policy.data",
                "aws_iam_role_policy",
                after={"role": "my-role"},
                unknown_keys=["policy"],
            ),
        ]
    )

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.UNKNOWN


def test_unknown_when_plan_did_not_succeed() -> None:
    plan = PlanResult(target_path="/x", status=PlanStatus.PLAN_PROVIDER_FAILURE)

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.UNKNOWN


def test_unknown_when_role_not_in_plan() -> None:
    plan = plan_with([])

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.UNKNOWN


def test_related_resource_addresses_include_role_and_policies() -> None:
    plan = plan_with(
        [
            role_resource(),
            resource(
                "aws_iam_role_policy.data",
                "aws_iam_role_policy",
                {
                    "role": "my-role",
                    "policy": policy_json([{"Effect": "Allow", "Action": "*", "Resource": "*"}]),
                },
            ),
        ]
    )

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert set(result.related_resource_addresses) == {ROLE, "aws_iam_role_policy.data"}


# --- Regression tests: real terraform plan data ---
# fixtures/real_plans/iam_{vulnerable,secure}_create_plan.json were
# captured from an ACTUAL `terraform plan` run against the AWS provider
# (see this invariant's module docstring). Confirmed a real, load-bearing
# characteristic during that run: an inline aws_iam_role_policy's own
# `policy` content resolves at plan time even though the correlating
# `role` reference (role = aws_iam_role.data.id) does not -- genuinely
# different from S3's bucket-policy case. A first implementation attempt
# also had a real bug caught only by running against this real data: the
# per-index "known after apply" marker for a resolved list field (e.g.
# cidr_blocks) is a list like [False], which is truthy in Python even
# though it means "known" -- see network_exposure.py's equivalent fix and
# test for the security-group analog of this exact mistake.


def test_real_plan_vulnerable_role_correctly_fails() -> None:
    plan = load_real_plan("iam_vulnerable_create_plan.json")

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.FAIL
    assert result.violated_conditions == ["admin_access_via:aws_iam_role_policy.data"]


def test_real_plan_secure_role_correctly_passes() -> None:
    plan = load_real_plan("iam_secure_create_plan.json")

    result = evaluate_iam_excessive_privilege_exposure(plan, ROLE)

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []
