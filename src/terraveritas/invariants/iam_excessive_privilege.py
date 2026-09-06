"""IAM_EXCESSIVE_PRIVILEGE_EXPOSURE invariant.

Grounded in AWS Config's own managed rule
`IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` (fetched and verified against
https://docs.aws.amazon.com/config/latest/developerguide/
iam-policy-no-statements-with-admin-access.html during design, not
invented): a statement with `Effect: Allow`, `Action: "*"` (the bare
wildcard, not a service-scoped one), and `Resource: "*"` is "admin access".
AWS's own documented COMPLIANT example uses `Action: "service:*"` over
`Resource: "*"` — only a completely bare `"*"` action is flagged, and this
invariant applies that identical distinction, not a broader "any wildcard
looks suspicious" heuristic.

Scope, v1 (disclosed, not silently assumed complete — mirrors the S3
invariant's own initial-scope discipline rather than attempting full
IAM-attachment-graph coverage in one pass):
- Only `aws_iam_role` plus directly-attached `aws_iam_role_policy`
  (inline) resources are evaluated. `aws_iam_user_policy` /
  `aws_iam_group_policy` (same shape, different principal type) and
  managed policies attached via `aws_iam_role_policy_attachment` (which
  would need a second reference hop to the separate `aws_iam_policy`
  resource's own content) are NOT evaluated — a real exposure reachable
  only through either of those paths evaluates as PASS here.
- `NotAction` / `NotResource` statements are not confidently evaluated —
  their semantics invert the normal match and this invariant does not
  implement that logic. A statement using either is excluded from the
  admin-access check for that statement (never counted as violating, never
  counted as safe) — mirroring the S3 invariant's treatment of
  `NotPrincipal`.
- A wildcard embedded WITHIN an otherwise-specific action/resource string
  (e.g. `"s3:Get*"` or `"arn:aws:s3:::my-bucket/*"`) is NOT itself "admin
  access" — only a literal, bare `"*"` for the whole `Action` or
  `Resource` value counts, exactly matching AWS's own cited definition.

Verified against a real captured plan (fixtures/real_plans/
iam_role_policy_admin_access_plan.json): an inline `aws_iam_role_policy`'s
own `policy` JSON content resolves at plan time even when the correlating
`role` reference itself does not — genuinely different from, and more
favorable than, the S3 bucket-policy case, where the policy's OWN content
is usually what ends up unresolved (see s3_public_access.py's disclosed
policy-unresolved handling). No equivalent partial-evaluation problem was
found here during design.
"""

from __future__ import annotations

import json
from typing import Any

from terraveritas.models.invariant import InvariantResult, InvariantStatus
from terraveritas.models.plan import PlannedResourceChange, PlanResult, PlanStatus

INVARIANT_ID = "IAM_EXCESSIVE_PRIVILEGE_EXPOSURE"

_BARE_WILDCARD = "*"


def evaluate_iam_excessive_privilege_exposure(
    plan: PlanResult, role_address: str
) -> InvariantResult:
    if plan.status != PlanStatus.PLAN_SUCCESS:
        return _unknown(role_address, f"plan did not succeed (status={plan.status.value})")

    role = _find_by_address(plan, "aws_iam_role", role_address)
    if role is None:
        return _unknown(role_address, "role not found in plan resource_changes")

    role_id = role.after.get("id") or role.after.get("name")
    if role_id is None:
        return _unknown(role_address, "could not resolve role identifier from plan")

    inline_policies = _find_all_by_role_reference(
        plan, "aws_iam_role_policy", role_id, role_address
    )
    related_addresses = [role_address] + [p.address for p in inline_policies]

    evidence: dict[str, Any] = {
        "role_id": role_id,
        "inline_policy_count": len(inline_policies),
    }

    if not inline_policies:
        return InvariantResult(
            invariant_id=INVARIANT_ID,
            resource_address=role_address,
            status=InvariantStatus.PASS,
            violated_conditions=[],
            reason="no inline role policy declared for this role",
            evidence=evidence,
            related_resource_addresses=related_addresses,
        )

    violated: list[str] = []
    unresolved_policy_addresses: list[str] = []

    for policy_rc in inline_policies:
        if "policy" in policy_rc.after_unknown_keys:
            unresolved_policy_addresses.append(policy_rc.address)
            continue
        raw = policy_rc.after.get("policy")
        if not isinstance(raw, str):
            unresolved_policy_addresses.append(policy_rc.address)
            continue
        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            unresolved_policy_addresses.append(policy_rc.address)
            continue

        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if not isinstance(statement, dict):
                continue
            if statement.get("Effect") != "Allow":
                continue
            if "NotAction" in statement or "NotResource" in statement:
                continue
            if _is_bare_wildcard(statement.get("Action")) and _is_bare_wildcard(
                statement.get("Resource")
            ):
                violated.append(f"admin_access_via:{policy_rc.address}")

    evidence["unresolved_inline_policies"] = unresolved_policy_addresses

    if violated:
        return InvariantResult(
            invariant_id=INVARIANT_ID,
            resource_address=role_address,
            status=InvariantStatus.FAIL,
            violated_conditions=sorted(set(violated)),
            reason=(
                "one or more inline role policies grant full admin access "
                f'(Effect=Allow, Action="*", Resource="*"): {sorted(set(violated))}'
            ),
            evidence=evidence,
            related_resource_addresses=related_addresses,
        )

    if unresolved_policy_addresses:
        return _unknown(
            role_address,
            "inline policy content could not be evaluated at plan time for: "
            f"{unresolved_policy_addresses}, and no independent violation was found on "
            "the resolvable policies",
            related=related_addresses,
        )

    return InvariantResult(
        invariant_id=INVARIANT_ID,
        resource_address=role_address,
        status=InvariantStatus.PASS,
        violated_conditions=[],
        reason="no inline role policy grants full admin access",
        evidence=evidence,
        related_resource_addresses=related_addresses,
    )


def _is_bare_wildcard(value: Any) -> bool:
    """True only for a literal bare "*" — as either the sole value or a
    member of a list. A service-scoped wildcard ("s3:*") or a wildcard
    embedded in a larger string ("s3:Get*") does NOT count, matching AWS's
    own cited COMPLIANT example exactly."""
    values = value if isinstance(value, list) else [value]
    return any(v == _BARE_WILDCARD for v in values)


def _unknown(
    role_address: str, reason: str, *, related: list[str] | None = None
) -> InvariantResult:
    return InvariantResult(
        invariant_id=INVARIANT_ID,
        resource_address=role_address,
        status=InvariantStatus.UNKNOWN,
        violated_conditions=[],
        reason=reason,
        evidence={},
        related_resource_addresses=related if related is not None else [role_address],
    )


def _find_by_address(
    plan: PlanResult, resource_type: str, address: str
) -> PlannedResourceChange | None:
    for rc in plan.resource_changes:
        if rc.resource_type == resource_type and rc.address == address:
            return rc
    return None


def _find_all_by_role_reference(
    plan: PlanResult, resource_type: str, role_id: str, role_address: str
) -> list[PlannedResourceChange]:
    """Correlates every resource of `resource_type` whose `role` argument
    references `role_address`, via the plan's static configuration
    reference graph — the same technique validated for S3's bucket
    correlation (`_find_by_bucket_reference` in s3_public_access.py),
    generalized to return every match rather than the first (a role can
    have more than one inline policy attached). Falls back to a
    resolved-value join (`after["role"] == role_id`) when the reference
    graph finds nothing — either because `raw_plan_json` isn't available
    (synthetic tests) or because `role` is a literal, hardcoded role name
    with no Terraform reference at all, exactly mirroring S3's own
    `_find_by_bucket` fallback."""
    matching_addresses: set[str] = set()
    if plan.raw_plan_json is not None:
        config_resources = (
            plan.raw_plan_json.get("configuration", {})
            .get("root_module", {})
            .get("resources", [])
        )
        for cfg in config_resources:
            if not isinstance(cfg, dict) or cfg.get("type") != resource_type:
                continue
            role_expr = cfg.get("expressions", {}).get("role", {})
            if not isinstance(role_expr, dict):
                continue
            references = role_expr.get("references", [])
            if isinstance(references, list) and role_address in references:
                address = cfg.get("address")
                if isinstance(address, str):
                    matching_addresses.add(address)

    matches = [
        rc
        for rc in plan.resource_changes
        if rc.resource_type == resource_type and rc.address in matching_addresses
    ]
    if matches:
        return matches
    return [
        rc
        for rc in plan.resource_changes
        if rc.resource_type == resource_type and rc.after.get("role") == role_id
    ]
