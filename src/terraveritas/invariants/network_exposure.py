"""NETWORK_SENSITIVE_PORT_EXPOSURE invariant.

Grounded in two of AWS Config's own managed rules, fetched and verified
during design, not invented:
- `restricted-ssh` (identifier INCOMING_SSH_DISABLED): a security group is
  NON_COMPLIANT if inbound SSH (port 22) is open to 0.0.0.0/0 or ::/0.
- `restricted-common-ports` (identifier RESTRICTED_INCOMING_TRAFFIC):
  NON_COMPLIANT if inbound TCP traffic to specified ports (default: 20, 21,
  3389, 3306 — FTP data/control, RDP, MySQL) is open to 0.0.0.0/0 or ::/0.

This invariant unions those two rules' own default port sets (22, 20, 21,
3306, 3389) — it does not add ports beyond what these two cited AWS rules
already specify by default. A broader "commonly sensitive" port list
(e.g. 5432 PostgreSQL, 1433 MSSQL, 27017 MongoDB) was deliberately NOT
added — extending beyond AWS's own cited default parameters would be this
project's own judgment call presented as authoritative; disclosed here as
an explicit, real scope limitation rather than silently included.

Structurally different from every other invariant in this project: the
security-relevant data (`ingress` rules) lives as a list of NESTED BLOCKS
directly on ONE resource (`aws_security_group`), not spread across
separate, cross-referenced resources. There is no multi-resource
correlation problem here at all — the entire correctness challenge is
reading Terraform's per-element "known after apply" tracking correctly
for a list of nested objects, which is a genuinely different mechanism
from the top-level `after_unknown_keys` used everywhere else in this
project. Verified against two real captured plans (fixtures/real_plans/):
when every field of an ingress rule is a literal, `after_unknown["ingress"]`
is a list of per-index dicts whose keys are absent (an index dict with no
"cidr_blocks" key means that field IS known for that rule); when one field
(cidr_blocks, built from a computed EIP's public IP in the verification
fixture) is genuinely unresolved, that field is OMITTED from
`after["ingress"][i]` and set to `True` under
`after_unknown["ingress"][i]["cidr_blocks"]`. When `ingress` itself is
built entirely dynamically (e.g. from an unresolved `for_each`),
`after_unknown["ingress"]` is a bare `True`, not a list — both shapes are
handled.

Scope, v1 (disclosed):
- Only the deprecated-but-still-extremely-common INLINE `ingress` block on
  `aws_security_group` is evaluated. The newer, decoupled
  `aws_security_group_rule` / `aws_vpc_security_group_ingress_rule`
  resources are NOT evaluated — a real exposure declared only that way
  evaluates as PASS here.
- Only TCP and "all protocols" (`-1`, which subsumes TCP) rules are
  considered — a UDP-only rule to one of these ports is not flagged,
  matching `restricted-common-ports`' own TCP-only scope exactly (it does
  not evaluate UDP either).
"""

from __future__ import annotations

import ipaddress
from typing import Any

from terraveritas.models.invariant import InvariantResult, InvariantStatus
from terraveritas.models.plan import PlannedResourceChange, PlanResult, PlanStatus

INVARIANT_ID = "NETWORK_SENSITIVE_PORT_EXPOSURE"

# Union of restricted-ssh's fixed scope (22) and restricted-common-ports'
# own default parameters (20, 21, 3306, 3389) -- see module docstring.
_SENSITIVE_PORTS = {22, 20, 21, 3306, 3389}

_OPEN_IPV4 = "0.0.0.0/0"
_OPEN_IPV6 = "::/0"


class _RuleUnresolved(Exception):
    """Raised internally when an ingress rule's relevant fields can't be
    confidently read — caught by the evaluator and treated as UNKNOWN
    contribution from that rule, never as evidence of safety."""


def evaluate_network_sensitive_port_exposure(
    plan: PlanResult, security_group_address: str
) -> InvariantResult:
    if plan.status != PlanStatus.PLAN_SUCCESS:
        return _unknown(
            security_group_address, f"plan did not succeed (status={plan.status.value})"
        )

    sg = _find_by_address(plan, "aws_security_group", security_group_address)
    if sg is None:
        return _unknown(security_group_address, "security group not found in plan resource_changes")

    # PlannedResourceChange only carries the flat top-level
    # after_unknown_keys (a list of key NAMES) -- ingress's per-rule
    # unknown-ness is a nested structure one level deeper (a list of
    # per-index dicts) that gets flattened away by _extract_resource_
    # changes(). Read it directly from the raw plan JSON instead of
    # extending the shared model for one invariant's nested-block need.
    raw_change = _find_raw_change(plan, security_group_address)
    ingress_rules = sg.after.get("ingress") or []
    raw_unknown = (raw_change or {}).get("after_unknown", {}).get("ingress")

    evidence: dict[str, Any] = {
        "ingress_rule_count": len(ingress_rules),
        "ingress_entirely_unresolved": raw_unknown is True,
    }

    if raw_unknown is True:
        return _unknown(
            security_group_address,
            "ingress rules are entirely unresolved at plan time (known after apply)",
        )

    violated: list[str] = []
    any_rule_unresolved = False

    for index, rule in enumerate(ingress_rules):
        per_rule_unknown = (
            raw_unknown[index] if isinstance(raw_unknown, list) and index < len(raw_unknown) else {}
        )
        try:
            if _rule_is_open_to_sensitive_port(rule, per_rule_unknown):
                violated.append(f"ingress[{index}]_open_to_sensitive_port")
        except _RuleUnresolved:
            any_rule_unresolved = True

    if violated:
        return InvariantResult(
            invariant_id=INVARIANT_ID,
            resource_address=security_group_address,
            status=InvariantStatus.FAIL,
            violated_conditions=sorted(set(violated)),
            reason=(
                "security group allows unrestricted (0.0.0.0/0 or ::/0) inbound access to "
                f"a sensitive port {sorted(_SENSITIVE_PORTS)}: {sorted(set(violated))}"
            ),
            evidence=evidence,
            related_resource_addresses=[security_group_address],
        )

    if any_rule_unresolved:
        return _unknown(
            security_group_address,
            "one or more ingress rules have unresolved content at plan time, and no "
            "independent violation was found on the resolvable rules",
        )

    return InvariantResult(
        invariant_id=INVARIANT_ID,
        resource_address=security_group_address,
        status=InvariantStatus.PASS,
        violated_conditions=[],
        reason="no ingress rule allows unrestricted access to a sensitive port",
        evidence=evidence,
        related_resource_addresses=[security_group_address],
    )


def _field_is_unresolved(value: Any) -> bool:
    """Terraform's per-index unknown marker for a nested block: a bare
    `True` means the whole field is unknown; a LIST (for list-typed fields
    like cidr_blocks) carries one boolean per element, e.g. `[False]` for a
    single, fully-known element -- itself truthy as a Python list even
    though it means "known", so a plain `if marker:` check is wrong and was
    the actual bug caught here (both fixtures returned UNKNOWN
    unconditionally until this was fixed, verified against real captured
    plans, not assumed). Absent entirely (`None`) means known, matching the
    convention for scalar fields."""
    if value is True:
        return True
    if isinstance(value, list):
        return any(v is True for v in value)
    return False


def _rule_is_open_to_sensitive_port(rule: dict[str, Any], per_rule_unknown: dict[str, Any]) -> bool:
    if not isinstance(rule, dict):
        raise _RuleUnresolved("ingress rule is not a plain object")

    for field in ("cidr_blocks", "ipv6_cidr_blocks", "from_port", "to_port", "protocol"):
        if _field_is_unresolved(per_rule_unknown.get(field)):
            raise _RuleUnresolved(f"{field} is unresolved at plan time")

    protocol = rule.get("protocol")
    if not isinstance(protocol, str):
        raise _RuleUnresolved("protocol is missing or not a string")

    if protocol not in ("tcp", "-1"):
        return False

    if not _cidrs_include_everyone(rule.get("cidr_blocks"), rule.get("ipv6_cidr_blocks")):
        return False

    if protocol == "-1":
        # All protocols, all ports -- AWS ignores from_port/to_port for -1.
        return True

    from_port = rule.get("from_port")
    to_port = rule.get("to_port")
    if not isinstance(from_port, int) or not isinstance(to_port, int):
        raise _RuleUnresolved("from_port/to_port missing or not integers")

    return any(from_port <= port <= to_port for port in _SENSITIVE_PORTS)


def _cidrs_include_everyone(ipv4_blocks: Any, ipv6_blocks: Any) -> bool:
    ipv4 = ipv4_blocks if isinstance(ipv4_blocks, list) else []
    ipv6 = ipv6_blocks if isinstance(ipv6_blocks, list) else []
    if _OPEN_IPV4 in ipv4 or _OPEN_IPV6 in ipv6:
        return True
    # A CIDR that isn't the literal "0.0.0.0/0" string but is still
    # network-equivalent to it (e.g. "0.0.0.0/0" with different
    # formatting) — defensive, not expected from Terraform's own
    # normalization, but checked rather than assumed.
    for block in ipv4:
        if isinstance(block, str):
            try:
                network = ipaddress.ip_network(block, strict=False)
            except ValueError:
                continue
            if network.version == 4 and network.prefixlen == 0:
                return True
    for block in ipv6:
        if isinstance(block, str):
            try:
                network = ipaddress.ip_network(block, strict=False)
            except ValueError:
                continue
            if network.version == 6 and network.prefixlen == 0:
                return True
    return False


def _unknown(security_group_address: str, reason: str) -> InvariantResult:
    return InvariantResult(
        invariant_id=INVARIANT_ID,
        resource_address=security_group_address,
        status=InvariantStatus.UNKNOWN,
        violated_conditions=[],
        reason=reason,
        evidence={},
        related_resource_addresses=[security_group_address],
    )


def _find_by_address(
    plan: PlanResult, resource_type: str, address: str
) -> PlannedResourceChange | None:
    for rc in plan.resource_changes:
        if rc.resource_type == resource_type and rc.address == address:
            return rc
    return None


def _find_raw_change(plan: PlanResult, address: str) -> dict[str, Any] | None:
    if plan.raw_plan_json is None:
        return None
    for c in plan.raw_plan_json.get("resource_changes", []):
        if c.get("address") == address:
            change: dict[str, Any] = c.get("change", {})
            return change
    return None
