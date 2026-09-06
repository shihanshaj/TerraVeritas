"""Tests for the NETWORK_SENSITIVE_PORT_EXPOSURE invariant.

The sensitive-port and CIDR test cases are taken directly from AWS
Config's own documented behavior for `restricted-ssh` and
`restricted-common-ports` (fetched during design), not invented. Uses raw
PlannedResourceChange construction directly (not the resource()/
resource_with_unknown() helpers) because this invariant reads a raw,
nested per-index unknown structure from `raw_plan_json` directly — a
structure PlannedResourceChange's flat `after_unknown_keys` cannot
represent at all (see the module's own docstring for why).
"""

from __future__ import annotations

from terraveritas.invariants.network_exposure import evaluate_network_sensitive_port_exposure
from terraveritas.models.invariant import InvariantStatus
from terraveritas.models.plan import PlannedResourceChange, PlanResult, PlanStatus

from .helpers import load_real_plan

SG = "aws_security_group.data"


def _sg_plan(
    ingress: list[dict[str, object]], *, ingress_unknown: object = None
) -> PlanResult:
    """Builds a plan with a single aws_security_group resource whose
    resolved `ingress` list is exactly what's given, plus a matching raw
    `resource_changes[].change.after_unknown.ingress` structure -- the
    nested shape this invariant reads directly, verified against a real
    captured plan (see network_exposure.py's docstring)."""
    resolved_ingress_unknown = ingress_unknown if ingress_unknown is not None else []
    resource_changes = [
        PlannedResourceChange(
            address=SG,
            resource_type="aws_security_group",
            resource_name="data",
            provider_name="registry.terraform.io/hashicorp/aws",
            actions=["create"],
            after={"name": "my-sg", "ingress": ingress},
            after_unknown_keys=[],
        )
    ]
    raw_plan_json = {
        "resource_changes": [
            {
                "address": SG,
                "type": "aws_security_group",
                "change": {
                    "after": {"name": "my-sg", "ingress": ingress},
                    "after_unknown": {"ingress": resolved_ingress_unknown},
                },
            }
        ]
    }
    return PlanResult(
        target_path="/fixture",
        status=PlanStatus.PLAN_SUCCESS,
        resource_changes=resource_changes,
        raw_plan_json=raw_plan_json,
    )


def _rule(
    *,
    from_port: int = 22,
    to_port: int = 22,
    protocol: str = "tcp",
    cidr_blocks: list[str] | None = None,
    ipv6_cidr_blocks: list[str] | None = None,
) -> dict[str, object]:
    return {
        "from_port": from_port,
        "to_port": to_port,
        "protocol": protocol,
        "cidr_blocks": cidr_blocks or [],
        "ipv6_cidr_blocks": ipv6_cidr_blocks or [],
    }


def test_ssh_open_to_the_world_fails() -> None:
    """AWS Config's own restricted-ssh definition: port 22 open to
    0.0.0.0/0 is NON_COMPLIANT."""
    plan = _sg_plan([_rule(cidr_blocks=["0.0.0.0/0"])])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.FAIL
    assert result.violated_conditions == ["ingress[0]_open_to_sensitive_port"]


def test_ssh_open_to_ipv6_world_fails() -> None:
    plan = _sg_plan([_rule(cidr_blocks=[], ipv6_cidr_blocks=["::/0"])])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.FAIL


def test_ssh_restricted_to_specific_cidr_passes() -> None:
    plan = _sg_plan([_rule(cidr_blocks=["203.0.113.0/24"])])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []


def test_non_sensitive_port_open_to_the_world_passes() -> None:
    """restricted-common-ports/restricted-ssh only cover a specific port
    set (see module docstring) -- port 8080 open to everyone is a real
    exposure this invariant does not claim to cover, by disclosed design."""
    plan = _sg_plan([_rule(from_port=8080, to_port=8080, cidr_blocks=["0.0.0.0/0"])])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.PASS


def test_port_range_covering_a_sensitive_port_fails() -> None:
    """A wide range that happens to include a sensitive port must still
    be caught, not just an exact from_port==to_port==22 match."""
    plan = _sg_plan([_rule(from_port=1, to_port=1024, cidr_blocks=["0.0.0.0/0"])])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.FAIL


def test_all_protocols_rule_open_to_the_world_fails_regardless_of_port_range() -> None:
    """protocol="-1" (all protocols) makes from_port/to_port meaningless in
    AWS's own semantics -- must be treated as covering every sensitive
    port regardless of the declared range."""
    plan = _sg_plan([_rule(from_port=0, to_port=0, protocol="-1", cidr_blocks=["0.0.0.0/0"])])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.FAIL


def test_udp_only_rule_to_sensitive_port_passes() -> None:
    """Disclosed scope: restricted-common-ports is TCP-only; this
    invariant matches that scope exactly rather than extending it."""
    plan = _sg_plan([_rule(protocol="udp", cidr_blocks=["0.0.0.0/0"])])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.PASS


def test_no_ingress_rules_passes() -> None:
    plan = _sg_plan([])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.PASS


def test_one_open_rule_among_several_still_fails() -> None:
    plan = _sg_plan(
        [
            _rule(from_port=443, to_port=443, cidr_blocks=["0.0.0.0/0"]),
            _rule(cidr_blocks=["0.0.0.0/0"]),
        ]
    )

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.FAIL
    assert result.violated_conditions == ["ingress[1]_open_to_sensitive_port"]


# --- Unresolved-content handling: the real bug this project's own real-plan
# discipline caught before any test was ever written against it. A
# per-index unknown marker for a resolved list field is itself a list
# (e.g. [False] for one known element) -- truthy in Python even though it
# means "known". The first implementation attempt treated any truthy
# marker as unresolved, which made EVERY security group -- vulnerable or
# secure -- evaluate as UNKNOWN unconditionally. Caught by smoke-testing
# against real captured plans before writing these tests, not by a test
# that happened to already cover it.


def test_known_marker_shaped_as_a_list_is_not_mistaken_for_unresolved() -> None:
    """Regression test for the exact bug above: cidr_blocks' unknown marker
    is [False] (one known element), not a bare False or absent -- must
    still evaluate confidently, not fall back to UNKNOWN."""
    known_marker = {
        "cidr_blocks": [False],
        "ipv6_cidr_blocks": [],
        "prefix_list_ids": [],
        "security_groups": [],
    }
    plan = _sg_plan([_rule(cidr_blocks=["0.0.0.0/0"])], ingress_unknown=[known_marker])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.FAIL


def test_unresolved_cidr_stays_unknown_never_pass() -> None:
    plan = _sg_plan(
        [_rule(cidr_blocks=[])],
        ingress_unknown=[{"cidr_blocks": True}],
    )

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.UNKNOWN
    assert result.violated_conditions == []


def test_entirely_unresolved_ingress_list_stays_unknown() -> None:
    plan = _sg_plan([], ingress_unknown=True)

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.UNKNOWN


def test_unresolved_rule_does_not_hide_a_known_violation_elsewhere() -> None:
    """An unresolved side can still contribute FAIL via another, fully
    known rule -- mirroring the same safety-preserving principle already
    established for the S3 and IAM invariants."""
    plan = _sg_plan(
        [_rule(cidr_blocks=["0.0.0.0/0"]), _rule(from_port=443, to_port=443, cidr_blocks=[])],
        ingress_unknown=[
            {},
            {"cidr_blocks": True},
        ],
    )

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.FAIL
    assert result.violated_conditions == ["ingress[0]_open_to_sensitive_port"]


def test_unknown_when_plan_did_not_succeed() -> None:
    plan = PlanResult(target_path="/x", status=PlanStatus.PLAN_PROVIDER_FAILURE)

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.UNKNOWN


def test_unknown_when_security_group_not_in_plan() -> None:
    plan = PlanResult(target_path="/x", status=PlanStatus.PLAN_SUCCESS, resource_changes=[])

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.UNKNOWN


# --- Regression tests: real terraform plan data ---
# fixtures/real_plans/sg_{vulnerable,secure}_create_plan.json were
# captured from an ACTUAL `terraform plan` run against the AWS provider.
# These are the exact real plans whose per-index unknown-marker shape
# ([False] for a known element vs. a bare True for a genuinely unresolved
# one, confirmed via a third, dynamic-CIDR probe fixture not committed
# here) is what the synthetic tests above are modeled on.


def test_real_plan_vulnerable_security_group_correctly_fails() -> None:
    plan = load_real_plan("sg_vulnerable_create_plan.json")

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.FAIL
    assert result.violated_conditions == ["ingress[0]_open_to_sensitive_port"]


def test_real_plan_secure_security_group_correctly_passes() -> None:
    plan = load_real_plan("sg_secure_create_plan.json")

    result = evaluate_network_sensitive_port_exposure(plan, SG)

    assert result.status == InvariantStatus.PASS
    assert result.violated_conditions == []
