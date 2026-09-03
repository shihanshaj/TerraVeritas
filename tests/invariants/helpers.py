"""Synthetic PlanResult/PlannedResourceChange factories for invariant tests.

Shaped to match the exact `terraform show -json` schema verified against a
real Terraform CLI run in Prompt 5 (resource_changes[].{address, type, name,
provider_name, change: {actions, after, after_unknown}}) — not a live plan
of a real aws_s3_bucket, which this sandbox cannot reliably produce (AWS
provider download constraint, documented in plan.py). See
s3_public_access.py's module docstring for the disclosed testing gap this
implies.
"""

from __future__ import annotations

from typing import Any

from terraveritas.models.plan import PlannedResourceChange, PlanResult, PlanStatus


def resource(
    address: str, resource_type: str, after: dict[str, Any]
) -> PlannedResourceChange:
    name = address.split(".")[-1]
    return PlannedResourceChange(
        address=address,
        resource_type=resource_type,
        resource_name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        actions=["create"],
        after=after,
        after_unknown_keys=[],
    )


def plan_with(resources: list[PlannedResourceChange]) -> PlanResult:
    return PlanResult(
        target_path="/fixture",
        status=PlanStatus.PLAN_SUCCESS,
        terraform_version="1.14.3",
        resource_changes=resources,
    )
