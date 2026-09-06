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

import json
from pathlib import Path
from typing import Any

from terraveritas.models.plan import PlannedResourceChange, PlanResult, PlanStatus
from terraveritas.terraform.plan import _extract_resource_changes


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


def resource_with_unknown(
    address: str,
    resource_type: str,
    *,
    after: dict[str, Any],
    unknown_keys: list[str],
) -> PlannedResourceChange:
    """Like `resource()`, but for a resource whose content is unresolved at
    plan time — `after_unknown_keys` lists which keys are known only after
    apply, matching a real `resource_changes[].change.after_unknown` shape."""
    name = address.split(".")[-1]
    return PlannedResourceChange(
        address=address,
        resource_type=resource_type,
        resource_name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        actions=["create"],
        after=after,
        after_unknown_keys=unknown_keys,
    )


def plan_with(resources: list[PlannedResourceChange]) -> PlanResult:
    return PlanResult(
        target_path="/fixture",
        status=PlanStatus.PLAN_SUCCESS,
        terraform_version="1.14.3",
        resource_changes=resources,
    )


def load_real_plan(fixture_name: str) -> PlanResult:
    """Loads a real captured plan from fixtures/real_plans/ through this
    project's own real parsing path (_extract_resource_changes), not a
    hand-rolled re-parse — exercises exactly the code a live run does.
    Shared across every invariant's test file (S3, IAM, network) since all
    three verify against real Terraform CLI output the same way."""
    fixture_path = Path(__file__).resolve().parents[2] / "fixtures" / "real_plans" / fixture_name
    raw = json.loads(fixture_path.read_text())
    return PlanResult(
        target_path=str(fixture_path),
        status=PlanStatus.PLAN_SUCCESS,
        terraform_version=raw.get("terraform_version"),
        resource_changes=_extract_resource_changes(raw),
        raw_plan_json=raw,
    )
