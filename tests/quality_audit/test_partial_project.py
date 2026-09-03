"""QA audit: a partial/incomplete Terraform project — a resource file
referencing a variable declared nowhere in the directory (as if a
variables.tf file were missing from a checkout or an extraction step).
Never previously tested. Checks that both the scanner and the planner
handle this without crashing, and classify it honestly rather than
silently treating it as either "clean" or "the same as valid HCL"."""

from __future__ import annotations

from pathlib import Path

from terraveritas.models.finding import ScanStatus
from terraveritas.models.plan import PlanStatus
from terraveritas.scanners.checkov import CheckovAdapter
from terraveritas.terraform.plan import TerraformPlanner

_MAIN_TF = """
resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
"""


def test_checkov_still_flags_the_real_finding_despite_the_missing_variable_file(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.tf").write_text(_MAIN_TF)  # variables.tf deliberately absent

    adapter = CheckovAdapter()
    result = adapter.scan(tmp_path, timeout_seconds=60)

    # Real finding: Checkov's static analysis does not need the variable
    # to actually resolve in order to see the literal `acl = "public-read"`.
    assert result.status == ScanStatus.SUCCESS
    assert any(f.rule_id == "CKV_AWS_20" for f in result.findings)


def test_planner_never_silently_succeeds_on_a_broken_project(tmp_path: Path) -> None:
    """This fixture uses aws_* resources, so the planner's provider-
    injection path needs registry access to even reach the point of
    checking variable resolution — and this session's own audit already
    found that access to be non-deterministic (see the reproducibility
    findings). A first version of this test asserted the specific
    PLAN_UNRESOLVED_DEPENDENCY status and failed when init itself hit the
    now-documented network flakiness (PLAN_TIMEOUT) before ever reaching
    variable resolution — a flaw in this test, not in TerraformPlanner.
    The property that actually matters, and holds regardless of which
    failure surfaces first, is asserted here instead: never PLAN_SUCCESS
    with an empty resource_changes list, which would be indistinguishable
    from "nothing to do" on a genuinely broken project. The specific
    PLAN_UNRESOLVED_DEPENDENCY classification, isolated from any network
    dependency, is already covered by test_unresolved_required_variable
    in tests/terraform/test_plan.py."""
    (tmp_path / "main.tf").write_text(_MAIN_TF)

    planner = TerraformPlanner()
    result = planner.plan(tmp_path, timeout_seconds=60)

    assert not (result.status == PlanStatus.PLAN_SUCCESS and result.resource_changes == [])
    assert result.status != PlanStatus.PLAN_SUCCESS
    assert result.error_message is not None
