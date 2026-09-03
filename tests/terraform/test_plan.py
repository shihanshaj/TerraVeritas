"""Integration tests for TerraformPlanner against a real Terraform CLI.

Uses Terraform's builtin terraform_data resource (ships with the CLI, zero
network dependency) for the success/validity/dependency paths, so these
tests are genuinely real end-to-end runs and not mocks — while staying
independent of this environment's demonstrated inability to reliably
download the AWS provider (see plan.py's module docstring). The
init-failure fixture uses a nonexistent provider source, which fails fast
and deterministically regardless of network bandwidth.
"""

from __future__ import annotations

from pathlib import Path

from terraveritas.models.plan import PlanStatus
from terraveritas.terraform.plan import TerraformPlanner

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "terraform_plan"


def test_plan_success_on_builtin_provider_resource() -> None:
    planner = TerraformPlanner()

    result = planner.plan(FIXTURES / "success", timeout_seconds=60)

    assert result.status == PlanStatus.PLAN_SUCCESS
    assert result.terraform_version is not None
    assert len(result.resource_changes) == 1
    change = result.resource_changes[0]
    assert change.address == "terraform_data.example"
    assert change.resource_type == "terraform_data"
    assert change.actions == ["create"]
    assert change.after["input"] == "hello"
    assert "id" in change.after_unknown_keys
    assert "output" in change.after_unknown_keys
    assert result.raw_plan_json is not None
    assert result.commands_run[0][1] == "init"
    assert result.commands_run[-1][1] == "show"


def test_broken_syntax_is_caught_before_any_terraform_subprocess_runs() -> None:
    """Verified necessary: real `terraform init` refuses to run at all on
    broken HCL syntax (it must parse the config to find providers to
    install) and fails with PLAN_INIT_FAILURE-shaped output — that would
    conflate "AI produced invalid HCL" with "a provider/module couldn't be
    installed". The pre-init hcl2 syntax check catches this first."""
    planner = TerraformPlanner()

    result = planner.plan(FIXTURES / "invalid_syntax", timeout_seconds=60)

    assert result.status == PlanStatus.PLAN_INVALID_CONFIGURATION
    assert result.error_message is not None
    assert result.resource_changes == []
    assert result.commands_run == []


def test_schema_invalid_configuration_is_caught_by_real_validate() -> None:
    """Syntactically valid HCL that real Terraform's schema validation
    rejects — must reach and be caught by `terraform validate`, not the
    pre-init hcl2 check (hcl2 has no schema awareness, so it accepts this
    fine)."""
    planner = TerraformPlanner()

    result = planner.plan(FIXTURES / "invalid_schema", timeout_seconds=60)

    assert result.status == PlanStatus.PLAN_INVALID_CONFIGURATION
    assert "nonexistent_argument" in (result.error_message or "")
    assert [c[1] for c in result.commands_run] == ["init", "validate"]


def test_unresolved_required_variable() -> None:
    planner = TerraformPlanner()

    result = planner.plan(FIXTURES / "unresolved_variable", timeout_seconds=60)

    assert result.status == PlanStatus.PLAN_UNRESOLVED_DEPENDENCY
    assert result.error_message is not None
    assert "required_input" in result.error_message


def test_unresolved_variable_succeeds_when_value_supplied() -> None:
    """Same fixture as above, but with the variable supplied — proves the
    UNRESOLVED_DEPENDENCY classification is about the missing value, not
    something wrong with the fixture itself."""
    planner = TerraformPlanner()

    result = planner.plan(
        FIXTURES / "unresolved_variable",
        timeout_seconds=60,
        tfvars={"required_input": "supplied-value"},
    )

    assert result.status == PlanStatus.PLAN_SUCCESS
    assert result.resource_changes[0].after["input"] == "supplied-value"


def test_deterministic_init_failure_on_nonexistent_provider() -> None:
    planner = TerraformPlanner()

    result = planner.plan(FIXTURES / "init_failure_bad_provider", timeout_seconds=30)

    assert result.status == PlanStatus.PLAN_INIT_FAILURE
    assert result.error_message is not None
    assert result.commands_run == [["terraform", "init", "-input=false", "-no-color"]]


def test_unsupported_remote_module_detected_before_network_access() -> None:
    planner = TerraformPlanner()

    result = planner.plan(FIXTURES / "unsupported_remote_module", timeout_seconds=30)

    assert result.status == PlanStatus.PLAN_UNSUPPORTED
    assert "terraform-aws-modules/vpc/aws" in (result.error_message or "")
    # Rejected pre-flight — no terraform subprocess was ever invoked.
    assert result.commands_run == []


def test_invalid_target_directory() -> None:
    planner = TerraformPlanner()

    result = planner.plan(FIXTURES / "does_not_exist", timeout_seconds=30)

    assert result.status == PlanStatus.PLAN_INVALID_TARGET
    assert result.commands_run == []


def test_timeout_during_init() -> None:
    planner = TerraformPlanner()

    result = planner.plan(FIXTURES / "success", timeout_seconds=0.001)

    assert result.status == PlanStatus.PLAN_TIMEOUT


def test_working_directory_is_never_mutated_in_place() -> None:
    """The planner must operate on an isolated copy — verify no .terraform
    directory or plan artifacts appear in the tracked fixture itself."""
    planner = TerraformPlanner()
    fixture_dir = FIXTURES / "success"

    planner.plan(fixture_dir, timeout_seconds=60)

    assert not (fixture_dir / ".terraform").exists()
    assert not (fixture_dir / "tfplan").exists()
    assert not (fixture_dir / ".terraform.lock.hcl").exists()


def test_missing_terraform_executable_returns_structured_result_not_a_crash() -> None:
    """Regression test for a confirmed crash: before this fix, a missing
    `terraform` binary let FileNotFoundError escape plan() as a raw
    traceback instead of the structured PlanResult every other expected
    failure mode produces."""
    planner = TerraformPlanner(terraform_executable="terraveritas-nonexistent-terraform-xyz")

    result = planner.plan(FIXTURES / "success", timeout_seconds=10)

    assert result.status == PlanStatus.PLAN_TERRAFORM_NOT_INSTALLED
    assert result.error_message is not None
    assert "terraveritas-nonexistent-terraform-xyz" in result.error_message
