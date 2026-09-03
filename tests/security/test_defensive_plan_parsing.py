"""Regression tests for H1 and C2 (Prompt 14 zero-trust review), exercised
through the real TerraformPlanner.plan() control flow via a mocked
subprocess layer — no real `terraform` execution or network access needed,
since these are failure modes in stages *after* init that this sandbox
cannot reliably reach for real (see terraform/plan.py's module docstring).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

from terraveritas.models.plan import PlanStatus
from terraveritas.terraform.plan import TerraformPlanner


def _completed(argv: list[str], returncode: int, stdout: str = "", stderr: str = "") -> mock.Mock:
    result = mock.Mock(spec=subprocess.CompletedProcess)
    result.args = argv
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


def _stage(argv: list[str]) -> str:
    for known in ("init", "validate", "plan", "show"):
        if known in argv:
            return known
    return "unknown"


def _minimal_fixture(tmp_path: Path) -> Path:
    source = tmp_path / "fixture"
    source.mkdir()
    (source / "main.tf").write_text('resource "terraform_data" "x" {}\n')
    return source


def test_validate_crash_is_classified_not_silently_ignored(tmp_path: Path) -> None:
    """H1: validate exits non-zero with output that doesn't parse as the
    structured "valid": false JSON shape. Before the fix, this fell
    through and the code proceeded to `terraform plan` anyway."""
    source = _minimal_fixture(tmp_path)

    def fake_run(argv, cwd, env, timeout_seconds):  # noqa: ANN001, ARG001
        stage = _stage(argv)
        if stage == "init":
            return _completed(argv, 0)
        if stage == "validate":
            return _completed(argv, 1, stdout="", stderr="Terraform crashed: panic: nil pointer")
        # If execution reaches plan/show, the bug has NOT been fixed.
        raise AssertionError(f"unexpected stage reached after validate crash: {stage}")

    with mock.patch("terraveritas.terraform.plan._run", side_effect=fake_run):
        result = TerraformPlanner().plan(source, timeout_seconds=30)

    assert result.status == PlanStatus.PLAN_ERROR
    assert result.error_message is not None
    assert "panic" in result.error_message


def test_malformed_resource_changes_is_classified_not_a_crash(tmp_path: Path) -> None:
    """C2: `show -json` succeeds and parses, but a resource_changes entry
    is missing a key this project's schema assumptions require. Before the
    fix, this raised an uncaught KeyError straight out of plan()."""
    source = _minimal_fixture(tmp_path)
    malformed_show_json = (
        '{"terraform_version": "1.14.3", "resource_changes": '
        '[{"address": "x", "type": "terraform_data", '
        '"change": {"actions": ["create"], "after": {}}}]}'  # "name" key missing
    )

    def fake_run(argv, cwd, env, timeout_seconds):  # noqa: ANN001, ARG001
        stage = _stage(argv)
        if stage == "init":
            return _completed(argv, 0)
        if stage == "validate":
            return _completed(argv, 0, stdout='{"valid": true, "diagnostics": []}')
        if stage == "plan":
            return _completed(argv, 0, stdout="")
        if stage == "show":
            return _completed(argv, 0, stdout=malformed_show_json)
        raise AssertionError(f"unexpected stage: {stage}")

    with mock.patch("terraveritas.terraform.plan._run", side_effect=fake_run):
        result = TerraformPlanner().plan(source, timeout_seconds=30)

    assert result.status == PlanStatus.PLAN_ERROR
    assert result.error_message is not None
    assert "resource_changes" in result.error_message


def test_well_formed_resource_changes_still_succeeds(tmp_path: Path) -> None:
    """Confirms the C2 fix's try/except doesn't over-catch — a genuinely
    well-formed payload must still reach PLAN_SUCCESS."""
    source = _minimal_fixture(tmp_path)
    good_show_json = (
        '{"terraform_version": "1.14.3", "resource_changes": '
        '[{"address": "terraform_data.x", "type": "terraform_data", "name": "x", '
        '"change": {"actions": ["create"], "after": {}}}]}'
    )

    def fake_run(argv, cwd, env, timeout_seconds):  # noqa: ANN001, ARG001
        stage = _stage(argv)
        if stage == "init":
            return _completed(argv, 0)
        if stage == "validate":
            return _completed(argv, 0, stdout='{"valid": true, "diagnostics": []}')
        if stage == "plan":
            return _completed(argv, 0, stdout="")
        if stage == "show":
            return _completed(argv, 0, stdout=good_show_json)
        raise AssertionError(f"unexpected stage: {stage}")

    with mock.patch("terraveritas.terraform.plan._run", side_effect=fake_run):
        result = TerraformPlanner().plan(source, timeout_seconds=30)

    assert result.status == PlanStatus.PLAN_SUCCESS
    assert len(result.resource_changes) == 1
    assert result.resource_changes[0].address == "terraform_data.x"
