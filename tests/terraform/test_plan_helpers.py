"""Unit tests for pure-logic helpers in plan.py that don't need a real
terraform run: module-source detection, AWS-provider-injection heuristic,
and plan-failure classification.

The PLAN_PROVIDER_FAILURE classification patterns are, per plan.py's module
docstring, NOT verified against a real AWS-provider run in this project's
environment (the AWS provider could not be downloaded — see project notes).
These tests verify the pattern-matching logic in isolation against
synthetic diagnostic text modeled on documented AWS SDK error strings —
that is a real, verifiable unit of behavior, but it is not the same claim
as "this fires correctly against a genuine AWS provider failure."
"""

from __future__ import annotations

from pathlib import Path

import pytest

from terraveritas.models.plan import PlanStatus
from terraveritas.security import SENSITIVE_ENV_VAR_NAMES
from terraveritas.terraform.plan import (
    _classify_plan_failure,
    _detect_unsupported_module_sources,
    _needs_aws_provider_injection,
    _sandboxed_env,
)


def _write(tmp_path: Path, content: str, name: str = "main.tf") -> None:
    (tmp_path / name).write_text(content)


def test_local_module_source_is_supported(tmp_path: Path) -> None:
    _write(tmp_path, 'module "x" { source = "./modules/x" }')

    assert _detect_unsupported_module_sources(tmp_path) == []


def test_registry_module_source_is_unsupported(tmp_path: Path) -> None:
    _write(tmp_path, 'module "vpc" { source = "terraform-aws-modules/vpc/aws" }')

    unsupported = _detect_unsupported_module_sources(tmp_path)

    assert len(unsupported) == 1
    assert "vpc" in unsupported[0]


def test_no_module_blocks_is_supported(tmp_path: Path) -> None:
    _write(tmp_path, 'resource "terraform_data" "x" { input = "y" }')

    assert _detect_unsupported_module_sources(tmp_path) == []


def test_needs_provider_injection_when_aws_resource_present_and_unconfigured(
    tmp_path: Path,
) -> None:
    _write(tmp_path, 'resource "aws_s3_bucket" "data" { bucket = "x" }')

    assert _needs_aws_provider_injection(tmp_path) is True


def test_no_injection_needed_when_no_aws_resources(tmp_path: Path) -> None:
    _write(tmp_path, 'resource "terraform_data" "x" { input = "y" }')

    assert _needs_aws_provider_injection(tmp_path) is False


def test_no_injection_when_aws_provider_already_configured(tmp_path: Path) -> None:
    _write(
        tmp_path,
        """
        resource "aws_s3_bucket" "data" { bucket = "x" }
        provider "aws" { region = "us-east-1" }
        """,
    )

    assert _needs_aws_provider_injection(tmp_path) is False


def test_no_injection_when_aws_in_required_providers_already(tmp_path: Path) -> None:
    _write(
        tmp_path,
        """
        resource "aws_s3_bucket" "data" { bucket = "x" }
        terraform {
          required_providers {
            aws = { source = "hashicorp/aws", version = "5.0.0" }
          }
        }
        """,
    )

    assert _needs_aws_provider_injection(tmp_path) is False


def test_needs_injection_when_aws_data_source_present(tmp_path: Path) -> None:
    _write(tmp_path, 'data "aws_caller_identity" "current" {}')

    assert _needs_aws_provider_injection(tmp_path) is True


def test_classify_unresolved_dependency() -> None:
    stdout = (
        '{"@level":"error","diagnostic":{"summary":"No value for required variable",'
        '"detail":"..."}}\n'
    )

    status, message = _classify_plan_failure(stdout, "")

    assert status == PlanStatus.PLAN_UNRESOLVED_DEPENDENCY
    assert "No value for required variable" in message


def test_classify_provider_failure_from_known_pattern() -> None:
    """Synthetic diagnostic text modeled on documented AWS SDK error
    strings — NOT a real AWS provider run. See module docstring above."""
    stdout = (
        '{"@level":"error","diagnostic":{"summary":"error configuring Terraform AWS Provider",'
        '"detail":"no valid credential sources for Terraform AWS Provider found"}}\n'
    )

    status, message = _classify_plan_failure(stdout, "")

    assert status == PlanStatus.PLAN_PROVIDER_FAILURE
    assert "credential" in message


def test_classify_unmatched_failure_falls_back_to_generic_not_a_guess() -> None:
    """An unrecognized failure must never be mis-labeled as one of the
    specific categories — it stays visibly unclassified instead."""
    stdout = (
        '{"@level":"error","diagnostic":{"summary":"Something entirely novel broke",'
        '"detail":"unprecedented failure mode"}}\n'
    )

    status, message = _classify_plan_failure(stdout, "")

    assert status == PlanStatus.PLAN_ERROR
    assert "Something entirely novel broke" in message


def test_classify_falls_back_to_stderr_when_no_json_diagnostics() -> None:
    status, message = _classify_plan_failure("", "raw stderr text, no json at all")

    assert status == PlanStatus.PLAN_ERROR
    assert message == "raw stderr text, no json at all"


# --- Regression tests: fragile assumptions about hcl2's output shape ---
# Verified empirically (not assumed) that hcl2 always list-wraps a single
# argument value and keeps duplicate module names as separate list entries
# — no crash risk from either. The real, confirmed issue is a MISLEADING
# result: an unresolved HCL expression (a variable reference, not a literal
# path) was reported as if it were a known non-local module source.


def test_unresolved_variable_source_is_distinguished_from_a_literal_remote_source(
    tmp_path: Path,
) -> None:
    """`source = var.module_source` parses to the literal string
    "${var.module_source}" (verified against real hcl2 output) — this is
    an unresolved expression, not evidence the module is actually remote.
    Before this fix it was reported identically to a genuine registry
    source, with a message implying "${var.module_source}" was itself the
    non-local path."""
    _write(tmp_path, 'module "a" { source = var.module_source }')

    unsupported = _detect_unsupported_module_sources(tmp_path)

    assert len(unsupported) == 1
    assert "cannot statically determine" in unsupported[0].lower()
    assert "unresolved" in unsupported[0].lower()


def test_duplicate_module_names_are_each_checked_independently(tmp_path: Path) -> None:
    """Verified against real hcl2 output: duplicate module labels are kept
    as separate list entries, not merged or overwritten — both must still
    be checked, not just the first or last."""
    _write(
        tmp_path,
        'module "dup" { source = "./one" }\n'
        'module "dup" { source = "git::https://example.com/repo.git" }\n',
    )

    unsupported = _detect_unsupported_module_sources(tmp_path)

    assert len(unsupported) == 1
    assert "git::" in unsupported[0]


def test_module_block_with_missing_source_argument_is_skipped_not_crashed(
    tmp_path: Path,
) -> None:
    """Invalid Terraform (source is required) but a plausible malformed/
    partial AI-generation artifact — must be skipped, never crash the
    caller. (validate/plan will separately and correctly reject this.)"""
    _write(tmp_path, 'module "incomplete" { count = 1 }')

    assert _detect_unsupported_module_sources(tmp_path) == []


# --- Regression tests: environment sanitization must share one policy ---
# Root cause, confirmed: _sandboxed_env maintained its own, separate,
# incomplete strip-list (4 vars) instead of reusing security.py's
# SENSITIVE_ENV_VAR_NAMES (8 vars) — missing AWS_ROLE_ARN and
# AWS_WEB_IDENTITY_TOKEN_FILE specifically, the pair that enables
# AssumeRoleWithWebIdentity (how GitHub Actions OIDC AWS auth works). If
# TerraVeritas ran inside such a CI job, those vars would leak through
# unstripped to a scanned config's AWS provider.


def test_sandboxed_env_never_contains_a_real_leaked_credential_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simpler, more direct framing of the same property: whatever ends up
    in the sandboxed env for each sensitive var, it must never be the real
    value that was set on the host — either popped entirely or overwritten
    with a known-fake placeholder, never passed through."""
    for var in SENSITIVE_ENV_VAR_NAMES:
        monkeypatch.setenv(var, "leaked-value-should-not-survive")

    env = _sandboxed_env(plugin_cache_dir=None)

    for var in SENSITIVE_ENV_VAR_NAMES:
        assert env.get(var) != "leaked-value-should-not-survive"
