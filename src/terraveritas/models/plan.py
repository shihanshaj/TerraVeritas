"""Data model for Terraform plan processing.

Mirrors the ScanStatus/ScanResult pattern from models/finding.py: every
expected failure mode is a PlanStatus value the caller can branch on, never
an exception, and PLAN_SUCCESS is never the default when a stage failed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class PlanStatus(StrEnum):
    PLAN_SUCCESS = "plan_success"

    PLAN_INVALID_TARGET = "plan_invalid_target"
    """The target directory does not exist. Mirrors ScanStatus.INVALID_TARGET."""

    PLAN_TERRAFORM_NOT_INSTALLED = "plan_terraform_not_installed"
    """The `terraform` executable could not be found or executed at all —
    distinct from every other status, all of which assume Terraform itself
    ran. Mirrors ScanStatus's shutil.which() pattern in scanners/base.py."""

    PLAN_INVALID_CONFIGURATION = "plan_invalid_configuration"
    """`terraform validate` reported the configuration itself is invalid
    (syntax error, type error, missing required argument). Never means the
    security property is unevaluable for AWS-semantic reasons — that's a
    different, later concern."""

    PLAN_INIT_FAILURE = "plan_init_failure"
    """`terraform init` failed: provider download failed (including network
    issues), a required module source could not be fetched, or backend
    initialization failed. Precedes validate/plan, so those never ran."""

    PLAN_UNRESOLVED_DEPENDENCY = "plan_unresolved_dependency"
    """A required input (most commonly a variable with no default and no
    supplied value) could not be resolved, so no concrete plan could be
    produced. The configuration may be perfectly valid in isolation."""

    PLAN_PROVIDER_FAILURE = "plan_provider_failure"
    """Init and validation succeeded, but `plan` itself failed because a
    provider needed a live API call it couldn't make (no/invalid
    credentials, no network to AWS). This is expected and safe: the
    planner deliberately runs with sabotaged, non-functional AWS
    credentials (see plan.py) specifically so any config that truly needs
    a live call fails here rather than silently succeeding against a real
    account."""

    PLAN_UNSUPPORTED = "plan_unsupported"
    """The configuration uses a construct this Phase 1 planner deliberately
    does not attempt — currently: any non-local (registry/git/http) module
    source. Detected before touching the network, not discovered via a
    failed init."""

    PLAN_TIMEOUT = "plan_timeout"
    """A stage (init/validate/plan/show) exceeded the timeout."""

    PLAN_ERROR = "plan_error"
    """A stage failed in a way that didn't match any more specific
    classification above. Always carries the raw diagnostic text — an
    unclassified failure must stay visibly unclassified, never get folded
    into one of the specific categories on a guess."""


@dataclass(frozen=True, slots=True)
class PlannedResourceChange:
    """One resource's planned change, normalized from `terraform show -json`."""

    address: str
    resource_type: str
    resource_name: str
    provider_name: str
    actions: list[str]
    after: dict[str, Any]
    after_unknown_keys: list[str]
    """Attribute names Terraform marked "(known after apply)" — not
    resolvable before a real apply (e.g. provider-generated ARNs/IDs).
    Callers evaluating invariants against `after` must treat these
    attributes as unknown, not absent or false."""


@dataclass(frozen=True, slots=True)
class PlanResult:
    target_path: str
    status: PlanStatus
    terraform_version: str | None = None
    resource_changes: list[PlannedResourceChange] = field(default_factory=list)
    raw_plan_json: dict[str, Any] | None = None
    """The full `terraform show -json` payload, only present on
    PLAN_SUCCESS. Kept so a later invariant evaluator that needs more than
    the normalized resource_changes (e.g. `configuration` for reference
    tracing) isn't blocked on this module re-deriving it."""
    commands_run: list[list[str]] = field(default_factory=list)
    error_message: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
