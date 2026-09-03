"""Data model for one AI-repair generation record.

Every field the experimental protocol requires is represented explicitly —
nothing is reconstructed after the fact from partial data. `human_label` is
nullable by design: as of Prompt 8's verification pass, no accessible,
independently-verified ground-truth dataset exists for this task, so every
record currently generated has `human_label=None`. That absence must stay
visible, not be silently defaulted to a guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from terraveritas.models.diff import DifferentialResult
from terraveritas.models.finding import ScanResult
from terraveritas.models.invariant import InvariantResult
from terraveritas.models.oracle import OracleVerdict
from terraveritas.models.plan import PlanResult, PlanStatus


@dataclass(frozen=True, slots=True)
class SystemConfiguration:
    """Generation-call parameters. Fields are optional because they don't
    all apply to every generator (e.g. a self-authored pilot case has no
    temperature) — absence must be explicit, not zero-filled."""

    temperature: float | None = None
    max_output_tokens: int | None = None
    other_parameters: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HumanLabel:
    """A human adjudication attached to a record, when one exists."""

    label: str
    annotator: str
    labeled_at: datetime
    notes: str = ""


@dataclass(frozen=True, slots=True)
class RepairRecord:
    experiment_id: str
    case_id: str
    generated_at: datetime

    # Original state
    original_terraform: str
    original_terraform_sha256: str
    """SHA-256 of `original_terraform`, computed at record-creation time —
    a stable content fingerprint independent of file path or storage
    location, for exact-match provenance verification."""
    original_security_issue_rule_id: str
    original_security_issue_description: str
    vulnerability_class: str
    """The invariant_id this case targets, e.g. S3_PUBLIC_ACCESS_EXPOSURE."""

    # Generation provenance
    ai_model: str
    model_version: str
    prompt_template_id: str
    rendered_prompt: str
    system_configuration: SystemConfiguration
    raw_ai_output: str
    extracted_terraform: str

    # Evidence
    before_scan: ScanResult
    after_scan: ScanResult
    differential: DifferentialResult
    before_plan_status: PlanStatus
    after_plan_status: PlanStatus
    oracle_verdict: OracleVerdict | None

    # Ground truth, when available
    human_label: HumanLabel | None = None

    # Reproducibility snapshot, captured at generation time
    environment: dict[str, str] = field(default_factory=dict)

    # Full evidence, additive and optional (default None so existing
    # callers/records aren't broken): before_plan_status/after_plan_status
    # above are bare status enums — a stored record with only those cannot
    # be independently re-audited, since the resource_changes/raw plan JSON
    # that actually fed the invariant is discarded before it ever reaches
    # this dataclass. Found during the Prompt 14 review. New callers should
    # populate these; save_record's redaction pass covers them the same as
    # every other field.
    before_plan: PlanResult | None = None
    after_plan: PlanResult | None = None
    before_invariant: InvariantResult | None = None
    after_invariant: InvariantResult | None = None
