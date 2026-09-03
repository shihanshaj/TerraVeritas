"""Regression test for H2 (Prompt 14 zero-trust review): RepairRecord must
be able to carry the full PlanResult/InvariantResult, not just their
terminal status enums — a stored record with only the status cannot be
independently re-audited for why a classification was reached. Additive
fields (default None) so this doesn't break records/callers that predate
the fix."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from terraveritas.experiments.storage import load_record, save_record
from terraveritas.models.diff import DifferentialResult
from terraveritas.models.experiment import RepairRecord, SystemConfiguration
from terraveritas.models.finding import ScanResult, ScanStatus
from terraveritas.models.invariant import InvariantResult, InvariantStatus
from terraveritas.models.plan import PlannedResourceChange, PlanResult, PlanStatus

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _base_record() -> RepairRecord:
    empty_scan = ScanResult(
        scanner_name="checkov",
        scanner_version="3.3.16",
        target_path="/x",
        status=ScanStatus.SUCCESS,
    )
    return RepairRecord(
        experiment_id="evidence-test",
        case_id="case-000",
        generated_at=_TS,
        original_terraform="",
        original_terraform_sha256="",
        original_security_issue_rule_id="X",
        original_security_issue_description="",
        vulnerability_class="S3_PUBLIC_ACCESS_EXPOSURE",
        ai_model="test",
        model_version="test",
        prompt_template_id="minimal_v1",
        rendered_prompt="",
        system_configuration=SystemConfiguration(),
        raw_ai_output="",
        extracted_terraform="",
        before_scan=empty_scan,
        after_scan=empty_scan,
        differential=DifferentialResult(
            scanner_name="checkov", removed=[], persistent=[], new=[], relocated=[]
        ),
        before_plan_status=PlanStatus.PLAN_SUCCESS,
        after_plan_status=PlanStatus.PLAN_SUCCESS,
        oracle_verdict=None,
    )


def test_records_without_full_evidence_still_round_trip(tmp_path: Path) -> None:
    """Backward compatibility: a record built the old way (no before_plan/
    after_plan/before_invariant/after_invariant) must still save and load."""
    record = _base_record()

    path = save_record(record, base_dir=tmp_path)
    loaded = load_record(path)

    assert loaded.before_plan is None
    assert loaded.after_plan is None
    assert loaded.before_invariant is None
    assert loaded.after_invariant is None


def test_full_plan_and_invariant_evidence_round_trips(tmp_path: Path) -> None:
    plan = PlanResult(
        target_path="/fixture",
        status=PlanStatus.PLAN_SUCCESS,
        terraform_version="1.14.3",
        resource_changes=[
            PlannedResourceChange(
                address="aws_s3_bucket.data",
                resource_type="aws_s3_bucket",
                resource_name="data",
                provider_name="registry.terraform.io/hashicorp/aws",
                actions=["create"],
                after={"id": "b", "bucket": "b"},
                after_unknown_keys=["arn"],
            )
        ],
        raw_plan_json={"terraform_version": "1.14.3"},
        commands_run=[["terraform", "init"]],
    )
    invariant = InvariantResult(
        invariant_id="S3_PUBLIC_ACCESS_EXPOSURE",
        resource_address="aws_s3_bucket.data",
        status=InvariantStatus.FAIL,
        violated_conditions=["acl_grants_public"],
        reason="bucket is publicly reachable via: acl_grants_public",
        evidence={"acl_grants_public": True},
    )
    record = replace(
        _base_record(),
        before_plan=plan,
        after_plan=plan,
        before_invariant=invariant,
        after_invariant=invariant,
    )

    path = save_record(record, base_dir=tmp_path)
    loaded = load_record(path)

    assert loaded.before_plan is not None
    assert loaded.before_plan.status == PlanStatus.PLAN_SUCCESS
    assert loaded.before_plan.resource_changes[0].address == "aws_s3_bucket.data"
    assert loaded.before_plan.resource_changes[0].after_unknown_keys == ["arn"]
    assert loaded.before_invariant is not None
    assert loaded.before_invariant.violated_conditions == ["acl_grants_public"]


def test_full_evidence_is_redacted_on_disk_too(tmp_path: Path) -> None:
    """The whole point of storing this evidence is auditability — it must
    not become a second, unredacted channel for the same secrets
    save_record already redacts from original_terraform/raw_ai_output."""
    plan = PlanResult(
        target_path="/fixture",
        status=PlanStatus.PLAN_SUCCESS,
        resource_changes=[
            PlannedResourceChange(
                address="aws_iam_access_key.leak",
                resource_type="aws_iam_access_key",
                resource_name="leak",
                provider_name="aws",
                actions=["create"],
                after={"secret": "AKIAIOSFODNN7EXAMPLE-embedded-in-plan-output"},
                after_unknown_keys=[],
            )
        ],
    )
    record = replace(_base_record(), before_plan=plan)

    path = save_record(record, base_dir=tmp_path)

    assert "AKIAIOSFODNN7EXAMPLE" not in path.read_text()
