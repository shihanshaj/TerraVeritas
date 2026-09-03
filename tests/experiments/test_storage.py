"""Round-trip serialization tests: every field must survive save -> load
unchanged. Uses full, realistic nested objects (ScanResult with Findings,
a DifferentialResult with all four buckets populated, an OracleVerdict) so
a schema drift in any nested type is caught here, not discovered later
against real pilot data."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from terraveritas.experiments.identifiers import content_hash
from terraveritas.experiments.storage import load_record, record_to_dict, save_record
from terraveritas.models.diff import (
    DifferentialResult,
    NewFinding,
    PersistentFinding,
    RelocatedFinding,
    RemovedFinding,
)
from terraveritas.models.experiment import HumanLabel, RepairRecord, SystemConfiguration
from terraveritas.models.finding import Finding, FindingOutcome, ScanResult, ScanStatus
from terraveritas.models.oracle import Classification, Confidence, OracleVerdict
from terraveritas.models.plan import PlanStatus

_TS = datetime(2026, 9, 2, 12, 0, 0, tzinfo=UTC)


def _finding(rule_id: str, resource_id: str) -> Finding:
    return Finding(
        scanner_name="checkov",
        scanner_version="3.2.0",
        rule_id=rule_id,
        outcome=FindingOutcome.FAILED,
        file_path="main.tf",
        description="example",
        raw_evidence={"check_id": rule_id},
        scan_timestamp=_TS,
        resource_id=resource_id,
    )


def _full_record() -> RepairRecord:
    scan = ScanResult(
        scanner_name="checkov",
        scanner_version="3.2.0",
        target_path="/fixture",
        status=ScanStatus.SUCCESS,
        findings=[_finding("CKV_AWS_20", "aws_s3_bucket.data")],
        started_at=_TS,
        finished_at=_TS,
        exit_code=1,
    )
    differential = DifferentialResult(
        scanner_name="checkov",
        removed=[
            RemovedFinding(
                before=_finding("CKV_AWS_20", "aws_s3_bucket.data"),
                resource_still_present_in_after=True,
                same_identity_now_passes=True,
            )
        ],
        persistent=[
            PersistentFinding(
                before=_finding("CKV_AWS_18", "aws_s3_bucket.data"),
                after=_finding("CKV_AWS_18", "aws_s3_bucket.data"),
            )
        ],
        new=[NewFinding(after=_finding("CKV_AWS_99", "aws_s3_bucket.data"))],
        relocated=[
            RelocatedFinding(
                before=_finding("CKV2_AWS_6", "aws_s3_bucket.old"),
                after=_finding("CKV2_AWS_6", "aws_s3_bucket.new"),
                note="test relocation",
            )
        ],
    )
    verdict = OracleVerdict(
        classification=Classification.INCONCLUSIVE,
        confidence=Confidence.LOW,
        invariant_id="S3_PUBLIC_ACCESS_EXPOSURE",
        resource_address="aws_s3_bucket.data",
        evidence_used=["before plan (plan_provider_failure)"],
        reasons=["plan did not succeed"],
        remaining_uncertainty=["no plan evidence available"],
    )

    return RepairRecord(
        experiment_id="2026-09-02-pilot-s3exposure",
        case_id="minimal-000",
        generated_at=_TS,
        original_terraform='resource "aws_s3_bucket_acl" "data" { acl = "public-read" }',
        original_terraform_sha256=content_hash(
            'resource "aws_s3_bucket_acl" "data" { acl = "public-read" }'
        ),
        original_security_issue_rule_id="CKV_AWS_20",
        original_security_issue_description="S3 Bucket has public-read ACL",
        vulnerability_class="S3_PUBLIC_ACCESS_EXPOSURE",
        ai_model="claude",
        model_version="claude-sonnet-5",
        prompt_template_id="minimal_v1",
        rendered_prompt="You are repairing a Terraform configuration...",
        system_configuration=SystemConfiguration(
            temperature=None, other_parameters={"self_authored": True}
        ),
        raw_ai_output='```hcl\nresource "aws_s3_bucket_acl" "data" { acl = "private" }\n```',
        extracted_terraform='resource "aws_s3_bucket_acl" "data" { acl = "private" }',
        before_scan=scan,
        after_scan=scan,
        differential=differential,
        before_plan_status=PlanStatus.PLAN_SUCCESS,
        after_plan_status=PlanStatus.PLAN_PROVIDER_FAILURE,
        oracle_verdict=verdict,
        human_label=HumanLabel(
            label="illustrative_only", annotator="test", labeled_at=_TS, notes="synthetic"
        ),
        environment={"terraform_version": "1.14.3"},
    )


def test_round_trip_preserves_every_field(tmp_path: Path) -> None:
    record = _full_record()

    path = save_record(record, base_dir=tmp_path)
    loaded = load_record(path)

    assert record_to_dict(loaded) == record_to_dict(record)


def test_round_trip_with_no_oracle_verdict_or_human_label(tmp_path: Path) -> None:
    record = _full_record()
    stripped = replace(record, oracle_verdict=None, human_label=None)

    path = save_record(stripped, base_dir=tmp_path)
    loaded = load_record(path)

    assert loaded.oracle_verdict is None
    assert loaded.human_label is None


def test_save_record_writes_to_expected_path(tmp_path: Path) -> None:
    record = _full_record()

    path = save_record(record, base_dir=tmp_path)

    expected = tmp_path / "2026-09-02-pilot-s3exposure" / "records" / "minimal-000.json"
    assert path == expected
    assert path.exists()
