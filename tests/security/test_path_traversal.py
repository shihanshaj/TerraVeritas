"""Regression tests: experiment_id/case_id must never be usable to escape
base_dir via a `..`-containing or absolute-path value. save_record and
save_manifest use these values directly as path components."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from terraveritas.experiments.storage import save_manifest, save_record
from terraveritas.models.diff import DifferentialResult
from terraveritas.models.experiment import RepairRecord, SystemConfiguration
from terraveritas.models.finding import ScanResult, ScanStatus
from terraveritas.models.plan import PlanStatus

_TS = datetime(2026, 1, 1, tzinfo=UTC)

_MALICIOUS_IDS = [
    "../../../etc/evil",
    "..",
    "a/../../b",
    "/etc/passwd",
    "a/b",
    "a\\b",
]


def _minimal_record(experiment_id: str, case_id: str) -> RepairRecord:
    empty_scan = ScanResult(
        scanner_name="checkov",
        scanner_version="3.3.16",
        target_path="/x",
        status=ScanStatus.SUCCESS,
    )
    return RepairRecord(
        experiment_id=experiment_id,
        case_id=case_id,
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


@pytest.mark.parametrize("malicious_id", _MALICIOUS_IDS)
def test_save_record_rejects_malicious_experiment_id(tmp_path: Path, malicious_id: str) -> None:
    record = _minimal_record(malicious_id, "safe-case-000")

    with pytest.raises(ValueError, match="experiment_id"):
        save_record(record, base_dir=tmp_path)

    # Confirm nothing escaped tmp_path regardless of the ValueError.
    assert not (tmp_path.parent / "evil").exists()


@pytest.mark.parametrize("malicious_id", _MALICIOUS_IDS)
def test_save_record_rejects_malicious_case_id(tmp_path: Path, malicious_id: str) -> None:
    record = _minimal_record("safe-experiment", malicious_id)

    with pytest.raises(ValueError, match="case_id"):
        save_record(record, base_dir=tmp_path)


@pytest.mark.parametrize("malicious_id", _MALICIOUS_IDS)
def test_save_manifest_rejects_malicious_experiment_id(tmp_path: Path, malicious_id: str) -> None:
    with pytest.raises(ValueError, match="experiment_id"):
        save_manifest(malicious_id, base_dir=tmp_path, matrix_cells=[], record_count=0)


def test_save_record_still_works_for_legitimate_ids(tmp_path: Path) -> None:
    record = _minimal_record("2026-09-02-pilot-s3exposure", "minimal-000")

    path = save_record(record, base_dir=tmp_path)

    assert path.exists()
    assert path == tmp_path / "2026-09-02-pilot-s3exposure" / "records" / "minimal-000.json"
