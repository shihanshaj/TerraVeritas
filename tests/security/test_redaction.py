"""Regression tests for credential redaction. Two things must both hold:
(1) redact_secrets() actually catches key-based and pattern-based secrets,
and (2) save_record applies it to what's written to disk while
record_to_dict() (in-memory use) stays lossless — the design decision
documented in storage.py."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from terraveritas.experiments.storage import record_to_dict, save_record
from terraveritas.models.diff import DifferentialResult
from terraveritas.models.experiment import RepairRecord, SystemConfiguration
from terraveritas.models.finding import ScanResult, ScanStatus
from terraveritas.models.plan import PlanStatus
from terraveritas.security import redact_secrets

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def test_redact_secrets_by_key_name() -> None:
    payload = {
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "resource": "aws_iam_access_key.example",
        "nested": {"password": "hunter2", "unrelated": "keep-me"},
    }

    redacted = redact_secrets(payload)

    assert redacted["aws_secret_access_key"] == "[REDACTED]"
    assert redacted["nested"]["password"] == "[REDACTED]"
    assert redacted["nested"]["unrelated"] == "keep-me"
    assert redacted["resource"] == "aws_iam_access_key.example"  # not a sensitive key name


def test_redact_secrets_by_value_pattern_regardless_of_key_name() -> None:
    payload = {
        "description": "found access key AKIAIOSFODNN7EXAMPLE in a bucket policy statement",
        "pem": (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----"
        ),
        "auth_header": "Bearer abc123.def456.ghi789",
    }

    redacted = redact_secrets(payload)

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted["description"]
    assert "[REDACTED]" in redacted["description"]
    assert redacted["pem"] == "[REDACTED]"
    assert redacted["auth_header"] == "Bearer [REDACTED]"


def test_redact_secrets_preserves_structure_and_non_sensitive_content() -> None:
    payload = {"a": [1, 2, {"b": "plain text, nothing sensitive here"}], "c": None}

    redacted = redact_secrets(payload)

    assert redacted == payload


def _record_with_secret_in_raw_terraform() -> RepairRecord:
    empty_scan = ScanResult(
        scanner_name="checkov",
        scanner_version="3.3.16",
        target_path="/x",
        status=ScanStatus.SUCCESS,
    )
    return RepairRecord(
        experiment_id="redaction-test",
        case_id="case-000",
        generated_at=_TS,
        original_terraform=(
            'provider "aws" {\n  access_key = "AKIAIOSFODNN7EXAMPLE"\n'
            '  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n}'
        ),
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


def test_save_record_redacts_the_persisted_file(tmp_path: Path) -> None:
    record = _record_with_secret_in_raw_terraform()

    path = save_record(record, base_dir=tmp_path)
    on_disk = json.loads(path.read_text())

    assert "AKIAIOSFODNN7EXAMPLE" not in path.read_text()
    assert "[REDACTED]" in on_disk["original_terraform"]


def test_record_to_dict_stays_lossless_for_in_memory_use() -> None:
    """The in-memory serialization function is deliberately NOT redacted —
    only the on-disk write path is. This is tested explicitly so a future
    change doesn't accidentally make record_to_dict lossy."""
    record = _record_with_secret_in_raw_terraform()

    as_dict = record_to_dict(record)

    assert "AKIAIOSFODNN7EXAMPLE" in as_dict["original_terraform"]
