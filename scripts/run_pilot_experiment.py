"""Runs the 2-cell pilot experiment for Prompt 9 and stops.

This is explicitly NOT mass generation. It proves the full pipeline
(prompt template -> repair -> scan -> differential -> plan attempt ->
invariant -> oracle -> storage -> round-trip) works end to end on genuine
data, and nothing more.

The "AI model" for this pilot is this session itself (disclosed below) —
there is no external multi-model API wired into this environment yet. The
two repair texts are self-authored to exercise two different, already-
verified pipeline behaviors (a genuine fix, and the resource-rename
identity-evasion pattern from Prompt 4) rather than to measure a real
prompt-strategy effect, which a 2-case pilot cannot do regardless.

Also disclosed: this sandbox cannot reach the Terraform provider registry
(established in Prompt 5), so `terraform plan` fails for every case here
regardless of repair quality, and the oracle stage bottlenecks at
INCONCLUSIVE. That is treated as a valid, informative pilot outcome, not a
failure — it is the exact safety property Prompt 7 was built to guarantee.
"""

from __future__ import annotations

import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from terraveritas.differential.scanner_diff import compare_scan_results  # noqa: E402
from terraveritas.experiments.identifiers import (  # noqa: E402
    content_hash,
    make_case_id,
    make_experiment_id,
)
from terraveritas.experiments.prompts import render_intent_explicit, render_minimal  # noqa: E402
from terraveritas.experiments.reproducibility import capture_environment  # noqa: E402
from terraveritas.experiments.storage import save_manifest, save_record  # noqa: E402
from terraveritas.invariants import s3_public_access  # noqa: E402
from terraveritas.models.experiment import RepairRecord, SystemConfiguration  # noqa: E402
from terraveritas.models.plan import PlanResult  # noqa: E402
from terraveritas.scanners.checkov import CheckovAdapter  # noqa: E402
from terraveritas.terraform.plan import TerraformPlanner  # noqa: E402
from terraveritas.verification.oracle import classify_repair  # noqa: E402

FIXTURES = REPO_ROOT / "fixtures" / "terraform"
DATASETS = REPO_ROOT / "datasets" / "experiments"
MIRROR_DIR = REPO_ROOT / ".terraform-mirror"

ORIGINAL_TF = (FIXTURES / "s3_vulnerable" / "main.tf").read_text()

GENUINE_FIX_TF = (FIXTURES / "s3_secure" / "main.tf").read_text()
RENAMED_STILL_VULNERABLE_TF = (FIXTURES / "s3_vulnerable_renamed" / "main.tf").read_text()

ENVIRONMENT = capture_environment()


def _scan(tf_content: str, adapter: CheckovAdapter):
    with tempfile.TemporaryDirectory() as tmp:
        tf_dir = Path(tmp)
        (tf_dir / "main.tf").write_text(tf_content)
        return adapter.scan(tf_dir, timeout_seconds=60)


def _attempt_plan(tf_content: str, planner: TerraformPlanner) -> PlanResult:
    with tempfile.TemporaryDirectory() as tmp:
        tf_dir = Path(tmp)
        (tf_dir / "main.tf").write_text(tf_content)
        return planner.plan(tf_dir, timeout_seconds=60)


def run_case(
    *,
    experiment_id: str,
    cell_label: str,
    index: int,
    prompt_strategy: str,
    repaired_tf: str,
    resource_address_after: str,
    adapter: CheckovAdapter,
    planner: TerraformPlanner,
) -> RepairRecord:
    case_id = make_case_id(cell_label, index)

    if prompt_strategy == "minimal":
        rendered = render_minimal(
            rule_id="CKV_AWS_20",
            rule_description="S3 Bucket has an ACL defined which allows public READ access",
            resource_id="aws_s3_bucket_acl.data",
            file_path="main.tf",
            terraform_file=ORIGINAL_TF,
        )
    else:
        rendered = render_intent_explicit(
            invariant_id="S3_PUBLIC_ACCESS_EXPOSURE",
            rule_id="CKV_AWS_20",
            rule_description="S3 Bucket has an ACL defined which allows public READ access",
            resource_id="aws_s3_bucket_acl.data",
            file_path="main.tf",
            terraform_file=ORIGINAL_TF,
        )

    before_scan = _scan(ORIGINAL_TF, adapter)
    after_scan = _scan(repaired_tf, adapter)
    differential = compare_scan_results(before_scan, after_scan)

    before_plan = _attempt_plan(ORIGINAL_TF, planner)
    after_plan = _attempt_plan(repaired_tf, planner)

    before_invariant = s3_public_access.evaluate_s3_public_access_exposure(
        before_plan, "aws_s3_bucket.data"
    )
    after_invariant = s3_public_access.evaluate_s3_public_access_exposure(
        after_plan, resource_address_after
    )

    verdict = classify_repair(
        before_invariant,
        after_invariant,
        before_plan_status=before_plan.status,
        after_plan_status=after_plan.status,
        differential_results=[differential],
    )

    record = RepairRecord(
        experiment_id=experiment_id,
        case_id=case_id,
        generated_at=datetime.now(UTC),
        original_terraform=ORIGINAL_TF,
        original_terraform_sha256=content_hash(ORIGINAL_TF),
        original_security_issue_rule_id="CKV_AWS_20",
        original_security_issue_description=(
            "S3 Bucket has an ACL defined which allows public READ access"
        ),
        vulnerability_class="S3_PUBLIC_ACCESS_EXPOSURE",
        ai_model="self-authored-pilot",
        model_version="claude-sonnet-5 (session-authored, not API-invoked; see script docstring)",
        prompt_template_id=rendered.template_id,
        rendered_prompt=rendered.text,
        system_configuration=SystemConfiguration(
            temperature=None,
            other_parameters={"note": "self-authored pilot case, no sampling parameters apply"},
        ),
        raw_ai_output=repaired_tf,
        extracted_terraform=repaired_tf,
        before_scan=before_scan,
        after_scan=after_scan,
        differential=differential,
        before_plan_status=before_plan.status,
        after_plan_status=after_plan.status,
        oracle_verdict=verdict,
        human_label=None,
        environment=ENVIRONMENT,
        # Prompt 14 fix (H2): keep the actual evidence, not just its status.
        before_plan=before_plan,
        after_plan=after_plan,
        before_invariant=before_invariant,
        after_invariant=after_invariant,
    )
    save_record(record, base_dir=DATASETS)
    return record


def main() -> None:
    if not MIRROR_DIR.exists():
        print(f"Provider mirror not found at {MIRROR_DIR}.")
        print("Run: uv run python scripts/build_provider_mirror.py")
        raise SystemExit(1)

    experiment_id = make_experiment_id("pilot-s3exposure")
    adapter = CheckovAdapter()
    planner = TerraformPlanner(filesystem_mirror_dir=MIRROR_DIR)

    records = [
        run_case(
            experiment_id=experiment_id,
            cell_label="minimal",
            index=0,
            prompt_strategy="minimal",
            repaired_tf=GENUINE_FIX_TF,
            resource_address_after="aws_s3_bucket.data",
            adapter=adapter,
            planner=planner,
        ),
        run_case(
            experiment_id=experiment_id,
            cell_label="intent_explicit",
            index=0,
            prompt_strategy="intent_explicit",
            repaired_tf=RENAMED_STILL_VULNERABLE_TF,
            resource_address_after="aws_s3_bucket.archive",
            adapter=adapter,
            planner=planner,
        ),
    ]

    save_manifest(
        experiment_id,
        base_dir=DATASETS,
        matrix_cells=["minimal-000", "intent_explicit-000"],
        record_count=len(records),
    )

    for record in records:
        v = record.oracle_verdict
        print(f"\n=== {record.case_id} ===")
        print(f"prompt_template: {record.prompt_template_id}")
        print(f"before_plan_status: {record.before_plan_status.value}")
        print(f"after_plan_status: {record.after_plan_status.value}")
        print(f"differential: removed={len(record.differential.removed)} "
              f"persistent={len(record.differential.persistent)} "
              f"new={len(record.differential.new)} "
              f"relocated={len(record.differential.relocated)}")
        if v:
            print(f"oracle_classification: {v.classification.value}")
            print(f"oracle_confidence: {v.confidence.value}")
            print(f"oracle_reasons: {v.reasons}")


if __name__ == "__main__":
    main()
