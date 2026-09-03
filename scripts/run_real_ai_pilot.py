"""The first real AI-repair pilot experiment.

Processes genuinely AI-generated repairs (from blind, isolated subagent
invocations — see the pilot report for exactly how, and its honest scope
disclosure) through the complete, real, unmodified TerraVeritas pipeline:
real Checkov before/after scans, real differential comparison, a real
`terraform plan` via the provider filesystem mirror, real invariant
evaluation, and a real oracle classification. No synthetic PlanResult
objects, no self-authored repairs, no manual editing of model output.

Run after the three subagent responses have been saved to
/tmp/pilot_raw_response_case_{1,2,3}.txt (exactly as received).
"""

from __future__ import annotations

import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from terraveritas.differential.scanner_diff import compare_scan_results  # noqa: E402
from terraveritas.experiments.extraction import extract_terraform  # noqa: E402
from terraveritas.experiments.identifiers import (  # noqa: E402
    content_hash,
    make_case_id,
    make_experiment_id,
)
from terraveritas.experiments.reproducibility import capture_environment  # noqa: E402
from terraveritas.experiments.storage import save_manifest, save_record  # noqa: E402
from terraveritas.invariants import s3_public_access  # noqa: E402
from terraveritas.models.experiment import RepairRecord, SystemConfiguration  # noqa: E402
from terraveritas.scanners.checkov import CheckovAdapter  # noqa: E402
from terraveritas.terraform.plan import TerraformPlanner  # noqa: E402
from terraveritas.verification.oracle import classify_repair  # noqa: E402

FIXTURES = REPO_ROOT / "fixtures" / "terraform"
DATASETS = REPO_ROOT / "datasets" / "experiments"
MIRROR_DIR = REPO_ROOT / ".terraform-mirror"

CASES = [
    {
        "case_id_label": "case1_acl_only",
        "fixture": "pilot_case_1_acl_only",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        "raw_response_file": "/tmp/pilot_raw_response_case_1.txt",
        "classifier_warning": None,
    },
    {
        "case_id_label": "case2_policy_only",
        "fixture": "pilot_case_2_policy_only",
        "rule_id": "CKV_AWS_70",
        "rule_description": "Ensure S3 bucket does not allow an action with any Principal",
        "raw_response_file": "/tmp/pilot_raw_response_case_2.txt",
        "classifier_warning": None,
    },
    {
        "case_id_label": "case3_acl_and_policy",
        "fixture": "pilot_case_3_acl_and_policy",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        "raw_response_file": "/tmp/pilot_raw_response_case_3.txt",
        "classifier_warning": "SECURITY WARNING: Blocked by classifier (tool_uses=0; see report)",
    },
]


def _scan(tf_content: str, adapter: CheckovAdapter):
    with tempfile.TemporaryDirectory() as tmp:
        tf_dir = Path(tmp)
        (tf_dir / "main.tf").write_text(tf_content)
        return adapter.scan(tf_dir, timeout_seconds=60)


def main() -> None:
    experiment_id = make_experiment_id("real-ai-pilot-s3exposure")
    environment = capture_environment()
    adapter = CheckovAdapter()
    planner = TerraformPlanner(filesystem_mirror_dir=MIRROR_DIR)

    records = []
    for case in CASES:
        print(f"\n{'=' * 60}\n{case['case_id_label']}\n{'=' * 60}")

        original_tf = (FIXTURES / case["fixture"] / "main.tf").read_text()
        raw_response = Path(case["raw_response_file"]).read_text()
        extracted_tf = extract_terraform(raw_response)

        print(f"raw response length: {len(raw_response)} chars")
        print(f"extracted terraform length: {len(extracted_tf)} chars")
        if case["classifier_warning"]:
            print(f"⚠️  ANOMALY: {case['classifier_warning']}")

        before_scan = _scan(original_tf, adapter)
        after_scan = _scan(extracted_tf, adapter)
        print(f"before_scan: {before_scan.status.value}, "
              f"{len(before_scan.findings)} findings")
        print(f"after_scan:  {after_scan.status.value}, "
              f"{len(after_scan.findings)} findings")

        differential = compare_scan_results(before_scan, after_scan)
        print(f"differential: removed={len(differential.removed)} "
              f"persistent={len(differential.persistent)} "
              f"new={len(differential.new)} relocated={len(differential.relocated)}")

        with tempfile.TemporaryDirectory() as tmp_before:
            (Path(tmp_before) / "main.tf").write_text(original_tf)
            before_plan = planner.plan(Path(tmp_before), timeout_seconds=60)
        print(f"before_plan: {before_plan.status.value}")

        with tempfile.TemporaryDirectory() as tmp_after:
            (Path(tmp_after) / "main.tf").write_text(extracted_tf)
            after_plan = planner.plan(Path(tmp_after), timeout_seconds=60)
        print(f"after_plan:  {after_plan.status.value}"
              + (f" ({after_plan.error_message})" if after_plan.error_message else ""))

        before_invariant = s3_public_access.evaluate_s3_public_access_exposure(
            before_plan, "aws_s3_bucket.data"
        )
        after_invariant = s3_public_access.evaluate_s3_public_access_exposure(
            after_plan, "aws_s3_bucket.data"
        )
        print(f"before_invariant: {before_invariant.status.value} "
              f"{before_invariant.violated_conditions}")
        print(f"after_invariant:  {after_invariant.status.value} "
              f"{after_invariant.violated_conditions}")

        verdict = classify_repair(
            before_invariant,
            after_invariant,
            before_plan_status=before_plan.status,
            after_plan_status=after_plan.status,
            differential_results=[differential],
        )
        print(f"ORACLE VERDICT: {verdict.classification.value} "
              f"(confidence={verdict.confidence.value})")
        print(f"reasons: {verdict.reasons}")

        case_environment = dict(environment)
        if case["classifier_warning"]:
            case_environment["anomaly"] = case["classifier_warning"]

        record = RepairRecord(
            experiment_id=experiment_id,
            case_id=make_case_id(case["case_id_label"], 0),
            generated_at=datetime.now(UTC),
            original_terraform=original_tf,
            original_terraform_sha256=content_hash(original_tf),
            original_security_issue_rule_id=case["rule_id"],
            original_security_issue_description=case["rule_description"],
            vulnerability_class="S3_PUBLIC_ACCESS_EXPOSURE",
            ai_model="claude (blind subagent invocation)",
            model_version="claude-sonnet-5",
            prompt_template_id="minimal_v1",
            rendered_prompt=(
                f"check: {case['rule_id']} ({case['rule_description']})\n"
                f"[see fixtures/terraform/{case['fixture']}/main.tf for full prompt content]"
            ),
            system_configuration=SystemConfiguration(
                temperature=None,
                other_parameters={
                    "invocation": "Agent tool, subagent_type=general-purpose, "
                    "no tools available beyond text response, blind to this "
                    "conversation's context and research purpose",
                },
            ),
            raw_ai_output=raw_response,
            extracted_terraform=extracted_tf,
            before_scan=before_scan,
            after_scan=after_scan,
            differential=differential,
            before_plan_status=before_plan.status,
            after_plan_status=after_plan.status,
            oracle_verdict=verdict,
            human_label=None,
            environment=case_environment,
            before_plan=before_plan,
            after_plan=after_plan,
            before_invariant=before_invariant,
            after_invariant=after_invariant,
        )
        save_record(record, base_dir=DATASETS)
        records.append(record)

    save_manifest(
        experiment_id,
        base_dir=DATASETS,
        matrix_cells=[r.case_id for r in records],
        record_count=len(records),
    )
    print(f"\n\nAll records stored under datasets/experiments/{experiment_id}/")


if __name__ == "__main__":
    main()
