"""The canonical experiment-execution script, built on
experiments.pipeline.evaluate_repair.

Implements, for every case, exactly the sequence Phase 6 of this project's
development specifies:

  1. Preserve the original vulnerable Terraform (fixtures/terraform/*).
  2. Run the real scanner before repair.
  3. Generate the real AI repair (a genuinely blind Agent-tool subagent
     invocation -- done OUTSIDE this script; see CASES below for how the
     raw response arrives).
  4. Preserve raw model output.
  5. Extract the Terraform repair mechanically.
  6. Run the scanner after repair.
  7. Generate a real Terraform plan for both configurations.
  8. Run the invariant.
  9. Run the differential analysis.
  10. Run the oracle.
  11. Record the scanner-only baseline.
  12. Persist all evidence.

Steps 2 and 5-11 are one call to experiments.pipeline.evaluate_repair --
see that module for why four earlier scripts had drifted into duplicating
this sequence by hand. No synthetic PlanResult or ScanResult is used
anywhere in this script; every plan and scan is real.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from terraveritas.experiments.identifiers import (  # noqa: E402
    content_hash,
    make_case_id,
    make_experiment_id,
)
from terraveritas.experiments.pipeline import evaluate_repair  # noqa: E402
from terraveritas.experiments.reproducibility import capture_environment  # noqa: E402
from terraveritas.experiments.storage import save_manifest, save_record  # noqa: E402
from terraveritas.models.experiment import RepairRecord, SystemConfiguration  # noqa: E402
from terraveritas.scanners.checkov import CheckovAdapter  # noqa: E402
from terraveritas.terraform.plan import TerraformPlanner  # noqa: E402

FIXTURES = REPO_ROOT / "fixtures" / "terraform"
DATASETS = REPO_ROOT / "datasets" / "experiments"
MIRROR_DIR = REPO_ROOT / ".terraform-mirror"
SCRATCH = Path(
    "/private/tmp/claude-501/-Users-shihanshaj-Desktop-Test/"
    "11641d1f-d8e1-4499-8b3d-035a3c5133c0/scratchpad"
)

CASES = [
    {
        "case_id_label": "phase6_case_a_genuine_fix",
        "fixture": "phase2_case_a_genuine_fix",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        # Genuinely fresh blind Agent-tool subagent invocation (subagent_type=
        # general-purpose, no tools, no awareness of TerraVeritas or this
        # script), same prompt template as every prior real experiment --
        # saved to this file exactly as returned, before this script ran.
        "raw_response_file": SCRATCH / "phase6_case_a_raw.txt",
    },
]


def main() -> None:
    experiment_id = make_experiment_id("phase6-canonical-pipeline")
    environment = capture_environment()
    scanner = CheckovAdapter()
    planner = TerraformPlanner(filesystem_mirror_dir=MIRROR_DIR)

    records = []
    for case in CASES:
        print(f"\n{'=' * 70}\n{case['case_id_label']}\n{'=' * 70}")
        original_tf = (FIXTURES / case["fixture"] / "main.tf").read_text()
        raw_ai_output = case["raw_response_file"].read_text()

        evaluation = evaluate_repair(
            original_tf=original_tf,
            raw_ai_output=raw_ai_output,
            rule_id=case["rule_id"],
            planner=planner,
            scanner=scanner,
        )

        print(f"before_plan: {evaluation.before_plan.status.value}")
        print(f"after_plan:  {evaluation.after_plan.status.value}")
        print(
            f"before_invariant: {evaluation.before_invariant.status.value} "
            f"{evaluation.before_invariant.violated_conditions}"
        )
        print(
            f"after_invariant:  {evaluation.after_invariant.status.value} "
            f"{evaluation.after_invariant.violated_conditions}"
        )
        print(
            f"ORACLE VERDICT: {evaluation.oracle_verdict.classification.value} "
            f"(confidence={evaluation.oracle_verdict.confidence.value})"
        )
        print(
            f"SCANNER-ONLY BASELINE: narrow={evaluation.scanner_baseline.narrow_conclusion.value} "
            f"broad={evaluation.scanner_baseline.broad_conclusion.value}"
        )

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
            prompt_template_id="phase2_negative_case_v1",
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
                    "pipeline": "experiments.pipeline.evaluate_repair (canonical, "
                    "consolidated -- see scripts/run_experiment.py)",
                },
            ),
            raw_ai_output=raw_ai_output,
            extracted_terraform=evaluation.extracted_terraform,
            before_scan=evaluation.before_scan,
            after_scan=evaluation.after_scan,
            differential=evaluation.differential,
            before_plan_status=evaluation.before_plan.status,
            after_plan_status=evaluation.after_plan.status,
            oracle_verdict=evaluation.oracle_verdict,
            human_label=None,
            environment=environment,
            before_plan=evaluation.before_plan,
            after_plan=evaluation.after_plan,
            before_invariant=evaluation.before_invariant,
            after_invariant=evaluation.after_invariant,
            scanner_baseline=evaluation.scanner_baseline,
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
