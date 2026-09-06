"""Priority 6: the first genuinely cross-vendor experiment.

Every prior repair in this project's dataset came from Anthropic (Claude
Sonnet 5 or Haiku 4.5) -- disclosed honestly at every point as same-vendor,
not independent-source evidence (see Phase 3's session record and
scripts/run_phase3_alternate_model_experiment.py's own docstring). This
script uses Google's Gemini API (a genuinely different lab, different
model family, different training) as the repair-generating model, holding
everything else constant:

- SAME three vulnerable fixtures as Phase 2/3's cases A, B, E
  (fixtures/terraform/phase2_case_{a,b,e}_*).
- SAME prompt text, byte-for-byte, as those same cases.
- SAME evaluation environment: experiments.pipeline.evaluate_repair (the
  canonical, real pipeline consolidated in Phase 6) -- real Checkov scans,
  real Terraform plans via the provider filesystem mirror, the real
  invariant, the real oracle, the real scanner-only baseline.
- DIFFERENT generating model: gemini-3.6-flash via a direct, real API call
  (see /tmp scratch call script referenced in the session record; raw
  responses saved to the paths below exactly as returned, before this
  script ever ran).

A small, deliberate pilot (3 cases, not a full re-run of the whole corpus)
-- exactly the scope Priority 6 asked for. Case selection mirrors Phase
3's own choice of a representative subset: A (single-vector, positive
control), B (context-limited, the case that produced the project's first
real PARTIAL_FIX under a different model), E (the policy-only,
idiomatic-.arn shape that's architecturally forced to stay INCONCLUSIVE
regardless of model).
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from terraveritas.experiments.extraction import extract_terraform  # noqa: E402
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

AI_MODEL_LABEL = "gemini-3.6-flash (Google, direct API call) -- genuinely independent vendor"
MODEL_VERSION = "gemini-3.6-flash"

# Identical to Phase 2/3's case_b merge block -- the untouched policy
# resource text the model was never shown.
_CASE_B_UNTOUCHED_POLICY = '''
resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::terraveritas-phase2b-bucket/*"
      }
    ]
  })
}
'''


def _case_b_after_tf(raw_response: str) -> str:
    extracted = extract_terraform(raw_response)
    return extracted + "\n" + _CASE_B_UNTOUCHED_POLICY


CASES = [
    {
        "case_id_label": "cross_vendor_case_a_genuine_fix",
        "fixture": "phase2_case_a_genuine_fix",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        "raw_response_file": SCRATCH / "gemini_case_a_raw.txt",
        "after_tf_builder": None,
    },
    {
        "case_id_label": "cross_vendor_case_b_partial_fix",
        "fixture": "phase2_case_b_partial_fix",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        "raw_response_file": SCRATCH / "gemini_case_b_raw.txt",
        "after_tf_builder": _case_b_after_tf,
    },
    {
        "case_id_label": "cross_vendor_case_e_inconclusive",
        "fixture": "phase2_case_e_inconclusive",
        "rule_id": "CKV_AWS_70",
        "rule_description": "Ensure S3 bucket does not allow an action with any Principal",
        "raw_response_file": SCRATCH / "gemini_case_e_raw.txt",
        "after_tf_builder": None,
    },
]


def main() -> None:
    experiment_id = make_experiment_id("cross-vendor-pilot-gemini")
    environment = capture_environment()
    scanner = CheckovAdapter()
    planner = TerraformPlanner(filesystem_mirror_dir=MIRROR_DIR)

    records = []
    for case in CASES:
        print(f"\n{'=' * 70}\n{case['case_id_label']}\n{'=' * 70}")

        original_tf = (FIXTURES / case["fixture"] / "main.tf").read_text()
        generated_at = datetime.now(UTC)
        raw_response = case["raw_response_file"].read_text()
        extracted_override = None
        if case["after_tf_builder"] is not None:
            extracted_override = case["after_tf_builder"](raw_response)

        evaluation = evaluate_repair(
            original_tf=original_tf,
            raw_ai_output=raw_response,
            rule_id=case["rule_id"],
            planner=planner,
            scanner=scanner,
            extracted_tf_override=extracted_override,
        )

        err = evaluation.after_plan.error_message
        after_plan_error = f" ({err})" if err else ""
        print(f"before_plan: {evaluation.before_plan.status.value}")
        print(f"after_plan:  {evaluation.after_plan.status.value}{after_plan_error}")
        print(
            f"before_invariant: {evaluation.before_invariant.status.value} "
            f"{evaluation.before_invariant.violated_conditions}"
        )
        print(
            f"after_invariant:  {evaluation.after_invariant.status.value} "
            f"{evaluation.after_invariant.violated_conditions} | "
            f"{evaluation.after_invariant.reason}"
        )
        print(
            f"ORACLE VERDICT: {evaluation.oracle_verdict.classification.value} "
            f"(confidence={evaluation.oracle_verdict.confidence.value})"
        )
        print(f"reasons: {evaluation.oracle_verdict.reasons}")
        print(
            f"SCANNER-ONLY BASELINE: narrow={evaluation.scanner_baseline.narrow_conclusion.value} "
            f"broad={evaluation.scanner_baseline.broad_conclusion.value}"
        )

        record = RepairRecord(
            experiment_id=experiment_id,
            case_id=make_case_id(case["case_id_label"], 0),
            generated_at=generated_at,
            original_terraform=original_tf,
            original_terraform_sha256=content_hash(original_tf),
            original_security_issue_rule_id=case["rule_id"],
            original_security_issue_description=case["rule_description"],
            vulnerability_class="S3_PUBLIC_ACCESS_EXPOSURE",
            ai_model=AI_MODEL_LABEL,
            model_version=MODEL_VERSION,
            prompt_template_id="phase2_negative_case_v1",
            rendered_prompt=(
                f"check: {case['rule_id']} ({case['rule_description']})\n"
                f"[see fixtures/terraform/{case['fixture']}/main.tf for full prompt content -- "
                "identical prompt text to the corresponding Phase 2/3 case]"
            ),
            system_configuration=SystemConfiguration(
                temperature=None,
                other_parameters={
                    "invocation": "direct REST API call to "
                    "generativelanguage.googleapis.com, no tools, no system "
                    "prompt beyond the rendered prompt itself, blind to this "
                    "project's research purpose, oracle, or evaluation criteria",
                    "multi_vendor": True,
                    "note": "Google (Gemini), not Anthropic -- the first genuinely "
                    "independent-vendor repair source in this project's dataset.",
                },
            ),
            raw_ai_output=raw_response,
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
