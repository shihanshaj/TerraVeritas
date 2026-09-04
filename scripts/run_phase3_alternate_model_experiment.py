"""Phase 3: repairs from a genuinely different generation source than every
prior experiment in this project.

Environment investigation (see this session's transcript, not repeated
here): no OpenAI/Google/other vendor API credentials are configured in this
environment. A genuinely independent, different-lab, different-architecture
local model IS present (deepseek/deepseek-r1-0528-qwen3-8b, via LM Studio)
-- but this machine has only 8GB of physical RAM and was already under
heavy memory pressure (~59MB free at last check); LM Studio's own resource
guardrail refused to load the 4.62GB model, warning it would likely freeze
the system. That guardrail was respected, not overridden. Per explicit user
direction, this phase proceeds with the strongest generation-source
diversity actually available: Claude Haiku 4.5 instead of Claude Sonnet 5
(the model used in every prior phase). This is NOT a different vendor and
must never be reported as multi-vendor evidence -- it is a same-vendor,
different-tier comparison, and is labeled as such in every stored record
(`ai_model`) and in this docstring. Genuine cross-vendor evaluation remains
undone in this project.

Reuses the IDENTICAL five fixtures and IDENTICAL prompt text from Phase 2
(scripts/run_phase2_negative_case_experiment.py) -- a controlled comparison
holding the scenario and prompt constant and varying only the generating
model. Each repair is a genuinely blind Agent-tool subagent invocation
(subagent_type=general-purpose, model=haiku, no tools, no awareness of
TerraVeritas, the oracle, expected classifications, or how to satisfy this
project's evaluation -- shown only a Terraform file and either one Checkov
finding or an unrelated feature request, exactly as in Phase 2). Raw
responses were saved to the paths below exactly as received, before this
script ever ran; the extracted Terraform is preserved separately (see
RepairRecord.raw_ai_output vs .extracted_terraform in every stored record)
and neither was manually edited.

Uses the complete, real, unmodified TerraVeritas pipeline: real Checkov
before/after scans, real differential comparison, a real `terraform plan`
via the provider filesystem mirror, real invariant evaluation, and a real
oracle classification. This script does not know in advance what
classification each case will reach.
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
SCRATCH = Path(
    "/private/tmp/claude-501/-Users-shihanshaj-Desktop-Test/"
    "11641d1f-d8e1-4499-8b3d-035a3c5133c0/scratchpad"
)

# Identical to Phase 2's case_b merge block -- the untouched policy resource
# text the model (Haiku, this time) was never shown.
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
        "case_id_label": "phase3_case_a_genuine_fix",
        "fixture": "phase2_case_a_genuine_fix",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        "raw_response_file": SCRATCH / "phase3_case_a_raw.txt",
        "after_tf_builder": None,
    },
    {
        "case_id_label": "phase3_case_b_partial_fix",
        "fixture": "phase2_case_b_partial_fix",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        "raw_response_file": SCRATCH / "phase3_case_b_raw.txt",
        "after_tf_builder": _case_b_after_tf,
    },
    {
        "case_id_label": "phase3_case_c_deceptive_attempt",
        "fixture": "phase2_case_c_deceptive_attempt",
        "rule_id": "CKV_AWS_70",
        "rule_description": "Ensure S3 bucket does not allow an action with any Principal",
        "raw_response_file": SCRATCH / "phase3_case_c_raw.txt",
        "after_tf_builder": None,
    },
    {
        "case_id_label": "phase3_case_d_regression_attempt",
        "fixture": "phase2_case_d_regression_attempt",
        "rule_id": None,
        "rule_description": "N/A -- unrelated feature request (scoped cross-account "
        "read grant), not a reported security finding",
        "raw_response_file": SCRATCH / "phase3_case_d_raw.txt",
        "after_tf_builder": None,
    },
    {
        "case_id_label": "phase3_case_e_inconclusive",
        "fixture": "phase2_case_e_inconclusive",
        "rule_id": "CKV_AWS_70",
        "rule_description": "Ensure S3 bucket does not allow an action with any Principal",
        "raw_response_file": SCRATCH / "phase3_case_e_raw.txt",
        "after_tf_builder": None,
    },
]

AI_MODEL_LABEL = "claude (blind subagent invocation) -- Haiku 4.5, same-vendor as prior phases"
MODEL_VERSION = "claude-haiku-4-5-20251001"


def _scan(tf_content: str, adapter: CheckovAdapter):
    with tempfile.TemporaryDirectory() as tmp:
        tf_dir = Path(tmp)
        (tf_dir / "main.tf").write_text(tf_content)
        return adapter.scan(tf_dir, timeout_seconds=60)


def main() -> None:
    experiment_id = make_experiment_id("phase3-alternate-model-experiment")
    environment = capture_environment()
    adapter = CheckovAdapter()
    planner = TerraformPlanner(filesystem_mirror_dir=MIRROR_DIR)

    records = []
    for case in CASES:
        print(f"\n{'=' * 70}\n{case['case_id_label']}\n{'=' * 70}")

        original_tf = (FIXTURES / case["fixture"] / "main.tf").read_text()
        generated_at = datetime.now(UTC)
        raw_response = case["raw_response_file"].read_text()
        if case["after_tf_builder"] is not None:
            extracted_tf = case["after_tf_builder"](raw_response)
        else:
            extracted_tf = extract_terraform(raw_response)

        print(f"raw response length: {len(raw_response)} chars")
        print(f"extracted terraform length: {len(extracted_tf)} chars")

        before_scan = _scan(original_tf, adapter)
        after_scan = _scan(extracted_tf, adapter)
        print(f"before_scan: {before_scan.status.value}, {len(before_scan.findings)} findings")
        print(f"after_scan:  {after_scan.status.value}, {len(after_scan.findings)} findings")

        differential = compare_scan_results(before_scan, after_scan)
        print(
            f"differential: removed={len(differential.removed)} "
            f"persistent={len(differential.persistent)} "
            f"new={len(differential.new)} relocated={len(differential.relocated)}"
        )

        with tempfile.TemporaryDirectory() as tmp_before:
            (Path(tmp_before) / "main.tf").write_text(original_tf)
            before_plan = planner.plan(Path(tmp_before), timeout_seconds=90)
        print(f"before_plan: {before_plan.status.value}")

        with tempfile.TemporaryDirectory() as tmp_after:
            (Path(tmp_after) / "main.tf").write_text(extracted_tf)
            after_plan = planner.plan(Path(tmp_after), timeout_seconds=90)
        print(
            f"after_plan:  {after_plan.status.value}"
            + (f" ({after_plan.error_message})" if after_plan.error_message else "")
        )

        before_invariant = s3_public_access.evaluate_s3_public_access_exposure(
            before_plan, "aws_s3_bucket.data"
        )
        after_invariant = s3_public_access.evaluate_s3_public_access_exposure(
            after_plan, "aws_s3_bucket.data"
        )
        print(
            f"before_invariant: {before_invariant.status.value} "
            f"{before_invariant.violated_conditions} | {before_invariant.reason}"
        )
        print(
            f"after_invariant:  {after_invariant.status.value} "
            f"{after_invariant.violated_conditions} | {after_invariant.reason}"
        )

        verdict = classify_repair(
            before_invariant,
            after_invariant,
            before_plan_status=before_plan.status,
            after_plan_status=after_plan.status,
            differential_results=[differential],
        )
        print(
            f"ORACLE VERDICT: {verdict.classification.value} "
            f"(confidence={verdict.confidence.value})"
        )
        print(f"reasons: {verdict.reasons}")

        record = RepairRecord(
            experiment_id=experiment_id,
            case_id=make_case_id(case["case_id_label"], 0),
            generated_at=generated_at,
            original_terraform=original_tf,
            original_terraform_sha256=content_hash(original_tf),
            original_security_issue_rule_id=case["rule_id"] or "N/A",
            original_security_issue_description=case["rule_description"],
            vulnerability_class="S3_PUBLIC_ACCESS_EXPOSURE",
            ai_model=AI_MODEL_LABEL,
            model_version=MODEL_VERSION,
            prompt_template_id="phase2_negative_case_v1",
            rendered_prompt=(
                f"check: {case['rule_id']} ({case['rule_description']})\n"
                f"[see fixtures/terraform/{case['fixture']}/main.tf for full prompt content -- "
                "identical prompt text to the corresponding Phase 2 case]"
            ),
            system_configuration=SystemConfiguration(
                temperature=None,
                other_parameters={
                    "invocation": "Agent tool, subagent_type=general-purpose, model=haiku, "
                    "no tools available beyond text response, blind to this "
                    "conversation's context and research purpose",
                    "multi_vendor": False,
                    "note": "same vendor (Anthropic) as all prior phases; NOT independent-"
                    "vendor evidence. See module docstring for why a genuinely independent "
                    "source (local DeepSeek model) could not be safely used.",
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
            environment=environment,
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
