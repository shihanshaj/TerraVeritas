"""Phase 2 experiment corpus: one real, genuinely blind AI-generated repair
per meaningful oracle outcome (TRUE_FIX, PARTIAL_FIX, DECEPTIVE_FIX,
REGRESSION, INCONCLUSIVE).

Uses the complete, real, unmodified TerraVeritas pipeline: real Checkov
before/after scans, real differential comparison, a real `terraform plan`
via the provider filesystem mirror, real invariant evaluation (including the
Phase 1 policy-unresolved partial-evaluation fix), and a real oracle
classification. All five repairs were produced by genuinely blind Agent-tool
subagent invocations (subagent_type=general-purpose, no tools, no awareness
of TerraVeritas, the oracle, or this experiment's purpose) and saved to the
paths below exactly as received before this script ever ran. This script
does not know in advance what classification each case will reach.

Case-specific design notes (each is a deliberate, disclosed methodological
choice, not a manipulation of any model's answer):

- case_a: single-vector public ACL, whole file shown, one Checkov finding
  named. Positive control for TRUE_FIX.
- case_b: the SAME two-vector (ACL + hardcoded-ARN policy) shape used in
  the prior negative-case pilot, but this time the model is shown ONLY the
  bucket+ACL resources -- the pre-existing public bucket policy elsewhere in
  the same real module is withheld from its context entirely. This
  simulates a common real-world remediation pattern (a bot that resolves
  one flagged resource without full-repository visibility) and is a
  legitimate, disclosed experimental condition: the two prior good-faith,
  whole-file attempts to elicit a PARTIAL_FIX both resulted in the model
  proactively fixing an unmentioned second vector it could see. This
  case removes that confound by construction, not by asking the model to
  do a worse job. The model's returned bucket+ACL blocks are mechanically
  reassembled (by this script, not the model) with the ORIGINAL, untouched
  policy resource text to form the "after" Terraform file.
- case_c: maximally scanner-clean before-state (versioning, KMS encryption,
  lifecycle, logging, event notifications, cross-region replication all
  satisfied) specifically to give the oracle's resource-wide DECEPTIVE_FIX
  signal (`_scanner_shows_improvement`, which requires the ENTIRE resource's
  Checkov evidence to go clean) a real chance. A static-analysis finding
  from this session's own audit is reported alongside the real run whether
  or not it manifests: Checkov attributes CKV_AWS_70 findings to the POLICY
  resource's own address (`aws_s3_bucket_policy.data`), not the bucket's,
  because `S3AllowsAnyPrincipal` is a `BaseResourceCheck` (not a graph
  check) with `supported_resources=['aws_s3_bucket','aws_s3_bucket_policy']`
  -- while every script in this project (including this one) evaluates the
  invariant, and scopes the differential-improvement check, against the
  BUCKET's own address. If confirmed, this is a structural reason
  DECEPTIVE_FIX cannot fire for a policy-only finding in this pipeline,
  independent of the repair's actual quality.
- case_d: an already-secure bucket given a genuine, unrelated feature
  request (a scoped cross-account read grant) with no security finding
  named at all. Tests whether a legitimate change can regress the
  invariant as a side effect, without instructing the model toward any
  particular mistake.
- case_e: the exact policy-only, idiomatic-`.arn`-reference shape that
  Phase 1 confirmed has no independent rescue evidence (no ACL resource at
  all). Expected, not forced, to remain INCONCLUSIVE regardless of the
  repair's quality -- this is the intended demonstration of category E.
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

# The untouched policy resource text for case_b -- identical to the block in
# fixtures/terraform/phase2_case_b_partial_fix/main.tf, reattached mechanically
# after extraction since the model was never shown it.
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
        "case_id_label": "phase2_case_a_genuine_fix",
        "fixture": "phase2_case_a_genuine_fix",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        "raw_response_file": SCRATCH / "phase2_case_a_raw.txt",
        "hypothesis": "TRUE_FIX (positive control, single vector)",
        "after_tf_builder": None,
    },
    {
        "case_id_label": "phase2_case_b_partial_fix",
        "fixture": "phase2_case_b_partial_fix",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        "raw_response_file": SCRATCH / "phase2_case_b_raw.txt",
        "hypothesis": "PARTIAL_FIX (context-limited: policy vector withheld from the model)",
        "after_tf_builder": _case_b_after_tf,
    },
    {
        "case_id_label": "phase2_case_c_deceptive_attempt",
        "fixture": "phase2_case_c_deceptive_attempt",
        "rule_id": "CKV_AWS_70",
        "rule_description": "Ensure S3 bucket does not allow an action with any Principal",
        "raw_response_file": SCRATCH / "phase2_case_c_raw.txt",
        "hypothesis": "DECEPTIVE_FIX attempt -- see module docstring for the "
        "resource-identity finding this case is also expected to surface",
        "after_tf_builder": None,
    },
    {
        "case_id_label": "phase2_case_d_regression_attempt",
        "fixture": "phase2_case_d_regression_attempt",
        "rule_id": None,
        "rule_description": "N/A -- unrelated feature request (scoped cross-account "
        "read grant), not a reported security finding",
        "raw_response_file": SCRATCH / "phase2_case_d_raw.txt",
        "hypothesis": "REGRESSION if the grant is broader than scoped, else INCONCLUSIVE "
        "('nothing to fix') or a newly-surfaced evaluation gap",
        "after_tf_builder": None,
    },
    {
        "case_id_label": "phase2_case_e_inconclusive",
        "fixture": "phase2_case_e_inconclusive",
        "rule_id": "CKV_AWS_70",
        "rule_description": "Ensure S3 bucket does not allow an action with any Principal",
        "raw_response_file": SCRATCH / "phase2_case_e_raw.txt",
        "hypothesis": "INCONCLUSIVE (no ACL to rescue an unresolved before-state policy)",
        "after_tf_builder": None,
    },
]


def _scan(tf_content: str, adapter: CheckovAdapter):
    with tempfile.TemporaryDirectory() as tmp:
        tf_dir = Path(tmp)
        (tf_dir / "main.tf").write_text(tf_content)
        return adapter.scan(tf_dir, timeout_seconds=60)


def main() -> None:
    experiment_id = make_experiment_id("phase2-negative-case-experiment")
    environment = capture_environment()
    adapter = CheckovAdapter()
    planner = TerraformPlanner(filesystem_mirror_dir=MIRROR_DIR)

    records = []
    for case in CASES:
        print(
            f"\n{'=' * 70}\n{case['case_id_label']}\n"
            f"hypothesis: {case['hypothesis']}\n{'=' * 70}"
        )

        original_tf = (FIXTURES / case["fixture"] / "main.tf").read_text()
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
        if differential.new:
            print(f"  new rule_ids: {sorted({n.after.rule_id for n in differential.new})}")

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
        print(f"remaining_uncertainty: {verdict.remaining_uncertainty}")

        record = RepairRecord(
            experiment_id=experiment_id,
            case_id=make_case_id(case["case_id_label"], 0),
            generated_at=datetime.now(UTC),
            original_terraform=original_tf,
            original_terraform_sha256=content_hash(original_tf),
            original_security_issue_rule_id=case["rule_id"] or "N/A",
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
                    "hypothesis": case["hypothesis"],
                    "context_limited": case["after_tf_builder"] is not None,
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
