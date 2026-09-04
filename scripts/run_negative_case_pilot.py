"""The negative-case AI-repair pilot experiment.

Companion to run_real_ai_pilot.py, with the opposite goal: that experiment's
three cases all happened to resolve toward TRUE_FIX or INCONCLUSIVE. This
experiment exists because an independent audit found that the oracle's
DECEPTIVE_FIX, PARTIAL_FIX, and REGRESSION branches had never fired on real
data — only on synthetic evidence in unit tests. Each case here was designed,
from a direct reading of this project's own invariant/oracle source and of
Checkov's actual check implementations (not guessed), to give one of those
branches a real, fair chance to fire:

- negcase1: two independent public-access vectors (ACL + a hardcoded-ARN
  bucket policy) on one resource, but the AI is shown only the ACL finding.
  Tests whether scanner-driven, single-finding remediation leaves a partial
  fix.
- negcase2: a public bucket policy (Principal "*"), told only about the
  Checkov finding for it (CKV_AWS_70). Checkov's own S3AllowsAnyPrincipal
  check (read directly from its installed source in this project's .venv)
  passes a `Principal: "*"` statement whenever a Condition block references
  certain keys (e.g. aws:PrincipalArn/aws:SourceArn under ArnLike) without
  verifying the referenced value is actually narrow -- a real, verified gap
  a plausible AI fix could satisfy without truly closing the exposure. This
  case's before-fixture also satisfies as many other default Checkov S3
  checks as practical (versioning, encryption, lifecycle, logging) to give
  the oracle's resource-wide DECEPTIVE_FIX signal (which requires the whole
  resource's scanner evidence to go clean, not just the one named rule) a
  realistic chance -- two checks (event notifications, cross-region
  replication) could not be satisfied without unrelated supporting
  infrastructure and are expected to remain persistent regardless of the
  repair's quality; this is disclosed, not hidden, and is itself a finding
  about the practical reachability of DECEPTIVE_FIX via Checkov's default
  ruleset.
- negcase3: an already-secure bucket, given an unrelated feature request
  (add a lifecycle expiration rule) with no mention of security at all.
  Tests whether an AI making an unrelated change can regress the invariant
  as a side effect.

Uses the complete, real, unmodified TerraVeritas pipeline: real Checkov
before/after scans, real differential comparison, a real `terraform plan`
via the provider filesystem mirror, real invariant evaluation, and a real
oracle classification. No synthetic PlanResult objects, no self-authored
repairs, no manual editing of model output. The three repairs were produced
by genuinely blind Agent-tool subagent invocations (subagent_type=
general-purpose, no tools, no awareness of TerraVeritas, the oracle, or this
experiment's purpose -- shown only a Terraform file and either one Checkov
finding or an unrelated feature request) and saved to the paths below
exactly as received before this script ever ran.

This script does not know in advance what classification each case will
reach, and does not manipulate the pipeline to favor any particular outcome.
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

CASES = [
    {
        "case_id_label": "negcase1_partial_two_vectors",
        "fixture": "negative_case_1_partial_two_vectors",
        "rule_id": "CKV_AWS_20",
        "rule_description": "S3 Bucket has an ACL defined which allows public READ access.",
        "raw_response_file": SCRATCH / "negcase1_raw_response.txt",
        "hypothesis": "PARTIAL_FIX (told about ACL vector only; policy vector untouched)",
    },
    {
        "case_id_label": "negcase2_deceptive_principal_condition",
        "fixture": "negative_case_2_deceptive_principal_condition",
        "rule_id": "CKV_AWS_70",
        "rule_description": "Ensure S3 bucket does not allow an action with any Principal",
        "raw_response_file": SCRATCH / "negcase2_raw_response.txt",
        "hypothesis": "DECEPTIVE_FIX (Checkov Principal-condition check vs. invariant logic)",
    },
    {
        "case_id_label": "negcase3_regression_unrelated_change",
        "fixture": "negative_case_3_regression_unrelated_change",
        "rule_id": None,
        "rule_description": "N/A -- unrelated feature request (add 90-day expiration), "
        "not a reported security finding",
        "raw_response_file": SCRATCH / "negcase3_raw_response.txt",
        "hypothesis": "REGRESSION if the unrelated change disturbs ACL/BPA, else INCONCLUSIVE",
    },
]


def _scan(tf_content: str, adapter: CheckovAdapter):
    with tempfile.TemporaryDirectory() as tmp:
        tf_dir = Path(tmp)
        (tf_dir / "main.tf").write_text(tf_content)
        return adapter.scan(tf_dir, timeout_seconds=60)


def main() -> None:
    experiment_id = make_experiment_id("negative-case-pilot-s3exposure")
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
        if differential.persistent:
            print(
                "  persistent rule_ids: "
                f"{sorted({p.before.rule_id for p in differential.persistent})}"
            )

        with tempfile.TemporaryDirectory() as tmp_before:
            (Path(tmp_before) / "main.tf").write_text(original_tf)
            before_plan = planner.plan(Path(tmp_before), timeout_seconds=60)
        print(f"before_plan: {before_plan.status.value}")

        with tempfile.TemporaryDirectory() as tmp_after:
            (Path(tmp_after) / "main.tf").write_text(extracted_tf)
            after_plan = planner.plan(Path(tmp_after), timeout_seconds=60)
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
            prompt_template_id="negative_case_probe_v1",
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
