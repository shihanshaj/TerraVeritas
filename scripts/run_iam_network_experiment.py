"""The IAM/network experimental phase: does TerraVeritas generalize beyond
S3_PUBLIC_ACCESS_EXPOSURE?

Ten real, controlled vulnerable scenarios (five IAM_EXCESSIVE_PRIVILEGE_
EXPOSURE, five NETWORK_SENSITIVE_PORT_EXPOSURE -- fixtures/terraform/
{iam,net}_exp_*), each independently verified (real `terraform plan`, real
Checkov scan, real invariant evaluation) to produce its intended before-
state before any AI repair was generated -- see
docs/iam_network_experiment_report.md for that verification and for the
full experimental design.

Repairs come from two genuinely independent sources:
- Claude (Agent tool, subagent_type=general-purpose, explicitly instructed
  to use no tools and respond from the prompt text alone; blind to
  TerraVeritas, the oracle, and this experiment's purpose) -- all 10 cases.
- Gemini 3.6 Flash (Google, direct REST API call, same blind-prompt
  methodology as scripts/run_cross_vendor_pilot.py) -- a 4-case subset
  (the positive control and the partial-fix case for each invariant),
  mirroring that script's own "small deliberate pilot, not the full
  corpus" scope decision.

Every raw response was saved to disk exactly as received before this
script was written, and is read from disk here verbatim -- this script
never edits, regenerates, or cherry-picks a response.

Uses the same real evaluate_repair() pipeline as every other experiment in
this project, generalized in this same session (see
src/terraveritas/experiments/pipeline.py's `invariant_evaluator`/
`resource_address` parameters and
src/terraveritas/evaluation/scanner_baseline.py's `broad_relevant_rules`)
to support IAM and network in addition to S3.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from terraveritas.evaluation.scanner_baseline import (  # noqa: E402
    IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES,
    NETWORK_SENSITIVE_PORT_RELEVANT_RULES,
)
from terraveritas.experiments.identifiers import (  # noqa: E402
    content_hash,
    make_case_id,
    make_experiment_id,
)
from terraveritas.experiments.pipeline import evaluate_repair  # noqa: E402
from terraveritas.experiments.reproducibility import capture_environment  # noqa: E402
from terraveritas.experiments.storage import save_manifest, save_record  # noqa: E402
from terraveritas.invariants.iam_excessive_privilege import (  # noqa: E402
    evaluate_iam_excessive_privilege_exposure,
)
from terraveritas.invariants.network_exposure import (  # noqa: E402
    evaluate_network_sensitive_port_exposure,
)
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

CLAUDE_LABEL = "claude (blind subagent invocation, tool use disallowed by instruction)"
CLAUDE_VERSION = "claude-sonnet-5"
GEMINI_LABEL = "gemini-3.6-flash (Google, direct API call) -- genuinely independent vendor"
GEMINI_VERSION = "gemini-3.6-flash"

CASES = [
    # --- IAM_EXCESSIVE_PRIVILEGE_EXPOSURE ---
    {
        "case_id_label": "iam_exp_a_admin_wildcard_claude",
        "fixture": "iam_exp_a_admin_wildcard",
        "invariant_id": "IAM_EXCESSIVE_PRIVILEGE_EXPOSURE",
        "resource_address": "aws_iam_role.data",
        "invariant_evaluator": evaluate_iam_excessive_privilege_exposure,
        "broad_relevant_rules": IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES,
        "rule_id": "CKV_AWS_62",
        "rule_description": 'Ensure IAM policies that allow full "*-*" administrative '
        "privileges are not created",
        "raw_response_file": SCRATCH / "claude_iam_a_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "TRUE_FIX (positive control, single vector, single statement)",
    },
    {
        "case_id_label": "iam_exp_a_admin_wildcard_gemini",
        "fixture": "iam_exp_a_admin_wildcard",
        "invariant_id": "IAM_EXCESSIVE_PRIVILEGE_EXPOSURE",
        "resource_address": "aws_iam_role.data",
        "invariant_evaluator": evaluate_iam_excessive_privilege_exposure,
        "broad_relevant_rules": IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES,
        "rule_id": "CKV_AWS_62",
        "rule_description": 'Ensure IAM policies that allow full "*-*" administrative '
        "privileges are not created",
        "raw_response_file": SCRATCH / "gemini_iam_a_raw.txt",
        "ai_model": GEMINI_LABEL,
        "model_version": GEMINI_VERSION,
        "hypothesis": "cross-vendor replication check for the Claude positive control",
    },
    {
        "case_id_label": "iam_exp_b_multi_statement_mixed_claude",
        "fixture": "iam_exp_b_multi_statement_mixed",
        "invariant_id": "IAM_EXCESSIVE_PRIVILEGE_EXPOSURE",
        "resource_address": "aws_iam_role.data",
        "invariant_evaluator": evaluate_iam_excessive_privilege_exposure,
        "broad_relevant_rules": IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES,
        "rule_id": "CKV_AWS_62",
        "rule_description": 'Ensure IAM policies that allow full "*-*" administrative '
        "privileges are not created",
        "raw_response_file": SCRATCH / "claude_iam_b_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "TRUE_FIX if the benign ReadReportsBucket statement survives "
        "unchanged; tests statement-level discrimination within one policy",
    },
    {
        "case_id_label": "iam_exp_c_partial_fix_named_statement_claude",
        "fixture": "iam_exp_c_partial_fix_named_statement",
        "invariant_id": "IAM_EXCESSIVE_PRIVILEGE_EXPOSURE",
        "resource_address": "aws_iam_role.data",
        "invariant_evaluator": evaluate_iam_excessive_privilege_exposure,
        "broad_relevant_rules": IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES,
        "rule_id": "CKV_AWS_62",
        "rule_description": 'Ensure IAM policies that allow full "*-*" administrative '
        "privileges are not created",
        "raw_response_file": SCRATCH / "claude_iam_c_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "PARTIAL_FIX opportunity: two admin-wildcard statements in one "
        "policy, only one named in the finding",
    },
    {
        "case_id_label": "iam_exp_c_partial_fix_named_statement_gemini",
        "fixture": "iam_exp_c_partial_fix_named_statement",
        "invariant_id": "IAM_EXCESSIVE_PRIVILEGE_EXPOSURE",
        "resource_address": "aws_iam_role.data",
        "invariant_evaluator": evaluate_iam_excessive_privilege_exposure,
        "broad_relevant_rules": IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES,
        "rule_id": "CKV_AWS_62",
        "rule_description": 'Ensure IAM policies that allow full "*-*" administrative '
        "privileges are not created",
        "raw_response_file": SCRATCH / "gemini_iam_c_raw.txt",
        "ai_model": GEMINI_LABEL,
        "model_version": GEMINI_VERSION,
        "hypothesis": "cross-vendor replication check for the Claude partial-fix case",
    },
    {
        "case_id_label": "iam_exp_d_unresolved_policy_claude",
        "fixture": "iam_exp_d_unresolved_policy",
        "invariant_id": "IAM_EXCESSIVE_PRIVILEGE_EXPOSURE",
        "resource_address": "aws_iam_role.data",
        "invariant_evaluator": evaluate_iam_excessive_privilege_exposure,
        "broad_relevant_rules": IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES,
        "rule_id": "CKV_AWS_62",
        "rule_description": 'Ensure IAM policies that allow full "*-*" administrative '
        "privileges are not created",
        "raw_response_file": SCRATCH / "claude_iam_d_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "before=UNKNOWN (policy content unresolvable at plan time via a "
        "self-referential unique_id interpolation); after depends on whether the "
        "repair's own Sid keeps the same self-reference",
    },
    {
        "case_id_label": "iam_exp_e_attached_managed_policy_blindspot_claude",
        "fixture": "iam_exp_e_attached_managed_policy_blindspot",
        "invariant_id": "IAM_EXCESSIVE_PRIVILEGE_EXPOSURE",
        "resource_address": "aws_iam_role.data",
        "invariant_evaluator": evaluate_iam_excessive_privilege_exposure,
        "broad_relevant_rules": IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES,
        "rule_id": "CKV_AWS_62",
        "rule_description": 'Ensure IAM policies that allow full "*-*" administrative '
        "privileges are not created",
        "raw_response_file": SCRATCH / "claude_iam_e_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "before=PASS (disclosed scope gap: invariant does not evaluate "
        "attached managed policy content); a real, verifiable fix is expected to "
        "still classify INCONCLUSIVE ('PASS->PASS, nothing to fix')",
    },
    # --- NETWORK_SENSITIVE_PORT_EXPOSURE ---
    {
        "case_id_label": "net_exp_a_ssh_open_claude",
        "fixture": "net_exp_a_ssh_open",
        "invariant_id": "NETWORK_SENSITIVE_PORT_EXPOSURE",
        "resource_address": "aws_security_group.data",
        "invariant_evaluator": evaluate_network_sensitive_port_exposure,
        "broad_relevant_rules": NETWORK_SENSITIVE_PORT_RELEVANT_RULES,
        "rule_id": "CKV_AWS_24",
        "rule_description": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
        "raw_response_file": SCRATCH / "claude_net_a_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "TRUE_FIX (positive control, single vector)",
    },
    {
        "case_id_label": "net_exp_a_ssh_open_gemini",
        "fixture": "net_exp_a_ssh_open",
        "invariant_id": "NETWORK_SENSITIVE_PORT_EXPOSURE",
        "resource_address": "aws_security_group.data",
        "invariant_evaluator": evaluate_network_sensitive_port_exposure,
        "broad_relevant_rules": NETWORK_SENSITIVE_PORT_RELEVANT_RULES,
        "rule_id": "CKV_AWS_24",
        "rule_description": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
        "raw_response_file": SCRATCH / "gemini_net_a_raw.txt",
        "ai_model": GEMINI_LABEL,
        "model_version": GEMINI_VERSION,
        "hypothesis": "cross-vendor replication check for the Claude positive control",
    },
    {
        "case_id_label": "net_exp_b_db_port_open_claude",
        "fixture": "net_exp_b_db_port_open",
        "invariant_id": "NETWORK_SENSITIVE_PORT_EXPOSURE",
        "resource_address": "aws_security_group.data",
        "invariant_evaluator": evaluate_network_sensitive_port_exposure,
        "broad_relevant_rules": NETWORK_SENSITIVE_PORT_RELEVANT_RULES,
        "rule_id": None,
        "rule_description": "Manual security review (no matching Checkov rule exists in "
        "this Checkov version for port 3306 -- confirmed by inspecting "
        "checkov/terraform/checks/resource/aws/ directly): MySQL (3306) open to "
        "0.0.0.0/0",
        "raw_response_file": SCRATCH / "claude_net_b_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "TRUE_FIX by the invariant; scanner-only narrow baseline has "
        "nothing to check (no rule exists) -- direct evidence of invariant value "
        "beyond Checkov's default ruleset",
    },
    {
        "case_id_label": "net_exp_c_partial_fix_named_rule_claude",
        "fixture": "net_exp_c_partial_fix_named_rule",
        "invariant_id": "NETWORK_SENSITIVE_PORT_EXPOSURE",
        "resource_address": "aws_security_group.data",
        "invariant_evaluator": evaluate_network_sensitive_port_exposure,
        "broad_relevant_rules": NETWORK_SENSITIVE_PORT_RELEVANT_RULES,
        "rule_id": "CKV_AWS_24",
        "rule_description": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
        "raw_response_file": SCRATCH / "claude_net_c_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "PARTIAL_FIX opportunity: two sensitive-port rules (22, 3389), "
        "only 22 named in the finding",
    },
    {
        "case_id_label": "net_exp_c_partial_fix_named_rule_gemini",
        "fixture": "net_exp_c_partial_fix_named_rule",
        "invariant_id": "NETWORK_SENSITIVE_PORT_EXPOSURE",
        "resource_address": "aws_security_group.data",
        "invariant_evaluator": evaluate_network_sensitive_port_exposure,
        "broad_relevant_rules": NETWORK_SENSITIVE_PORT_RELEVANT_RULES,
        "rule_id": "CKV_AWS_24",
        "rule_description": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
        "raw_response_file": SCRATCH / "gemini_net_c_raw.txt",
        "ai_model": GEMINI_LABEL,
        "model_version": GEMINI_VERSION,
        "hypothesis": "cross-vendor replication check for the Claude partial-fix case",
    },
    {
        "case_id_label": "net_exp_d_unresolved_cidr_claude",
        "fixture": "net_exp_d_unresolved_cidr",
        "invariant_id": "NETWORK_SENSITIVE_PORT_EXPOSURE",
        "resource_address": "aws_security_group.data",
        "invariant_evaluator": evaluate_network_sensitive_port_exposure,
        "broad_relevant_rules": NETWORK_SENSITIVE_PORT_RELEVANT_RULES,
        "rule_id": None,
        "rule_description": "No finding reported -- open-ended review prompt; Checkov "
        "itself does not flag this fixture (CKV_AWS_24 passes, since cidr_blocks is "
        "not the literal string 0.0.0.0/0)",
        "raw_response_file": SCRATCH / "claude_net_d_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "before=UNKNOWN (unresolved EIP-derived CIDR); after status "
        "depends on whether the repair's own after-state plan resolves cleanly -- "
        "the repair introduces a required input variable with no default",
    },
    {
        "case_id_label": "net_exp_e_multi_sg_nested_complexity_claude",
        "fixture": "net_exp_e_multi_sg_nested_complexity",
        "invariant_id": "NETWORK_SENSITIVE_PORT_EXPOSURE",
        "resource_address": "aws_security_group.data",
        "invariant_evaluator": evaluate_network_sensitive_port_exposure,
        "broad_relevant_rules": NETWORK_SENSITIVE_PORT_RELEVANT_RULES,
        "rule_id": "CKV_AWS_24",
        "rule_description": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
        "raw_response_file": SCRATCH / "claude_net_e_raw.txt",
        "ai_model": CLAUDE_LABEL,
        "model_version": CLAUDE_VERSION,
        "hypothesis": "TRUE_FIX with correct discrimination: one real violation buried "
        "among 2 safe rules on the target SG, plus a second, decoy SG "
        "(aws_security_group.web) that must not be touched or confused",
    },
]


def main() -> None:
    experiment_id = make_experiment_id("iam-network-experiment")
    environment = capture_environment()
    scanner = CheckovAdapter()
    planner = TerraformPlanner(filesystem_mirror_dir=MIRROR_DIR)

    records = []
    for case in CASES:
        print(
            f"\n{'=' * 70}\n{case['case_id_label']}\n"
            f"hypothesis: {case['hypothesis']}\n{'=' * 70}"
        )

        original_tf = (FIXTURES / case["fixture"] / "main.tf").read_text()
        generated_at = datetime.now(UTC)
        raw_response = case["raw_response_file"].read_text()

        evaluation = evaluate_repair(
            original_tf=original_tf,
            raw_ai_output=raw_response,
            rule_id=case["rule_id"],
            planner=planner,
            scanner=scanner,
            resource_address=case["resource_address"],
            invariant_evaluator=case["invariant_evaluator"],
            broad_relevant_rules=case["broad_relevant_rules"],
        )

        err = evaluation.after_plan.error_message
        after_plan_error = f" ({err})" if err else ""
        print(f"before_plan: {evaluation.before_plan.status.value}")
        print(f"after_plan:  {evaluation.after_plan.status.value}{after_plan_error}")
        print(
            f"before_invariant: {evaluation.before_invariant.status.value} "
            f"{evaluation.before_invariant.violated_conditions} | "
            f"{evaluation.before_invariant.reason}"
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
        print(f"remaining_uncertainty: {evaluation.oracle_verdict.remaining_uncertainty}")
        print(
            f"SCANNER-ONLY BASELINE: narrow={evaluation.scanner_baseline.narrow_conclusion.value} "
            f"({evaluation.scanner_baseline.narrow_reason})"
        )
        print(
            f"                       broad={evaluation.scanner_baseline.broad_conclusion.value} "
            f"({evaluation.scanner_baseline.broad_reason})"
        )

        record = RepairRecord(
            experiment_id=experiment_id,
            case_id=make_case_id(case["case_id_label"], 0),
            generated_at=generated_at,
            original_terraform=original_tf,
            original_terraform_sha256=content_hash(original_tf),
            original_security_issue_rule_id=case["rule_id"] or "N/A",
            original_security_issue_description=case["rule_description"],
            vulnerability_class=case["invariant_id"],
            ai_model=case["ai_model"],
            model_version=case["model_version"],
            prompt_template_id="iam_network_experiment_v1",
            rendered_prompt=(
                f"check: {case['rule_id']} ({case['rule_description']})\n"
                f"[see fixtures/terraform/{case['fixture']}/main.tf for the exact "
                "Terraform configuration shown to the model]"
            ),
            system_configuration=SystemConfiguration(
                temperature=None,
                other_parameters={
                    "invocation": (
                        "Agent tool, subagent_type=general-purpose, instructed to use "
                        "no tools, blind to this project's research purpose, oracle, "
                        "or evaluation criteria"
                        if case["ai_model"] == CLAUDE_LABEL
                        else "direct REST API call to generativelanguage.googleapis.com, "
                        "no tools, no system prompt beyond the rendered prompt itself, "
                        "blind to this project's research purpose, oracle, or "
                        "evaluation criteria"
                    ),
                    "hypothesis": case["hypothesis"],
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
