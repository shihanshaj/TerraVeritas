"""Real, non-synthetic end-to-end pipeline proof.

Runs the actual, unmodified project code — TerraformPlanner,
evaluate_s3_public_access_exposure, classify_repair — against real
Terraform fixtures, using the local provider filesystem mirror (see
build_provider_mirror.py) so `terraform init`/`plan` complete without
depending on this environment's unstable network for the bulk provider
download. No synthetic PlanResult objects anywhere in this script.

Scenario A: aws_s3_bucket with a public-read ACL (violates
S3_PUBLIC_ACCESS_EXPOSURE). Scenario B: the same bucket, repaired (private
ACL + full Block Public Access).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from terraveritas.invariants import s3_public_access  # noqa: E402
from terraveritas.models.plan import PlanStatus  # noqa: E402
from terraveritas.terraform.plan import TerraformPlanner  # noqa: E402
from terraveritas.verification.oracle import classify_repair  # noqa: E402

MIRROR_DIR = REPO_ROOT / ".terraform-mirror"
EVIDENCE_DIR = REPO_ROOT / "datasets" / "real_e2e_pipeline_proof"

SCENARIO_A_TF = """\
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

resource "aws_s3_bucket" "data" {
  bucket = "terraveritas-e2e-vulnerable-bucket"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
"""

SCENARIO_B_TF = """\
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

resource "aws_s3_bucket" "data" {
  bucket = "terraveritas-e2e-vulnerable-bucket"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


def main() -> None:
    if not MIRROR_DIR.exists():
        print(f"Provider mirror not found at {MIRROR_DIR}.")
        print("Run: uv run python scripts/build_provider_mirror.py")
        sys.exit(1)

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "scenario_a" / "main.tf").parent.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "scenario_b" / "main.tf").parent.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "scenario_a" / "main.tf").write_text(SCENARIO_A_TF)
    (EVIDENCE_DIR / "scenario_b" / "main.tf").write_text(SCENARIO_B_TF)

    planner = TerraformPlanner(filesystem_mirror_dir=MIRROR_DIR)

    print("=== Scenario A: real terraform plan (vulnerable) ===")
    plan_a = planner.plan(EVIDENCE_DIR / "scenario_a", timeout_seconds=60)
    print(f"status: {plan_a.status.value}")
    print(f"commands_run: {[c[1] for c in plan_a.commands_run]}")
    if plan_a.status != PlanStatus.PLAN_SUCCESS:
        print(f"BLOCKED: {plan_a.error_message}")
        sys.exit(1)
    print(f"resource_changes: {[rc.address for rc in plan_a.resource_changes]}")
    (EVIDENCE_DIR / "scenario_a" / "real_plan.json").write_text(
        json.dumps(plan_a.raw_plan_json, indent=2)
    )

    print("\n=== Scenario B: real terraform plan (repaired) ===")
    plan_b = planner.plan(EVIDENCE_DIR / "scenario_b", timeout_seconds=60)
    print(f"status: {plan_b.status.value}")
    if plan_b.status != PlanStatus.PLAN_SUCCESS:
        print(f"BLOCKED: {plan_b.error_message}")
        sys.exit(1)
    print(f"resource_changes: {[rc.address for rc in plan_b.resource_changes]}")
    (EVIDENCE_DIR / "scenario_b" / "real_plan.json").write_text(
        json.dumps(plan_b.raw_plan_json, indent=2)
    )

    print("\n=== Real invariant evaluation ===")
    before_invariant = s3_public_access.evaluate_s3_public_access_exposure(
        plan_a, "aws_s3_bucket.data"
    )
    after_invariant = s3_public_access.evaluate_s3_public_access_exposure(
        plan_b, "aws_s3_bucket.data"
    )
    print(f"before: status={before_invariant.status.value}, "
          f"violated_conditions={before_invariant.violated_conditions}")
    print(f"after:  status={after_invariant.status.value}, "
          f"violated_conditions={after_invariant.violated_conditions}")

    print("\n=== Real oracle classification ===")
    verdict = classify_repair(
        before_invariant,
        after_invariant,
        before_plan_status=plan_a.status,
        after_plan_status=plan_b.status,
    )
    print(f"classification: {verdict.classification.value}")
    print(f"confidence: {verdict.confidence.value}")
    print(f"reasons: {verdict.reasons}")

    evidence = {
        "scenario_a_plan_status": plan_a.status.value,
        "scenario_a_resource_changes": [rc.address for rc in plan_a.resource_changes],
        "scenario_b_plan_status": plan_b.status.value,
        "scenario_b_resource_changes": [rc.address for rc in plan_b.resource_changes],
        "before_invariant_status": before_invariant.status.value,
        "before_invariant_violated_conditions": before_invariant.violated_conditions,
        "after_invariant_status": after_invariant.status.value,
        "after_invariant_violated_conditions": after_invariant.violated_conditions,
        "oracle_classification": verdict.classification.value,
        "oracle_confidence": verdict.confidence.value,
        "oracle_reasons": verdict.reasons,
    }
    (EVIDENCE_DIR / "summary.json").write_text(json.dumps(evidence, indent=2))
    print(f"\nEvidence stored under {EVIDENCE_DIR}")

    assert verdict.classification.value == "true_fix", (
        f"expected true_fix from a genuine repair, got {verdict.classification.value}"
    )
    print("\n✅ REAL end-to-end pipeline succeeded: real plan -> real invariant -> real oracle.")


if __name__ == "__main__":
    main()
