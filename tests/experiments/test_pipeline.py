"""Real, end-to-end integration test for experiments.pipeline.evaluate_repair.

Deliberately NOT synthetic: uses the real Terraform CLI (via the provider
filesystem mirror) and the real Checkov binary, exactly as every
scripts/run_*.py experiment does. This is the test that proves the
consolidated pipeline is behaviorally equivalent to the hand-rolled version
it replaces, not just a unit test of its wiring -- see Phase 6 of the
session history in the project's own development record for why this
consolidation happened.

Slower than the rest of the suite (two real `terraform plan` invocations
and two real Checkov scans) but not disabled -- this project's own
constitution treats "never claim something works without running it" as
non-negotiable, and this module is exactly the kind of code that must
prove itself against real execution, not a mock.
"""

from __future__ import annotations

from pathlib import Path

from terraveritas.experiments.pipeline import evaluate_repair
from terraveritas.models.baseline import BaselineConclusion
from terraveritas.models.invariant import InvariantStatus
from terraveritas.models.oracle import Classification
from terraveritas.models.plan import PlanStatus
from terraveritas.scanners.checkov import CheckovAdapter
from terraveritas.terraform.plan import TerraformPlanner

REPO_ROOT = Path(__file__).resolve().parents[2]
MIRROR_DIR = REPO_ROOT / ".terraform-mirror"
FIXTURE = REPO_ROOT / "fixtures" / "terraform" / "phase2_case_a_genuine_fix" / "main.tf"


def test_real_pipeline_reproduces_the_known_true_fix_result() -> None:
    """phase2_case_a_genuine_fix's real repair (public-read ACL -> private)
    is already independently verified as TRUE_FIX by
    scripts/run_phase2_negative_case_experiment.py's real run (see
    datasets/experiments/2026-09-04-phase2-negative-case-experiment/). This
    test re-derives the same result through the new consolidated pipeline,
    against the real Terraform CLI and real Checkov, to prove the
    consolidation didn't change behavior."""
    original_tf = FIXTURE.read_text()
    raw_ai_output = (
        "```hcl\n"
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "terraveritas-phase2a-bucket"\n'
        "}\n\n"
        'resource "aws_s3_bucket_acl" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        '  acl    = "private"\n'
        "}\n"
        "```\n"
    )

    result = evaluate_repair(
        original_tf=original_tf,
        raw_ai_output=raw_ai_output,
        rule_id="CKV_AWS_20",
        planner=TerraformPlanner(filesystem_mirror_dir=MIRROR_DIR),
        scanner=CheckovAdapter(),
    )

    assert result.before_plan.status == PlanStatus.PLAN_SUCCESS
    assert result.after_plan.status == PlanStatus.PLAN_SUCCESS
    assert result.before_invariant.status == InvariantStatus.FAIL
    assert result.after_invariant.status == InvariantStatus.PASS
    assert result.oracle_verdict.classification == Classification.TRUE_FIX
    assert result.scanner_baseline.narrow_conclusion == BaselineConclusion.FIX_ACCEPTED
