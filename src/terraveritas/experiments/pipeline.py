"""The canonical, real repair-evaluation pipeline.

Given an original Terraform config and a raw AI repair response, runs every
real evaluation step this project performs and returns a fully-populated
bundle: mechanical extraction, real before/after Checkov scans, real
Terraform plans for both configurations via the provider filesystem mirror,
real invariant evaluation on both sides, differential comparison, oracle
classification, and the scanner-only baseline. Every step here is real
execution -- no synthetic PlanResult or ScanResult is ever constructed by
this module. (Synthetic PlanResult objects remain legitimate for invariant
*unit* tests, which check implementation correctness against the exact
`terraform show -json` schema, not for anything that becomes part of the
experimental dataset -- see tests/invariants/helpers.py.)

Four experiment scripts (run_real_ai_pilot.py, run_negative_case_pilot.py,
run_phase2_negative_case_experiment.py, run_phase3_alternate_model_
experiment.py) had drifted into copy-pasted near-duplicates of this exact
step sequence before this module existed. New experiment scripts should
call `evaluate_repair` here rather than re-implementing it inline.

Does NOT generate the AI repair itself -- that happens via a real, blind
model invocation the caller controls (see any scripts/run_*.py's own
docstring for how "blind" is actually enforced) -- and does NOT decide
which invariant applies to a given finding: `bucket_address` and the
S3_PUBLIC_ACCESS_EXPOSURE invariant are the only ones this project
implements today, so they are the (overridable) defaults, not a dispatch
mechanism.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from terraveritas.differential.scanner_diff import compare_scan_results
from terraveritas.evaluation.scanner_baseline import compute_scanner_only_baseline
from terraveritas.experiments.extraction import extract_terraform
from terraveritas.invariants.s3_public_access import evaluate_s3_public_access_exposure
from terraveritas.models.baseline import ScannerOnlyBaseline
from terraveritas.models.diff import DifferentialResult
from terraveritas.models.finding import ScanResult
from terraveritas.models.invariant import InvariantResult
from terraveritas.models.oracle import OracleVerdict
from terraveritas.models.plan import PlanResult
from terraveritas.scanners.base import ScannerAdapter
from terraveritas.terraform.plan import TerraformPlanner
from terraveritas.verification.oracle import classify_repair


@dataclass(frozen=True, slots=True)
class RepairEvaluation:
    extracted_terraform: str
    before_scan: ScanResult
    after_scan: ScanResult
    differential: DifferentialResult
    before_plan: PlanResult
    after_plan: PlanResult
    before_invariant: InvariantResult
    after_invariant: InvariantResult
    oracle_verdict: OracleVerdict
    scanner_baseline: ScannerOnlyBaseline


def _scan(tf_content: str, scanner: ScannerAdapter, *, timeout_seconds: float) -> ScanResult:
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "main.tf").write_text(tf_content)
        return scanner.scan(Path(tmp), timeout_seconds=timeout_seconds)


def _plan(tf_content: str, planner: TerraformPlanner, *, timeout_seconds: float) -> PlanResult:
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "main.tf").write_text(tf_content)
        return planner.plan(Path(tmp), timeout_seconds=timeout_seconds)


def evaluate_repair(
    *,
    original_tf: str,
    raw_ai_output: str,
    rule_id: str | None,
    planner: TerraformPlanner,
    scanner: ScannerAdapter,
    resource_address: str = "aws_s3_bucket.data",
    invariant_evaluator: Callable[
        [PlanResult, str], InvariantResult
    ] = evaluate_s3_public_access_exposure,
    broad_relevant_rules: set[str] | None = None,
    extracted_tf_override: str | None = None,
    timeout_seconds: float = 90.0,
) -> RepairEvaluation:
    """Runs the complete real pipeline. `extracted_tf_override`, when given,
    is used as the after-state Terraform INSTEAD of mechanically extracting
    it from `raw_ai_output` -- for the one legitimate case this project has
    needed so far (a context-limited repair whose extracted snippet must be
    mechanically reattached to an untouched resource the model never saw;
    see run_phase2_negative_case_experiment.py's case_b). The raw response
    is still stored by the caller either way; this function never edits it.

    `invariant_evaluator` and `resource_address` generalize this pipeline
    beyond S3: any invariant with the `(PlanResult, resource_address) ->
    InvariantResult` shape (every invariant in this project has this shape
    today -- see s3_public_access.py, iam_excessive_privilege.py,
    network_exposure.py) can be evaluated through the same real
    scan/plan/differential/oracle machinery. Defaults preserve the exact
    prior behavior (S3, `aws_s3_bucket.data`) for every existing caller,
    none of which passed the old `bucket_address` parameter explicitly --
    confirmed via `git grep` before this rename, not assumed."""
    extracted_tf = (
        extracted_tf_override
        if extracted_tf_override is not None
        else extract_terraform(raw_ai_output)
    )

    before_scan = _scan(original_tf, scanner, timeout_seconds=timeout_seconds)
    after_scan = _scan(extracted_tf, scanner, timeout_seconds=timeout_seconds)
    differential = compare_scan_results(before_scan, after_scan)

    before_plan = _plan(original_tf, planner, timeout_seconds=timeout_seconds)
    after_plan = _plan(extracted_tf, planner, timeout_seconds=timeout_seconds)

    before_invariant = invariant_evaluator(before_plan, resource_address)
    after_invariant = invariant_evaluator(after_plan, resource_address)

    oracle_verdict = classify_repair(
        before_invariant,
        after_invariant,
        before_plan_status=before_plan.status,
        after_plan_status=after_plan.status,
        differential_results=[differential],
    )

    scanner_baseline = compute_scanner_only_baseline(
        rule_id=rule_id,
        after_scan=after_scan,
        differential=differential,
        broad_relevant_rules=broad_relevant_rules,
    )

    return RepairEvaluation(
        extracted_terraform=extracted_tf,
        before_scan=before_scan,
        after_scan=after_scan,
        differential=differential,
        before_plan=before_plan,
        after_plan=after_plan,
        before_invariant=before_invariant,
        after_invariant=after_invariant,
        oracle_verdict=oracle_verdict,
        scanner_baseline=scanner_baseline,
    )
