"""CLI entry point.

Two subcommands, both thin wrappers around already-tested pipeline code —
no new business logic lives here, only argument parsing, orchestration of
existing functions, and rendering (see reporting/render.py):

- `scan`: run Checkov against a directory and report findings.
- `verify`: run the full real pipeline (Checkov + real terraform plan +
  the S3_PUBLIC_ACCESS_EXPOSURE invariant + the oracle) against a
  before/after directory pair and report a classification per S3 bucket
  found.

Deliberately not exposed: anything not backed by real, tested code. Only
one invariant (S3_PUBLIC_ACCESS_EXPOSURE) exists, so `verify` only
evaluates `aws_s3_bucket` resources — this is stated explicitly in output
when no such resource is found, not silently done.

Exit codes for `verify`, chosen to make this usable as a CI gate without
parsing output: 0 only if every evaluated resource reached TRUE_FIX
(this project's documented sole allow-condition for automated
progression), 1 if the tool ran successfully but at least one resource
did not reach TRUE_FIX, 2 for a tool/environment error (bad arguments,
Terraform unavailable, plan failed, etc.) — the distinction matters: exit
1 means "the tool worked and found something to block on", exit 2 means
"the tool itself could not complete the check".
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from terraveritas.differential.scanner_diff import compare_scan_results
from terraveritas.invariants.s3_public_access import evaluate_s3_public_access_exposure
from terraveritas.models.finding import ScanStatus
from terraveritas.models.plan import PlanStatus
from terraveritas.reporting.render import (
    render_plan_failure_human,
    render_scan_human,
    render_scan_json,
    render_verdict_human,
    render_verdict_json,
)
from terraveritas.scanners.checkov import CheckovAdapter
from terraveritas.terraform.plan import TerraformPlanner
from terraveritas.verification.oracle import classify_repair

_PLAN_STATUS_HINTS: dict[PlanStatus, str] = {
    PlanStatus.PLAN_TERRAFORM_NOT_INSTALLED: (
        "Install Terraform: https://developer.hashicorp.com/terraform/install"
    ),
    PlanStatus.PLAN_INVALID_TARGET: "Check that the directory path is correct.",
    PlanStatus.PLAN_INVALID_CONFIGURATION: (
        "The Terraform configuration itself is invalid — this is a signal "
        "about the input, not a tool failure. Run `terraform validate` "
        "directly for full diagnostics."
    ),
    PlanStatus.PLAN_INIT_FAILURE: (
        "Provider or module installation failed. If this is a fresh "
        "checkout, build the local provider mirror first: "
        "uv run python scripts/build_provider_mirror.py"
    ),
    PlanStatus.PLAN_UNRESOLVED_DEPENDENCY: (
        "A required Terraform variable has no default and none was supplied."
    ),
    PlanStatus.PLAN_PROVIDER_FAILURE: (
        "A live AWS API call was required and was rejected by this tool's "
        "deliberately sandboxed, fake credentials. This can be a correct, "
        "safe result — not necessarily a bug — if the repair introduced a "
        "construct (e.g. a `data` source) that genuinely needs live AWS "
        "access this tool intentionally never grants."
    ),
    PlanStatus.PLAN_UNSUPPORTED: (
        "This configuration uses a construct (e.g. a non-local module "
        "source) this tool does not fetch during evaluation."
    ),
    PlanStatus.PLAN_TIMEOUT: (
        "A Terraform stage exceeded its timeout. If this is a fresh "
        "checkout, build the provider mirror: "
        "uv run python scripts/build_provider_mirror.py"
    ),
    PlanStatus.PLAN_ERROR: "An unclassified Terraform failure — see the detail above.",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_mirror_dir() -> Path | None:
    mirror = _repo_root() / ".terraform-mirror"
    return mirror if mirror.exists() else None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="terraveritas",
        description="Automated security-intent oracle for AI-repaired Terraform.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the installed TerraVeritas version and exit.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan", help="Run Checkov against a Terraform directory and report findings."
    )
    scan_parser.add_argument("directory", type=Path, help="Directory containing .tf files.")
    scan_parser.add_argument(
        "--json", action="store_true", help="Emit structured JSON instead of human-readable text."
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help=(
            "Evaluate whether an AI repair genuinely fixes a security issue. "
            "Currently supports S3_PUBLIC_ACCESS_EXPOSURE (aws_s3_bucket) only."
        ),
    )
    verify_parser.add_argument("before_directory", type=Path, help="Original configuration.")
    verify_parser.add_argument("after_directory", type=Path, help="Repaired configuration.")
    verify_parser.add_argument(
        "--json", action="store_true", help="Emit structured JSON instead of human-readable text."
    )
    verify_parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Per-stage Terraform timeout in seconds (default: 120).",
    )

    return parser


def _cmd_scan(directory: Path, *, json_output: bool) -> int:
    if not directory.is_dir():
        print(f"error: directory does not exist: {directory}", file=sys.stderr)
        return 2

    result = CheckovAdapter().scan(directory)

    if json_output:
        print(json.dumps(render_scan_json(result), indent=2))
    else:
        print(render_scan_human(result))

    if result.status != ScanStatus.SUCCESS:
        return 2
    has_failures = any(f.outcome.value == "failed" for f in result.findings)
    return 1 if has_failures else 0


def _cmd_verify(
    before_directory: Path, after_directory: Path, *, json_output: bool, timeout: float
) -> int:
    for label, directory in (("before", before_directory), ("after", after_directory)):
        if not directory.is_dir():
            print(f"error: {label} directory does not exist: {directory}", file=sys.stderr)
            return 2

    checkov = CheckovAdapter()
    before_scan = checkov.scan(before_directory, timeout_seconds=timeout)
    after_scan = checkov.scan(after_directory, timeout_seconds=timeout)

    differential_results = []
    if before_scan.status == ScanStatus.SUCCESS and after_scan.status == ScanStatus.SUCCESS:
        differential_results = [compare_scan_results(before_scan, after_scan)]
    elif not json_output:
        print(
            "Note: scanner comparison unavailable "
            f"(before={before_scan.status.value}, after={after_scan.status.value}); "
            "continuing with plan-based evaluation only.\n"
        )

    planner = TerraformPlanner(filesystem_mirror_dir=_default_mirror_dir())
    before_plan = planner.plan(before_directory, timeout_seconds=timeout)
    after_plan = planner.plan(after_directory, timeout_seconds=timeout)

    for label, plan in (("before", before_plan), ("after", after_plan)):
        if plan.status != PlanStatus.PLAN_SUCCESS:
            hint = _PLAN_STATUS_HINTS.get(plan.status, "See the detail above.")
            if json_output:
                print(
                    json.dumps(
                        {
                            "error": f"{label} plan did not succeed",
                            "status": plan.status.value,
                            "detail": plan.error_message,
                            "hint": hint,
                        },
                        indent=2,
                    )
                )
            else:
                print(f"Could not evaluate: {label} configuration did not produce a usable plan.")
                print(render_plan_failure_human(plan.status, plan.error_message, hint))
            return 2

    bucket_addresses = sorted(
        {rc.address for rc in before_plan.resource_changes if rc.resource_type == "aws_s3_bucket"}
    )
    if not bucket_addresses:
        message = (
            "No supported resource type found in the before configuration. "
            "TerraVeritas currently evaluates S3_PUBLIC_ACCESS_EXPOSURE "
            "(aws_s3_bucket) only — see README.md for what is and is not "
            "implemented today."
        )
        if json_output:
            print(json.dumps({"error": message}, indent=2))
        else:
            print(message)
        return 2

    all_true_fix = True
    verdicts_json = []
    for address in bucket_addresses:
        before_invariant = evaluate_s3_public_access_exposure(before_plan, address)
        after_invariant = evaluate_s3_public_access_exposure(after_plan, address)
        verdict = classify_repair(
            before_invariant,
            after_invariant,
            before_plan_status=before_plan.status,
            after_plan_status=after_plan.status,
            differential_results=differential_results,
        )
        if verdict.classification.value != "true_fix":
            all_true_fix = False

        if json_output:
            verdicts_json.append(render_verdict_json(verdict))
        else:
            print(render_verdict_human(verdict, resource_address=address))

    if json_output:
        print(json.dumps({"resources_evaluated": verdicts_json}, indent=2))

    return 0 if all_true_fix else 1


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        from importlib.metadata import version

        print(version("terraveritas"))
        return

    if args.command == "scan":
        sys.exit(_cmd_scan(args.directory, json_output=args.json))
    elif args.command == "verify":
        sys.exit(
            _cmd_verify(
                args.before_directory,
                args.after_directory,
                json_output=args.json,
                timeout=args.timeout,
            )
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
