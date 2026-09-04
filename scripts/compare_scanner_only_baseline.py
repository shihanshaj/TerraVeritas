"""Scanner-only baseline vs. TerraVeritas, across every real experiment
record on file.

Produces docs/scanner_only_baseline_comparison.json, the data behind
docs/scanner_only_baseline_comparison.md. Answers: does TerraVeritas
provide evidence beyond simply re-running Checkov? Two scanner-only
baselines are computed per case, not one -- see the module-level comment on
_PUBLIC_ACCESS_RELEVANT_RULES for why a naive "broader" baseline had to be
corrected before it was fair.

For each record with full plan JSON stored, recomputes the invariant/oracle
verdict fresh against the CURRENT codebase using the record's own stored
real plan JSON and scanner differential -- not the possibly-stale verdict
stored at generation time -- so this reflects what TerraVeritas actually
does today, not a historical snapshot. The two earliest records (2026-09-02)
predate full plan-JSON storage and use their originally stored verdict
as-is (both were plan_timeout, a state unaffected by later invariant fixes).
Nothing here re-runs a real Terraform plan or a real scan; all of that
evidence already exists in the stored records.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from terraveritas.invariants import s3_public_access  # noqa: E402
from terraveritas.models.diff import (  # noqa: E402
    DifferentialResult,
    NewFinding,
    PersistentFinding,
    RelocatedFinding,
    RemovedFinding,
)
from terraveritas.models.finding import Finding, FindingOutcome  # noqa: E402
from terraveritas.models.plan import PlanResult, PlanStatus  # noqa: E402
from terraveritas.terraform.plan import _extract_resource_changes  # noqa: E402
from terraveritas.verification.oracle import classify_repair  # noqa: E402

RECORDS_ROOT = REPO_ROOT / "datasets" / "experiments"
OUT_PATH = REPO_ROOT / "docs" / "scanner_only_baseline_comparison.json"


def _load_plan(record: dict, side: str) -> PlanResult:
    p = record[f"{side}_plan"]
    raw = p.get("raw_plan_json")
    return PlanResult(
        target_path=p["target_path"],
        status=PlanStatus(p["status"]),
        terraform_version=p.get("terraform_version"),
        resource_changes=_extract_resource_changes(raw) if raw else [],
        raw_plan_json=raw,
        error_message=p.get("error_message"),
    )


def _finding(fd: dict) -> Finding:
    return Finding(
        rule_id=fd["rule_id"],
        resource_id=fd["resource_id"],
        resource_type=fd["resource_type"],
        description=fd["description"],
        file_path=fd["file_path"],
        line_start=fd["line_start"],
        line_end=fd["line_end"],
        outcome=FindingOutcome(fd["outcome"]),
        scanner_name=fd["scanner_name"],
        scanner_version=fd["scanner_version"],
        severity=fd.get("severity"),
        scan_timestamp=fd["scan_timestamp"],
        raw_evidence=fd.get("raw_evidence", {}),
    )


def _rebuild_differential(record: dict) -> DifferentialResult:
    d = record["differential"]
    return DifferentialResult(
        scanner_name=d["scanner_name"],
        removed=[
            RemovedFinding(
                before=_finding(r["before"]),
                resource_still_present_in_after=r["resource_still_present_in_after"],
                same_identity_now_passes=r["same_identity_now_passes"],
            )
            for r in d["removed"]
        ],
        persistent=[
            PersistentFinding(before=_finding(p["before"]), after=_finding(p["after"]))
            for p in d["persistent"]
        ],
        new=[NewFinding(after=_finding(n["after"])) for n in d["new"]],
        relocated=[
            RelocatedFinding(
                before=_finding(r["before"]), after=_finding(r["after"]), note=r["note"]
            )
            for r in d["relocated"]
        ],
    )


# Checkov rule IDs that fire only when there is an ACTUAL public-access
# GRANT (a canned public ACL, an explicit public ACL grant block, or a
# bucket-policy statement allowing any principal) -- the set a MORE
# THOROUGH scanner-only gate would check, as opposed to a narrow gate that
# only re-checks the one originally-reported rule_id. Deliberately EXCLUDES
# "protective control absent" advisories like CKV2_AWS_6 (no Block Public
# Access resource) and the standalone BPA-flag checks (CKV_AWS_53-56):
# absence of a hardening control is not itself evidence of exposure, by
# this project's own invariant's logic, and a first attempt at this
# baseline that included CKV2_AWS_6 produced FIX REJECTED on cases already
# independently confirmed as genuinely fixed (case1_acl_only, etc.) --
# conflating "not maximally hardened" with "actually exposed" is exactly
# the kind of imprecision this project exists to avoid, including in its
# own baseline. Compiled by reading real scan output, not guessed.
_PUBLIC_ACCESS_RELEVANT_RULES = {
    "CKV_AWS_20",  # ACL public READ
    "CKV_AWS_57",  # ACL public WRITE
    "CKV_AWS_70",  # bucket policy allows any principal
    "CKV2_AWS_43",  # ACL allows all Authenticated users
    "CKV_AWS_375",  # ACL global view
}


def _broad_baseline(record: dict) -> tuple[str, str]:
    after_failed = {
        f["rule_id"] for f in record["after_scan"]["findings"] if f["outcome"] == "failed"
    }
    hit = sorted(after_failed & _PUBLIC_ACCESS_RELEVANT_RULES)
    if hit:
        return ("FIX REJECTED (BROAD RE-SCAN)", f"public-access-relevant rule(s) still fail: {hit}")
    return (
        "FIX ACCEPTED (BROAD RE-SCAN)",
        "no public-access-relevant rule fails in the after-scan",
    )


def _narrow_baseline(record: dict) -> tuple[str, str]:
    rule_id = record.get("original_security_issue_rule_id")
    after_failed = {
        f["rule_id"] for f in record["after_scan"]["findings"] if f["outcome"] == "failed"
    }
    new_findings = record["differential"]["new"]

    if not rule_id or rule_id == "N/A":
        if new_findings:
            new_ids = sorted({n["after"]["rule_id"] for n in new_findings})
            return (
                "NO FINDING TO RE-CHECK, BUT NEW FINDING(S) APPEARED",
                "no security finding was originally reported for this case, so a "
                f"scanner-only gate has nothing to re-verify -- but the re-scan shows "
                f"new failing check(s): {new_ids}",
            )
        return (
            "N/A -- NO FINDING TO RE-CHECK",
            "no security finding was originally reported for this case (e.g. an "
            "unrelated feature request); a scanner-only gate has no basis to evaluate "
            "it at all",
        )

    if rule_id in after_failed:
        return ("FIX REJECTED", f"{rule_id} is still FAILED in the after-scan")

    if new_findings:
        new_ids = sorted({n["after"]["rule_id"] for n in new_findings})
        return (
            "FIX ACCEPTED (WITH NEW FINDINGS)",
            f"{rule_id} no longer fails, but new finding(s) appeared: {new_ids}",
        )

    return ("FIX ACCEPTED", f"{rule_id} no longer fails in the after-scan; nothing new appeared")


def main() -> None:
    rows = []
    for path in sorted(RECORDS_ROOT.glob("*/records/*.json")):
        record = json.loads(path.read_text())

        if "before_plan" in record and "after_plan" in record:
            before_plan = _load_plan(record, "before")
            after_plan = _load_plan(record, "after")
            before_inv = s3_public_access.evaluate_s3_public_access_exposure(
                before_plan, "aws_s3_bucket.data"
            )
            after_inv = s3_public_access.evaluate_s3_public_access_exposure(
                after_plan, "aws_s3_bucket.data"
            )
            differential = _rebuild_differential(record)
            verdict = classify_repair(
                before_inv,
                after_inv,
                before_plan_status=before_plan.status,
                after_plan_status=after_plan.status,
                differential_results=[differential],
            )
            tv_before, tv_after = before_inv.status.value, after_inv.status.value
            tv_classification = verdict.classification.value
            tv_confidence = verdict.confidence.value
            tv_reasons, recomputed = verdict.reasons, True
        else:
            ov = record["oracle_verdict"]
            tv_before = tv_after = "unknown"
            tv_classification, tv_confidence = ov["classification"], ov["confidence"]
            tv_reasons, recomputed = ov["reasons"], False

        narrow_conclusion, narrow_reason = _narrow_baseline(record)
        broad_conclusion, broad_reason = _broad_baseline(record)

        rows.append(
            {
                "case_id": record["case_id"],
                "rule_id": record.get("original_security_issue_rule_id") or "N/A",
                "narrow_baseline_conclusion": narrow_conclusion,
                "narrow_baseline_reason": narrow_reason,
                "broad_baseline_conclusion": broad_conclusion,
                "broad_baseline_reason": broad_reason,
                "tv_classification": tv_classification,
                "tv_confidence": tv_confidence,
                "tv_before_invariant": tv_before,
                "tv_after_invariant": tv_after,
                "tv_reasons": tv_reasons,
                "recomputed_against_current_code": recomputed,
            }
        )

    OUT_PATH.write_text(json.dumps(rows, indent=2))
    for r in rows:
        print(f"\n{r['case_id']}  (rule: {r['rule_id']})")
        print(f"  BASELINE (narrow): {r['narrow_baseline_conclusion']}")
        print(f"  BASELINE (broad) : {r['broad_baseline_conclusion']}")
        print(
            f"  TERRAVERITAS: {r['tv_classification']} (confidence={r['tv_confidence']}) "
            f"[inv before={r['tv_before_invariant']} after={r['tv_after_invariant']}]"
        )
    print(f"\n\nWrote {len(rows)} rows to {OUT_PATH}")


if __name__ == "__main__":
    main()
