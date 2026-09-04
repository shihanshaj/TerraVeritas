"""Computes what a scanner-only baseline would conclude about a repair —
see models/baseline.py and docs/scanner_only_baseline_comparison.md.

Two baselines are computed, not one, because a single "trust the scanner"
definition hides an important distinction: a narrow, single-rule CI gate
(the realistic common case) is a much weaker comparison than a thorough
re-scan. Both are computed from real Checkov before/after scan evidence
only — never from the invariant, the plan, or the oracle.

_PUBLIC_ACCESS_RELEVANT_RULES is scoped to S3_PUBLIC_ACCESS_EXPOSURE, the
only invariant this project currently implements. A first version of this
set included CKV2_AWS_6 ("no Block Public Access resource") and the
standalone BPA-flag checks (CKV_AWS_53-56) — that version rejected cases
already independently confirmed genuinely fixed (case1_acl_only, etc.),
because absence of a hardening control is not itself evidence of exposure.
Corrected to include only rules that fire on an ACTUAL public-access grant.
"""

from __future__ import annotations

from terraveritas.models.baseline import BaselineConclusion, ScannerOnlyBaseline
from terraveritas.models.diff import DifferentialResult
from terraveritas.models.finding import FindingOutcome, ScanResult

_PUBLIC_ACCESS_RELEVANT_RULES = {
    "CKV_AWS_20",  # ACL public READ
    "CKV_AWS_57",  # ACL public WRITE
    "CKV_AWS_70",  # bucket policy allows any principal
    "CKV2_AWS_43",  # ACL allows all Authenticated users
    "CKV_AWS_375",  # ACL global view
}


def compute_scanner_only_baseline(
    *,
    rule_id: str | None,
    after_scan: ScanResult,
    differential: DifferentialResult,
) -> ScannerOnlyBaseline:
    after_failed = {f.rule_id for f in after_scan.findings if f.outcome == FindingOutcome.FAILED}
    new_ids = sorted({n.after.rule_id for n in differential.new})

    # --- narrow: only the one originally-reported rule ---
    if not rule_id or rule_id == "N/A":
        if new_ids:
            narrow_conclusion = BaselineConclusion.NO_FINDING_TO_CHECK_BUT_NEW_FINDINGS
            narrow_reason = (
                "no security finding was originally reported for this case, so a "
                f"scanner-only gate has nothing to re-verify -- but the re-scan shows "
                f"new failing check(s): {new_ids}"
            )
        else:
            narrow_conclusion = BaselineConclusion.NO_FINDING_TO_CHECK
            narrow_reason = (
                "no security finding was originally reported for this case (e.g. an "
                "unrelated feature request); a scanner-only gate has no basis to "
                "evaluate it at all"
            )
    elif rule_id in after_failed:
        narrow_conclusion = BaselineConclusion.FIX_REJECTED
        narrow_reason = f"{rule_id} is still FAILED in the after-scan"
    elif new_ids:
        narrow_conclusion = BaselineConclusion.FIX_ACCEPTED_WITH_NEW_FINDINGS
        narrow_reason = f"{rule_id} no longer fails, but new finding(s) appeared: {new_ids}"
    else:
        narrow_conclusion = BaselineConclusion.FIX_ACCEPTED
        narrow_reason = f"{rule_id} no longer fails in the after-scan; nothing new appeared"

    # --- broad: every actual-grant-relevant rule ---
    broad_hit = sorted(after_failed & _PUBLIC_ACCESS_RELEVANT_RULES)
    if broad_hit:
        broad_conclusion = BaselineConclusion.FIX_REJECTED
        broad_reason = f"public-access-relevant rule(s) still fail: {broad_hit}"
    else:
        broad_conclusion = BaselineConclusion.FIX_ACCEPTED
        broad_reason = "no public-access-relevant rule fails in the after-scan"

    return ScannerOnlyBaseline(
        narrow_conclusion=narrow_conclusion,
        narrow_reason=narrow_reason,
        broad_conclusion=broad_conclusion,
        broad_reason=broad_reason,
    )
