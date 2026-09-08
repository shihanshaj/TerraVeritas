"""Computes what a scanner-only baseline would conclude about a repair —
see models/baseline.py and docs/scanner_only_baseline_comparison.md.

Two baselines are computed, not one, because a single "trust the scanner"
definition hides an important distinction: a narrow, single-rule CI gate
(the realistic common case) is a much weaker comparison than a thorough
re-scan. Both are computed from real Checkov before/after scan evidence
only — never from the invariant, the plan, or the oracle.

PUBLIC_ACCESS_RELEVANT_RULES is scoped to S3_PUBLIC_ACCESS_EXPOSURE, the
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

PUBLIC_ACCESS_RELEVANT_RULES = {
    "CKV_AWS_20",  # ACL public READ
    "CKV_AWS_57",  # ACL public WRITE
    "CKV_AWS_70",  # bucket policy allows any principal
    "CKV2_AWS_43",  # ACL allows all Authenticated users
    "CKV_AWS_375",  # ACL global view
}

# IAM_EXCESSIVE_PRIVILEGE_EXPOSURE-relevant Checkov rules -- every rule
# confirmed (empirically, via a real Checkov 3.3.16 scan of
# fixtures/terraform/iam_exp_a_admin_wildcard during the IAM/network
# experimental phase, not assumed from documentation) to fire on a bare
# Effect=Allow/Action="*"/Resource="*" inline policy statement. All are
# document-level checks on the policy resource, not per-statement --
# Checkov does not distinguish which statement within a multi-statement
# policy triggered them.
IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES = {
    "CKV_AWS_62",  # full admin ("*"/"*") privileges
    "CKV_AWS_63",  # "*" as a statement's actions
    "CKV_AWS_286",  # privilege escalation
    "CKV_AWS_287",  # credentials exposure
    "CKV_AWS_288",  # data exfiltration
    "CKV_AWS_289",  # permissions management / resource exposure
    "CKV_AWS_290",  # write access without constraints
    "CKV_AWS_355",  # "*" as a statement's resource
    "CKV2_AWS_40",  # full IAM privileges
}

# NETWORK_SENSITIVE_PORT_EXPOSURE-relevant Checkov rules -- confirmed
# empirically against a real Checkov 3.3.16 scan during the same
# experimental phase. Deliberately NOT a full match for this invariant's
# own _SENSITIVE_PORTS set {22, 20, 21, 3306, 3389}: Checkov 3.3.16's
# default AWS Terraform ruleset ships dedicated per-port ingress checks
# only for 22 (CKV_AWS_24), 3389 (CKV_AWS_25), 80 (CKV_AWS_260, not a
# sensitive port for this invariant), and protocol -1 / all traffic
# (CKV_AWS_277) -- there is NO Checkov rule for ports 20, 21, or 3306 in
# this version, confirmed by inspecting
# checkov/terraform/checks/resource/aws/ directly, not by a finding's
# absence alone. A security group open on 3306 (MySQL) is therefore a
# case Checkov's default policy set cannot flag at all, while this
# invariant can -- see docs/iam_network_experiment_report.md for the
# real experimental case this was discovered from (net_exp_b_db_port_open).
NETWORK_SENSITIVE_PORT_RELEVANT_RULES = {
    "CKV_AWS_24",  # SSH (22) open to 0.0.0.0/0 or ::/0
    "CKV_AWS_25",  # RDP (3389) open to 0.0.0.0/0 or ::/0
    "CKV_AWS_277",  # all protocols/ports (-1) open to 0.0.0.0/0 or ::/0
}


def compute_scanner_only_baseline(
    *,
    rule_id: str | None,
    after_scan: ScanResult,
    differential: DifferentialResult,
    broad_relevant_rules: set[str] | None = None,
) -> ScannerOnlyBaseline:
    """`broad_relevant_rules` defaults to `PUBLIC_ACCESS_RELEVANT_RULES`,
    preserving the exact prior behavior for every existing caller (none of
    which passed this parameter before it existed). Pass
    `IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES` or
    `NETWORK_SENSITIVE_PORT_RELEVANT_RULES` for those invariants' own
    experiments -- using the S3 set for a non-S3 case would silently
    report `FIX_ACCEPTED` regardless of the real outcome, since none of
    those rule IDs could ever appear in a non-S3 scan."""
    relevant_rules = (
        broad_relevant_rules if broad_relevant_rules is not None else PUBLIC_ACCESS_RELEVANT_RULES
    )
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
    broad_hit = sorted(after_failed & relevant_rules)
    if broad_hit:
        broad_conclusion = BaselineConclusion.FIX_REJECTED
        broad_reason = f"relevant rule(s) still fail: {broad_hit}"
    else:
        broad_conclusion = BaselineConclusion.FIX_ACCEPTED
        broad_reason = "no relevant rule fails in the after-scan"

    return ScannerOnlyBaseline(
        narrow_conclusion=narrow_conclusion,
        narrow_reason=narrow_reason,
        broad_conclusion=broad_conclusion,
        broad_reason=broad_reason,
    )
