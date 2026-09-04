"""Data model for a scanner-only baseline verdict.

What a CI gate that trusted Checkov's re-scan alone — no Terraform plan, no
invariant, no oracle — would conclude about a repair. Exists to make
explicit, per case, whether TerraVeritas's own verdict adds anything beyond
what a re-scan already shows. See
docs/scanner_only_baseline_comparison.md for the analysis this was built to
support, including why a naive "broad" baseline had to be corrected before
it was fair (see evaluation/scanner_baseline.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class BaselineConclusion(StrEnum):
    FIX_ACCEPTED = "fix_accepted"
    """The relevant rule(s) no longer fail in the after-scan, and nothing
    new appeared."""

    FIX_REJECTED = "fix_rejected"
    """A relevant rule still fails in the after-scan."""

    FIX_ACCEPTED_WITH_NEW_FINDINGS = "fix_accepted_with_new_findings"
    """The relevant rule(s) no longer fail, but the differential shows at
    least one new failing finding the scanner didn't report before."""

    NO_FINDING_TO_CHECK = "no_finding_to_check"
    """No security finding was originally reported for this case (e.g. an
    unrelated feature request) — a scanner-only gate has no basis to
    evaluate it at all. Narrow baseline only; the broad baseline always has
    something to check, since it isn't scoped to one originally-reported
    rule."""

    NO_FINDING_TO_CHECK_BUT_NEW_FINDINGS = "no_finding_to_check_but_new_findings"
    """As above, but the differential shows new failing finding(s) anyway."""


@dataclass(frozen=True, slots=True)
class ScannerOnlyBaseline:
    narrow_conclusion: BaselineConclusion
    narrow_reason: str
    """Re-checks only the ONE originally-reported rule_id -- how most real
    CI integrations actually work (a required-status-check tied to one
    specific rule ID)."""

    broad_conclusion: BaselineConclusion
    broad_reason: str
    """Re-checks every rule that fires on an ACTUAL public-access grant,
    regardless of which one was originally reported -- a more thorough
    scanner-only gate, still using nothing but Checkov's own output."""
