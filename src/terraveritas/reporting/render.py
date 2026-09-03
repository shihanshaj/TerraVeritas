"""Human-readable and JSON rendering for CLI output.

The one hard requirement everything here is designed around: a reader must
never be able to mistake INCONCLUSIVE for SAFE. That's enforced by always
printing the classification, an explicit non-safety banner for every
classification except TRUE_FIX, the reasons, the remaining uncertainty,
and a next-step line — never just a bare verdict name.
"""

from __future__ import annotations

from typing import Any

from terraveritas.models.finding import FindingOutcome, ScanResult, ScanStatus
from terraveritas.models.oracle import Classification, OracleVerdict
from terraveritas.models.plan import PlanStatus

_RULE = "=" * 70

_NON_SAFE_BANNERS: dict[Classification, str] = {
    Classification.TRUE_FIX: "",
    Classification.DECEPTIVE_FIX: (
        "⚠ NOT SAFE. Scanner evidence looks improved, but the security "
        "property is still violated. This is exactly the pattern this "
        "tool exists to catch."
    ),
    Classification.PARTIAL_FIX: (
        "⚠ NOT SAFE. The security property remains violated."
    ),
    Classification.REGRESSION: (
        "⚠ NOT SAFE. A new problem was introduced, or the property that "
        "held before now fails."
    ),
    Classification.INVALID_CONFIGURATION: (
        "⚠ NOT EVALUATED. The repaired configuration is not valid "
        "Terraform — the security property could not be checked at all."
    ),
    Classification.INCONCLUSIVE: (
        "⚠ INCONCLUSIVE DOES NOT MEAN SAFE. There was not enough evidence "
        "to determine whether the security property holds. Treat this "
        "exactly as you would treat 'unknown', never as 'probably fine'."
    ),
}

_NEXT_STEPS: dict[Classification, str] = {
    Classification.TRUE_FIX: (
        "Per this project's documented policy, TRUE_FIX is the only "
        "classification suitable for automated progression (e.g. "
        "auto-merge). No further action required for this check."
    ),
    Classification.DECEPTIVE_FIX: "Block. Do not merge. Requires human security review.",
    Classification.PARTIAL_FIX: "Block. Do not merge. Requires human security review.",
    Classification.REGRESSION: "Block. Do not merge. Requires human security review.",
    Classification.INVALID_CONFIGURATION: (
        "Fix the Terraform syntax/schema errors and re-run — the security "
        "property cannot be assessed until the configuration is valid."
    ),
    Classification.INCONCLUSIVE: (
        "Block automated progression. Require human review. Do not treat "
        "as passing — see 'remaining_uncertainty' below for exactly what "
        "evidence is missing."
    ),
}


def render_scan_human(result: ScanResult) -> str:
    lines = [
        f"Scanner: {result.scanner_name} {result.scanner_version}",
        f"Status: {result.status.value}",
    ]
    if result.status != ScanStatus.SUCCESS:
        lines.append(f"Detail: {result.error_message or '(no further detail)'}")
        return "\n".join(lines)

    failed = [f for f in result.findings if f.outcome == FindingOutcome.FAILED]
    passed = [f for f in result.findings if f.outcome == FindingOutcome.PASSED]
    lines.append(f"Findings: {len(failed)} failed, {len(passed)} passed")
    for f in failed:
        resource = f.resource_id or "(no resource)"
        lines.append(f"  FAIL {f.rule_id}  {resource}  {f.description}")
    return "\n".join(lines)


def render_scan_json(result: ScanResult) -> dict[str, Any]:
    return {
        "scanner_name": result.scanner_name,
        "scanner_version": result.scanner_version,
        "status": result.status.value,
        "error_message": result.error_message,
        "findings": [
            {
                "rule_id": f.rule_id,
                "outcome": f.outcome.value,
                "resource_id": f.resource_id,
                "description": f.description,
            }
            for f in result.findings
        ],
    }


def render_plan_failure_human(status: PlanStatus, error_message: str | None, hint: str) -> str:
    lines = [
        f"Terraform plan status: {status.value}",
        f"Detail: {error_message or '(no further detail)'}",
        f"Hint: {hint}",
    ]
    return "\n".join(lines)


def render_verdict_human(verdict: OracleVerdict, *, resource_address: str) -> str:
    lines = [
        _RULE,
        f"RESOURCE: {resource_address}",
        f"CLASSIFICATION: {verdict.classification.value.upper()}",
    ]
    banner = _NON_SAFE_BANNERS.get(verdict.classification, "")
    if banner:
        lines.append(banner)
    lines.append("")
    lines.append(
        f"Confidence: {verdict.confidence.value.upper()}  "
        "(reflects evidence completeness only — never a probability that "
        "the infrastructure is secure, and not comparable across different "
        "classifications)"
    )
    lines.append("")
    lines.append("Why this classification was reached:")
    for reason in verdict.reasons:
        lines.append(f"  - {reason}")
    lines.append("")
    lines.append("Remaining uncertainty:")
    if verdict.remaining_uncertainty:
        for item in verdict.remaining_uncertainty:
            lines.append(f"  - {item}")
    else:
        lines.append("  - none noted")
    lines.append("")
    lines.append("Evidence used:")
    for item in verdict.evidence_used:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append(f"Next steps: {_NEXT_STEPS.get(verdict.classification, 'Requires human review.')}")
    lines.append(_RULE)
    return "\n".join(lines)


def render_verdict_json(verdict: OracleVerdict) -> dict[str, Any]:
    return {
        "classification": verdict.classification.value,
        "confidence": verdict.confidence.value,
        "invariant_id": verdict.invariant_id,
        "resource_address": verdict.resource_address,
        "reasons": verdict.reasons,
        "remaining_uncertainty": verdict.remaining_uncertainty,
        "evidence_used": verdict.evidence_used,
        "safe_for_automated_progression": verdict.classification == Classification.TRUE_FIX,
    }
