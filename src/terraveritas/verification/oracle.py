"""The security-intent oracle: a pure decision function over evidence.

`classify_repair` takes an invariant evaluated against the original and
repaired configurations, plus (optional) scanner differential evidence, and
returns a Classification with an explicit evidence trail. No I/O, no
orchestration — it doesn't run scanners, evaluate plans, or select which
invariant applies to a given finding. Those are the caller's
responsibility (see module-level scoping note below).

Two safety properties hold by construction, not just by convention:

1. Scanner evidence can only ever DOWNGRADE a verdict (toward DECEPTIVE_FIX
   or REGRESSION) — it is never used to reach TRUE_FIX. TRUE_FIX is
   reachable only through the invariant's own before=FAIL -> after=PASS
   transition (see the decision table in project notes).
2. Any UNKNOWN invariant result on either side short-circuits to
   INCONCLUSIVE before the TRUE_FIX/DECEPTIVE_FIX/PARTIAL_FIX branch is
   even reached — a lack of evidence can never produce a positive verdict.

Scoping assumption the caller must satisfy: the two InvariantResult objects
must already be for the SAME invariant, evaluated against the same logical
resource before and after the repair (their `resource_address` fields may
differ if the resource was renamed — that's fine and expected — but they
must refer to the same physical resource, e.g. via a RelocatedFinding from
the differential engine). This oracle does not attempt to verify that on
its own. Likewise, `differential_results` should be scoped to evidence
relevant to this repair; passing an entire unrelated scan's differential
will make regression detection over-broad (a disclosed, safe-direction
limitation — it can only cause spurious REGRESSION verdicts, never a false
TRUE_FIX/PASS).
"""

from __future__ import annotations

from terraveritas.models.diff import DifferentialResult
from terraveritas.models.invariant import InvariantResult, InvariantStatus
from terraveritas.models.oracle import Classification, Confidence, OracleVerdict
from terraveritas.models.plan import PlanStatus


def classify_repair(
    invariant_before: InvariantResult,
    invariant_after: InvariantResult,
    *,
    before_plan_status: PlanStatus,
    after_plan_status: PlanStatus,
    differential_results: list[DifferentialResult] | None = None,
) -> OracleVerdict:
    if invariant_before.invariant_id != invariant_after.invariant_id:
        raise ValueError(
            "before/after InvariantResults must be for the same invariant: "
            f"{invariant_before.invariant_id!r} != {invariant_after.invariant_id!r}"
        )

    differential_results = differential_results or []
    evidence_used = [
        f"before plan ({before_plan_status.value})",
        f"after plan ({after_plan_status.value})",
        f"before invariant evaluation ({invariant_before.status.value})",
        f"after invariant evaluation ({invariant_after.status.value})",
    ]
    evidence_used += [f"{d.scanner_name} differential" for d in differential_results]

    # --- Priority 1: the repair itself is broken Terraform ---
    if after_plan_status == PlanStatus.PLAN_INVALID_CONFIGURATION:
        return OracleVerdict(
            classification=Classification.INVALID_CONFIGURATION,
            confidence=Confidence.HIGH,
            invariant_id=invariant_after.invariant_id,
            resource_address=invariant_after.resource_address,
            evidence_used=evidence_used,
            reasons=[
                "the repaired configuration is not valid Terraform (PLAN_INVALID_CONFIGURATION)"
            ],
            remaining_uncertainty=[
                "the security property could not be evaluated because the repair itself is broken"
            ],
        )

    # --- Priority 2: regression, checked before the fix outcome itself ---
    has_new_findings, new_findings_notes = _has_relevant_new_findings(differential_results)
    invariant_regressed = (
        invariant_before.status == InvariantStatus.PASS
        and invariant_after.status == InvariantStatus.FAIL
    )
    if has_new_findings or invariant_regressed:
        reasons = []
        if invariant_regressed:
            reasons.append(
                "the invariant was satisfied before the repair and is violated after it"
            )
        reasons.extend(new_findings_notes)
        confidence = Confidence.HIGH if differential_results else Confidence.LOW
        return OracleVerdict(
            classification=Classification.REGRESSION,
            confidence=confidence,
            invariant_id=invariant_after.invariant_id,
            resource_address=invariant_after.resource_address,
            evidence_used=evidence_used,
            reasons=reasons,
            remaining_uncertainty=[
                "regression detection is bounded by what the available scanners check — "
                "a new problem outside their coverage would not be visible here"
            ],
        )

    before_status = invariant_before.status
    after_status = invariant_after.status

    # --- Priority 3: missing invariant evidence never becomes a positive verdict ---
    if before_status == InvariantStatus.UNKNOWN or after_status == InvariantStatus.UNKNOWN:
        reasons = []
        if before_status == InvariantStatus.UNKNOWN:
            reasons.append(f"before-state evaluation inconclusive: {invariant_before.reason}")
        if after_status == InvariantStatus.UNKNOWN:
            reasons.append(f"after-state evaluation inconclusive: {invariant_after.reason}")
        return OracleVerdict(
            classification=Classification.INCONCLUSIVE,
            confidence=Confidence.LOW,
            invariant_id=invariant_after.invariant_id,
            resource_address=invariant_after.resource_address,
            evidence_used=evidence_used,
            reasons=reasons,
            remaining_uncertainty=[
                "insufficient evidence to determine whether the security property holds"
            ],
        )

    looks_improved, disagreement_notes = _scanner_shows_improvement(
        differential_results, invariant_before.resource_address, invariant_after.resource_address
    )
    confidence = Confidence.HIGH if differential_results else Confidence.MEDIUM

    # --- Priority 4: both sides resolved to PASS/FAIL ---
    if before_status == InvariantStatus.FAIL and after_status == InvariantStatus.PASS:
        return OracleVerdict(
            classification=Classification.TRUE_FIX,
            confidence=confidence,
            invariant_id=invariant_after.invariant_id,
            resource_address=invariant_after.resource_address,
            evidence_used=evidence_used,
            reasons=[
                "the invariant was violated before the repair and is satisfied after it",
                invariant_after.reason,
            ],
            remaining_uncertainty=disagreement_notes,
        )

    if before_status == InvariantStatus.FAIL and after_status == InvariantStatus.FAIL:
        if looks_improved:
            return OracleVerdict(
                classification=Classification.DECEPTIVE_FIX,
                confidence=confidence,
                invariant_id=invariant_after.invariant_id,
                resource_address=invariant_after.resource_address,
                evidence_used=evidence_used,
                reasons=[
                    "scanner evidence indicates the related finding was cleared, "
                    "but the security invariant still evaluates to FAIL",
                    invariant_after.reason,
                ],
                remaining_uncertainty=disagreement_notes,
            )
        before_set = set(invariant_before.violated_conditions)
        after_set = set(invariant_after.violated_conditions)
        narrowed = after_set < before_set
        reasons = [f"the invariant remains violated: {invariant_after.reason}"]
        if narrowed:
            reasons.append(
                f"partial narrowing detected: {sorted(before_set - after_set)} resolved, "
                f"{sorted(after_set)} remain"
            )
        else:
            reasons.append(
                "no measurable narrowing detected between before and after — classified as "
                "partial only in the sense that no concealment or new regression was found, "
                "not that progress was proven"
            )
        return OracleVerdict(
            classification=Classification.PARTIAL_FIX,
            confidence=confidence,
            invariant_id=invariant_after.invariant_id,
            resource_address=invariant_after.resource_address,
            evidence_used=evidence_used,
            reasons=reasons,
            remaining_uncertainty=disagreement_notes,
        )

    # invariant_before.status == PASS and invariant_after.status == PASS:
    # the premise "original violated the invariant" doesn't hold.
    return OracleVerdict(
        classification=Classification.INCONCLUSIVE,
        confidence=Confidence.LOW,
        invariant_id=invariant_after.invariant_id,
        resource_address=invariant_after.resource_address,
        evidence_used=evidence_used,
        reasons=[
            "the invariant was already satisfied before the repair — "
            "there was nothing for this invariant to fix"
        ],
        remaining_uncertainty=[
            "if a scanner finding was cleared, it may correspond to a different "
            "security property than this invariant covers"
        ],
    )


def _has_relevant_new_findings(
    differential_results: list[DifferentialResult],
) -> tuple[bool, list[str]]:
    notes = []
    found = False
    for d in differential_results:
        if d.new:
            found = True
            notes.append(f"{d.scanner_name}: {len(d.new)} new finding(s) introduced by the repair")
    return found, notes


def _scanner_shows_improvement(
    differential_results: list[DifferentialResult],
    before_address: str,
    after_address: str,
) -> tuple[bool, list[str]]:
    """Conservative: requires at least one scanner to show the resource's
    finding removed, AND no scanner to show it persistent or merely
    relocated (still failing under a new address) — a single contradicting
    scanner is enough to withhold the "looks improved" signal entirely."""
    saw_removed = False
    saw_contradiction = False
    notes: list[str] = []
    for d in differential_results:
        removed_here = any(r.before.resource_id == before_address for r in d.removed)
        persistent_here = any(
            p.before.resource_id == before_address or p.after.resource_id == after_address
            for p in d.persistent
        )
        relocated_here = any(rl.before.resource_id == before_address for rl in d.relocated)
        if removed_here and not persistent_here and not relocated_here:
            saw_removed = True
        if persistent_here or relocated_here:
            saw_contradiction = True
            notes.append(
                f"{d.scanner_name}: still flags or relocates a finding for this resource"
            )
    return (saw_removed and not saw_contradiction), notes
