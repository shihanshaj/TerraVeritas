"""Data model for BEFORE/AFTER scanner-evidence comparison.

This classifies scanner evidence only — REMOVED does not mean "fixed" and
PERSISTENT does not mean "still broken as originally reported." Deciding
what the evidence *means* for the underlying security property is the
oracle's job (terraveritas.verification), not this module's.
"""

from __future__ import annotations

from dataclasses import dataclass

from terraveritas.models.finding import Finding


@dataclass(frozen=True, slots=True)
class RemovedFinding:
    """A FAILED finding present in BEFORE with no exact-identity match in AFTER.

    The two flags below preserve exactly the evidence the oracle needs to
    distinguish "this specific check now passes on the same resource" from
    "this resource address no longer appears in the evidence at all" —
    collapsing both into a bare removal would throw away information a later
    classification step cannot recover.
    """

    before: Finding
    resource_still_present_in_after: bool
    same_identity_now_passes: bool


@dataclass(frozen=True, slots=True)
class PersistentFinding:
    """The same (rule_id, resource_id) reported FAILED in both BEFORE and AFTER."""

    before: Finding
    after: Finding


@dataclass(frozen=True, slots=True)
class NewFinding:
    """A FAILED finding in AFTER with no exact or relocation-candidate match in BEFORE."""

    after: Finding


@dataclass(frozen=True, slots=True)
class RelocatedFinding:
    """An unmatched BEFORE/AFTER pair sharing (rule_id, resource_type) but not
    resource_id — the unambiguous (exactly one candidate per side) case only.

    This is a *candidate*, not a confirmed identity: nothing in this
    component proves the resource was renamed rather than deleted-and-
    coincidentally-replaced. It exists so that evidence isn't silently split
    into an unrelated-looking REMOVED + NEW pair when a single, unambiguous
    explanation is available.
    """

    before: Finding
    after: Finding
    note: str


@dataclass(frozen=True, slots=True)
class DifferentialResult:
    """The full BEFORE/AFTER comparison for one scanner's evidence.

    Always scoped to a single scanner — evidence from different scanners is
    never combined here, matching the non-merging principle from the
    scanner adapter layer.
    """

    scanner_name: str
    removed: list[RemovedFinding]
    persistent: list[PersistentFinding]
    new: list[NewFinding]
    relocated: list[RelocatedFinding]
