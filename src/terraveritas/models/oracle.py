"""Data model for the security-intent oracle's output.

See verification/oracle.py for the decision process. This module is pure
data — the classification enum and the verdict shape every caller consumes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Classification(StrEnum):
    TRUE_FIX = "true_fix"
    DECEPTIVE_FIX = "deceptive_fix"
    PARTIAL_FIX = "partial_fix"
    REGRESSION = "regression"
    INVALID_CONFIGURATION = "invalid_configuration"
    INCONCLUSIVE = "inconclusive"


class Confidence(StrEnum):
    """Reflects evidence *completeness* for the checks this oracle actually
    performs — never an AI-generated probability, and never a statement
    about the invariant's own disclosed scope gaps (an invariant's
    known_gaps, e.g. S3 Access Points for S3_PUBLIC_ACCESS_EXPOSURE, can
    make a HIGH-confidence verdict wrong in ways this field says nothing
    about — see the invariant's own documentation)."""

    HIGH = "high"
    """Both plans reached PLAN_SUCCESS, both invariant evaluations resolved
    to PASS/FAIL (neither UNKNOWN), and at least one scanner's differential
    evidence was available to check for scanner-visible corroboration/
    regression."""

    MEDIUM = "medium"
    """Both plans succeeded and both invariant evaluations resolved, but no
    scanner differential evidence was available — regression detection via
    scanner evidence and DECEPTIVE_FIX detection were both unavailable."""

    LOW = "low"
    """A classification was still reached, but on incomplete evidence —
    typically INCONCLUSIVE or INVALID_CONFIGURATION, or a REGRESSION/
    PARTIAL_FIX verdict reached without differential corroboration."""


@dataclass(frozen=True, slots=True)
class OracleVerdict:
    classification: Classification
    confidence: Confidence
    invariant_id: str
    resource_address: str
    evidence_used: list[str] = field(default_factory=list)
    """Human-readable labels for each evidence source actually consulted,
    e.g. "before plan (PLAN_SUCCESS)", "checkov differential"."""
    reasons: list[str] = field(default_factory=list)
    """Ordered list of the specific facts that drove this classification —
    always non-empty, even for INCONCLUSIVE."""
    remaining_uncertainty: list[str] = field(default_factory=list)
    """What is NOT known, or what evidence sources disagreed — always
    populated when applicable, never omitted to make a verdict look more
    certain than the evidence supports."""
