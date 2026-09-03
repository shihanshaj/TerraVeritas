"""Data model for security invariant evaluation results.

An invariant answers "does the AWS security property actually hold" from
the resolved plan, independent of any scanner's rule logic (see Prompt 6's
design notes). InvariantStatus is intentionally 3-valued — PASS/FAIL/UNKNOWN
— so "we couldn't evaluate this" is a distinct, visible state, never
collapsed into either PASS or FAIL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class InvariantStatus(StrEnum):
    PASS = "pass"  # noqa: S105 - enum value, not a credential
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class InvariantResult:
    invariant_id: str
    resource_address: str
    status: InvariantStatus
    violated_conditions: list[str] = field(default_factory=list)
    """Which named sub-conditions of the invariant are currently violated —
    empty when status is PASS. Non-empty on FAIL. Used by the oracle to
    detect partial narrowing between a before/after pair (see
    verification/oracle.py) without re-deriving invariant-specific logic."""
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    """Raw evidence snapshot (resolved attribute values, not full plan JSON)
    kept for transparency and debugging — never used as the sole basis for
    a downstream decision without going through `status`/`violated_conditions`."""
