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
    related_resource_addresses: list[str] = field(default_factory=list)
    """Every Terraform resource address this evaluation actually examined to
    reach its verdict — e.g. for S3_PUBLIC_ACCESS_EXPOSURE, the bucket plus
    whichever of its ACL/policy/Block-Public-Access/ownership-controls
    resources were found. `resource_address` above stays the single
    canonical identity for display and correlation; this field exists so a
    caller comparing SCANNER evidence (which a tool like Checkov may
    attribute to a sibling resource — e.g. a bucket policy finding
    reported against the separate `aws_s3_bucket_policy` resource, not the
    bucket itself) knows the full set of addresses that are actually part
    of this security judgment, not just the bucket's own address. Empty by
    default (not [resource_address]) so a caller can tell "this invariant
    doesn't populate this yet" apart from "this invariant examined exactly
    one resource" and fall back accordingly — see
    verification/oracle.py's use of it."""
