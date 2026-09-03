"""Experiment and case identifier scheme.

experiment_id encodes the run date and a descriptive slug, so runs sort
chronologically and are self-describing without opening a manifest.
case_id encodes the matrix cell (so a record's experimental condition is
readable from its filename alone) plus a sequential index, and a content
hash of the rendered prompt for exact-duplicate detection across runs.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime


def make_experiment_id(slug: str, *, on: date | None = None) -> str:
    run_date = on or datetime.now(UTC).date()
    return f"{run_date.isoformat()}-{slug}"


def make_case_id(cell_label: str, index: int) -> str:
    return f"{cell_label}-{index:03d}"


def content_hash(text: str) -> str:
    """SHA-256 of prompt/output text, for exact-duplicate detection and
    byte-level provenance verification across replication runs."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
