"""BEFORE/AFTER scanner-evidence comparison.

See the module docstring in terraveritas.models.diff for what each output
bucket means. This module implements exactly the two-tier algorithm
described there: exact-identity multiset matching, then a narrow,
confidence-scoped relocation-candidate pass over what's left. Nothing
fuzzier than that — string/content similarity heuristics were deliberately
rejected (see project notes) as a source of false confidence.
"""

from __future__ import annotations

from collections import defaultdict

from terraveritas.models.diff import (
    DifferentialResult,
    NewFinding,
    PersistentFinding,
    RelocatedFinding,
    RemovedFinding,
)
from terraveritas.models.finding import Finding, FindingOutcome, ScanResult, ScanStatus

IdentityKey = tuple[str, str | None]
RelocationKey = tuple[str, str | None]


def compare_scan_results(before: ScanResult, after: ScanResult) -> DifferentialResult:
    """Compare two ScanResults from the same scanner.

    Raises ValueError if either scan did not complete successfully, or if
    the two results are from different scanners — both are situations where
    proceeding would mean treating an absence of evidence as evidence of
    absence, which this project explicitly refuses to do.
    """
    if before.scanner_name != after.scanner_name:
        raise ValueError(
            f"cannot compare results from different scanners: "
            f"before={before.scanner_name!r}, after={after.scanner_name!r}"
        )
    if before.status != ScanStatus.SUCCESS:
        raise ValueError(
            f"before scan did not succeed (status={before.status.value}); "
            "no reliable evidence of prior state to compare against"
        )
    if after.status != ScanStatus.SUCCESS:
        raise ValueError(
            f"after scan did not succeed (status={after.status.value}); "
            "no reliable evidence of repaired state to compare against"
        )

    scanner_name = before.scanner_name
    before_failed = [f for f in before.findings if f.outcome == FindingOutcome.FAILED]
    after_failed = [f for f in after.findings if f.outcome == FindingOutcome.FAILED]

    persistent, unmatched_before, unmatched_after = _match_exact(before_failed, after_failed)
    relocated, still_removed_before, still_new_after = _match_relocation_candidates(
        unmatched_before, unmatched_after
    )

    removed = [
        _build_removed(f, after.findings) for f in still_removed_before
    ]
    new = [NewFinding(after=f) for f in still_new_after]

    return DifferentialResult(
        scanner_name=scanner_name,
        removed=removed,
        persistent=persistent,
        new=new,
        relocated=relocated,
    )


def _identity_key(f: Finding) -> IdentityKey:
    return (f.rule_id, f.resource_id)


def _relocation_key(f: Finding) -> RelocationKey:
    return (f.rule_id, f.resource_type)


def _match_exact(
    before_failed: list[Finding], after_failed: list[Finding]
) -> tuple[list[PersistentFinding], list[Finding], list[Finding]]:
    """Tier 1: exact (rule_id, resource_id) match, multiset-based so
    duplicate identical findings on either side are paired up rather than
    collapsed or dropped."""
    before_buckets: dict[IdentityKey, list[Finding]] = defaultdict(list)
    for f in before_failed:
        before_buckets[_identity_key(f)].append(f)
    after_buckets: dict[IdentityKey, list[Finding]] = defaultdict(list)
    for f in after_failed:
        after_buckets[_identity_key(f)].append(f)

    persistent: list[PersistentFinding] = []
    unmatched_before: list[Finding] = []
    unmatched_after: list[Finding] = []

    for key in set(before_buckets) | set(after_buckets):
        b_list = before_buckets.get(key, [])
        a_list = after_buckets.get(key, [])
        n = min(len(b_list), len(a_list))
        for i in range(n):
            persistent.append(PersistentFinding(before=b_list[i], after=a_list[i]))
        unmatched_before.extend(b_list[n:])
        unmatched_after.extend(a_list[n:])

    return persistent, unmatched_before, unmatched_after


def _match_relocation_candidates(
    unmatched_before: list[Finding], unmatched_after: list[Finding]
) -> tuple[list[RelocatedFinding], list[Finding], list[Finding]]:
    """Tier 2: among what's left, group by (rule_id, resource_type). Only an
    unambiguous 1:1 group becomes a relocation candidate; a key with more
    than one candidate on either side is left unresolved rather than guessed."""
    before_groups: dict[RelocationKey, list[Finding]] = defaultdict(list)
    for f in unmatched_before:
        before_groups[_relocation_key(f)].append(f)
    after_groups: dict[RelocationKey, list[Finding]] = defaultdict(list)
    for f in unmatched_after:
        after_groups[_relocation_key(f)].append(f)

    relocated: list[RelocatedFinding] = []
    relocated_before_ids: set[int] = set()
    relocated_after_ids: set[int] = set()

    for key in set(before_groups) & set(after_groups):
        b_list = before_groups[key]
        a_list = after_groups[key]
        if len(b_list) == 1 and len(a_list) == 1 and b_list[0].resource_id != a_list[0].resource_id:
            before_item, after_item = b_list[0], a_list[0]
            relocated.append(
                RelocatedFinding(
                    before=before_item,
                    after=after_item,
                    note=(
                        "unambiguous match on (rule_id, resource_type) with a different "
                        "resource address; consistent with a rename/move, not confirmed"
                    ),
                )
            )
            relocated_before_ids.add(id(before_item))
            relocated_after_ids.add(id(after_item))

    still_before = [f for f in unmatched_before if id(f) not in relocated_before_ids]
    still_after = [f for f in unmatched_after if id(f) not in relocated_after_ids]

    return relocated, still_before, still_after


def _build_removed(before_finding: Finding, after_all_findings: list[Finding]) -> RemovedFinding:
    resource_still_present = any(
        f.resource_id is not None and f.resource_id == before_finding.resource_id
        for f in after_all_findings
    )
    same_identity_now_passes = any(
        f.rule_id == before_finding.rule_id
        and f.resource_id == before_finding.resource_id
        and f.outcome == FindingOutcome.PASSED
        for f in after_all_findings
    )
    return RemovedFinding(
        before=before_finding,
        resource_still_present_in_after=resource_still_present,
        same_identity_now_passes=same_identity_now_passes,
    )
