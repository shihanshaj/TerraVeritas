"""QA audit: large-file input handling — never previously tested anywhere
in this project. Generates a genuinely large Terraform file (300 buckets,
~2400 lines) and confirms Checkov and the differential engine handle it
correctly and within a sane time bound, rather than hanging or crashing."""

from __future__ import annotations

import time
from pathlib import Path

from terraveritas.differential.scanner_diff import compare_scan_results
from terraveritas.scanners.checkov import CheckovAdapter

_BUCKET_COUNT = 300


def _generate_large_config(*, public: bool) -> str:
    blocks = []
    for i in range(_BUCKET_COUNT):
        blocks.append(f'resource "aws_s3_bucket" "b{i}" {{\n  bucket = "large-fixture-{i}"\n}}')
        acl = "public-read" if public else "private"
        blocks.append(
            f'resource "aws_s3_bucket_acl" "b{i}" {{\n'
            f"  bucket = aws_s3_bucket.b{i}.id\n"
            f'  acl    = "{acl}"\n'
            "}"
        )
    return "\n\n".join(blocks)


def test_large_file_scans_correctly_and_within_a_sane_time_bound(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(_generate_large_config(public=True))
    adapter = CheckovAdapter()

    started = time.monotonic()
    result = adapter.scan(tmp_path, timeout_seconds=120)
    elapsed = time.monotonic() - started

    assert result.status.value == "success"
    public_read_findings = [f for f in result.findings if f.rule_id == "CKV_AWS_20"]
    assert len(public_read_findings) == _BUCKET_COUNT
    # Not a tight perf assertion — just a sanity bound that it didn't hang.
    assert elapsed < 100, f"large-file scan took {elapsed:.1f}s, expected well under 100s"


def test_large_file_differential_correctly_distinguishes_all_removed_findings(
    tmp_path: Path,
) -> None:
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    before_dir.mkdir()
    after_dir.mkdir()
    (before_dir / "main.tf").write_text(_generate_large_config(public=True))
    (after_dir / "main.tf").write_text(_generate_large_config(public=False))

    adapter = CheckovAdapter()
    before_scan = adapter.scan(before_dir, timeout_seconds=120)
    after_scan = adapter.scan(after_dir, timeout_seconds=120)

    differential = compare_scan_results(before_scan, after_scan)

    removed_acl_findings = [r for r in differential.removed if r.before.rule_id == "CKV_AWS_20"]
    assert len(removed_acl_findings) == _BUCKET_COUNT
    assert all(r.same_identity_now_passes for r in removed_acl_findings)
