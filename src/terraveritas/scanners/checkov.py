"""Checkov adapter.

Behavior below is verified against a real `checkov==3.3.16` install run
against fixtures/terraform/{s3_vulnerable,s3_secure,invalid_hcl,empty_dir},
not assumed from documentation. Three load-bearing, non-obvious findings
from that verification:

1. Checkov exits 0 whenever `summary.failed == 0` — that includes a clean
   scan, a directory with zero .tf files, AND a directory whose only file
   failed to parse. Exit code alone says nothing about whether the target
   was actually evaluated. It exits 1 whenever `summary.failed > 0`. Neither
   is an execution failure; both must be treated as ScanStatus.SUCCESS at
   the adapter level.
2. By default, `checkov -o json` makes an outbound network call to
   api0.prismacloud.io to fetch guideline metadata (used to populate
   `severity`), even with no API key configured. This is a reproducibility
   and security-boundary problem (Prompt 12/15) independent of whether the
   call succeeds. `--skip-download` disables it entirely — verified to
   produce identical finding data with a clean, network-free run. The
   observable cost is that `severity` is None on every finding without a
   Bridgecrew/Prisma account, which is disclosed here rather than silently
   absorbed.
3. The JSON payload has three distinct real shapes:
   (a) normal: {"check_type", "results": {passed_checks, failed_checks,
       skipped_checks, parsing_errors}, "summary", "url"}
   (b) all-content-unparseable: same shape as (a), but passed/failed/skipped
       are all empty and results.parsing_errors lists the broken file(s).
   (c) zero .tf files in the directory: bare {"passed", "failed", "skipped",
       "parsing_errors", "resource_count", "checkov_version"} with NO
       "results" or "check_type" key at all — parsing_output must not assume
       "results" is present.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from terraveritas.models.finding import Finding, FindingOutcome, ParsedScanOutput
from terraveritas.scanners.base import ScannerAdapter

_OUTCOME_BY_RESULT_KEY = {
    "passed_checks": FindingOutcome.PASSED,
    "failed_checks": FindingOutcome.FAILED,
    "skipped_checks": FindingOutcome.SKIPPED,
}


def _resource_type_from_address(resource_id: str | None) -> str | None:
    """Extract the resource type from a Terraform address.

    The resource type is always the segment immediately before the final
    (resource name) segment, regardless of how many `module.<name>.` prefixes
    precede it: "module.storage.aws_s3_bucket.data" -> "aws_s3_bucket", same
    as the unprefixed "aws_s3_bucket.data". Splitting on the *first* dot
    (an earlier version of this function did) incorrectly returns "module"
    for any module-nested resource.
    """
    if not resource_id:
        return None
    parts = resource_id.split(".")
    if len(parts) < 2:
        return None
    return parts[-2]


class CheckovAdapter(ScannerAdapter):
    name = "checkov"
    executable = "checkov"

    def _get_version(self) -> str:
        import shutil
        import subprocess

        # Resolve the absolute path explicitly rather than letting a second,
        # separate PATH lookup happen inside subprocess.run — closes the
        # narrow window between this and scan()'s own shutil.which() check
        # where PATH could theoretically change and resolve to a different
        # binary than the one just verified to exist.
        resolved = shutil.which(self.executable)
        if resolved is None:
            raise FileNotFoundError(f"executable not found on PATH: {self.executable}")

        completed = subprocess.run(  # noqa: S603 - resolved absolute path, no shell
            [resolved, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return completed.stdout.strip()

    def _build_command(self, target_dir: Path) -> list[str]:
        return [
            "checkov",
            "-d",
            str(target_dir),
            "-o",
            "json",
            "--compact",
            "--framework",
            "terraform",
            # See module docstring point (2): avoids an outbound network call
            # to Prisma Cloud and keeps scans deterministic/offline. Costs us
            # severity data, which we do not have without a platform account.
            "--skip-download",
        ]

    def _is_success_exit_code(self, returncode: int) -> bool:
        # Verified: 0 = summary.failed == 0 (including zero-resource and
        # all-unparseable cases), 1 = summary.failed > 0. Neither is a
        # scanner execution failure.
        return returncode in (0, 1)

    def _parse_output(self, stdout: str, *, scan_timestamp: datetime) -> ParsedScanOutput:
        payload: dict[str, Any] = json.loads(stdout)

        # Shape (c): zero .tf files in the target — no "results" key at all.
        if "results" not in payload:
            return ParsedScanOutput(findings=[], unparseable_files=[])

        results = payload["results"]
        version = str(payload.get("summary", {}).get("checkov_version", "unknown"))

        findings: list[Finding] = []
        for result_key, outcome in _OUTCOME_BY_RESULT_KEY.items():
            for check in results.get(result_key, []):
                line_range = check.get("file_line_range") or [None, None]
                resource_id = check.get("resource")
                resource_type = _resource_type_from_address(resource_id)
                findings.append(
                    Finding(
                        scanner_name=self.name,
                        scanner_version=version,
                        rule_id=check["check_id"],
                        outcome=outcome,
                        file_path=check.get("file_path", "unknown"),
                        description=check.get("check_name", ""),
                        raw_evidence=check,
                        scan_timestamp=scan_timestamp,
                        severity=check.get("severity"),
                        resource_id=resource_id,
                        resource_type=resource_type,
                        line_start=line_range[0],
                        line_end=line_range[1],
                    )
                )

        unparseable_files = list(results.get("parsing_errors", []))

        return ParsedScanOutput(findings=findings, unparseable_files=unparseable_files)
