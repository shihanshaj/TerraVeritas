"""Scanner adapter interface.

Every adapter turns "run this scanner against this directory" into a
ScanResult. Expected failure modes (missing binary, timeout, unparseable
output) are represented as ScanStatus values on the returned ScanResult, not
raised as exceptions — the oracle needs to reason about a scanner having
failed exactly the same way it reasons about a scanner having found nothing.
Only truly exceptional/programmer errors (e.g. invalid arguments) raise.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path

from terraveritas.models.finding import ParsedScanOutput, ScanResult, ScanStatus
from terraveritas.security import sanitized_subprocess_env


class ScannerAdapter(ABC):
    """Base class for all scanner adapters."""

    #: Human-readable scanner name, used in Finding.scanner_name.
    name: str

    #: Executable to look up on PATH before attempting to run.
    executable: str

    def scan(self, target_dir: Path, *, timeout_seconds: float = 60.0) -> ScanResult:
        if not target_dir.is_dir():
            return ScanResult(
                scanner_name=self.name,
                scanner_version=self._safe_version(),
                target_path=str(target_dir),
                status=ScanStatus.INVALID_TARGET,
                error_message=f"target directory does not exist: {target_dir}",
            )

        if shutil.which(self.executable) is None:
            return ScanResult(
                scanner_name=self.name,
                scanner_version="unknown",
                target_path=str(target_dir),
                status=ScanStatus.SCANNER_NOT_FOUND,
                error_message=f"executable not found on PATH: {self.executable}",
            )

        command = self._build_command(target_dir)
        started_at = datetime.now(UTC)
        try:
            completed = subprocess.run(  # noqa: S603 - command is built from fixed args, no shell
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                env=sanitized_subprocess_env(),
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner_name=self.name,
                scanner_version=self._safe_version(),
                target_path=str(target_dir),
                status=ScanStatus.TIMEOUT,
                command=command,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error_message=f"scan exceeded {timeout_seconds}s timeout",
            )
        except OSError as exc:
            return ScanResult(
                scanner_name=self.name,
                scanner_version=self._safe_version(),
                target_path=str(target_dir),
                status=ScanStatus.EXECUTION_ERROR,
                command=command,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error_message=str(exc),
            )

        finished_at = datetime.now(UTC)

        if not self._is_success_exit_code(completed.returncode):
            return ScanResult(
                scanner_name=self.name,
                scanner_version=self._safe_version(),
                target_path=str(target_dir),
                status=ScanStatus.EXECUTION_ERROR,
                command=command,
                started_at=started_at,
                finished_at=finished_at,
                exit_code=completed.returncode,
                error_message=completed.stderr.strip() or "non-zero exit with no stderr output",
            )

        try:
            parsed = self._parse_output(completed.stdout, scan_timestamp=finished_at)
        except (ValueError, KeyError, RecursionError) as exc:
            # RecursionError is a RuntimeError subclass, not a ValueError —
            # caught explicitly so pathologically deep JSON nesting (e.g.
            # from a maliciously crafted or degenerately complex Terraform
            # module that causes the scanner to emit deeply nested output)
            # is classified as OUTPUT_PARSE_ERROR rather than crashing the
            # whole scan call. See SECURITY.md.
            return ScanResult(
                scanner_name=self.name,
                scanner_version=self._safe_version(),
                target_path=str(target_dir),
                status=ScanStatus.OUTPUT_PARSE_ERROR,
                command=command,
                started_at=started_at,
                finished_at=finished_at,
                exit_code=completed.returncode,
                error_message=f"failed to parse scanner output: {exc}",
            )

        # Every file in the target failed to parse as IaC: reporting this as a
        # plain SUCCESS with zero findings would be indistinguishable from a
        # genuinely clean scan. Surface it as its own status instead.
        status = (
            ScanStatus.TARGET_UNPARSEABLE
            if not parsed.findings and parsed.unparseable_files
            else ScanStatus.SUCCESS
        )

        return ScanResult(
            scanner_name=self.name,
            scanner_version=self._safe_version(),
            target_path=str(target_dir),
            status=status,
            findings=parsed.findings,
            unparseable_files=parsed.unparseable_files,
            command=command,
            started_at=started_at,
            finished_at=finished_at,
            exit_code=completed.returncode,
        )

    def _safe_version(self) -> str:
        """Best-effort version lookup that never raises.

        Version info is diagnostic metadata attached to evidence; failing to
        obtain it must never prevent a scan from proceeding or being reported.
        """
        try:
            return self._get_version()
        except Exception:  # noqa: BLE001 - version lookup is best-effort by design
            return "unknown"

    @abstractmethod
    def _get_version(self) -> str:
        """Return the installed scanner's version string."""

    @abstractmethod
    def _build_command(self, target_dir: Path) -> list[str]:
        """Build the subprocess argv for scanning `target_dir`."""

    @abstractmethod
    def _is_success_exit_code(self, returncode: int) -> bool:
        """Whether this exit code represents a completed scan (findings or not).

        Many scanners exit non-zero when they *find something*, which is not
        an execution failure. This must distinguish "scan ran, found issues"
        from "scan could not run".
        """

    @abstractmethod
    def _parse_output(self, stdout: str, *, scan_timestamp: datetime) -> ParsedScanOutput:
        """Parse raw stdout into normalized findings plus any unparseable files."""
