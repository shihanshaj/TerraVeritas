"""Captures an environment snapshot at experiment-generation time.

Every RepairRecord carries this snapshot in its `environment` field so a
replication attempt can check whether a version mismatch, not a real
behavioral difference, explains a discrepancy.
"""

from __future__ import annotations

import platform
import re
import subprocess


def capture_environment() -> dict[str, str]:
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "terraform_version": _terraform_version(),
        "checkov_version": _checkov_version(),
        "git_commit": _git_commit(),
    }


def _run(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _terraform_version() -> str:
    output = _run(["terraform", "version"])
    if output is None:
        return "unknown"
    first_line = output.splitlines()[0]
    match = re.search(r"v?(\d+\.\d+\.\d+)", first_line)
    return match.group(1) if match else first_line


def _checkov_version() -> str:
    output = _run(["checkov", "--version"])
    return output if output is not None else "unknown"


def _git_commit() -> str:
    output = _run(["git", "rev-parse", "HEAD"])
    return output if output is not None else "unknown"
