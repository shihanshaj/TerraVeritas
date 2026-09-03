"""Regression tests: scanner subprocesses must never inherit real cloud
credentials from the parent environment, even though this project's own
scanning is static analysis that shouldn't need them — "assume all input
is potentially malicious" means not trusting that assumption to hold for
every third-party scanner's internals either."""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

from terraveritas.security import SENSITIVE_ENV_VAR_NAMES, sanitized_subprocess_env

from ..scanners.fakes import FakeScannerAdapter


def test_sanitized_env_strips_all_known_sensitive_vars() -> None:
    fake_parent_env = {name: "REAL-SECRET-VALUE" for name in SENSITIVE_ENV_VAR_NAMES}
    fake_parent_env["PATH"] = "/usr/bin"

    with mock.patch.dict(os.environ, fake_parent_env, clear=True):
        sanitized = sanitized_subprocess_env()

    for name in SENSITIVE_ENV_VAR_NAMES:
        assert name not in sanitized, f"{name} leaked into sanitized subprocess env"
    assert sanitized["PATH"] == "/usr/bin"  # non-sensitive vars still pass through
    assert sanitized["AWS_EC2_METADATA_DISABLED"] == "true"


def test_scanner_subprocess_does_not_see_real_credential_from_parent(tmp_path: Path) -> None:
    """End-to-end: a real AWS credential set in this test process's
    environment must not reach the scanner subprocess at all."""
    adapter = FakeScannerAdapter(
        "fake",
        "import os, json; print(json.dumps([{"
        "'rule_id': 'PROBE', 'outcome': 'passed', 'file_path': 'x', "
        "'description': os.environ.get('AWS_SECRET_ACCESS_KEY', 'ABSENT')}]))",
    )

    with mock.patch.dict(
        os.environ, {"AWS_SECRET_ACCESS_KEY": "REAL-SECRET-DO-NOT-LEAK"}, clear=False
    ):
        result = adapter.scan(tmp_path)

    assert result.status.value == "success"
    assert result.findings[0].description == "ABSENT"
