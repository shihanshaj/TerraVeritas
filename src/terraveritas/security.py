"""Shared security utilities: subprocess environment sanitization and
credential redaction for stored/logged output.

Consolidated here (rather than duplicated per-module) specifically so this
file is the one place a security reviewer needs to read to audit both
concerns — see SECURITY.md for the full threat model this implements.
"""

from __future__ import annotations

import os
import re
from typing import Any

# Environment variables that could carry real cloud credentials into a
# subprocess that scans or plans untrusted, potentially malicious Terraform.
# Stripped unconditionally before spawning ANY scanner or Terraform
# subprocess — never passed through from the parent process on the
# assumption that "this tool probably doesn't need them".
SENSITIVE_ENV_VAR_NAMES: frozenset[str] = frozenset(
    {
        "AWS_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    }
)


def sanitized_subprocess_env() -> dict[str, str]:
    """A copy of the current environment with all known credential-bearing
    variables removed, plus IMDS lookups disabled as defense in depth. Used
    for subprocesses (scanners) that should need no cloud credentials at
    all to do static analysis — unlike TerraformPlanner's env (which
    additionally injects fake credentials because the AWS provider needs
    *some* configured value to initialize), this only strips."""
    env = os.environ.copy()
    for var in SENSITIVE_ENV_VAR_NAMES:
        env.pop(var, None)
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    return env


# --- Credential redaction for stored/logged output ---

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(secret|password|passwd|private_key|api_key|apikey|access_key|auth_token|"
    r"session_token|client_secret|bearer)",
    re.IGNORECASE,
)

_AWS_ACCESS_KEY_ID_PATTERN = re.compile(
    r"\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b"
)
_PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
)
_BEARER_TOKEN_PATTERN = re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)

REDACTED = "[REDACTED]"


def _redact_string(value: str) -> str:
    value = _PEM_PRIVATE_KEY_PATTERN.sub(REDACTED, value)
    value = _AWS_ACCESS_KEY_ID_PATTERN.sub(REDACTED, value)
    value = _BEARER_TOKEN_PATTERN.sub(f"Bearer {REDACTED}", value)
    return value


def redact_secrets(value: Any) -> Any:
    """Recursively redact credential-shaped content from a JSON-like
    structure (dict/list/str/primitives) before it is written to disk or a
    log. Two strategies, combined: (1) any dict value whose KEY name looks
    sensitive (secret, password, private_key, access_key, ...) is redacted
    regardless of its shape — directly relevant to this project's own
    domain, since Terraform's own provider/IAM blocks use exactly these
    field names; (2) any string value, regardless of key, is scanned for
    recognizable credential shapes (AWS access key IDs, PEM private key
    blocks, bearer tokens) that can appear embedded in scanner evidence or
    subprocess error text with no informative key name at all."""
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            if isinstance(k, str) and _SENSITIVE_KEY_PATTERN.search(k):
                result[k] = REDACTED if v is not None else v
            else:
                result[k] = redact_secrets(v)
        return result
    if isinstance(value, list):
        return [redact_secrets(v) for v in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value
