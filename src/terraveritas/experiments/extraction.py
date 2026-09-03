"""Mechanical extraction of Terraform content from a raw AI model response.

Deliberately dumb: looks for a fenced code block (```hcl, ```terraform, or
a bare ```), and returns its content verbatim. No cleanup, no formatting,
no "fixing" of the model's output — the whole point is that the extracted
text is exactly what the model produced, just with the prose/fence wrapper
mechanically stripped, so it can be written to a .tf file and run.
"""

from __future__ import annotations

import re

_FENCE_PATTERN = re.compile(r"```(?:hcl|terraform|tf)?\n(.*?)```", re.DOTALL)


def extract_terraform(raw_response: str) -> str:
    """Returns the content of the first fenced code block, or the raw
    response unchanged if no fence is found (some models return bare code
    with no markdown formatting at all)."""
    match = _FENCE_PATTERN.search(raw_response)
    if match is None:
        return raw_response.strip()
    return match.group(1).strip()
