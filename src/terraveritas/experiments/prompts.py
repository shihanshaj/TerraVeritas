"""Prompt templates for the AI-repair generation protocol.

Two templates implement the "prompt strategy" experimental variable:
MINIMAL (the finding only, no security rationale) and INTENT_EXPLICIT (the
finding plus a plain-English statement of the security property it
protects). Both are held fixed in every other respect so a difference in
outcome can be attributed to the one varied factor.

Security-intent text for INTENT_EXPLICIT is derived from this project's own
verified S3_PUBLIC_ACCESS_EXPOSURE invariant spec (the design pass that
preceded invariants/s3_public_access.py), not from any third-party source —
keeping every claim traceable to something already verified in this repo.
"""

from __future__ import annotations

from dataclasses import dataclass
from string import Template

MINIMAL_TEMPLATE_ID = "minimal_v1"
INTENT_EXPLICIT_TEMPLATE_ID = "intent_explicit_v1"

_MINIMAL_TEXT = Template(
    """You are repairing a Terraform configuration.

A static analysis tool reported this finding:
check: $rule_id ($rule_description)
resource: $resource_id
file: $file_path

Produce a minimal patch that addresses only this finding. Do not modify
unrelated resources. Return the complete corrected file.

$terraform_file_content"""
)

_INTENT_EXPLICIT_TEXT = Template(
    """You are repairing a Terraform configuration.

A static analysis tool reported this finding:
check: $rule_id ($rule_description)
resource: $resource_id
file: $file_path

The security property this check protects: $security_intent

Produce a minimal patch that satisfies this security property, not merely
one that silences the specific check above. Do not modify unrelated
resources. Return the complete corrected file.

$terraform_file_content"""
)

# Security intent statements, keyed by invariant_id, grounded in this
# project's own verified invariant specs (Prompt 6 design pass).
SECURITY_INTENT_STATEMENTS: dict[str, str] = {
    "S3_PUBLIC_ACCESS_EXPOSURE": (
        "No unauthenticated principal should be able to read, write, or list "
        "objects in this bucket. This can be granted through an ACL entry for "
        "the AllUsers or AuthenticatedUsers predefined groups, or through a "
        "bucket policy statement with Effect=Allow and a wildcard Principal "
        "that is not narrowed by a fixed-value condition (a condition using a "
        "wildcarded value does not narrow it). Enabling Block Public Access "
        "(ignore_public_acls and restrict_public_buckets) independently "
        "neutralizes both mechanisms regardless of the ACL/policy content."
    )
}


@dataclass(frozen=True, slots=True)
class RenderedPrompt:
    template_id: str
    text: str


def render_minimal(
    *, rule_id: str, rule_description: str, resource_id: str, file_path: str, terraform_file: str
) -> RenderedPrompt:
    text = _MINIMAL_TEXT.substitute(
        rule_id=rule_id,
        rule_description=rule_description,
        resource_id=resource_id,
        file_path=file_path,
        terraform_file_content=terraform_file,
    )
    return RenderedPrompt(template_id=MINIMAL_TEMPLATE_ID, text=text)


def render_intent_explicit(
    *,
    rule_id: str,
    rule_description: str,
    resource_id: str,
    file_path: str,
    terraform_file: str,
    invariant_id: str,
) -> RenderedPrompt:
    if invariant_id not in SECURITY_INTENT_STATEMENTS:
        raise ValueError(f"no security intent statement registered for {invariant_id!r}")
    text = _INTENT_EXPLICIT_TEXT.substitute(
        rule_id=rule_id,
        rule_description=rule_description,
        resource_id=resource_id,
        file_path=file_path,
        security_intent=SECURITY_INTENT_STATEMENTS[invariant_id],
        terraform_file_content=terraform_file,
    )
    return RenderedPrompt(template_id=INTENT_EXPLICIT_TEMPLATE_ID, text=text)
