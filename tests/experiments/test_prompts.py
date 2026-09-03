from __future__ import annotations

import pytest

from terraveritas.experiments.prompts import (
    INTENT_EXPLICIT_TEMPLATE_ID,
    MINIMAL_TEMPLATE_ID,
    render_intent_explicit,
    render_minimal,
)

_KWARGS = {
    "rule_id": "CKV_AWS_20",
    "rule_description": "S3 Bucket has an ACL defined which allows public READ access",
    "resource_id": "aws_s3_bucket_acl.data",
    "file_path": "main.tf",
    "terraform_file": 'resource "aws_s3_bucket_acl" "data" { acl = "public-read" }',
}


def test_minimal_template_substitutes_all_fields() -> None:
    prompt = render_minimal(**_KWARGS)

    assert prompt.template_id == MINIMAL_TEMPLATE_ID
    assert "CKV_AWS_20" in prompt.text
    assert "aws_s3_bucket_acl.data" in prompt.text
    assert 'acl = "public-read"' in prompt.text
    # Minimal template must NOT mention the security intent at all.
    assert "unauthenticated" not in prompt.text


def test_intent_explicit_template_includes_security_property() -> None:
    prompt = render_intent_explicit(invariant_id="S3_PUBLIC_ACCESS_EXPOSURE", **_KWARGS)

    assert prompt.template_id == INTENT_EXPLICIT_TEMPLATE_ID
    assert "unauthenticated principal" in prompt.text
    assert "Block Public Access" in prompt.text
    assert "CKV_AWS_20" in prompt.text


def test_intent_explicit_raises_for_unregistered_invariant() -> None:
    with pytest.raises(ValueError, match="no security intent statement"):
        render_intent_explicit(invariant_id="NOT_A_REAL_INVARIANT", **_KWARGS)


def test_templates_are_the_only_difference_between_strategies() -> None:
    """The two prompt strategies must differ only in the security-intent
    block — everything else (finding text, instructions, file content)
    must be identical, or the "prompt strategy" variable would be
    confounded with unrelated wording changes."""
    minimal = render_minimal(**_KWARGS).text
    explicit = render_intent_explicit(invariant_id="S3_PUBLIC_ACCESS_EXPOSURE", **_KWARGS).text

    assert _KWARGS["terraform_file"] in minimal
    assert _KWARGS["terraform_file"] in explicit
    assert "Produce a minimal patch" in minimal
    assert "Produce a minimal patch" in explicit
