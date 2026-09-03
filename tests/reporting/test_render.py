"""Tests for CLI output rendering.

The one property every test in this file ultimately serves: a reader must
never be able to mistake INCONCLUSIVE for SAFE.
"""

from __future__ import annotations

from terraveritas.models.oracle import Classification, Confidence, OracleVerdict
from terraveritas.reporting.render import render_verdict_human, render_verdict_json


def _verdict(classification: Classification, **overrides: object) -> OracleVerdict:
    defaults: dict[str, object] = {
        "classification": classification,
        "confidence": Confidence.LOW,
        "invariant_id": "S3_PUBLIC_ACCESS_EXPOSURE",
        "resource_address": "aws_s3_bucket.data",
        "evidence_used": ["before plan (plan_success)"],
        "reasons": ["some reason"],
        "remaining_uncertainty": [],
    }
    defaults.update(overrides)
    return OracleVerdict(**defaults)  # type: ignore[arg-type]


def test_inconclusive_human_output_contains_explicit_not_safe_warning() -> None:
    verdict = _verdict(
        Classification.INCONCLUSIVE,
        remaining_uncertainty=[
            "insufficient evidence to determine whether the security property holds"
        ],
    )

    output = render_verdict_human(verdict, resource_address="aws_s3_bucket.data")

    assert "INCONCLUSIVE" in output
    assert "DOES NOT MEAN SAFE" in output
    assert "Block automated progression" in output


def test_inconclusive_never_contains_the_word_safe_without_a_negation() -> None:
    """A stricter, more mechanical check: every occurrence of "safe" in the
    INCONCLUSIVE rendering must be part of a negation ("not safe", "does
    not mean safe") — never a bare, affirmative "safe"."""
    verdict = _verdict(Classification.INCONCLUSIVE)

    output = render_verdict_human(verdict, resource_address="aws_s3_bucket.data").lower()

    for idx in range(len(output)):
        if output[idx : idx + 4] == "safe":
            preceding = output[max(0, idx - 12) : idx]
            assert "not" in preceding or "does" in preceding, (
                f"found un-negated 'safe' near: {output[max(0, idx - 20): idx + 20]!r}"
            )


def test_true_fix_human_output_has_no_warning_banner() -> None:
    verdict = _verdict(
        Classification.TRUE_FIX, confidence=Confidence.HIGH, remaining_uncertainty=[]
    )

    output = render_verdict_human(verdict, resource_address="aws_s3_bucket.data")

    assert "TRUE_FIX" in output
    assert "⚠" not in output
    assert "automated progression" in output


def test_deceptive_fix_human_output_warns_not_safe() -> None:
    verdict = _verdict(Classification.DECEPTIVE_FIX)

    output = render_verdict_human(verdict, resource_address="aws_s3_bucket.data")

    assert "NOT SAFE" in output


def test_json_output_has_explicit_safety_boolean() -> None:
    true_fix = render_verdict_json(_verdict(Classification.TRUE_FIX))
    inconclusive = render_verdict_json(_verdict(Classification.INCONCLUSIVE))

    assert true_fix["safe_for_automated_progression"] is True
    assert inconclusive["safe_for_automated_progression"] is False


def test_json_output_never_marks_anything_but_true_fix_as_safe() -> None:
    for classification in Classification:
        if classification == Classification.TRUE_FIX:
            continue
        rendered = render_verdict_json(_verdict(classification))
        assert rendered["safe_for_automated_progression"] is False, (
            f"{classification} was incorrectly marked safe for automated progression"
        )


def test_every_classification_has_a_human_rendering_with_confidence_caveat() -> None:
    for classification in Classification:
        output = render_verdict_human(_verdict(classification), resource_address="x")
        assert "never a probability" in output
