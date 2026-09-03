"""Tests for the evaluation harness itself.

Uses small, hand-computed label sets so every metric can be checked against
values worked out by hand — this validates the harness's arithmetic, not
any claim about oracle accuracy (no real ground truth exists yet; see
project notes on the verification pass for Prompt 8).
"""

from __future__ import annotations

import pytest

from terraveritas.evaluation.metrics import (
    LabeledCase,
    evaluate,
    find_disagreements,
    stratified_split,
)
from terraveritas.models.oracle import Classification

TF = Classification.TRUE_FIX
DF = Classification.DECEPTIVE_FIX
PF = Classification.PARTIAL_FIX
IC = Classification.INCONCLUSIVE


def case(case_id: str, predicted: Classification, actual: Classification) -> LabeledCase:
    return LabeledCase(case_id=case_id, predicted=predicted, actual=actual)


def test_confusion_matrix_hand_computed() -> None:
    # 2 correct TRUE_FIX, 1 TRUE_FIX predicted but actually DECEPTIVE_FIX,
    # 1 DECEPTIVE_FIX predicted but actually TRUE_FIX.
    cases = [
        case("1", TF, TF),
        case("2", TF, TF),
        case("3", TF, DF),
        case("4", DF, TF),
        case("5", DF, DF),
    ]

    report = evaluate(cases)

    assert report.confusion_matrix[TF][TF] == 2
    assert report.confusion_matrix[DF][TF] == 1  # actual=DF, predicted=TF
    assert report.confusion_matrix[TF][DF] == 1  # actual=TF, predicted=DF
    assert report.confusion_matrix[DF][DF] == 1
    assert report.n == 5
    assert report.accuracy == pytest.approx(3 / 5)


def test_precision_recall_f1_hand_computed() -> None:
    # TRUE_FIX: predicted 3 times (2 correct, 1 wrong) -> precision 2/3
    #           actual 3 times (2 caught, 1 missed as DF) -> recall 2/3
    cases = [
        case("1", TF, TF),
        case("2", TF, TF),
        case("3", TF, DF),  # false positive for TF, false negative for DF... wait actual=DF
        case("4", DF, TF),  # false negative for TF (actual TF, predicted DF)
        case("5", DF, DF),
    ]
    # actual TF: cases 1,2,4 (3 total). predicted TF correctly for 1,2 -> recall 2/3
    # predicted TF: cases 1,2,3 (3 total). correct for 1,2 -> precision 2/3

    report = evaluate(cases)
    tf_metrics = report.per_class[TF]

    assert tf_metrics.support == 3
    assert tf_metrics.true_positives == 2
    assert tf_metrics.false_positives == 1  # case 3: predicted TF, actual DF
    assert tf_metrics.false_negatives == 1  # case 4: actual TF, predicted DF
    assert tf_metrics.precision == pytest.approx(2 / 3)
    assert tf_metrics.recall == pytest.approx(2 / 3)
    assert tf_metrics.f1 == pytest.approx(2 / 3)


def test_false_positive_and_negative_rates() -> None:
    cases = [
        case("1", TF, TF),
        case("2", TF, DF),  # FP for TF
        case("3", DF, DF),
        case("4", DF, DF),
    ]
    report = evaluate(cases)
    tf_metrics = report.per_class[TF]

    # TF: TP=1, FP=1, FN=0, TN=2 (cases 3,4 correctly not predicted TF)
    assert tf_metrics.false_positive_rate == pytest.approx(1 / 3)  # FP/(FP+TN) = 1/3
    assert tf_metrics.false_negative_rate == pytest.approx(0.0)


def test_undefined_precision_when_class_never_predicted() -> None:
    cases = [case("1", TF, TF), case("2", TF, DF)]
    report = evaluate(cases)

    # DECEPTIVE_FIX is never predicted at all.
    assert report.per_class[DF].precision is None
    assert report.per_class[DF].recall == pytest.approx(0.0)  # 0 of 1 actual DF caught


def test_macro_averages_zero_division_convention() -> None:
    """A class with undefined precision contributes 0 to the macro average
    (documented zero_division=0 convention), not excluded from it."""
    cases = [case("1", TF, TF), case("2", TF, DF)]
    report = evaluate(cases)

    # TF: precision=0.5, recall=1.0, f1=2*0.5*1/(1.5)=0.667
    # DF: precision=None->0, recall=0.0, f1=None->0
    # PARTIAL_FIX/REGRESSION/etc have support=0, excluded from macro entirely.
    assert report.macro_precision == pytest.approx((0.5 + 0.0) / 2)
    assert report.macro_recall == pytest.approx((1.0 + 0.0) / 2)


def test_evaluate_raises_on_empty_input() -> None:
    with pytest.raises(ValueError, match="empty"):
        evaluate([])


def test_find_disagreements() -> None:
    cases = [case("1", TF, TF), case("2", TF, DF), case("3", DF, DF)]

    disagreements = find_disagreements(cases)

    assert [c.case_id for c in disagreements] == ["2"]


def test_stratified_split_preserves_class_balance() -> None:
    cases = (
        [case(f"tf-{i}", TF, TF) for i in range(10)]
        + [case(f"df-{i}", DF, DF) for i in range(4)]
    )

    dev, eval_set = stratified_split(cases, eval_fraction=0.2, seed=42)

    dev_tf = sum(1 for c in dev if c.actual == TF)
    eval_tf = sum(1 for c in eval_set if c.actual == TF)
    dev_df = sum(1 for c in dev if c.actual == DF)
    eval_df = sum(1 for c in eval_set if c.actual == DF)

    assert dev_tf + eval_tf == 10
    assert dev_df + eval_df == 4
    assert eval_tf >= 1  # both classes represented in eval, not just the majority one
    assert eval_df >= 1


def test_stratified_split_is_reproducible_with_same_seed() -> None:
    cases = [case(f"c-{i}", TF, TF if i % 2 == 0 else DF) for i in range(20)]

    dev1, eval1 = stratified_split(cases, eval_fraction=0.25, seed=7)
    dev2, eval2 = stratified_split(cases, eval_fraction=0.25, seed=7)

    assert [c.case_id for c in dev1] == [c.case_id for c in dev2]
    assert [c.case_id for c in eval1] == [c.case_id for c in eval2]


def test_stratified_split_covers_every_case_exactly_once() -> None:
    cases = [case(f"c-{i}", TF, TF if i % 3 == 0 else DF) for i in range(15)]

    dev, eval_set = stratified_split(cases, eval_fraction=0.3, seed=1)

    dev_ids = {c.case_id for c in dev}
    eval_ids = {c.case_id for c in eval_set}
    assert dev_ids.isdisjoint(eval_ids)
    assert dev_ids | eval_ids == {c.case_id for c in cases}


def test_stratified_split_rejects_invalid_fraction() -> None:
    with pytest.raises(ValueError, match="eval_fraction"):
        stratified_split([case("1", TF, TF)], eval_fraction=1.5, seed=0)
