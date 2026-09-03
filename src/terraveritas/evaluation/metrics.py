"""Precision/recall/F1/confusion-matrix/error-analysis over labeled cases.

Operates on TerraVeritas's own `Classification` enum only. Mapping an
external ground-truth scheme's labels into that space (documenting any
incompatible definitions along the way, per the mapping table in project
notes) is the caller's responsibility — this module never guesses at a
label correspondence on its own.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from terraveritas.models.oracle import Classification


@dataclass(frozen=True, slots=True)
class LabeledCase:
    """One case with both a human (ground-truth) label and the oracle's
    predicted classification, plus enough context to report a disagreement
    without going back to raw data."""

    case_id: str
    predicted: Classification
    actual: Classification
    original_summary: str = ""
    repaired_summary: str = ""
    oracle_reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ClassMetrics:
    label: Classification
    support: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float | None
    recall: float | None
    f1: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    n: int
    accuracy: float
    confusion_matrix: dict[Classification, dict[Classification, int]]
    """confusion_matrix[actual][predicted] = count."""
    per_class: dict[Classification, ClassMetrics]
    macro_precision: float
    macro_recall: float
    macro_f1: float


def evaluate(cases: list[LabeledCase]) -> EvaluationReport:
    if not cases:
        raise ValueError("cannot evaluate an empty case list")

    all_labels = list(Classification)
    confusion: dict[Classification, dict[Classification, int]] = {
        a: dict.fromkeys(all_labels, 0) for a in all_labels
    }
    for case in cases:
        confusion[case.actual][case.predicted] += 1

    n = len(cases)
    correct = sum(confusion[label][label] for label in all_labels)
    accuracy = correct / n

    per_class: dict[Classification, ClassMetrics] = {}
    for label in all_labels:
        tp = confusion[label][label]
        fn = sum(confusion[label][p] for p in all_labels if p != label)
        fp = sum(confusion[a][label] for a in all_labels if a != label)
        tn = n - tp - fn - fp
        support = tp + fn

        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall = tp / (tp + fn) if (tp + fn) > 0 else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and (precision + recall) > 0
            else None
        )
        fpr = fp / (fp + tn) if (fp + tn) > 0 else None
        fnr = fn / (fn + tp) if (fn + tp) > 0 else None

        per_class[label] = ClassMetrics(
            label=label,
            support=support,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            precision=precision,
            recall=recall,
            f1=f1,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
        )

    # Macro average over classes with at least one ground-truth instance,
    # treating an undefined precision/recall (no predictions of that class
    # at all) as 0 — the conventional zero_division=0 behavior, chosen so a
    # class the oracle never predicts pulls the macro score down rather
    # than being silently excluded.
    supported = [m for m in per_class.values() if m.support > 0]
    macro_precision = sum(m.precision or 0.0 for m in supported) / len(supported)
    macro_recall = sum(m.recall or 0.0 for m in supported) / len(supported)
    macro_f1 = sum(m.f1 or 0.0 for m in supported) / len(supported)

    return EvaluationReport(
        n=n,
        accuracy=accuracy,
        confusion_matrix=confusion,
        per_class=per_class,
        macro_precision=macro_precision,
        macro_recall=macro_recall,
        macro_f1=macro_f1,
    )


def find_disagreements(cases: list[LabeledCase]) -> list[LabeledCase]:
    return [c for c in cases if c.predicted != c.actual]


def stratified_split(
    cases: list[LabeledCase], *, eval_fraction: float, seed: int
) -> tuple[list[LabeledCase], list[LabeledCase]]:
    """Split into (dev, eval), stratified by the `actual` label so class
    balance is preserved in both sets even at small N per class.

    The eval set must never be used to tune the oracle's decision logic —
    only to report a final, honest estimate. Any threshold or heuristic
    adjustment belongs on the dev set alone. This function only performs
    the split; it cannot enforce that discipline on the caller.
    """
    if not 0.0 < eval_fraction < 1.0:
        raise ValueError(f"eval_fraction must be in (0, 1), got {eval_fraction}")

    rng = random.Random(seed)  # noqa: S311 - reproducible dev/eval split, not cryptographic use
    by_label: dict[Classification, list[LabeledCase]] = {}
    for case in cases:
        by_label.setdefault(case.actual, []).append(case)

    dev: list[LabeledCase] = []
    eval_set: list[LabeledCase] = []
    for _label, group in by_label.items():
        shuffled = list(group)
        rng.shuffle(shuffled)
        n_eval = max(1, round(len(shuffled) * eval_fraction)) if len(shuffled) > 1 else 0
        eval_set.extend(shuffled[:n_eval])
        dev.extend(shuffled[n_eval:])

    return dev, eval_set
