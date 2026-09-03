from __future__ import annotations

from datetime import date

from terraveritas.experiments.identifiers import content_hash, make_case_id, make_experiment_id


def test_experiment_id_encodes_date_and_slug() -> None:
    experiment_id = make_experiment_id("pilot-s3exposure", on=date(2026, 9, 2))

    assert experiment_id == "2026-09-02-pilot-s3exposure"


def test_case_id_encodes_cell_and_index() -> None:
    assert make_case_id("minimal", 0) == "minimal-000"
    assert make_case_id("intent_explicit", 7) == "intent_explicit-007"


def test_content_hash_is_deterministic() -> None:
    assert content_hash("hello world") == content_hash("hello world")


def test_content_hash_distinguishes_different_content() -> None:
    assert content_hash("hello world") != content_hash("hello world!")
