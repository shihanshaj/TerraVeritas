from __future__ import annotations

from terraveritas.experiments.extraction import extract_terraform


def test_extracts_hcl_fenced_block() -> None:
    raw = 'Here is the fix:\n```hcl\nresource "x" "y" {}\n```\nDone.'

    assert extract_terraform(raw) == 'resource "x" "y" {}'


def test_extracts_bare_fenced_block_no_language_tag() -> None:
    raw = '```\nresource "x" "y" {}\n```'

    assert extract_terraform(raw) == 'resource "x" "y" {}'


def test_falls_back_to_raw_text_when_no_fence() -> None:
    raw = 'resource "x" "y" {}'

    assert extract_terraform(raw) == 'resource "x" "y" {}'


def test_extracts_first_fence_when_multiple_present() -> None:
    raw = '```hcl\nresource "first" "a" {}\n```\nSome text\n```hcl\nresource "second" "b" {}\n```'

    assert extract_terraform(raw) == 'resource "first" "a" {}'
