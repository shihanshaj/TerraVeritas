"""Regression test for the resource-type extraction bug found while building
the differential engine: splitting a Terraform address on the *first* dot
returns "module" for any module-nested resource instead of the real type."""

from __future__ import annotations

import pytest

from terraveritas.scanners.checkov import _resource_type_from_address


@pytest.mark.parametrize(
    ("resource_id", "expected_type"),
    [
        ("aws_s3_bucket.data", "aws_s3_bucket"),
        ("module.storage.aws_s3_bucket.data", "aws_s3_bucket"),
        ("module.a.module.b.aws_s3_bucket.data", "aws_s3_bucket"),
        ("aws_instance.web[0]", "aws_instance"),
        (None, None),
        ("", None),
        ("no_dot_at_all", None),
    ],
)
def test_resource_type_from_address(resource_id: str | None, expected_type: str | None) -> None:
    assert _resource_type_from_address(resource_id) == expected_type
