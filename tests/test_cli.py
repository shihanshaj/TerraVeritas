"""Smoke test: package imports and CLI parser build without error."""

from terraveritas.cli import build_parser


def test_build_parser_returns_parser_with_version_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["--version"])
    assert args.version is True
