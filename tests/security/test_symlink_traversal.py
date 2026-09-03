"""Regression test for C1 (Prompt 14 zero-trust review): TerraformPlanner's
copy step must never follow a symlink out of the source directory. The
default shutil.copytree(symlinks=False) does exactly that — confirmed by
direct reproduction during the review, before the fix — and would copy an
arbitrary readable file's real content into the working directory for a
malicious repo containing a symlink to it (e.g. ~/.aws/credentials)."""

from __future__ import annotations

import shutil
from pathlib import Path


def test_copytree_with_symlinks_true_does_not_follow_links_outside_source(
    tmp_path: Path,
) -> None:
    outside_secret = tmp_path / "outside" / "secret.txt"
    outside_secret.parent.mkdir()
    outside_secret.write_text("TOP-SECRET-CONTENT-should-never-be-copied")

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "evil.tf").symlink_to(outside_secret)

    work_dir = tmp_path / "work"
    # Exact call shape used in terraform/plan.py's TerraformPlanner.plan().
    shutil.copytree(source_dir, work_dir, dirs_exist_ok=True, symlinks=True)

    copied = work_dir / "evil.tf"
    assert copied.is_symlink()
    assert copied.readlink() == outside_secret


def test_default_copytree_would_have_leaked_the_secret_documenting_the_bug() -> None:
    """Not a test of TerraVeritas — a permanent, executable record of the
    exact bug this review found and fixed, so a future refactor that drops
    symlinks=True regresses visibly rather than silently."""
    import tempfile

    src = Path(tempfile.mkdtemp())
    secret = Path(tempfile.mkdtemp()) / "secret.txt"
    secret.write_text("TOP-SECRET")
    (src / "evil.tf").symlink_to(secret)

    dst = Path(tempfile.mkdtemp()) / "copy"
    shutil.copytree(src, dst, dirs_exist_ok=True)  # default: symlinks=False

    assert (dst / "evil.tf").is_symlink() is False
    assert (dst / "evil.tf").read_text() == "TOP-SECRET"
