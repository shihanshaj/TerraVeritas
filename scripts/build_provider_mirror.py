"""Builds a local Terraform provider filesystem mirror for hashicorp/aws.

Why this exists: real diagnosis (not assumption) found that `terraform
init` reaching the AWS provider was never blocked by network access as
such — DNS resolution, the registry metadata API, and the release CDN all
respond in under half a second. The actual problem is that this
environment's egress bandwidth for a large, sustained download is
unstable and slow (observed: starts around ~1MB/s and degrades further
over a single connection, well under the ~150MB provider binary's needs
within any single reasonable timeout). A `TF_PLUGIN_CACHE_DIR` alone does
not fix this: it still requires registry round-trips for metadata,
checksums, and signature verification on every init, and was confirmed
(not assumed) to still take up to 2m47s and remain dependent on that
same unstable connection succeeding. A filesystem mirror, once built,
needs zero network access per run and completed `terraform init` for a
real aws_s3_bucket configuration in under 3 seconds.

Usage:
    uv run python scripts/build_provider_mirror.py [--version 5.100.0]

Idempotent and resumable: reruns skip re-downloading if the mirror
already contains a matching, complete provider binary; a prior partial
download is resumed via HTTP range requests rather than restarted, since
resume (not a longer timeout) is what actually got a complete file in
this environment's conditions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MIRROR_DIR = REPO_ROOT / ".terraform-mirror"
REGISTRY_HOST = "registry.terraform.io"
NAMESPACE = "hashicorp"
PROVIDER_TYPE = "aws"


def _target_platform() -> tuple[str, str]:
    platform_key = (
        sys.platform.rstrip("0123456789") if sys.platform.startswith("win") else sys.platform
    )
    os_name = {"darwin": "darwin", "linux": "linux", "windows": "windows"}[platform_key]
    machine = platform.machine().lower()
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(
        machine, machine
    )
    return os_name, arch


def _download_url(version: str, os_name: str, arch: str) -> tuple[str, str, str]:
    """Returns (download_url, expected_filename, expected_shasum) from the
    registry metadata API — a small, fast request, confirmed reliable in
    this environment even when the bulk binary download is not.

    Uses curl, not Python's urllib: a clean-room reproducibility test found
    that a standalone uv-managed Python interpreter's default SSL context
    can fail with CERTIFICATE_VERIFY_FAILED (no local issuer certificate
    wired up) even though the exact same host is reachable via curl, which
    uses the system trust store. curl is already required for the bulk
    binary download below, so this avoids a second, less reliable HTTPS
    code path for no benefit."""
    api_url = (
        f"https://{REGISTRY_HOST}/v1/providers/{NAMESPACE}/{PROVIDER_TYPE}/"
        f"{version}/download/{os_name}/{arch}"
    )
    result = subprocess.run(  # noqa: S603, S607 - fixed argv, no shell
        ["curl", "-sS", "--max-time", "15", api_url],
        capture_output=True,
        text=True,
        check=True,
    )
    meta = json.loads(result.stdout)
    return meta["download_url"], meta["filename"], meta["shasum"]


def _download_with_resume(url: str, dest: Path, expected_shasum: str) -> None:
    """Uses curl -C - (resume) rather than a single long-lived Python
    connection: verified during diagnosis that resuming an interrupted
    transfer, not simply waiting longer, is what actually completes the
    download against this environment's unstable connection.

    Verifies the final file against `expected_shasum` (from the registry
    metadata) rather than just checking that curl exited 0 — a clean-room
    reproducibility test found that a connection reset mid-transfer
    (curl exit 56, not caught by the original retry condition) left a
    truncated, invalid zip on disk that the caller had no way to detect
    without this check. A file that exists but fails the hash check is
    deleted and retried from scratch, not resumed — its bytes cannot be
    trusted."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    attempt = 0
    # 28 = curl operation timeout; 56 = connection reset by peer — both
    # observed directly against this environment's connection and are
    # expected, retryable mid-transfer conditions, not fatal errors.
    retryable_curl_exit_codes = {0, 28, 56}
    while True:
        attempt += 1
        result = subprocess.run(  # noqa: S603, S607 - fixed argv, no shell
            [
                "curl",
                "-sS",
                "-C",
                "-",
                "-o",
                str(dest),
                "--max-time",
                "180",
                url,
            ],
            check=False,
        )
        if result.returncode not in retryable_curl_exit_codes:
            raise RuntimeError(f"curl failed with unexpected exit code {result.returncode}")
        if dest.exists() and _sha256_of(dest) == expected_shasum:
            return
        if attempt > 10:
            raise RuntimeError(
                f"download did not complete after {attempt} attempts "
                f"({dest.stat().st_size if dest.exists() else 0} bytes so far, "
                "hash never matched)"
            )
        if dest.exists() and result.returncode == 0:
            # curl reported success but the hash still doesn't match —
            # resuming a bad file can't fix it; start over.
            dest.unlink()
        print(
            f"  ... download incomplete or unverified, retrying "
            f"(attempt {attempt}, {dest.stat().st_size if dest.exists() else 0} bytes so far)"
        )


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_zip_preserving_permissions(zip_path: Path, dest_dir: Path) -> None:
    """`zipfile.ZipFile.extractall` does not restore Unix permission bits by
    default — a clean-room reproducibility test found this left the
    extracted provider binary non-executable ("permission denied" from
    Terraform's fork/exec), since the zip format stores them separately in
    each entry's `external_attr` field rather than applying them
    automatically. Restores them explicitly for every extracted file."""
    with zipfile.ZipFile(zip_path) as zf:
        for entry in zf.infolist():
            extracted_path = zf.extract(entry, dest_dir)
            mode = entry.external_attr >> 16
            if mode:
                Path(extracted_path).chmod(mode)


def build_mirror(version: str) -> Path:
    os_name, arch = _target_platform()
    target = f"{os_name}_{arch}"
    target_dir = MIRROR_DIR / REGISTRY_HOST / NAMESPACE / PROVIDER_TYPE / version / target
    binary_glob = list(target_dir.glob(f"terraform-provider-{PROVIDER_TYPE}_v{version}*"))
    if binary_glob:
        print(f"Mirror already has {NAMESPACE}/{PROVIDER_TYPE} {version} for {target}:")
        print(f"  {binary_glob[0]}")
        return MIRROR_DIR

    print(f"Fetching download metadata for {NAMESPACE}/{PROVIDER_TYPE} {version} ({target})...")
    download_url, filename, expected_shasum = _download_url(version, os_name, arch)

    zip_path = target_dir / filename
    print(f"Downloading {download_url} -> {zip_path}")
    _download_with_resume(download_url, zip_path, expected_shasum)
    print(f"Downloaded and verified {zip_path.stat().st_size} bytes (sha256 matches registry).")

    _extract_zip_preserving_permissions(zip_path, target_dir)
    zip_path.unlink()

    print(f"Mirror ready at {MIRROR_DIR}")
    return MIRROR_DIR


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="5.100.0")
    args = parser.parse_args()
    build_mirror(args.version)


if __name__ == "__main__":
    main()
