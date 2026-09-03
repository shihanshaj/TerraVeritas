"""Terraform plan processing: validate -> plan -> show -json, safely.

Design decisions, grounded in behavior verified against a real Terraform
1.14.3 CLI in this project's environment (see docstrings below and
project notes for the exact commands run):

1. Every run happens in an isolated temp copy of the source directory,
   never in-place — a fixture must never accumulate .terraform/, lock
   files, or plan output from being planned.
2. AWS credentials are deliberately sabotaged (fake key/secret, IMDS
   lookups disabled, credentials/config files pointed at a nonexistent
   path) rather than merely "not provided". This isn't just about not
   needing real credentials — it guarantees that if a configuration
   contains something that *would* make a live AWS API call (e.g. a
   `data` source), that call fails safely and immediately with an auth
   error, rather than by chance succeeding against a real account if one
   happens to be configured in the host environment. Combined with the
   AWS provider's `skip_credentials_validation` /
   `skip_requesting_account_id` / `skip_metadata_api_check` flags
   (injected only when needed — see _needs_aws_provider_injection),
   configurations with no live-API dependency plan successfully and
   fully offline.
3. `terraform init` needs network access to download providers not
   already cached, and this is a genuine, disclosed limitation: in this
   project's own sandboxed development environment, downloading the
   ~150MB AWS provider binary failed with a connection reset on every
   attempt (verified three times, including a 9-minute-timeout attempt
   with a persistent plugin cache configured), while small/fast registry
   lookups and Terraform's builtin provider worked instantly. A
   real evaluation pipeline running in a similarly constrained sandbox
   needs a pre-warmed provider plugin cache baked into the environment,
   not a per-run download. PLAN_INIT_FAILURE exists specifically so this
   kind of failure is visible and countable, never silently absorbed
   into "this configuration couldn't be evaluated" with no further
   detail.
4. A remote (registry/git/http) module source is detected and rejected
   *before* attempting init, via a real HCL parse (not a regex) — Phase
   1 does not fetch arbitrary external module code during an evaluation
   run. This is a disclosed non-goal, not a bug: see PlanStatus.PLAN_UNSUPPORTED.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import hcl2

from terraveritas.models.plan import PlannedResourceChange, PlanResult, PlanStatus
from terraveritas.security import SENSITIVE_ENV_VAR_NAMES

_PROVIDER_FAILURE_PATTERNS = (
    # Known AWS SDK / provider error substrings for "couldn't reach AWS" or
    # "credentials rejected". NOT empirically verified against a real AWS
    # provider run in this project's environment (see module docstring,
    # point 3) — compiled from documented AWS SDK/provider error text.
    # Deliberately conservative: an unmatched provider-stage failure falls
    # back to PLAN_ERROR rather than being guessed into this category.
    "no valid credential sources",
    "failed to refresh cached credentials",
    "NoCredentialProviders",
    "could not find valid AWS credentials to satisfy provider",
    "error configuring Terraform AWS Provider",
    "RequestError: send request failed",
    "InvalidClientTokenId",
    "context deadline exceeded",
)

_UNRESOLVED_DEPENDENCY_PATTERNS = (
    "No value for required variable",
    "Required variable not set",
)


class TerraformPlanner:
    def __init__(
        self,
        *,
        terraform_executable: str = "terraform",
        plugin_cache_dir: Path | None = None,
        filesystem_mirror_dir: Path | None = None,
        aws_provider_version: str = "5.100.0",
    ) -> None:
        """filesystem_mirror_dir: a pre-populated Terraform provider
        filesystem mirror (see scripts/build_provider_mirror.py), pointing
        `init` at local provider binaries instead of the registry.
        Confirmed necessary, not merely convenient: `plugin_cache_dir`
        alone (this class's original, unexercised offline-install
        mechanism) was tested against this environment's real network
        conditions and still hung indefinitely — a plugin cache only skips
        re-downloading a binary already fetched via a prior real init, it
        does not skip the registry round-trips (metadata, checksums,
        signature verification) that a filesystem mirror bypasses
        entirely. This directly completes the intent already documented
        in this module's docstring point 3."""
        self.terraform_executable = terraform_executable
        self.plugin_cache_dir = plugin_cache_dir
        self.filesystem_mirror_dir = filesystem_mirror_dir
        self.aws_provider_version = aws_provider_version

    def plan(
        self,
        source_dir: Path,
        *,
        timeout_seconds: float = 300.0,
        tfvars: dict[str, str] | None = None,
    ) -> PlanResult:
        started_at = datetime.now(UTC)

        if not source_dir.is_dir():
            return PlanResult(
                target_path=str(source_dir),
                status=PlanStatus.PLAN_INVALID_TARGET,
                error_message=f"target directory does not exist: {source_dir}",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

        if shutil.which(self.terraform_executable) is None:
            return PlanResult(
                target_path=str(source_dir),
                status=PlanStatus.PLAN_TERRAFORM_NOT_INSTALLED,
                error_message=(
                    f"terraform executable not found on PATH: {self.terraform_executable}"
                ),
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

        syntax_errors = _detect_syntax_errors(source_dir)
        if syntax_errors:
            return PlanResult(
                target_path=str(source_dir),
                status=PlanStatus.PLAN_INVALID_CONFIGURATION,
                error_message="; ".join(syntax_errors),
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

        unsupported = _detect_unsupported_module_sources(source_dir)
        if unsupported:
            return PlanResult(
                target_path=str(source_dir),
                status=PlanStatus.PLAN_UNSUPPORTED,
                error_message=(
                    "non-local module source(s) not fetched in Phase 1 (no arbitrary "
                    f"network module fetches during evaluation): {', '.join(unsupported)}"
                ),
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

        with tempfile.TemporaryDirectory(prefix="terraveritas-plan-") as tmp:
            work_dir = Path(tmp)
            # symlinks=True: preserve symlinks as symlinks rather than
            # following them. The default (symlinks=False) copies the
            # TARGET file's real content — a malicious repo containing a
            # symlink to an arbitrary readable file (e.g. ~/.aws/credentials)
            # would have that content copied into the working directory.
            # Confirmed exploitable during the Prompt 14 review. Terraform
            # will simply see a broken/inert symlink for anything pointing
            # outside the copied tree, which is the correct, safe outcome.
            shutil.copytree(source_dir, work_dir, dirs_exist_ok=True, symlinks=True)
            if _needs_aws_provider_injection(source_dir):
                _write_injected_aws_provider(work_dir, self.aws_provider_version)
            if tfvars:
                _write_tfvars(work_dir, tfvars)

            cli_config_file = None
            if self.filesystem_mirror_dir is not None:
                cli_config_file = _write_filesystem_mirror_cli_config(
                    work_dir, self.filesystem_mirror_dir
                )
            env = _sandboxed_env(self.plugin_cache_dir, cli_config_file)
            commands_run: list[list[str]] = []

            init_argv = [self.terraform_executable, "init", "-input=false", "-no-color"]
            commands_run.append(init_argv)
            init_result = _run(init_argv, work_dir, env, timeout_seconds)
            if init_result is None:
                return self._timeout_result(source_dir, commands_run, started_at)
            if init_result.returncode != 0:
                return PlanResult(
                    target_path=str(source_dir),
                    status=PlanStatus.PLAN_INIT_FAILURE,
                    commands_run=commands_run,
                    error_message=init_result.stderr.strip() or init_result.stdout.strip(),
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )

            validate_argv = [self.terraform_executable, "validate", "-no-color", "-json"]
            commands_run.append(validate_argv)
            validate_result = _run(validate_argv, work_dir, env, timeout_seconds)
            if validate_result is None:
                return self._timeout_result(source_dir, commands_run, started_at)
            validate_payload = _try_parse_json(validate_result.stdout)
            if validate_payload is not None and validate_payload.get("valid") is False:
                diagnostics = validate_payload.get("diagnostics", [])
                summary = (
                    "; ".join(
                        f"{d.get('summary', '')}: {d.get('detail', '')}" for d in diagnostics
                    )
                    or "invalid configuration"
                )
                return PlanResult(
                    target_path=str(source_dir),
                    status=PlanStatus.PLAN_INVALID_CONFIGURATION,
                    commands_run=commands_run,
                    error_message=summary,
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )
            if validate_result.returncode != 0 and validate_payload is None:
                # validate failed AND its output didn't parse as the
                # structured "valid": false shape above — a genuine crash
                # (not just "config invalid"), previously silently ignored:
                # this branch didn't exist, so execution fell straight
                # through to attempting `terraform plan` on a configuration
                # validate couldn't even assess. Found during the Prompt 14
                # review by inspection, not by reproducing a live crash.
                return PlanResult(
                    target_path=str(source_dir),
                    status=PlanStatus.PLAN_ERROR,
                    commands_run=commands_run,
                    error_message=(
                        validate_result.stderr.strip()
                        or validate_result.stdout.strip()
                        or "terraform validate failed with no parseable output"
                    ),
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )

            plan_argv = [
                self.terraform_executable,
                "plan",
                "-input=false",
                "-no-color",
                "-json",
                "-out=tfplan",
            ]
            commands_run.append(plan_argv)
            plan_result = _run(plan_argv, work_dir, env, timeout_seconds)
            if plan_result is None:
                return self._timeout_result(source_dir, commands_run, started_at)
            if plan_result.returncode != 0:
                status, message = _classify_plan_failure(plan_result.stdout, plan_result.stderr)
                return PlanResult(
                    target_path=str(source_dir),
                    status=status,
                    commands_run=commands_run,
                    error_message=message,
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )

            show_argv = [self.terraform_executable, "show", "-json", "tfplan"]
            commands_run.append(show_argv)
            show_result = _run(show_argv, work_dir, env, timeout_seconds)
            if show_result is None:
                return self._timeout_result(source_dir, commands_run, started_at)
            if show_result.returncode != 0:
                return PlanResult(
                    target_path=str(source_dir),
                    status=PlanStatus.PLAN_ERROR,
                    commands_run=commands_run,
                    error_message=show_result.stderr.strip() or "terraform show failed",
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )

            show_payload = _try_parse_json(show_result.stdout)
            if show_payload is None:
                return PlanResult(
                    target_path=str(source_dir),
                    status=PlanStatus.PLAN_ERROR,
                    commands_run=commands_run,
                    error_message="terraform show -json produced unparseable output",
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )

            try:
                resource_changes = _extract_resource_changes(show_payload)
            except (KeyError, TypeError) as exc:
                # A resource_changes entry didn't match the schema this
                # parser assumes (never fully verified against a real,
                # complex plan — see module docstring point 3). Treating
                # this as PLAN_ERROR rather than letting the exception
                # propagate: the whole point of PlanStatus is that plan()
                # never raises for a failure mode it can name. Silently
                # dropping just the one malformed entry was considered and
                # rejected — a schema surprise on one entry means the same
                # assumption could be silently wrong on others too, and
                # this project does not treat missing evidence as evidence
                # of anything.
                return PlanResult(
                    target_path=str(source_dir),
                    status=PlanStatus.PLAN_ERROR,
                    commands_run=commands_run,
                    error_message=f"unexpected resource_changes schema: {exc}",
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )

            return PlanResult(
                target_path=str(source_dir),
                status=PlanStatus.PLAN_SUCCESS,
                terraform_version=show_payload.get("terraform_version"),
                resource_changes=resource_changes,
                raw_plan_json=show_payload,
                commands_run=commands_run,
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

    def _timeout_result(
        self, source_dir: Path, commands_run: list[list[str]], started_at: datetime
    ) -> PlanResult:
        return PlanResult(
            target_path=str(source_dir),
            status=PlanStatus.PLAN_TIMEOUT,
            commands_run=commands_run,
            error_message="a plan stage exceeded the configured timeout",
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


def _run(
    argv: list[str], cwd: Path, env: dict[str, str], timeout_seconds: float
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(  # noqa: S603 - argv is built from fixed literals, no shell
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None


def _try_parse_json(text: str) -> dict[str, Any] | None:
    """`terraform validate -json` and `terraform show -json` each emit a
    single JSON object; `terraform plan -json` emits newline-delimited
    JSON events instead (handled separately in _classify_plan_failure)."""
    try:
        result: dict[str, Any] = json.loads(text)
        return result
    except (json.JSONDecodeError, ValueError):
        return None


def _classify_plan_failure(stdout: str, stderr: str) -> tuple[PlanStatus, str]:
    """`terraform plan -json` emits newline-delimited JSON event objects;
    error events carry a `diagnostic` field with `summary`/`detail` text."""
    diagnostic_texts: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        diagnostic = event.get("diagnostic")
        if diagnostic:
            summary = diagnostic.get("summary", "")
            detail = diagnostic.get("detail", "")
            diagnostic_texts.append(f"{summary}: {detail}")

    combined = "\n".join(diagnostic_texts) or stderr.strip() or stdout.strip()

    for pattern in _UNRESOLVED_DEPENDENCY_PATTERNS:
        if pattern in combined:
            return PlanStatus.PLAN_UNRESOLVED_DEPENDENCY, combined
    for pattern in _PROVIDER_FAILURE_PATTERNS:
        if pattern in combined:
            return PlanStatus.PLAN_PROVIDER_FAILURE, combined
    return PlanStatus.PLAN_ERROR, combined or "plan failed with no diagnostic output"


def _extract_resource_changes(show_payload: dict[str, Any]) -> list[PlannedResourceChange]:
    changes = []
    for rc in show_payload.get("resource_changes", []):
        change = rc.get("change", {})
        after = change.get("after") or {}
        after_unknown = change.get("after_unknown") or {}
        changes.append(
            PlannedResourceChange(
                address=rc["address"],
                resource_type=rc["type"],
                resource_name=rc["name"],
                provider_name=rc.get("provider_name", "unknown"),
                actions=list(change.get("actions", [])),
                after=after,
                after_unknown_keys=[k for k, v in after_unknown.items() if v is True],
            )
        )
    return changes


def _write_filesystem_mirror_cli_config(work_dir: Path, mirror_dir: Path) -> Path:
    """Writes a Terraform CLI config forcing provider installation to come
    ONLY from the local filesystem mirror for hashicorp/aws — no registry
    round-trip at all (metadata, checksums, or signature verification),
    which is what actually matters here: a plugin cache alone still needs
    those round-trips and was confirmed (not assumed) to hang indefinitely
    against this environment's real, unstable network. See build_provider_
    mirror.py for how the mirror directory itself is populated."""
    config_path = work_dir / "_terraveritas_cli_config.tfrc"
    mirror_path = str(mirror_dir).replace("\\", "\\\\").replace('"', '\\"')
    config_path.write_text(
        f"""provider_installation {{
  filesystem_mirror {{
    path    = "{mirror_path}"
    include = ["registry.terraform.io/hashicorp/aws"]
  }}
  direct {{
    exclude = ["registry.terraform.io/hashicorp/aws"]
  }}
}}
"""
    )
    return config_path


def _sandboxed_env(
    plugin_cache_dir: Path | None, cli_config_file: Path | None = None
) -> dict[str, str]:
    """Strip any real AWS credentials/config from the host environment and
    replace them with values that are guaranteed to fail cleanly against a
    real AWS API, rather than by chance succeeding. See module docstring
    point 2.

    Strip-list is security.py's SENSITIVE_ENV_VAR_NAMES, not a locally
    maintained copy — a prior version of this function kept its own,
    shorter list (4 vars) that missed AWS_ROLE_ARN and
    AWS_WEB_IDENTITY_TOKEN_FILE, the pair that enables
    AssumeRoleWithWebIdentity (how GitHub Actions OIDC AWS auth works);
    those two would have leaked through unstripped to a scanned config's
    AWS provider if this ran inside such a CI job. One shared policy,
    tested in tests/terraform/test_plan_helpers.py against divergence."""
    env = os.environ.copy()
    for var in SENSITIVE_ENV_VAR_NAMES:
        env.pop(var, None)
    env["AWS_ACCESS_KEY_ID"] = "test"
    env["AWS_SECRET_ACCESS_KEY"] = "test"  # noqa: S105 - deliberately fake, see module docstring
    env["AWS_SHARED_CREDENTIALS_FILE"] = "/nonexistent-terraveritas-sandbox-credentials"
    env["AWS_CONFIG_FILE"] = "/nonexistent-terraveritas-sandbox-config"
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    env["TF_IN_AUTOMATION"] = "1"
    env["TF_INPUT"] = "0"
    env["TF_CLI_ARGS"] = "-no-color"
    if plugin_cache_dir is not None:
        env["TF_PLUGIN_CACHE_DIR"] = str(plugin_cache_dir)
    if cli_config_file is not None:
        env["TF_CLI_CONFIG_FILE"] = str(cli_config_file)
    return env


def _detect_syntax_errors(source_dir: Path) -> list[str]:
    """A pre-init syntax check using the same HCL parser as the module-source
    and AWS-provider-injection checks below.

    Verified necessary: `terraform init` itself refuses to run on
    syntactically broken HCL (it must parse the config to determine which
    providers/modules to install) and fails with the same diagnostic
    `terraform validate` would give — without this pre-check, broken syntax
    would surface as PLAN_INIT_FAILURE, conflating "the AI produced invalid
    HCL" with "a required provider/module couldn't be installed", which are
    different signals for the research question this project is answering.

    Not authoritative: hcl2 is a third-party HCL parser, not Terraform's
    own. A file that parses here but that real Terraform still rejects will
    correctly fall through and surface as PLAN_INIT_FAILURE from init
    itself — this pre-check only improves classification precision for the
    common case, it doesn't replace init/validate as ground truth.
    """
    errors = []
    for tf_file in sorted(source_dir.glob("*.tf")):
        try:
            with tf_file.open() as f:
                hcl2.load(f)  # type: ignore[attr-defined] # bc-python-hcl2 has no py.typed marker
        except Exception as exc:  # noqa: BLE001 - any parse failure here is a syntax error to surface
            errors.append(f"{tf_file.name}: {exc}")
    return errors


def _parse_all_hcl(source_dir: Path) -> list[dict[str, Any]]:
    parsed_files = []
    for tf_file in sorted(source_dir.glob("*.tf")):
        try:
            with tf_file.open() as f:
                parsed_files.append(hcl2.load(f))  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001, S112 - a file that fails to parse here will fail
            # validate too, which is the real, diagnostic-bearing error path — no logging
            # needed here without duplicating that later, more informative failure.
            continue
    return parsed_files


def _detect_unsupported_module_sources(source_dir: Path) -> list[str]:
    """Guaranteed by hcl2 (verified empirically, not assumed): a single
    argument's value is always list-wrapped, and duplicate module labels
    are kept as separate entries in the `module` list, never merged. NOT
    guaranteed: that `module_block` is always a single-key dict, or that
    `source` is always a literal string — both are defended below rather
    than assumed, since AI-generated or hand-malformed HCL is exactly the
    adversarial input this function must survive without crashing."""
    unsupported = []
    for parsed in _parse_all_hcl(source_dir):
        for module_block in parsed.get("module", []):
            if not isinstance(module_block, dict):
                continue
            for module_name, body in module_block.items():
                if not isinstance(body, dict):
                    continue
                source_list = body.get("source", [None])
                source = source_list[0] if isinstance(source_list, list) and source_list else None
                if not isinstance(source, str) or not source:
                    continue
                if source.startswith("./") or source.startswith("../"):
                    continue
                if source.startswith("${") and source.endswith("}"):
                    # An unresolved HCL expression (e.g. a variable
                    # reference), not a literal path — genuinely unknown
                    # whether it's local or remote without evaluation, so
                    # it's reported distinctly rather than implied to BE a
                    # known non-local source (the bug this replaces).
                    unsupported.append(
                        f"module.{module_name}: cannot statically determine module source "
                        f"(unresolved expression: {source})"
                    )
                    continue
                unsupported.append(f"module.{module_name} -> {source}")
    return unsupported


def _needs_aws_provider_injection(source_dir: Path) -> bool:
    """Only inject a provider config when the source actually uses AWS
    resources/data sources AND doesn't already declare its own aws
    provider — injecting one unconditionally would make provider-less or
    other-provider fixtures (e.g. this module's own builtin-provider test
    fixtures) require a network download they don't otherwise need."""
    uses_aws = False
    already_configured = False
    for parsed in _parse_all_hcl(source_dir):
        for resource_block in parsed.get("resource", []):
            if any(rtype.startswith("aws_") for rtype in resource_block):
                uses_aws = True
        for data_block in parsed.get("data", []):
            if any(rtype.startswith("aws_") for rtype in data_block):
                uses_aws = True
        for provider_block in parsed.get("provider", []):
            if "aws" in provider_block:
                already_configured = True
        for tf_block in parsed.get("terraform", []):
            required_providers = tf_block.get("required_providers", [{}])
            rp_list = (
                required_providers if isinstance(required_providers, list) else [required_providers]
            )
            for rp in rp_list:
                if "aws" in rp:
                    already_configured = True
    return uses_aws and not already_configured


def _write_injected_aws_provider(work_dir: Path, version: str) -> None:
    (work_dir / "_terraveritas_injected_provider.tf").write_text(
        f"""terraform {{
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "= {version}"
    }}
  }}
}}

provider "aws" {{
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}}
"""
    )


def _write_tfvars(work_dir: Path, tfvars: dict[str, str]) -> None:
    (work_dir / "terraveritas.auto.tfvars.json").write_text(json.dumps(tfvars))
