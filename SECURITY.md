# Security

TerraVeritas analyzes Terraform repositories and AI-generated repairs to
them. Both inputs are treated as **potentially malicious** — a scanned
repository is not a trusted artifact, and neither is an AI model's output.
This document is the threat model and the record of the security review
performed against the actual codebase (not a generic checklist), plus how
to report a new finding.

## Operational guarantees

- **TerraVeritas never runs `terraform apply` or any other command that
  provisions, modifies, or destroys real infrastructure.** Verified by
  direct search of the codebase — the string `apply` does not appear in
  any subprocess command anywhere in `src/` or `scripts/`.
- **No subprocess is ever spawned via a shell.** Every subprocess call
  (`scanners/base.py`, `scanners/checkov.py`, `terraform/plan.py`,
  `experiments/reproducibility.py`) uses `subprocess.run` with an explicit
  argv list and `shell=False` (the default) — confirmed by search: zero
  occurrences of `shell=True`, `os.system`, `os.popen`, `eval`, `exec`, or
  `pickle` anywhere in the codebase. User- or repository-controlled content
  (directory names, file contents) is never interpolated into a command
  string; it only ever appears as an individual argv element, which shell
  metacharacters cannot escape.
- **Terraform planning never uses real AWS credentials.** `TerraformPlanner`
  strips any real AWS credential environment variables from its subprocess
  environment and replaces them with deliberately fake values
  (`AWS_ACCESS_KEY_ID=test`, etc.), disables EC2 instance metadata (IMDS)
  lookups, and points credential/config file paths at nonexistent files.
  This is not just "don't provide real credentials" — it guarantees that if
  a scanned configuration contains something that *would* make a live AWS
  API call, that call fails immediately and safely rather than by chance
  succeeding against whatever account happens to be configured on the host
  running this tool.
- **Scanner subprocesses (Checkov) also never see real cloud credentials**,
  as of this review — `scanners/base.py` now passes a sanitized environment
  (`security.sanitized_subprocess_env()`) to every scanner subprocess,
  stripping the same credential variables. This was a gap before this
  review: only the Terraform planning path had sanitization; the scanner
  path inherited the full parent environment.
- **All working directories are ephemeral, isolated copies.** Both
  `TerraformPlanner` and the scanner path operate inside
  `tempfile.TemporaryDirectory()` — created with restrictive permissions,
  guaranteed unique (no predictable-path race), and cleaned up automatically
  on exit, including on exception. A scanned repository is never planned or
  scanned in place.

## Findings from this review

| # | Threat | Severity | Scenario | Mitigation | Regression test |
|---|---|---|---|---|---|
| 1 | Scanner subprocess inherited real cloud credentials from the parent environment | Medium | If the host running TerraVeritas has real `AWS_*` credentials set, they were passed unfiltered to the Checkov subprocess. Checkov's static analysis shouldn't need them, but "assume malicious input" means not trusting that a third-party tool's internals never attempt a live call. | `security.sanitized_subprocess_env()`, wired into `ScannerAdapter.scan()` | `tests/security/test_env_sanitization.py` |
| 2 | Path traversal via `experiment_id`/`case_id` | Medium-High | `experiments/storage.py` built filesystem paths as `base_dir / experiment_id / ... / f"{case_id}.json"` with no validation. A value like `../../../etc/evil` would escape `base_dir` (pathlib's `/` does not sanitize `..`). Not reachable through any current caller (both values come from this project's own `identifiers.py`), but the storage function itself had no defense-in-depth. | `_validate_path_segment()` rejects any value containing a path separator, `.`, or `..`, applied in both `save_record` and `save_manifest` | `tests/security/test_path_traversal.py` (6 malicious inputs × 3 entry points) |
| 3 | Credentials embedded in scanned Terraform flow verbatim into stored evidence | **High** | Checkov's raw finding output (`raw_evidence`) can include literal source snippets. A scanned repository with a hardcoded `secret_key`/`access_key` (real or fixture) would be faithfully preserved — by design, per the project's "never destroy evidence" principle — all the way into the JSON files written to `datasets/experiments/`, which are exactly the "reports" this review's instructions say must never expose credentials. | `security.redact_secrets()`: redacts by sensitive key name (`secret`, `password`, `private_key`, `access_key`, ...) and by value pattern (AWS access key IDs, PEM private key blocks, bearer tokens) regardless of key name. Applied at `save_record`'s write boundary — the one place a "report" is actually produced. `record_to_dict()` itself stays lossless, deliberately, for legitimate in-memory re-analysis of a loaded record. | `tests/security/test_redaction.py` |
| 4 | Pathologically nested scanner JSON output crashes the scan instead of being classified | Low-Medium | `RecursionError` (from Python's `json` module hitting its recursion limit on deeply nested output) is a `RuntimeError` subclass, not a `ValueError` — the original exception handling in `base.py` only caught `ValueError`/`KeyError`, so this propagated uncaught and crashed the whole `scan()` call. A degenerately complex or adversarially crafted Terraform module could plausibly cause a scanner to emit such output. | Broadened the catch to include `RecursionError`, classified as `OUTPUT_PARSE_ERROR` like any other unparseable output | `tests/security/test_recursion_error_handling.py` |
| 5 | Checkov's own `asteval` dependency pinned to a version with a known CVE | **High** (if reachable) | `uvx pip-audit` found `asteval==1.0.6` (a dependency of every published `checkov` release through 3.3.16) vulnerable to GHSA-9w56-46f6-3qhx / CVE-2026-55244. `asteval` is an expression evaluator; if Checkov's variable/expression resolution passes attacker-controlled HCL expression content through it, this is a real code-execution-adjacent risk under this project's own "assume malicious input" framing. | Forced `asteval>=1.0.9` via `[tool.uv] override-dependencies` (checkov pins it exactly, with no compatible release yet available) — resolved to 1.0.10, confirmed clean by a second `pip-audit` pass. Verified against the full test suite (139 tests, all passing) that the override doesn't change Checkov's observable behavior for how this project invokes it. | Covered indirectly by the full existing Checkov integration test suite continuing to pass; see `pyproject.toml`'s `[tool.uv]` comment for the full writeup |
| 6 | Executable resolved twice via `PATH`, once to verify it exists and again (implicitly, by name) to actually run it | Low | `CheckovAdapter._get_version()` ran `subprocess.run(["checkov", "--version"], ...)`, re-resolving `"checkov"` by name via `PATH` rather than using the already-verified absolute path from `scan()`'s `shutil.which()` check — a narrow TOCTOU-shaped gap if `PATH` changed between the two lookups. | `_get_version()` now resolves via `shutil.which()` itself and runs the absolute path | Covered by existing `test_version_is_captured` in `tests/scanners/test_checkov.py`, which still passes against the resolved-path form |
| 7 | Dead code referencing an unrelated, predictable `/tmp` path | Low | `scripts/run_pilot_experiment.py` had a leftover `shutil.rmtree("/tmp/checkov_probe", ...)` — a reference to unrelated ad hoc manual exploration from an earlier session, not connected to the pilot's actual logic. Not a live vulnerability (nothing in the pipeline ever wrote there), but dead code referencing a predictable shared-tmp path is exactly the shape flagged by static analysis (`ruff`'s `S108`) for good reason in general. | Removed | N/A — removal, not a behavior to regress-test |

## Accepted, monitored risks (not fixed — no fix available)

- **`ecdsa==0.19.2` — PYSEC-2026-1325, no fix version published.** This is a
  long-standing, publicly known class of issue in `python-ecdsa` that its
  maintainers have not patched. It is a transitive dependency of `checkov`,
  likely used for its (disabled, via `--skip-download`) Bridgecrew/Prisma
  Cloud API authentication path. Exposure is believed reduced by that flag,
  but not eliminated, since the package remains installed regardless.
  Tracked for re-audit; no action possible until either checkov drops the
  dependency or a fix is published upstream.

## Explicitly out of scope for this review

- **Container escapes / Docker usage: not applicable.** TerraVeritas does
  not use Docker anywhere in the current codebase, despite it being named
  as an aspirational tech-stack preference in early project documentation.
  This section will need real content once a container image is actually
  built (referenced as future work in `docs/experiment_reproducibility.md`).
- **Git history review for accidental credentials: no history exists yet.**
  This repository has zero commits as of this review (`git log` confirms
  "your current branch 'main' does not have any commits yet"). There is
  nothing to review. This section should be re-run as an actual check once
  commits exist, not assumed clean by extension of this finding.
- **CI/CD secret exposure.** Reviewed `.github/workflows/ci.yml` directly:
  it runs `uv sync`, `ruff check`, `mypy`, `pytest` only — no secrets are
  referenced, configured, or required by the workflow as it exists today.

## Static analysis and dependency checks run

- `ruff check --select S src scripts` (bandit-equivalent security rules,
  scoped to source and scripts — `tests/` intentionally excluded, since
  `S101` "use of assert" fires on every pytest assertion by design and
  provides no signal there): clean after the fixes above.
- `ruff check .` (full default ruleset, whole repo): clean.
- `mypy src` (strict mode): clean, 29 source files.
- `uvx pip-audit` against the resolved dependency set: 3 known
  vulnerabilities in 2 packages found; 1 package (`asteval`) fixed via
  override, 1 finding (`ecdsa`) has no available fix and is documented
  above as an accepted risk. Caveat for reproducing this: `pip-audit -r
  <(uv export --no-hashes)` does not work cleanly once the `asteval`
  override is in place — `pip`'s own resolver (which `pip-audit` shells out
  to) doesn't understand `uv`'s override mechanism and reports a false
  conflict between checkov's declared `asteval==1.0.6` pin and the actually
  -installed `1.0.10`. Verification here was via isolated single-package
  checks (`pip-audit -r <(printf "asteval==1.0.10\n") --no-deps`, confirmed
  clean; same for `ecdsa==0.19.2`, confirmed still flagged) rather than one
  clean whole-environment command — recorded exactly as run, not glossed
  over. **Re-run at release-audit time with a cleaner method**: installing
  `pip` directly into the project's own `.venv` (`uv pip install pip
  --python .venv/bin/python3`) and running
  `PIPAPI_PYTHON_LOCATION=.venv/bin/python3 pip-audit --local` avoids the
  resolver conflict entirely, since it audits packages already installed
  rather than asking pip to re-resolve them — one clean command, same
  result: `ecdsa==0.19.2` (PYSEC-2026-1325) is the only finding, `asteval`
  does not appear (confirming the override remains effective).
- Manual grep sweep for hardcoded secret patterns (AWS access key IDs, PEM
  private key headers, `aws_secret_access_key = "..."` literals) across the
  working tree: none found.
- `uv.lock` is present and tracked (not excluded by `.gitignore`) —
  dependency resolution is reproducible and pinned, not re-resolved fresh
  on every install.

## Reporting a vulnerability

This is a research project without a dedicated security contact address
yet. If you find a vulnerability, open an issue describing the impact and
reproduction steps; avoid including real credentials or other sensitive
data in the report itself.
