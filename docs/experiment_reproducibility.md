# Experiment reproducibility reference

For the quick-start workflow, see the main [README.md](../README.md). This
document covers exact record schemas, environment capture details, and the
network-dependency diagnosis and fix — useful when something doesn't match
what the README describes, or when extending the pipeline.

## What's captured automatically, per record

Every `RepairRecord` stored under `datasets/experiments/<experiment_id>/records/`
carries an `environment` snapshot (`src/terraveritas/experiments/reproducibility.py`),
captured at generation time, not reconstructed after the fact:

- `python_version`, `platform`
- `terraform_version` (parsed from `terraform version`)
- `checkov_version` (from `checkov --version`)
- `git_commit` (from `git rev-parse HEAD`; `"unknown"` if not in a git repo
  or if there are no commits yet — check the current state with `git log`
  rather than assume either way)

Plus, in every record: `prompt_template_id`, the fully rendered prompt
text, `ai_model` / `model_version`, `original_terraform_sha256` (a content
fingerprint of the original vulnerable configuration, independent of file
path), the raw vs. extracted Terraform, and — since the fix described
below — the **full** `before_plan`/`after_plan` (real `PlanResult`
objects, not just their status) and `before_invariant`/`after_invariant`
(real `InvariantResult` objects), so a stored record can be independently
re-audited without re-running anything. Secrets are redacted
(`src/terraveritas/security.py::redact_secrets`) before any of this is
written to disk.

## The provider registry network problem — diagnosed and solved

**Root cause, established by direct measurement, not assumption**: DNS
resolution, TCP/TLS, and the registry metadata API all responded in under
half a second in this project's own development environment. The actual
constraint was unstable, degrading throughput on the ~150MB AWS provider
binary download specifically — a `curl` with a 240s cap completed *less*
of the file than a 120s cap did on a separate attempt, meaning the
connection was not simply slow but degrading over its lifetime. It was,
however, resumable: `curl -C -` across two attempts completed the full,
verified-correct file.

**A plugin cache alone does not fix this.** It was tested directly: with
only `TF_PLUGIN_CACHE_DIR` set (no filesystem-mirror override), `terraform
init` eventually succeeded, but took 2 minutes 47 seconds and remained
dependent on registry round-trips for checksum and signature verification
on every single run — not deterministic, not suitable for CI or repeated
experiment runs.

**The fix**: a local Terraform provider *filesystem mirror*
(`provider_installation { filesystem_mirror { ... } }` in a generated CLI
config), which needs zero registry round-trips of any kind once built.
Measured: under 3 seconds for a real `terraform init` + `plan` +
`show -json` cycle, fully offline. Build it once with:

```bash
uv run python scripts/build_provider_mirror.py
```

`TerraformPlanner` (`src/terraveritas/terraform/plan.py`) accepts a
`filesystem_mirror_dir` parameter that every real-plan script in this
repository already passes. The mirror itself lives at
`.terraform-mirror/` — gitignored (a ~680MB unpacked, platform-specific
binary; rebuilt per machine via the script above, never committed).

## Running the pilots yourself

**Self-contained (fully reproducible by anyone with this repo)**:

```bash
uv run python scripts/run_pilot_experiment.py
```

Two cases, self-authored repair text (disclosed as such in every record's
`ai_model` field — this proves pipeline mechanics, not repair quality).
Writes `datasets/experiments/<today>-pilot-s3exposure/`.

**Real end-to-end proof, real Terraform plan both sides**:

```bash
uv run python scripts/run_real_e2e_pipeline.py
```

Writes `datasets/real_e2e_pipeline_proof/`, including the real captured
plan JSON for both scenarios.

**Real AI-generated repair pilot** — see the README's
["Running an experiment"](../README.md#running-an-experiment) section for
the honest scope limitation here: `scripts/run_real_ai_pilot.py` evaluates
already-saved model responses, it does not generate them itself.

All three are safe to re-run — read-only Checkov/Terraform calls, no
`apply`, and (for scripts that plan an AI-generated repair) fabricated AWS
credentials that fail closed rather than by chance reaching a real
account.

## A real bug this reproducibility work caught

Worth recording precisely, since it's a good illustration of why "the
pipeline runs" and "the pipeline is correct" are different claims: the
first time a real `terraform plan` ever succeeded in this project (via
the mirror above), the invariant incorrectly reported the vulnerable
scenario as `PASS`. Root cause: a `create`-action plan (the only kind this
project ever produces, since `apply` is never run) leaves a computed
cross-reference like `bucket = aws_s3_bucket.data.id` entirely unresolved
in `after` — omitted, not a placeholder — so a join strategy based on
*resolved* values can never match the overwhelmingly common case of
referencing the bucket resource directly rather than hardcoding its name.
Fixed by adding a static-reference-graph join
(`configuration.root_module.resources[].expressions`) as the primary
correlation strategy. Regression-tested against the real captured plan
JSON in `fixtures/real_plans/` — not just synthetic data. This is exactly
why the "smallest real example" in the README matters as a check to run
after any change to the invariant or plan-parsing code, not only once.

## Extending to a larger study (not run yet)

The full study design (multiple models × prompt strategies × invariants)
has not been executed, per this project's own "pilot first, stop and
report" discipline. Running it requires: wiring a real model API into
`experiments/` (a generator interface analogous to `ScannerAdapter`'s
would fit the existing pattern), and implementing the remaining four
frozen-scope security properties — the provider-mirror network problem
above is no longer a blocker for either.
