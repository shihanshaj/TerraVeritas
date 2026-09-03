# TerraVeritas

Automating the security-intent oracle: machine-checkable invariants for
detecting deceptive fixes in LLM-repaired Terraform.

## What is this?

TerraVeritas is a research pipeline that evaluates whether an AI-generated
repair to a Terraform security finding genuinely fixes the underlying AWS
security problem — as opposed to merely making a scanner stop flagging it.

## Why does it exist?

A security scanner (Checkov, tfsec, etc.) no longer flagging a Terraform
configuration is not the same claim as "the underlying AWS security
property is now satisfied." An AI repair can make a scanner rule stop
firing while the actual vulnerability persists, moves to a different
resource, or only partially closes. TerraVeritas evaluates a repair
against a security invariant — a check grounded directly in AWS's own
documented security semantics, independent of any single scanner's rule
logic — and classifies the repair as one of six outcomes (see
[Verdicts](#what-each-verdict-means-and-does-not-mean) below).

This is a research project. The contribution is the verification
methodology and its empirical evaluation, not the software as a product —
see [Limitations](#limitations) for exactly how much of that methodology
is implemented today.

## What does it actually do today?

Concretely, working, real (not simulated) code exists for:

- **One security invariant**: `S3_PUBLIC_ACCESS_EXPOSURE` — whether an S3
  bucket is reachable by an unauthenticated principal via ACL grants or an
  unconditioned public bucket policy statement, evaluated against AWS's
  own documented "meaning of public" rules
  (`src/terraveritas/invariants/s3_public_access.py`).
- **One scanner integration**: Checkov (`src/terraveritas/scanners/`).
- **A real Terraform plan pipeline**: `terraform init` → `validate` →
  `plan` → `show -json`, safely sandboxed (fabricated AWS credentials, no
  live API calls, no `apply` — ever), producing a real, parsed
  `PlanResult` from a real Terraform CLI run
  (`src/terraveritas/terraform/plan.py`).
- **A differential engine** that compares before/after scanner evidence
  without assuming a disappeared finding means "fixed"
  (`src/terraveritas/differential/`).
- **An oracle** that combines invariant + differential evidence into one
  of six classifications, with an explicit evidence trail
  (`src/terraveritas/verification/oracle.py`).
- **A provider filesystem mirror** that makes the whole pipeline
  deterministic and offline after a one-time setup step (see
  [Prerequisites](#prerequisites)).
- **Two working experiment pilots**: one fully self-contained
  (`scripts/run_pilot_experiment.py`), one that evaluates real,
  externally-generated AI repairs (`scripts/run_real_ai_pilot.py`) — see
  [Running an experiment](#running-an-experiment).
- **A CLI** — `terraveritas scan <directory>` and
  `terraveritas verify <before_directory> <after_directory>`. See
  [Usage](#usage) below. This is the smallest interface that exposes the
  real pipeline above; it is not a separate implementation of it.

## What does it not do?

- **No `compare`/`report`/other CLI subcommands beyond `scan` and
  `verify`.** Those two are the only ones backed by real, tested pipeline
  code end to end.
- **Four of five frozen research-scope security properties have no
  invariant implemented** — only S3 public access exposure is real.
  Security-group ingress, IAM wildcard grants, network reachability, and
  storage encryption are designed (see project design notes) but not
  built.
- **Only one scanner** (Checkov) is integrated. Trivy and KICS are not.
- **No live AI-model API integration.** Nothing in this repository can
  call an external model on its own — see
  [Running an experiment](#running-an-experiment) for exactly what that
  means for reproducing the AI-repair pilot.
- **A real, documented invariant blind spot**: a bucket policy whose
  `Resource` field references the bucket's own computed `.arn` attribute
  (the idiomatic, common way to write such a policy) is unresolved in
  every plan this pipeline produces, and the invariant correctly reports
  `INCONCLUSIVE` rather than guessing. This was found during the pilot
  experiment, not assumed — see `datasets/experiments/` for the record
  that surfaced it.

## Prerequisites

- **Python 3.13+** and [uv](https://docs.astral.sh/uv/) for dependency
  management.
- **Terraform CLI**, version 1.x (developed against 1.14.3). Install from
  the [official HashiCorp instructions](https://developer.hashicorp.com/terraform/install).
  Verify with `terraform version`.
  - If Terraform isn't installed or isn't on `PATH`, every real-plan
    script below fails cleanly with a `plan_terraform_not_installed`
    status and a one-line message naming the missing executable — not a
    crash. If you see this, install Terraform and re-run.
- **A one-time AWS provider mirror build** (see immediately below) —
  required before any real `terraform plan` will succeed.

### Why the provider mirror, and how to build it

`terraform init` needs to download the `hashicorp/aws` provider (~150MB)
from the public registry on first use. In network conditions with low or
unstable bandwidth, this download can be slow enough to time out — this
is a real, diagnosed condition (see
[docs/experiment_reproducibility.md](docs/experiment_reproducibility.md)),
not a hypothetical one. To make every experiment run deterministic
regardless of network conditions on the day you run it, build a local
provider mirror once:

```bash
uv run python scripts/build_provider_mirror.py
```

This downloads (resuming automatically if interrupted) and unpacks the
AWS provider into `.terraform-mirror/` (gitignored — platform-specific,
~680MB unpacked, rebuilt per machine, not committed). Every real-plan
script in this repository is already wired to use this mirror
automatically once it exists. Re-running the build script is safe and
fast — it detects an existing, complete mirror and does nothing.

## Installation

```bash
git clone <this-repository>
cd terraveritas
uv sync --all-groups
uv run python scripts/build_provider_mirror.py   # one-time, see above
uv run pytest                                     # confirm the install: should be all green
```

## Usage

The CLI is a thin wrapper around the pipeline described above — two
subcommands, both backed by real, tested code, nothing else:

```bash
# Scan a directory with Checkov and report findings.
uv run terraveritas scan fixtures/terraform/s3_vulnerable

# The actual point of this project: does a repair genuinely fix the
# security property, not just silence the scanner?
uv run terraveritas verify fixtures/terraform/s3_vulnerable fixtures/terraform/s3_secure
```

`verify` currently evaluates `aws_s3_bucket` resources only (the one
implemented invariant) — if none are found, it says so explicitly rather
than silently doing nothing. Both subcommands accept `--json` for
structured output; `verify`'s JSON includes an explicit
`safe_for_automated_progression` boolean (`true` only for `TRUE_FIX`) so a
CI script never has to parse prose to make that decision. `verify`'s exit
code encodes the same thing: `0` only if every evaluated resource reached
`TRUE_FIX`, `1` if the tool ran successfully but at least one resource did
not, `2` for a tool/environment error (bad path, Terraform missing, plan
failed). See [What each verdict means](#what-each-verdict-means-and-does-not-mean)
before wiring this into anything automated.

## How do I run the simplest real example?

The CLI command above (`terraveritas verify ...`) *is* the simplest real
example. This section additionally documents the underlying script it
wraps, useful when you want the full evidence trail written to disk
rather than just printed — a real `terraform plan` for a genuinely
vulnerable and a genuinely repaired S3 bucket, evaluated by the real
invariant and real oracle, no synthetic data anywhere:

```bash
uv run python scripts/run_real_e2e_pipeline.py
```

**Expected output** (abbreviated; exact wording may vary slightly by
Terraform/provider patch version, but the shape below should match):

```
=== Scenario A: real terraform plan (vulnerable) ===
status: plan_success
resource_changes: ['aws_s3_bucket.data', 'aws_s3_bucket_acl.data']

=== Scenario B: real terraform plan (repaired) ===
status: plan_success
resource_changes: ['aws_s3_bucket.data', 'aws_s3_bucket_acl.data', 'aws_s3_bucket_public_access_block.data']

=== Real invariant evaluation ===
before: status=fail, violated_conditions=['acl_grants_public']
after:  status=pass, violated_conditions=[]

=== Real oracle classification ===
classification: true_fix
confidence: medium
reasons: [...]

✅ REAL end-to-end pipeline succeeded: real plan -> real invariant -> real oracle.
```

Evidence (real plan JSON for both scenarios, plus a summary) is written to
`datasets/real_e2e_pipeline_proof/`. If this script does not end with the
✅ line, something in your environment differs from what's documented here
— see [Troubleshooting](#troubleshooting) before assuming the pipeline
itself is broken.

## Running an experiment

Two different scripts, with an important, honest distinction between them:

### 1. Self-contained pilot (fully reproducible by anyone)

```bash
uv run python scripts/run_pilot_experiment.py
```

Runs two cases through the complete pipeline (prompt template → repair →
scan → differential → plan → invariant → oracle → storage), using
**self-authored** repair text (clearly labeled as such in every stored
record's `ai_model` field) rather than output from an external model —
this proves the pipeline mechanics work, not that any particular AI model
produces good or bad repairs. Records land in
`datasets/experiments/<date>-pilot-s3exposure/`.

### 2. Real AI-generated repair pilot (not one-command reproducible — read this before trying)

`scripts/run_real_ai_pilot.py` evaluates repairs that were genuinely
generated by an AI model, blind to this project's research purpose. **This
script does not call any model itself** — it reads already-saved raw
model responses from fixed file paths and runs them through the real
pipeline. Generating those responses required Claude Code's `Agent` tool
to dispatch isolated subagents with no knowledge of this codebase, which
is not something this repository can invoke on its own, and not something
a generic `uv run python ...` command can reproduce in an arbitrary
environment. If you have your own access to an AI model (any vendor), you
can reproduce the same experiment design by: taking a real Checkov
finding for a fixture in `fixtures/terraform/`, rendering it with
`terraveritas.experiments.prompts.render_minimal`, sending that exact
prompt to your model, saving the raw response, and adapting
`scripts/run_real_ai_pilot.py`'s `CASES` list to point at your saved
response file. The pilot's findings and methodology are documented in the
project's experiment records, not reproduced by running this script
verbatim without model access.

### Expected output shape, either script

Every case prints its real Checkov before/after finding counts, the real
`terraform plan` status for both configurations, the real invariant
verdict for both, and the final oracle classification with reasons — then
writes a full `RepairRecord` (see
[docs/experiment_reproducibility.md](docs/experiment_reproducibility.md)
for the exact schema) to `datasets/experiments/<experiment_id>/records/`.
A `manifest.json` alongside the records lists every case in the run.
Secrets are redacted before anything is written to disk (see
`src/terraveritas/security.py`).

## What each verdict means (and does not mean)

| Classification | Means | Does NOT mean |
|---|---|---|
| `TRUE_FIX` | The invariant was violated before the repair and is confirmed satisfied after it, based on real evidence | That a scanner simply stopped flagging the issue — the invariant is evaluated independently of scanner output |
| `DECEPTIVE_FIX` | The invariant is still violated, but scanner evidence looks like it improved | — |
| `PARTIAL_FIX` | The invariant remains violated, with no clear evidence of concealment or new regression | Progress was necessarily made — see the verdict's own `reasons` field, which states this explicitly when narrowing wasn't measurable |
| `REGRESSION` | A new problem was introduced, or the invariant itself went from satisfied to violated | — |
| `INVALID_CONFIGURATION` | The repair itself is not valid Terraform | The security property was evaluated at all — it wasn't reachable |
| `INCONCLUSIVE` | **There was not enough evidence to determine whether the security property holds** | **"Probably fine." `INCONCLUSIVE` is not a weak form of safe — it is the pipeline explicitly refusing to guess.** |

**Only `TRUE_FIX` should ever be used as the allow condition for any
automated progression** (e.g. auto-merging a repair, closing a finding
without review). Every other classification — including `INCONCLUSIVE` —
must block or require human review, unless and until future research
explicitly establishes a different, evidence-backed policy. Do not build
a gate that allow-lists everything except `DECEPTIVE_FIX`/`REGRESSION`;
that silently treats `INCONCLUSIVE` as passing, which is exactly the
mistake this project exists to prevent.

**`confidence` (`high`/`medium`/`low`) reflects evidence completeness for
the checks this oracle actually performed — never a probability that the
infrastructure is secure**, and it is not comparable across different
classifications the way a percentage would be. A `high`-confidence
`TRUE_FIX` can still be wrong for reasons outside what was checked (see
the invariant's own disclosed scope gaps in its module docstring — e.g.
S3 Access Points are not evaluated at all).

## Repository layout

```
src/terraveritas/
    models/         Shared data models. Pure data, no I/O.
    scanners/       Scanner adapters that produce evidence. Never decide correctness.
    terraform/      Terraform CLI wrapper (init/validate/plan/show -json), sandboxed.
    invariants/     Security invariant specifications and evaluators. The scientific core.
    differential/   Before/after scanner-evidence comparison.
    verification/   The oracle: combines evidence + invariants into a classification.
    experiments/    Prompt templates, record schema, storage, reproducibility snapshot.
    evaluation/     Precision/recall/confusion-matrix harness for ground-truth comparison.
    reporting/      Human-readable and JSON rendering for CLI output (render.py).
    security.py     Subprocess sandboxing and credential redaction — read before extending.
    cli.py          `terraveritas scan` / `terraveritas verify` — see Usage above.

tests/            pytest suite, mirrors src/ structure. Run: uv run pytest
fixtures/         Controlled Terraform configurations (vulnerable, secure, real captured
                  plans, adversarial cases) used by tests and experiment scripts.
datasets/         Experiment output (RepairRecords) and real pipeline evidence. Generated
                  by running the scripts above — not hand-maintained.
scripts/          Runnable entry points — see "Running an experiment" above.
docs/             Deeper technical reference (reproducibility details, exact schemas).
```

## Troubleshooting

**`plan_terraform_not_installed` / "terraform executable not found on
PATH"** — Terraform isn't installed or isn't on `PATH`. Install it (see
[Prerequisites](#prerequisites)) and confirm with `terraform version`.

**A real-plan script hangs or times out on `terraform init`** — you likely
haven't built the provider mirror yet, or built it before this repo's
scripts were wired to use it. Run
`uv run python scripts/build_provider_mirror.py`, confirm
`.terraform-mirror/registry.terraform.io/hashicorp/aws/.../` contains a
provider binary, then retry.

**`plan_provider_failure` on an *after* plan the AI repair produced** —
this can be a genuine, correct pipeline result, not a bug: if the
generated repair introduced a `data` source or other construct requiring
a live AWS API call, this project's deliberately sabotaged, fake AWS
credentials make that call fail safely rather than by chance succeeding
against a real account. Read the `error_message` field in the stored
record before assuming something is broken.

**`INCONCLUSIVE` on a policy referencing `<bucket>.arn`** — a known,
documented invariant limitation (see
[What does it not do?](#what-does-it-not-do)), not a bug to work around
by editing the fixture.

**Tests fail after `uv sync`** — run `uv run pytest -q` for the full
picture; if a specific `tests/terraform/` or `tests/scanners/` test fails
while everything else passes, check that `terraform` and this project's
own dependencies (`checkov`, installed automatically by `uv sync`) are
both on `PATH` inside the `uv run` environment.

## Limitations

- One of five frozen-scope security properties has a real invariant.
- One of three originally-considered scanners is integrated.
- No CLI — every real workflow is a script.
- No live external-model API integration — see
  [Running an experiment](#running-an-experiment).
- The S3 invariant has disclosed, real gaps: legacy inline ACL attributes
  are not read; S3 Access Points are not evaluated at all (the one gap
  that is not safe-direction-only); a bucket-owner default for a bare
  bucket with nothing declared remains genuinely unverified against AWS's
  own documentation, not merely unconfirmed by assumption.
- Reproducibility of the *real AI-generated* pilot specifically depends
  on access to an AI model this repository cannot provide on its own —
  the *pipeline* that evaluates a repair is fully reproducible; the *act
  of generating* one from a real external model is not, without your own
  model access.

## Development

```bash
uv sync --all-groups
uv run pytest
uv run ruff check .
uv run mypy src
```

See [SECURITY.md](SECURITY.md) for the threat model and subprocess/credential
handling this project implements, and
[docs/experiment_reproducibility.md](docs/experiment_reproducibility.md)
for exact record schemas and environment capture details.
