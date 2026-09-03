# Contributing to TerraVeritas

This is a research project. The contribution that matters is the
verification methodology and its empirical evaluation — see README.md's
"What does it actually do today?" and "Limitations" sections before
proposing a change, and read `docs/experiment_reproducibility.md` for how
the existing pipeline was actually validated (including bugs that were
only found by running it against real data, not assumed fixed by
inspection).

## Before you start

- **Read the constitution this project follows**: research contribution
  before software, no feature without a research justification, small
  steps, no fake completion (never claim something works without running
  it), reproducibility, and explicit challenge of scope creep. A pull
  request that adds functionality without a clear research question behind
  it will be asked to justify itself.
- **Do not add functionality without adding tests that exercise it against
  real data wherever feasible**, not only synthetic fixtures. Several real
  bugs in this codebase (see `docs/experiment_reproducibility.md`) were
  found only because a real `terraform plan` or a real subagent-generated
  repair was run through the pipeline — synthetic test data alone did not
  catch them.

## Development setup

```bash
uv sync --all-groups
uv run python scripts/build_provider_mirror.py   # one-time
uv run pytest
uv run ruff check .
uv run mypy src
```

All four must pass before a change is proposed. See README.md's
Prerequisites section if the mirror build step is unfamiliar.

## Where contributions are actually needed

These are honestly the current gaps, not aspirational feature requests:

- **Four of five frozen-scope security invariants are unimplemented**
  (security-group ingress, IAM wildcard grants, network reachability,
  storage encryption). Each needs its own threat-model design pass before
  any code — see `src/terraveritas/invariants/s3_public_access.py`'s
  module docstring for the depth of AWS-semantics grounding a new
  invariant is expected to have, and note its own disclosed scope gaps
  (legacy ACL attributes, S3 Access Points) as an example of what "done"
  looks like: bounded and disclosed, not claimed complete.
- **Trivy and KICS scanner adapters** — the interface
  (`scanners/base.py::ScannerAdapter`) is designed for this; only Checkov
  is implemented.
- **Real, multi-vendor AI-model API integration** for experiment
  generation. `scripts/run_real_ai_pilot.py` currently evaluates repairs
  from blind Claude subagent invocations only (no external vendor API is
  wired into this repository) — see the README's "Running an experiment"
  section for exactly what that means.
- **The documented, disclosed invariant blind spot**: a bucket policy
  whose `Resource` references the bucket's own computed `.arn` is
  unresolved in every plan this pipeline produces. A partial-evaluation
  approach (resolving `Principal`/`Effect`/`Action` even when `Resource`
  alone is unknown) is a real, scoped research question, not yet
  investigated.

## Code style

- No comments explaining *what* code does — only *why*, when the reason
  isn't obvious from the code itself (a hidden constraint, a workaround
  for a specific verified bug, a subtle invariant). This codebase leans
  heavily on this style; look at any existing module before adding a new
  one.
- Prefer the smallest correct fix over a broader refactor, matching the
  "small steps" rule above — this project's own commit history and audit
  trail (see `docs/experiment_reproducibility.md`) is full of examples of
  a narrow, well-verified fix being preferred over a larger rewrite.
- New failure modes must be represented as explicit, named status values
  (see `PlanStatus`, `ScanStatus`) — never a raised exception for an
  expected condition, and never silently absorbed into an existing status
  that doesn't actually describe it.

## Reporting a security issue

See [SECURITY.md](SECURITY.md).
