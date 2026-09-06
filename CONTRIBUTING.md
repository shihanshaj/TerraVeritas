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

- **Three of the originally-scoped security invariants remain
  unimplemented** (network reachability and storage encryption, plus
  broader coverage of IAM exposure beyond the narrow inline-role-policy
  case below). Two were added — `iam_excessive_privilege.py`
  (`IAM_EXCESSIVE_PRIVILEGE_EXPOSURE`, grounded in AWS Config's own
  `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` rule) and
  `network_exposure.py` (`NETWORK_SENSITIVE_PORT_EXPOSURE`, grounded in
  AWS Config's `restricted-ssh` and `restricted-common-ports` rules) —
  each scoped deliberately narrow on its first pass (IAM: only
  `aws_iam_role` + directly-attached inline `aws_iam_role_policy`, not
  managed-policy attachments or user/group policies; network: only the
  inline `ingress` block on `aws_security_group`, not the decoupled
  `aws_security_group_rule` resources), with the gaps disclosed in each
  module's own docstring rather than silently assumed complete. Any new
  invariant needs its own threat-model design pass grounded in real AWS
  documentation before any code — see any of the three existing
  invariants' module docstrings for the depth of AWS-semantics grounding
  and disclosed-scope-gap discipline expected, and note that a real
  `terraform plan` run against a real fixture caught a genuine bug in the
  network invariant (a per-index "known after apply" marker shaped as a
  list, e.g. `[False]`, is truthy in Python even though it means "known" —
  the first implementation attempt treated every security group as
  UNKNOWN unconditionally) before a single test was ever written against
  it — do not skip that step for a new invariant.
- **Trivy and KICS scanner adapters** — the interface
  (`scanners/base.py::ScannerAdapter`) is designed for this; only Checkov
  is implemented.
- **Real, multi-vendor AI-model API integration** for experiment
  generation. `scripts/run_real_ai_pilot.py` currently evaluates repairs
  from blind Claude subagent invocations only (no external vendor API is
  wired into this repository) — see the README's "Running an experiment"
  section for exactly what that means.
- **Partially resolved**: a bucket policy whose `Resource` references the
  bucket's own computed `.arn` is unresolved in every create-action plan
  this pipeline produces. Investigated: field-level reconstruction
  (resolving `Principal`/`Effect`/`Action` independently of `Resource`) is
  **not possible** from Terraform's plan JSON — a real captured plan
  confirms `configuration...expressions.policy` for a `jsonencode(...)`
  call collapses to a flat reference list with no sub-key structure (see
  `s3_public_access.py`'s module docstring). What's implemented instead:
  the ACL and policy sides are evaluated independently, so a resolved,
  independently-public ACL is no longer discarded just because the policy
  is unresolved — verified against real data
  (`tests/invariants/test_s3_public_access.py`'s
  policy-unresolved-partial-evaluation tests). Remaining, still-open: a
  bucket exposed *only* through an unresolved policy (no ACL, or a safe
  ACL) still correctly reports UNKNOWN, not a verdict — genuinely resolving
  that case would need a different evidence source than the plan JSON
  (e.g. parsing the raw HCL policy expression directly), which has not
  been attempted.

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
