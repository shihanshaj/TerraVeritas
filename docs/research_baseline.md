# Research baseline — reproducibility audit

**Audit date:** 2026-09-07
**Auditor role:** research engineering / reproducibility audit (no invariant behavior, no historical experiment record, and no feature changed in this pass)

This document is a snapshot, not a claim of progress. It exists so the next experimental phase starts from a verified, exact state instead of an assumed one.

## Repository identity

| | |
|---|---|
| Repository URL | `https://github.com/shihanshaj/TerraVeritas.git` |
| Branch | `main` |
| HEAD commit | `48bc46bddfbc16e30b87584c9825a663333a5a34` |
| HEAD commit date | 2026-09-06 12:23:49 +0530 |
| HEAD commit subject | `feat: first genuinely cross-vendor experiment (Gemini vs. Claude)` |
| Working tree at audit time | clean (`git status --short` empty) |
| Local vs. `origin/main` | in sync (0 ahead, 0 behind) |
| Existing tags | `v0.1.0-validation` — points to `9255701` (`Final analysis: evidence-based metrics, claim audit, publication verdict`), predates commits `09d5ec8`, `2307737`, `7ee2ff7`, `48bc46b` |

`v0.1.0-validation` is **not** the latest stable state — it was cut before the BPA-rescue fix, the DECEPTIVE_FIX scoping fix, the IAM/network invariants, and the cross-vendor pilot. No new tag has been created in this audit pass (tagging is a project decision, not an audit action); `48bc46bddfbc16e30b87584c9825a663333a5a34` is the exact commit this document describes and should be cited directly until/unless the project chooses to tag it.

## Environment

| | |
|---|---|
| Python | 3.13.0 (pinned via `.python-version` = `3.13`; `pyproject.toml` requires `>=3.13,<3.14`) |
| Package/dependency manager | `uv 0.10.11` |
| Terraform CLI | v1.14.3, `darwin_arm64` (README documents "developed against 1.14.3"; a newer 1.16.1 is available upstream but not adopted) |
| Checkov | 3.3.16, resolved via `uv run checkov --version` from `uv.lock` — **not** installed as a standalone CLI on `PATH`; it is a project-managed dependency, always invoked through `uv run` |
| Operating system used for this audit | macOS (Darwin 25.5.0, arm64) |
| CI operating system | `ubuntu-latest` (`.github/workflows/ci.yml`) — the project has never been verified on Windows |
| Known dependency override | `asteval>=1.0.9` forced via `[tool.uv] override-dependencies`, overriding checkov's exact `asteval==1.0.6` pin, to remediate CVE-2026-55244 / GHSA-9w56-46f6-3qhx; verified against the full test suite; documented in `SECURITY.md` |
| AWS provider mirror | Required for any real `terraform plan`; built once locally at `.terraform-mirror/` (gitignored, not tracked — correctly a local build artifact, not a machine-specific path baked into source). Build instructions are in `README.md`. Tests that call `TerraformPlanner` depend on this mirror already existing on the machine that runs them. |
| AWS credentials | **Not required.** All plan-based analysis is static (`terraform plan`, no `apply`); `.env.example` documents this explicitly. |

## Verification performed in this audit

All commands below were run against `48bc46bddfbc16e30b87584c9825a663333a5a34` with a clean working tree.

```bash
git branch --show-current
git log -1 --format="%H %ci"
git tag -l -n99
git remote -v
git status --short
git rev-list --left-right --count origin/main...main

python3 --version
terraform version
uv run checkov --version

uv run pytest -q
uv run ruff check .
uv run mypy src
```

Results:

- **Tests:** `252 passed in 156.83s`, 0 failed, 0 skipped, 0 errors.
- **Lint (`ruff check .`):** `All checks passed!`
- **Type check (`uv run mypy src`):** `Success: no issues found in 36 source files`. Scope is `src` only, matching the project's own CI convention (`.github/workflows/ci.yml`) and `CONTRIBUTING.md` — not `mypy src tests`, which the project has already established (in an earlier phase) surfaces ~38 pre-existing, unrelated typing-looseness findings in test code that are out of the established CI contract and were deliberately not treated as regressions.

### Secrets, credentials, and machine-specific paths

```bash
git ls-files | grep -i '\.env'
git grep -InE "AQ\.[A-Za-z0-9_-]{20,}|AIzaSy[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|GEMINI_API_KEY\s*=\s*[\"']?[A-Za-z0-9]|ANTHROPIC_API_KEY\s*=\s*[\"']?sk-" -- .
git grep -In "<the literal Gemini key used in the cross-vendor pilot>" -- .
git grep -InE "/Users/shihanshaj|/private/tmp/claude-501" -- .
```

- Only `.env.example` is tracked (a placeholder documenting there is no AWS-credential requirement yet); no `.env` file is tracked. `.env` is listed in `.gitignore` and was never committed at any point in this project's history.
- No API key material, tokens, or credential-shaped strings found anywhere in tracked files, including the real Gemini key used in the cross-vendor pilot — it never touched a tracked file or a stored experiment record.
- **Reproducibility risk found (not fixed in this pass, since fixing it is a code change beyond audit scope):** five scripts hardcode a session-specific absolute scratch path from the assistant's own tooling, not a real project dependency:
  - [scripts/run_cross_vendor_pilot.py:58](scripts/run_cross_vendor_pilot.py:58)
  - [scripts/run_experiment.py:53](scripts/run_experiment.py:53)
  - [scripts/run_negative_case_pilot.py:82](scripts/run_negative_case_pilot.py:82)
  - [scripts/run_phase2_negative_case_experiment.py:88](scripts/run_phase2_negative_case_experiment.py:88)
  - [scripts/run_phase3_alternate_model_experiment.py:69](scripts/run_phase3_alternate_model_experiment.py:69)

  Each hardcodes `/private/tmp/claude-501/-Users-shihanshaj-Desktop-Test/<session-id>/scratchpad` as the location of a one-off raw-AI-response staging file (the actual API call that produced those files was never itself committed — only its output, already persisted into `datasets/experiments/`, matters for reproducibility). These scripts are historical run records, not part of the reusable pipeline (`experiments.pipeline.evaluate_repair` is the reusable part), and none of them are exercised by the test suite. But as written, none of these five scripts are re-runnable on any machine other than the one that originally produced them, since the path does not exist elsewhere. This should be fixed (e.g. accept the raw-response directory as an argument or read from a path relative to the repo) before anyone relies on re-running them as documentation of method rather than as a historical log.

### Experiment dataset immutability

```bash
git status --short datasets/
for d in datasets/experiments/*/; do git log --oneline -- "$d" | wc -l; done
```

- `datasets/` has zero working-tree diff against HEAD.
- Every one of the 7 dataset directories under `datasets/experiments/` has been touched by **exactly one** commit in the entire git history (its creation commit) — no dataset has ever been edited after being committed. This is the mechanical confirmation behind every "we did not silently overwrite historical results" claim made in the invariant-fix documentation (`docs/invariant_bpa_rescue_fix.md`, `docs/deceptive_fix_scoping.md`).

## Invariants currently implemented

| Invariant ID | File | Security domain | AI-repair experiments run against it |
|---|---|---|---|
| `S3_PUBLIC_ACCESS_EXPOSURE` | [src/terraveritas/invariants/s3_public_access.py](src/terraveritas/invariants/s3_public_access.py) | Storage exposure (bucket ACL / bucket policy / Block Public Access rescue logic) | **Yes** — all 22 real experiment records in `datasets/experiments/` |
| `IAM_EXCESSIVE_PRIVILEGE_EXPOSURE` | [src/terraveritas/invariants/iam_excessive_privilege.py](src/terraveritas/invariants/iam_excessive_privilege.py) | Identity/permissions (bare `Action="*"` + `Resource="*"` admin-access detection, grounded in AWS Config's `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS`) | **No** — verified only against real Terraform plans and 14 unit tests; zero end-to-end AI-repair experiments exist for this invariant |
| `NETWORK_SENSITIVE_PORT_EXPOSURE` | [src/terraveritas/invariants/network_exposure.py](src/terraveritas/invariants/network_exposure.py) | Network exposure (security groups open to `0.0.0.0/0`/`::/0` on ports 22, 20, 21, 3306, 3389) | **No** — verified only against real Terraform plans and 17 unit tests; zero end-to-end AI-repair experiments exist for this invariant |

This is the single most important scope fact for the next phase: **the "TerraVeritas is a methodology, not just an S3 analyzer" claim is currently only architecturally supported (three independently-reasoned invariants exist and pass real-plan verification), not experimentally supported (only one of the three has ever been run through an actual AI-repair experiment).** Do not describe IAM or network results as validated by AI-repair experiments in any future write-up — none exist yet.

## Consolidated experiment pipeline and scanner-only baseline

- `experiments.pipeline.evaluate_repair` ([src/terraveritas/experiments/pipeline.py](src/terraveritas/experiments/pipeline.py)) is the single canonical evaluation path, consolidated in commit `4e35d88` from four previously-duplicated per-script implementations. Every dataset from `2026-09-04-phase6-canonical-pipeline` onward uses it; the three dataset folders before that (`2026-09-02...`, `2026-09-03...`, and the `phase2`/`phase3` negative-case folders) predate the consolidation and were produced by the earlier per-script logic.
- Scanner-only baseline evaluation exists and is persisted as real data (`scanner_baseline` field on every `RepairRecord` from the consolidated pipeline onward; documented in `docs/scanner_only_baseline_comparison.md`), giving a real (not asserted) comparison point between "Checkov alone" and "TerraVeritas."
- Cross-vendor Gemini pilot: `scripts/run_cross_vendor_pilot.py`, dataset `datasets/experiments/2026-09-06-cross-vendor-pilot-gemini/`, documented fully in `docs/cross_vendor_pilot.md`. 3 real cases (A/B/E), same fixtures and prompts as the corresponding Phase 2/3 Claude cases, evaluated through the same canonical pipeline. This is the first non-Anthropic-sourced repair evidence in the project.

## Existing experiment datasets (all real, no synthetic `PlanResult`/`ScanResult` anywhere)

| Dataset | Created by commit | Cases |
|---|---|---|
| `2026-09-02-pilot-s3exposure` | `f9567ed` | 2 |
| `2026-09-03-real-ai-pilot-s3exposure` | `f9567ed` | 3 |
| `2026-09-04-negative-case-pilot-s3exposure` | `ab481c1` | 3 |
| `2026-09-04-phase2-negative-case-experiment` | `ab481c1` | 5 |
| `2026-09-04-phase3-alternate-model-experiment` | `ab481c1` | 5 |
| `2026-09-04-phase6-canonical-pipeline` | `4e35d88` | 1 |
| `2026-09-06-cross-vendor-pilot-gemini` | `48bc46b` | 3 |

Total: **22 real repair records**, all against the `S3_PUBLIC_ACCESS_EXPOSURE` invariant.

## Current real experimental results (oracle verdicts, all 22 records)

| Classification | Count |
|---|---|
| `TRUE_FIX` | 8 |
| `PARTIAL_FIX` | 2 |
| `REGRESSION` | 1 |
| `INCONCLUSIVE` | 11 |
| `DECEPTIVE_FIX` | 0 |

Notes on how these differ from the last full write-up (`docs/experimental_validation_report.md`, cut at tag `v0.1.0-validation`, 19 records, 7 `TRUE_FIX` / 1 `PARTIAL_FIX` / 1 `REGRESSION` / 10 `INCONCLUSIVE`):

- The 3 new records are the Gemini cross-vendor pilot: +1 `TRUE_FIX`, +1 `PARTIAL_FIX`, +1 `INCONCLUSIVE`.
- The BPA-rescue fix (`09d5ec8`) and the DECEPTIVE_FIX scoping fix (`2307737`) were each verified via read-only historical re-evaluation to produce **zero classification changes** across the pre-existing 19 records — both are documented in `docs/invariant_bpa_rescue_fix.md` and `docs/deceptive_fix_scoping.md`, including the specific records whose underlying invariant *reasoning* changed (2 records, UNKNOWN→PASS) without their oracle *classification* changing.
- `DECEPTIVE_FIX` remains at **zero real observations** across all 22 records and three separate genuine attempts to elicit it. This is unchanged by any fix made this arc and remains the single largest open question for the project's stated purpose.

## Known limitations (current, as of this commit)

1. **`DECEPTIVE_FIX` has never been observed.** Three deliberate attempts across two experimental generations produced no case where a repair satisfied the scanner while the invariant still failed on a properly-scoped related resource. The scoping fix in `2307737` makes the detection *more correct*, not *more likely to fire* — it has not yet been exercised by a genuine positive case.
2. **IAM and network invariants have zero AI-repair experimental evidence.** They exist, are grounded in real AWS semantics, and pass real-plan-based unit verification (14 and 17 tests respectively), but no repair generated by any model has ever been evaluated against them end-to-end.
3. **Human evaluation remains uncollected.** `docs/human_evaluation/packet.md`, `protocol.md`, and `answer_key.json` exist and were delivered to the sole available real evaluator (the user); as of this audit, no human classifications have been returned, so inter-rater agreement cannot be computed and the "oracle agrees with human judgment" claim remains untested.
4. **Cross-vendor evidence is n=3, one invariant, one prompt template, one vendor pair (Gemini vs. Claude).** `docs/cross_vendor_pilot.md` is explicit that this establishes replication of specific outcomes, not a generalizable rate claim.
5. **Five historical runner scripts hardcode a non-portable, session-specific scratch path** (listed above under Secrets/paths) — not a correctness bug in any stored result, but a reproducibility gap in those scripts' own re-runnability.
6. **The provider mirror is a required, undocumented-in-CI local prerequisite.** CI (`ubuntu-latest`) presumably builds or otherwise handles this differently from the documented local workflow; this audit did not verify CI's actual provider-fetch behavior, only the local `README.md` procedure.
7. **`v0.1.0-validation` is a stale tag** relative to `main` — four feature/fix commits ahead of it. Anyone citing that tag as "current" would be citing a superseded state.

## Known unresolved architectural issues

1. **`_has_relevant_new_findings`'s regression-detection scope is unscoped**, unlike the now-scoped `_scanner_shows_improvement` (fixed in `2307737`). This is a distinct but related architectural question: fixing it would change the classification of `negcase3_regression_unrelated_change` (the project's only real `REGRESSION` example), so it was deliberately flagged rather than fixed in `docs/deceptive_fix_scoping.md` and remains open for an explicit future decision — fixing it without deciding what should happen to that record would violate the "do not silently overwrite historical results" constraint this project operates under.
2. **No cross-resource correlation exists yet for the IAM or network invariants** comparable to `related_resource_addresses` on the S3 invariant. This has not caused an observed problem (no experiments have run against them), but the architectural gap is real and would need the same design attention Priority 3 gave to S3 before those invariants are relied on for cross-resource security scenarios (e.g., an IAM policy attached via a separate `aws_iam_role_policy_attachment` resource, or a security group rule defined via a standalone `aws_security_group_rule` rather than inline).

## Claims: experimentally demonstrated vs. untested

| Claim | Status |
|---|---|
| Can evaluate real, unscripted AI-generated Terraform repairs end-to-end (real plan, real scan, real invariant, real oracle) | **Experimentally demonstrated** — 22 real records, 3 vendor/model combinations |
| Distinguishes `TRUE_FIX` from `PARTIAL_FIX` on real data | **Experimentally demonstrated** — 2 real `PARTIAL_FIX` instances, now from two independent vendors (Haiku and Gemini) on the same fixture, per `docs/cross_vendor_pilot.md`'s own "load-bearing result" analysis |
| Provides evidence beyond scanner re-approval alone | **Experimentally demonstrated as possible** — real, persisted `scanner_baseline` comparisons exist (`docs/scanner_only_baseline_comparison.md`) |
| A known invariant gap (BPA/Object-Ownership rescue ordering) can be fixed without silently altering historical results | **Experimentally demonstrated** — real before/after re-evaluation on the full historical corpus, documented, zero silent changes |
| Cross-resource scanner-improvement scoping can be made more correct without regressing the existing corpus | **Experimentally demonstrated** — same read-only re-evaluation methodology, zero classification changes, applied to `2307737` |
| Detects a scanner-satisfying but still-insecure repair (`DECEPTIVE_FIX`) | **Untested** — zero real observations after three genuine attempts; structural reason (documented in `docs/deceptive_fix_scoping.md` and `docs/phase9_scientific_claim_audit.md`) to suspect this needs either a harder-to-satisfy fixture design or a different elicitation strategy, not just more of the same kind of run |
| Methodology generalizes beyond S3 to other AWS security domains | **Partially untested** — architecturally extended (2 new invariants, 3 domains) and unit/real-plan verified, but **not yet exercised by any AI-repair experiment** |
| Oracle agrees with independent human judgment | **Untested** — materials ready and delivered, zero labels returned as of this audit |
| Results replicate across model vendors, not just within Anthropic's own model family | **Experimentally demonstrated for n=3** (not generalizable beyond that sample size — stated explicitly in `docs/cross_vendor_pilot.md`) |

No claim above has been upgraded, downgraded, or reworded relative to the underlying evidence to make the project look more or less complete than the commands run in this audit actually show.

## Summary verdict

The repository at `48bc46bddfbc16e30b87584c9825a663333a5a34` on `main` is a clean, fully-passing (252/252 tests, ruff clean, strict-`mypy`-on-`src` clean), secret-free, dataset-immutable baseline. It is a legitimate, reproducible starting point for the next experimental phase. It is **not** a finished validation: `DECEPTIVE_FIX` is unproven, two of three invariants have zero AI-repair experimental evidence, human validation is uncollected, and cross-vendor evidence is a 3-case pilot. Anyone building on this baseline should treat those four gaps as the actual open research problem, not as already-closed background.
