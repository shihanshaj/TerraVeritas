# TerraVeritas Experimental Validation Report

Scope: this report covers the validation arc from the Phase 0 re-audit through the Phase 9 claim audit — an independent, evidence-driven attempt to determine whether TerraVeritas's central research claim is actually true, not to make the project look successful. Every number in this report traces to a real, stored artifact (a test, a dataset record, a doc produced earlier in this arc); nothing is recalled from memory without being re-checked. No academic paper is written here, per instruction.

---

## 1. Current repository state

As of the start of this phase: 6 original commits (`408714b` through `5ec09e2`, project foundation through CLI/docs) plus **36 uncommitted changed/new paths** (6 modified, 30 new) accumulated across Phases 0–9. Test suite: **213 passing**, 0 failing, across 34 source modules under `src/terraveritas/`. `ruff check .` and `mypy --strict src` both clean. **19 real experiment records** exist under `datasets/experiments/`, all built from real Terraform plans and real Checkov scans — confirmed by direct audit (Phase 6/7) that no synthetic `PlanResult` or `ScanResult` was ever constructed as part of the experimental dataset. Seven documentation artifacts now exist under `docs/` beyond the pre-existing `experiment_reproducibility.md`: the schema, the baseline comparison (`.md` + `.json`), the human-evaluation packet/protocol/answer-key, and the Phase 8/9 analysis and audit documents.

---

## 2. Problems discovered

Every one of these was found by running something real, not by inspection alone:

1. **Policy-unresolved blind spot** (Phase 1): a bucket policy interpolating the bucket's own computed `.arn` is entirely unknown at plan time in a create-action plan. The invariant returned a blanket `UNKNOWN` for the whole bucket the moment this happened, discarding an independently-conclusive ACL on the same resource. Root cause traced to a real captured plan (`case3_acl_and_policy`'s stored record) and to Terraform's own plan-JSON schema (`configuration.expressions.policy` collapses a `jsonencode(...)` call to a flat reference list — verified, not assumed, field-level reconstruction is not possible from this evidence source).
2. **A gap in the Phase 1 fix itself** (found in Phase 2/3, real data): the fix's independent-neutralization logic (an unresolved side can be rescued by a known-safe BPA flag) only applies when the content *is* resolved — it is never consulted when the content is unresolved, even though `restrict_public_buckets=True` would rescue it regardless of content. Confirmed twice, independently, by two different generating models producing the same shape (`phase2_case_d`, `phase3_case_d`).
3. **Resource-identity mismatch blocking `DECEPTIVE_FIX`** (Phase 2): Checkov attributes a policy-based finding (`CKV_AWS_70`) to the policy resource's own address, not the bucket's, because it's a `BaseResourceCheck`, not a graph check. Every experiment script scopes the oracle's scanner-improvement signal to the bucket's address — so this finding is structurally invisible to that signal, independent of repair quality. Confirmed by reading Checkov's actual installed source and by observing the real differential in `phase2_case_c`'s record.
4. **Whole-resource-must-be-scanner-clean bottleneck**, compounding #3: Checkov's comprehensive default S3 ruleset (versioning, encryption, logging, replication, notifications) means a bucket almost never reaches "fully clean" from one narrow fix, further constraining when `DECEPTIVE_FIX` could ever fire.
5. **Live-AWS-API-dependent Terraform data sources are unresolvable in this sandbox**, recurring 4 times independently across different cases and different models (`case2_policy_only`, `negcase2`, `phase2_case_c`, and analytically anticipated then confirmed again in `phase3`'s data-source-free result by contrast): `aws_caller_identity` requires a live STS call this sandboxed, non-applying evaluation model cannot make, regardless of whether the underlying repair is actually correct.
6. **`REGRESSION` classification is noisier than intended** (Phase 2/4/8): it fires on *any* new Checkov finding on the resource, not just security-relevant ones — confirmed in `negcase3`, where an unrelated multipart-upload-abort lint finding, not an actual security change, triggered the classification while the tracked invariant itself never changed.
7. **Local-model resource constraint** (Phase 3): the one genuinely independent, different-vendor open-source model present on this machine (`deepseek/deepseek-r1-0528-qwen3-8b`) could not be safely loaded — the machine has 8GB RAM and LM Studio's own guardrail refused, citing risk of a system freeze. Confirmed via `vm_stat` (~59MB free at the time), not assumed.
8. **A naive "broader" scanner-only baseline was itself wrong** (Phase 4, self-caught): a first version included `CKV2_AWS_6` ("no Block Public Access resource") as if absence-of-hardening meant exposure, which produced `FIX_REJECTED` on cases already independently confirmed genuinely safe. Corrected before publishing, with a regression test added (`test_broad_not_fooled_by_absence_of_hardening_control`) so it can't silently regress.
9. **`environment_anomalies` had no dedicated field** anywhere in the schema (Phase 7) — exactly one anomaly had ever been recorded, buried under a non-standard key in one script, and nowhere else, despite the schema requiring it.
10. **The scanner-only baseline was computed only retrospectively**, never persisted as part of a record's own evidence (Phase 6) — meaning "record the scanner-only baseline" (a required evidence step) wasn't actually satisfied by the live pipeline, only by a separate analysis run after the fact.
11. **Four experiment scripts had drifted into near-duplicate, hand-rolled implementations** of the same real-execution sequence (Phase 6), increasing the risk that a fix applied to one would silently not apply to the others.
12. **A caught near-miss, not a shipped bug**: while drafting the Phase 6 canonical script, a plausible-looking AI response was hardcoded directly into the script instead of coming from a real subagent invocation — exactly the kind of fabrication this project's own constitution forbids. Caught before the script was ever run against it; a genuine blind subagent was invoked instead, and the hardcoded text was discarded. Recorded here because a validation report that only lists problems found in the *product* and omits one caught in the *validation process itself* would be incomplete.

---

## 3. Changes made

**Source code** (`src/terraveritas/`):
- `invariants/s3_public_access.py` — the Phase 1 partial-evaluation fix (independent ACL/policy-side evaluation; an unresolved side can contribute `FAIL` but never `PASS`), plus updated module docstring documenting the investigation and its negative finding (field-level reconstruction is not possible).
- `models/baseline.py` (new) — `ScannerOnlyBaseline` / `BaselineConclusion`.
- `evaluation/scanner_baseline.py` (new) — `compute_scanner_only_baseline()`, narrow + corrected broad logic.
- `experiments/pipeline.py` (new) — `evaluate_repair()`, the consolidated real-execution pipeline replacing four hand-rolled duplicates.
- `models/experiment.py` — `RepairRecord` gained `scanner_baseline` and `environment_anomalies` fields (both additive, backward-compatible).
- `experiments/storage.py` — loader support for both new fields.

**Tests** (all real or, where synthetic, explicitly scoped to implementation-correctness, never the experimental dataset):
- 5 new invariant tests for the Phase 1 fix, 2 of them against real captured plan JSON extracted from the actual failing case (`fixtures/real_plans/s3_acl_{public,private}_policy_unresolved_*_plan.json`), 3 synthetic covering the symmetric direction and the critical safety boundary (unresolved side must never become `PASS`).
- 7 new tests for `compute_scanner_only_baseline`, including a direct regression test for problem #8 above.
- 1 new **real** end-to-end integration test (`tests/experiments/test_pipeline.py`) — genuine Terraform CLI + genuine Checkov, no mocks — proving the pipeline consolidation is behaviorally identical to what it replaced.
- Strengthened `test_round_trip_preserves_every_field` to exercise real, non-default values for the two new fields rather than letting them pass trivially via their defaults.
- Suite grew from 200 (session start) → 213.

**Experiment corpus** (`fixtures/terraform/`, `datasets/experiments/`, `scripts/`):
- 3 fixtures + `run_negative_case_pilot.py` (predate this Phase 0–10 arc; audited, not created, by Phase 0).
- 5 fixtures (`phase2_case_a`–`e`) + `run_phase2_negative_case_experiment.py`, run for real.
- Same 5 fixtures reused with `run_phase3_alternate_model_experiment.py` (Haiku 4.5), run for real.
- `run_experiment.py` (new canonical script on `evaluate_repair`), run for real with a genuinely fresh blind repair (problem #12's correction).
- 6 real experiment folders total, 19 real records, 0 deleted.

**Documentation**: `CONTRIBUTING.md` updated to remove a now-stale "not yet investigated" claim; `docs/scanner_only_baseline_comparison.{md,json}`, `docs/human_evaluation/{protocol.md,packet.md,answer_key.json}`, `docs/experiment_result_schema.md`, `docs/phase8_analysis.md`, `docs/phase9_scientific_claim_audit.md`, this report.

---

## 4. Experimental design

**Case construction**: every case pairs a hand-authored, deliberately minimal Terraform fixture (never AI-authored, to keep the *starting* vulnerability unambiguous) with a security finding or, in the regression-probe cases, an explicitly unrelated feature request. Two disclosed, deliberate methodological choices: (a) hardcoded literal bucket ARNs in policy statements where the case needed to be resolvable at plan time (sidesteps problem #1's underlying Terraform limitation, at the cost of being less naturalistic than idiomatic `.arn`-referencing Terraform — disclosed, not hidden); (b) one case (`phase2/3_case_b`) deliberately withholds part of the original file from the generating model, to isolate "does narrow-context remediation leave residual exposure" from "does a security-conscious model exceed its instructions when it can see everything" (already answered yes, twice, in earlier attempts).

**AI generation**: every repair comes from a genuinely blind Agent-tool subagent invocation (`subagent_type=general-purpose`), shown only a Terraform file and either one Checkov finding or an unrelated feature request — no awareness of TerraVeritas, the invariant, the oracle, expected classifications, or how to satisfy this project's evaluation. Two generating sources were used: Claude Sonnet 5 (the default) and Claude Haiku 4.5 (Phase 3) — both Anthropic. A genuinely independent, different-vendor local model was identified but could not be safely run (problem #7); no external vendor API credentials exist in this environment. **This is disclosed everywhere it matters, including in claim 6 of the Phase 9 audit — this project has never achieved genuine multi-vendor evaluation, and no report in this arc claims otherwise.**

**Baseline methodology**: two scanner-only baselines are computed per case from real before/after Checkov evidence alone — narrow (re-check only the originally-reported rule, matching most real CI gates) and broad (re-check every rule that fires on an actual public-access grant, deliberately excluding "protective control absent" advisories after problem #8 was found and fixed).

**Invariant methodology**: `S3_PUBLIC_ACCESS_EXPOSURE`, grounded in AWS's own documented Block Public Access semantics (verified against AWS's documentation during original design, and independently re-verified against Checkov's own installed check source in Phase 2 to confirm non-circularity — see Phase 9's claim 5). Evaluates ACL and policy sides independently since Phase 1; an unresolved side can contribute `FAIL` but never `PASS`.

**Oracle methodology**: a pure decision function (`classify_repair`) over the invariant's before/after results and scanner differential evidence, with two structural safety properties: scanner evidence can only ever downgrade a verdict, never produce `TRUE_FIX` on its own; any `UNKNOWN` invariant result on either side short-circuits to `INCONCLUSIVE` before the positive/negative branches are even reached.

**Evidence preservation**: every record stores the case ID, vulnerability type, original-config hash, model identifier, raw response (unedited), extracted repair, both scans, both plans, both invariant results, the differential, the oracle verdict and confidence, human label (currently always `None`), and environment anomalies — the full Phase 7 schema. Verified by direct audit that manifest record counts match files on disk in every experiment folder (nothing removed) and that no case has a `-001`/`-002` retry variant (nothing regenerated after seeing a result).

---

## 5. Complete results table — all 19 real cases

| Case | Experiment | Generating model | Classification |
|---|---|---|---|
| `intent_explicit` | 2026-09-02-pilot-s3exposure | self-authored (not AI) | `inconclusive` |
| `minimal` | 2026-09-02-pilot-s3exposure | self-authored (not AI) | `inconclusive` |
| `case1_acl_only` | 2026-09-03-real-ai-pilot-s3exposure | Claude Sonnet 5 | `true_fix` |
| `case2_policy_only` | 2026-09-03-real-ai-pilot-s3exposure | Claude Sonnet 5 | `inconclusive` |
| `case3_acl_and_policy` | 2026-09-03-real-ai-pilot-s3exposure | Claude Sonnet 5 | `inconclusive` |
| `negcase1_partial_two_vectors` | 2026-09-04-negative-case-pilot | Claude Sonnet 5 | `true_fix` |
| `negcase2_deceptive_principal_condition` | 2026-09-04-negative-case-pilot | Claude Sonnet 5 | `inconclusive` |
| `negcase3_regression_unrelated_change` | 2026-09-04-negative-case-pilot | Claude Sonnet 5 | `regression` |
| `phase2_case_a_genuine_fix` | 2026-09-04-phase2-negative-case-experiment | Claude Sonnet 5 | `true_fix` |
| `phase2_case_b_partial_fix` | 2026-09-04-phase2-negative-case-experiment | Claude Sonnet 5 | `true_fix` |
| `phase2_case_c_deceptive_attempt` | 2026-09-04-phase2-negative-case-experiment | Claude Sonnet 5 | `inconclusive` |
| `phase2_case_d_regression_attempt` | 2026-09-04-phase2-negative-case-experiment | Claude Sonnet 5 | `inconclusive` |
| `phase2_case_e_inconclusive` | 2026-09-04-phase2-negative-case-experiment | Claude Sonnet 5 | `inconclusive` |
| `phase3_case_a_genuine_fix` | 2026-09-04-phase3-alternate-model-experiment | Claude Haiku 4.5 | `true_fix` |
| `phase3_case_b_partial_fix` | 2026-09-04-phase3-alternate-model-experiment | Claude Haiku 4.5 | **`partial_fix`** |
| `phase3_case_c_deceptive_attempt` | 2026-09-04-phase3-alternate-model-experiment | Claude Haiku 4.5 | `true_fix` |
| `phase3_case_d_regression_attempt` | 2026-09-04-phase3-alternate-model-experiment | Claude Haiku 4.5 | `inconclusive` |
| `phase3_case_e_inconclusive` | 2026-09-04-phase3-alternate-model-experiment | Claude Haiku 4.5 | `inconclusive` |
| `phase6_case_a_genuine_fix` | 2026-09-04-phase6-canonical-pipeline | Claude Sonnet 5 | `true_fix` |

**Totals**: `true_fix`=7, `partial_fix`=1, `deceptive_fix`=0, `regression`=1, `inconclusive`=10. 7+1+0+1+10 = 19. No case removed, none hidden, none re-run after seeing its result.

---

## 6. Scanner-only versus TerraVeritas comparison

Full detail in `docs/scanner_only_baseline_comparison.md` and `docs/phase8_analysis.md`; summary here.

Using the **broad** baseline (the fair comparison — the narrow, single-rule baseline accepts almost everything and isn't a meaningful test): **agree on 9 of 19, disagree on 10 of 19.**

Of the 10 disagreements: **one** is a clean, verified case of TerraVeritas being *more accurate* than a thorough scanner re-scan (`phase2_case_b_partial_fix` — a Block Public Access resource neutralizes a policy Checkov's narrow rule still flags in isolation). **One** is TerraVeritas being *more sensitive but not clearly more correct* (`negcase3`'s regression, triggered by an unrelated lint finding). The remaining **eight** are TerraVeritas being *more conservative* than the scanner — refusing to certify what the scanner accepts, because it demands an actual successful `terraform plan`, split between an environment limitation (5 cases, live-AWS data-source dependency) and invariant limitations (the remaining share of that group).

**No claim of blanket superiority or inferiority is made anywhere in this arc.** The measured claim is narrower: TerraVeritas is more informative than a narrow, single-rule CI gate (the realistic alternative), and has exactly one demonstrated, mechanistically-explained case of catching what even a careful re-scan misses.

---

## 7. Negative-case evidence

| Classification | Observed on real data? | Evidence |
|---|---|---|
| `TRUE_FIX` | **Yes** — 7 cases | `case1_acl_only`, `negcase1`, `phase2_case_a`, `phase2_case_b`, `phase3_case_a`, `phase3_case_c`, `phase6_case_a` |
| `PARTIAL_FIX` | **Yes** — 1 case | `phase3_case_b_partial_fix`: a model shown only the ACL fixed exactly that and left an untouched, independently-resolvable public policy in place; oracle reasoning: `partial narrowing detected: ['acl_grants_public'] resolved, ['policy_grants_public'] remain` |
| `DECEPTIVE_FIX` | **No — remains experimentally unproven.** Three real, independent attempts (`negcase2`, `phase2_case_c`, `phase3_case_c`) across two different generating models produced zero. The classification logic exists and is unit-tested against synthetic evidence only (11 test references) — that is an implementation-level guarantee about the code, not evidence about the real-world capability. A structural reason to doubt it can currently fire at all for policy-based findings was found (problem #3 above), not just bad luck. |
| `REGRESSION` | **Yes** — 1 case | `negcase3_regression_unrelated_change`, though the trigger was an unrelated scanner finding rather than a change in the tracked security invariant — a real classification, with a caveat about what it actually demonstrates (see problem #6). |
| `INCONCLUSIVE` | **Yes** — 10 cases | Split exactly 5 infrastructure-limited / 5 invariant-limited (2 of those 5 a known, scoped, fixable gap; 3 more fundamental) — see `docs/phase8_analysis.md` section 11 for the full breakdown by case. |

---

## 8. Scientific claim audit

Full reasoning in `docs/phase9_scientific_claim_audit.md`. Summary:

| Claim | Classification |
|---|---|
| Can evaluate real AI-generated repairs | **EXPERIMENTALLY DEMONSTRATED** |
| Distinguishes true fixes from partial fixes | **EXPERIMENTALLY DEMONSTRATED** (n=1 partial_fix — real, thin) |
| Detects scanner-satisfying but insecure repairs | **UNTESTED** (structural reason to doubt) |
| Provides evidence beyond scanner re-approval | **EXPERIMENTALLY DEMONSTRATED as possible** (n=1 clean case) |
| Invariant avoids circularity in practice | **SUPPORTED HYPOTHESIS** |
| Methodology generalizes beyond S3 | **UNTESTED** |
| Oracle agrees with human judgment | **UNTESTED** (materials ready, zero labels collected — offered to the user, declined this round) |

---

## 9. Publication readiness decision

# PILOT PAPER READY

**Not** `NOT READY`: the central mechanism — real Terraform plan evidence, a security-intent invariant independently grounded in AWS semantics (not scanner-rule mimicry), and an oracle that reaches `TRUE_FIX` and, critically, a genuine `PARTIAL_FIX` on real, unscripted AI-generated repairs — is demonstrated, reproducibly, on real (not synthetic) evidence. That is a real, defensible, positive result, not an aspiration.

**Not** `STRONG EMPIRICAL PAPER READY`: that tier requires "multiple independent real experiments" supporting the central hypothesis, "including meaningful negative cases and baseline comparison." The baseline comparison exists and is real (section 6) — but the negative-case evidence is thin and one-sided: `DECEPTIVE_FIX`, arguably the single most important classification for the project's stated purpose (telling a genuine fix from one that merely satisfies a scanner), has **zero** real observations despite three genuine attempts, and there is now a specific, structural reason to suspect it may not be reachable as currently architected. `PARTIAL_FIX` has exactly one real instance. Half the corpus (10/19) is `inconclusive`. No genuinely independent (cross-vendor) generation source was ever used. No human validation exists. Any one of these alone might be an acceptable gap for a pilot; together, they are exactly what "strong empirical" is supposed to rule out.

**Therefore `PILOT PAPER READY`**: the evidence supports a limited pilot/prototype paper making the narrow, defensible claims this arc actually established — real plan-based evaluation works, a real `TRUE_FIX`/`PARTIAL_FIX` distinction has been shown on real data, and a real (if singular) case exists where the invariant outperforms scanner re-approval — while explicitly disclosing what remains open: `DECEPTIVE_FIX` unproven, generalization beyond S3 untested, human validation absent, cross-vendor evaluation absent. A paper claiming more than this would not be supported by what this arc actually found; a paper claiming exactly this would be honest and would still represent real, useful, verifiable research.
