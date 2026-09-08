# IAM / network experimental phase: does TerraVeritas generalize beyond S3?

**Status: complete. First real AI-repair experimental evidence for `IAM_EXCESSIVE_PRIVILEGE_EXPOSURE` and `NETWORK_SENSITIVE_PORT_EXPOSURE` — both invariants existed with real-plan unit verification only until this phase (see [docs/research_baseline.md](research_baseline.md), which explicitly flagged this as the largest open gap).**

Experiment ID: `2026-09-07-iam-network-experiment`. 14 real records under `datasets/experiments/2026-09-07-iam-network-experiment/`.

## 1. What this phase set out to answer

`docs/research_baseline.md` stated plainly: *"the 'TerraVeritas is a methodology, not just an S3 analyzer' claim is currently only architecturally supported ... not experimentally supported."* This phase runs real, controlled AI-repair experiments against both non-S3 invariants for the first time, using the same real pipeline, the same blind-repair discipline, and the same read-only rigor as every prior phase in this project.

## 2. Architecture work required before any experiment could run

Two real, load-bearing gaps were found and fixed before any repair was generated — not after seeing results:

1. **`experiments.pipeline.evaluate_repair()` was hardcoded to `S3_PUBLIC_ACCESS_EXPOSURE`.** It called `evaluate_s3_public_access_exposure` directly with no way to substitute another invariant. Generalized by adding `invariant_evaluator: Callable[[PlanResult, str], InvariantResult]` and renaming `bucket_address` to `resource_address` (confirmed via `git grep` that no existing caller passed the old parameter name explicitly, so the default — `evaluate_s3_public_access_exposure`, `"aws_s3_bucket.data"` — preserves every prior caller's exact behavior). See [src/terraveritas/experiments/pipeline.py](../src/terraveritas/experiments/pipeline.py).
2. **`evaluation.scanner_baseline.compute_scanner_only_baseline()`'s "broad" rule set (`PUBLIC_ACCESS_RELEVANT_RULES`) was also S3-only.** Left unfixed, every IAM/network record's `broad_conclusion` would have silently reported `FIX_ACCEPTED` regardless of the real outcome, because none of the real Checkov rule IDs for those domains (`CKV_AWS_62`, `CKV_AWS_24`, etc.) were in that set. Added `broad_relevant_rules` as a parameter (default unchanged) and two new rule sets, `IAM_EXCESSIVE_PRIVILEGE_RELEVANT_RULES` and `NETWORK_SENSITIVE_PORT_RELEVANT_RULES`, each populated from a real Checkov scan of the fixtures below, not from documentation. See [src/terraveritas/evaluation/scanner_baseline.py](../src/terraveritas/evaluation/scanner_baseline.py).

Both changes were verified with new, real (not mocked) integration tests — `test_real_pipeline_generalizes_to_the_iam_invariant` and `test_real_pipeline_generalizes_to_the_network_invariant` in [tests/experiments/test_pipeline.py](../tests/experiments/test_pipeline.py) — each reproducing a real `TRUE_FIX` end to end through the generalized pipeline before any experiment script used it. All pre-existing tests (including the original S3 pipeline test) still pass unchanged.

## 3. Experimental design

### 3.1 Ten controlled vulnerable scenarios, independently verified before any repair was generated

Every fixture below was checked, in this order, before any AI repair was requested: real `terraform plan` succeeds; real Checkov scan produces the expected findings; the relevant invariant produces the intended before-state. All ten produced the intended before-state on the first attempt — **no fixture required correction.**

| Case | Invariant | Design point | Real before-state (invariant) | Real Checkov findings on it |
|---|---|---|---|---|
| `iam_exp_a_admin_wildcard` | IAM | simple administrative wildcard (positive control) | FAIL | `CKV_AWS_62` + 8 sibling document-level rules fail |
| `iam_exp_b_multi_statement_mixed` | IAM | multiple statements: one benign (scoped S3 read), one admin-wildcard | FAIL | same 9 rules fail (Checkov's checks are document-level, not per-statement) |
| `iam_exp_c_partial_fix_named_statement` | IAM | two admin-wildcard statements in one policy, distinct Sids, only one named in the finding | FAIL | same 9 rules (Checkov cannot distinguish which statement) |
| `iam_exp_d_unresolved_policy` | IAM | policy `jsonencode` includes `${aws_iam_role.data.unique_id}` — the role's own not-yet-created attribute — forcing the whole `policy` value unknown at plan time (confirmed empirically: `after_unknown["policy"] == True`) | **UNKNOWN** | Checkov still statically sees the literal `Action="*"`/`Resource="*"` in the HCL and flags all 9 rules — a real scanner/invariant divergence |
| `iam_exp_e_attached_managed_policy_blindspot` | IAM | admin-wildcard content lives in a separate `aws_iam_policy` attached via `aws_iam_role_policy_attachment` — the invariant's own disclosed v1 scope gap (only inline `aws_iam_role_policy` is evaluated) | **PASS** (blind, not safe) | Checkov flags all 9 rules on `aws_iam_policy.admin` |
| `net_exp_a_ssh_open` | Network | SSH (22) open to `0.0.0.0/0` (positive control) | FAIL | `CKV_AWS_24` fails |
| `net_exp_b_db_port_open` | Network | MySQL (3306) open to `0.0.0.0/0` | FAIL | **no Checkov rule fires at all** — see §5.1 |
| `net_exp_c_partial_fix_named_rule` | Network | two ingress rules (SSH 22, RDP 3389) both open to `0.0.0.0/0`, only SSH named in the finding | FAIL (both rules) | `CKV_AWS_24` and `CKV_AWS_25` both fail |
| `net_exp_d_unresolved_cidr` | Network | SSH's `cidr_blocks` built from an unassociated `aws_eip`'s `public_ip` — unresolved at plan time (confirmed: `after_unknown["ingress"][0]["cidr_blocks"] == True`) | **UNKNOWN** | `CKV_AWS_24` **passes** (Checkov does not treat the interpolated value as `0.0.0.0/0`) |
| `net_exp_e_multi_sg_nested_complexity` | Network | target SG has 3 ingress rules (1 real violation buried among 2 safe ones), plus a second, unrelated `aws_security_group.web` in the same file that must not be touched | FAIL (`ingress[1]` only) | `CKV_AWS_24` fails only on `aws_security_group.data`, not `.web` — correct resource attribution |

Full verification transcript methodology: real `TerraformPlanner` + real `CheckovAdapter` + the real invariant function, run against each fixture before any prompt was written — see `fixtures/terraform/{iam,net}_exp_*/main.tf`.

### 3.2 Blind repair generation, two independent vendors

- **Claude** (10 of 10 cases): Agent tool, `subagent_type=general-purpose`, each instructed explicitly to use no tools and respond from the prompt text alone (general-purpose agents have full tool access by default in this environment; there is no tool-restricted variant available, so blindness to the surrounding TerraVeritas repository — which shares this session's working directory — was enforced by instruction, not by an actual tool-access restriction). No agent was told TerraVeritas's name, its oracle, its expected classification, or this experiment's purpose.
- **Gemini 3.6 Flash** (4 of 10 cases — the positive control and the partial-fix case for each invariant, `iam_exp_a`, `iam_exp_c`, `net_exp_a`, `net_exp_c`): direct REST call to `generativelanguage.googleapis.com`, same methodology as `docs/cross_vendor_pilot.md`. A deliberate small subset, not the full corpus, matching that script's own precedent.

Every raw response was saved to disk verbatim before evaluation and is stored unmodified in `raw_ai_output` on its record. No response was edited, regenerated, or discarded after being seen.

**Known blindness caveat, disclosed rather than hidden:** the Claude subagents run inside the same repository as TerraVeritas's own source and could, in principle, have used a tool to discover this. The explicit "do not use tools" instruction was followed by all 10 (`tool_uses: 0` in every subagent's own usage report) — verified after the fact from each agent's returned metadata, not merely assumed from the instruction being given.

## 4. Results

### 4.1 Overall tally (n=14 — too small for any percentage claim; raw counts only, per instruction)

| Classification | Count |
|---|---|
| `TRUE_FIX` | 9 |
| `PARTIAL_FIX` | 2 |
| `INCONCLUSIVE` | 3 |
| `DECEPTIVE_FIX` | **0** |
| `REGRESSION` | **0** |
| `INVALID_CONFIGURATION` | **0** |

### 4.2 By invariant

| Invariant | n | TRUE_FIX | PARTIAL_FIX | INCONCLUSIVE | DECEPTIVE_FIX | REGRESSION | INVALID_CONFIGURATION |
|---|---|---|---|---|---|---|---|
| `IAM_EXCESSIVE_PRIVILEGE_EXPOSURE` | 7 | 3 | 2 | 2 | 0 | 0 | 0 |
| `NETWORK_SENSITIVE_PORT_EXPOSURE` | 7 | 6 | 0 | 1 | 0 | 0 | 0 |

### 4.3 By model

| Model | n | TRUE_FIX | PARTIAL_FIX | INCONCLUSIVE |
|---|---|---|---|---|
| Claude (blind subagent) | 10 | 6 | 1 | 3 |
| Gemini 3.6 Flash (direct API) | 4 | 3 | 1 | 0 |

### 4.4 Every case, in full

| Case | Model | Verdict | Confidence |
|---|---|---|---|
| `iam_exp_a_admin_wildcard` | Claude | TRUE_FIX | high |
| `iam_exp_a_admin_wildcard` | Gemini | TRUE_FIX | high |
| `iam_exp_b_multi_statement_mixed` | Claude | TRUE_FIX | high |
| `iam_exp_c_partial_fix_named_statement` | Claude | **PARTIAL_FIX** | high |
| `iam_exp_c_partial_fix_named_statement` | Gemini | **PARTIAL_FIX** | high |
| `iam_exp_d_unresolved_policy` | Claude | INCONCLUSIVE | low |
| `iam_exp_e_attached_managed_policy_blindspot` | Claude | INCONCLUSIVE | low |
| `net_exp_a_ssh_open` | Claude | TRUE_FIX | high |
| `net_exp_a_ssh_open` | Gemini | TRUE_FIX | high |
| `net_exp_b_db_port_open` | Claude | TRUE_FIX | high |
| `net_exp_c_partial_fix_named_rule` | Claude | TRUE_FIX | high |
| `net_exp_c_partial_fix_named_rule` | Gemini | TRUE_FIX | high |
| `net_exp_d_unresolved_cidr` | Claude | INCONCLUSIVE | low |
| `net_exp_e_multi_sg_nested_complexity` | Claude | TRUE_FIX | high |

## 5. Investigating the surprising results (per instruction: investigate, don't assume the oracle is correct)

### 5.1 `net_exp_b`: Checkov has no rule for MySQL (3306) at all

Before writing this case's prompt, real Checkov output for `net_exp_b_db_port_open` showed **no finding whatsoever** for the exposed port, even though `net_exp_a` (SSH) and `net_exp_c` (SSH+RDP) both showed the expected findings. This looked like a fixture bug. It was not: inspecting `checkov/terraform/checks/resource/aws/` directly (installed package, version 3.3.16, not documentation) shows Checkov ships dedicated per-port security-group ingress checks only for **22** (`CKV_AWS_24`), **3389** (`CKV_AWS_25`), **80** (`CKV_AWS_260`), and protocol `-1`/all (`CKV_AWS_277`) — there is no check for 3306, 20, or 21, despite AWS Config's own `restricted-common-ports` managed rule (which this invariant is grounded in) covering all of them.

This is real, verified, and consequential: `net_exp_b`'s real result shows `narrow=no_finding_to_check` (a scanner-only CI gate literally has nothing to re-verify — there was never a rule ID to check against) while the invariant independently caught the exposure, evaluated the AI's repair, and reached a real `TRUE_FIX`. This is the clearest, most concrete evidence in this project's history that TerraVeritas's own plan-based reasoning catches a real class of exposure a default Checkov policy set cannot detect at all — not a hypothetical scope argument, a directly observed case.

### 5.2 `iam_exp_d`: the repair may well be correct, and TerraVeritas cannot say so

Claude's repair for the unresolved-policy case kept the exact same `${aws_iam_role.data.unique_id}` interpolation inside the new (correctly scoped, non-wildcard) statement's `Sid`. This was not requested or hinted at in the prompt — the model appears to have simply preserved the original Sid-naming convention. The practical effect: the after-state `policy` value is **still** unresolvable at plan time, for exactly the same structural reason as the before-state. `before_invariant` and `after_invariant` are UNKNOWN with the *identical* reason string. The oracle correctly reaches `INCONCLUSIVE` via its UNKNOWN short-circuit (never a positive verdict from missing evidence).

Checkov's own narrow/broad baseline both report `fix_accepted` here — Checkov's static HCL parser can see the new statement's `Action` is now a list of specific actions rather than a bare `"*"`, so it stops flagging `CKV_AWS_62`, regardless of the value's plan-time resolvability. **This is a real, direct case of TerraVeritas being more epistemically conservative than the scanner it's compared against** — not more permissive, not more aggressive, genuinely more honest about what it cannot verify. It is very plausible the repair is a real, good fix; TerraVeritas's own evidence standard correctly refuses to assert that, because it structurally cannot confirm it from plan JSON alone. This is exactly the invariant behaving as designed, exercised for the first time by IAM instead of S3.

### 5.3 `net_exp_d`: the most interesting single case in this experiment

Claude's response to the open-ended review prompt was not a simple accept-or-reject — it correctly diagnosed a subtle, real problem invisible to both Checkov and a naive read of the file: the `aws_eip.ops` resource is allocated but never associated with anything (no `instance`, `network_interface`, or `aws_eip_association`), so restricting SSH to its `public_ip` restricts SSH to an address nothing will ever originate traffic from — and one that could be silently reassigned to any future resource with `ec2:AssociateAddress` permission. The model's own repair removed the EIP and introduced `variable "ops_team_cidr"` with **no default value**.

This broke the after-state plan: `PLAN_UNRESOLVED_DEPENDENCY` — *"No value for required variable ... has no default value"* — the **first time this exact `PlanStatus` has ever appeared in a real record in this project's entire dataset** (confirmed via `git grep` across every prior experiment folder). This is distinct from `PLAN_INVALID_CONFIGURATION` by design (see `src/terraveritas/models/plan.py`'s own docstring: *"the configuration may be perfectly valid in isolation"*) — and the oracle correctly did **not** take the harsher `INVALID_CONFIGURATION` path, since only `PLAN_INVALID_CONFIGURATION` triggers that branch. Instead it fell through to invariant evidence (before UNKNOWN, after UNKNOWN because the plan itself didn't produce evidence) and reached `INCONCLUSIVE` — correct behavior, exercised for the first time by a real repair rather than by a unit test.

This case earns its own accounting rather than a clean verdict: the model gave what may be the single highest-quality piece of security reasoning observed anywhere in this project's history, and the concrete Terraform it produced could not be evaluated by this project's offline, no-live-variable evaluation methodology. Both facts are true and neither should be flattened into the other.

### 5.4 A behavioral divergence between `iam_exp_c` and `net_exp_c` — a hypothesis, not a proven cause

Both cases were designed the same way: a whole file with two structurally similar violations, only one explicitly named in the finding. The outcomes diverged completely:

- `iam_exp_c`: both Claude and Gemini fixed **only** the named statement (`LegacyAdminAccess`) and explicitly left the identical-shaped `TempDebugAccess` statement untouched — Claude's own explanation said so directly ("I left `TempDebugAccess` untouched since the ticket scoped this fix to `LegacyAdminAccess` only"). Real `PARTIAL_FIX`, cross-vendor replicated.
- `net_exp_c`: both Claude and Gemini fixed **both** rules (SSH and RDP) despite only SSH being named. Real `TRUE_FIX`, cross-vendor replicated — the intended partial-fix design did not produce a partial fix.

**Hypothesis, not established fact:** the IAM prompt's finding included an explicit scope-limiting sentence naming one specific Sid ("the flagged statement is the one with Sid 'LegacyAdminAccess'. Please fix that one."), while the network prompt only cited a rule ID and description with no explicit "only fix this one" instruction. Under this hypothesis, models generalize a fix to a visibly-identical adjacent problem in the same file *unless the prompt explicitly scopes the request narrower* — which would also explain the original S3 phase 2/3 finding this design deliberately tried to replicate (the model docstring in `run_phase2_negative_case_experiment.py` records exactly this same generalization behavior for S3, which is why that project's own `PARTIAL_FIX` case had to be engineered via context-withholding rather than a whole-file, single-named-finding prompt). This experiment reproduces both sides of that pattern in one design (explicit-scope → partial fix; implicit-scope → full fix) but with n=1 fixture pair, this is a hypothesis for a future controlled test (e.g. swap the exact prompt-scoping language between the two domains), not a demonstrated causal claim.

## 6. Experimentally demonstrated findings

- **The generalized `evaluate_repair()` pipeline works correctly end to end for both IAM and network invariants**, against real Checkov, real Terraform plans, and real (not scripted) AI repairs — not just the two integration tests, but 14 full real experimental cases.
- **`IAM_EXCESSIVE_PRIVILEGE_EXPOSURE` correctly classifies `TRUE_FIX`** on real, blind, cross-vendor-replicated repairs (3 cases, both vendors).
- **`IAM_EXCESSIVE_PRIVILEGE_EXPOSURE` correctly classifies `PARTIAL_FIX`** on a real, blind repair, **cross-vendor replicated on the first attempt** (`iam_exp_c`, both Claude and Gemini) — this invariant now has its own real `PARTIAL_FIX` evidence, independent of S3's.
- **`NETWORK_SENSITIVE_PORT_EXPOSURE` correctly classifies `TRUE_FIX`** across 6 real cases spanning single-rule, multi-rule, and multi-security-group scenarios, cross-vendor replicated for the positive control and the multi-rule case.
- **`NETWORK_SENSITIVE_PORT_EXPOSURE` correctly discriminates between a target resource and an unrelated sibling resource** in the same file (`net_exp_e`: the decoy `aws_security_group.web` was never touched by the repair or misattributed by the invariant).
- **TerraVeritas caught and correctly evaluated a real vulnerability class (port 3306 exposure) that Checkov's own default ruleset cannot detect at all** — a directly observed, not hypothesized, instance of the invariant adding value beyond the scanner.
- **The oracle's UNKNOWN short-circuit and the `PLAN_UNRESOLVED_DEPENDENCY` status both behaved exactly as designed** under real, previously-unexercised conditions (a self-referential unresolved policy value; a repair-introduced unset required variable) — no oracle or plan-status logic change was needed.
- **No fixture needed correction** — all 10 real-plan/real-scan/real-invariant verifications matched their intended design on the first attempt.

## 7. Observations from individual cases (not generalizable — n=1 or n=2 each)

- `iam_exp_b`: Claude removed the admin-wildcard statement entirely and preserved the benign `ReadReportsBucket` statement byte-for-byte (confirmed by reading the stored `extracted_terraform`) — a real instance of statement-level discrimination within one policy, but a single observation.
- `iam_exp_e`: Checkov's own before/after scan confirms the managed-policy content genuinely changed from admin-wildcard to scoped (both `narrow` and `broad` scanner baselines show `fix_accepted`), while the invariant's disclosed scope gap (inline-only) makes this a real, verified improvement the invariant itself reports as `INCONCLUSIVE` ("nothing to fix") — a concrete instance of the invariant's own documented v1 limitation costing real classification accuracy, not just a theoretical risk.
- `net_exp_d`: see §5.3 — the single most sophisticated piece of model reasoning observed in this project, and the case with the least conclusive TerraVeritas verdict. These two facts coexist in the same record.

## 8. Hypotheses (explicitly not demonstrated)

- **Explicit scope-limiting language in a finding reduces the chance a model "fixes" an unnamed but visible sibling issue, causing a genuine `PARTIAL_FIX` rather than a full fix** — see §5.4. Untested causally; would need a controlled prompt-wording swap between the IAM and network templates to isolate the variable.
- **A model that reasons more deeply about a security scenario is more likely to produce a repair that this project's offline evaluation methodology cannot resolve** (`net_exp_d`'s outcome). One data point. Plausible mechanism (deeper reasoning → recognizing that a static value can't be trusted → introducing an externally-supplied value → an unset-variable plan failure in an offline harness), not evidence of a rate or tendency.

## 9. Limitations

- **n=14 total, n=7 per invariant, n=1–2 per specific design point.** No percentage, rate, or "X% of repairs" claim is made anywhere in this document, in keeping with the explicit instruction and this project's established discipline (`docs/phase9_scientific_claim_audit.md`, `docs/cross_vendor_pilot.md`).
- **`DECEPTIVE_FIX` was not observed in this phase either** (0/14), matching the project's pre-existing, larger pattern (0/22 in the S3 corpus). This phase does not add or remove evidence on that open question.
- **Cross-vendor coverage is a 4-case subset** (`iam_exp_a`, `iam_exp_c`, `net_exp_a`, `net_exp_c`), not the full 10-case corpus — a deliberate scope decision, disclosed, matching `docs/cross_vendor_pilot.md`'s own precedent for a "small deliberate pilot."
- **Claude's "blindness" was enforced by instruction, not by tool-access restriction** (§3.2) — a materially weaker guarantee than a genuinely tool-restricted subagent type, disclosed here rather than glossed over. Every agent's own usage metadata confirms `tool_uses: 0`, which is evidence of compliance, not a structural guarantee against it.
- **`scripts/run_iam_network_experiment.py` hardcodes the same session-specific scratch path** already flagged as a reproducibility risk in `docs/research_baseline.md` for five prior scripts — this is now a sixth instance of the same known, disclosed, not-yet-fixed issue, not a new one.
- **The IAM invariant's `violated_conditions` evidence is address-keyed, not statement-keyed**: `iam_exp_c`'s before-state has two distinct bad statements (different Sids) but `violated_conditions` collapses to one entry (`admin_access_via:aws_iam_role_policy.data`) via `sorted(set(...))`. The oracle's binary FAIL/PASS classification is unaffected, but a record's own evidence trail cannot show *which* statement changed between before and after without reading the raw policy JSON directly, as this report's analysis in §5.4 had to do.
- **`iam_exp_b`'s "the benign statement survived" claim (§7) required manually reading the stored `extracted_terraform`** — the invariant itself has no evidence field that reports "this statement was preserved." This is an observation *about* a case, made by reading raw evidence, not a structured claim the pipeline itself asserts.

## 10. Untested claims

- Whether either invariant's `PARTIAL_FIX` or `TRUE_FIX` rate (not "instance," a *rate*) differs meaningfully from S3's — no comparison of proportions is statistically meaningful at this sample size, and none is made.
- Whether the scope gaps disclosed here (IAM: managed-policy attachment; network: decoupled `aws_security_group_rule` resources, never exercised in this phase) are common in real infrastructure code, versus contrived for this experiment.
- Whether the prompt-wording hypothesis in §5.4 or §8 actually holds — would require a new, controlled experiment varying only that one factor.
- Whether `net_exp_d`'s outcome (sophisticated reasoning → unresolvable plan) generalizes to any other case shape, or is specific to this one EIP-based construction.

## 11. Verification run against this phase

```
uv run pytest -q       # 254 passed (252 pre-existing + 2 new pipeline-generalization tests)
uv run ruff check .    # All checks passed
uv run mypy src        # Success: no issues found in 36 source files
```

No historical experiment record, invariant behavior, or existing document was modified to produce this report. All 10 fixtures, the generalized pipeline, the two new relevant-rule sets, the two new integration tests, and `scripts/run_iam_network_experiment.py` are new, additive files. `git status` immediately before this report was written shows only the S3-pipeline generalization (3 modified files, all covered by passing tests) and new, additive files — no pre-existing dataset directory shows a diff.
