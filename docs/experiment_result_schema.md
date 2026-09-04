# Pre-registered result schema

## Honest chronology disclosure — read this first

This schema was specified by the user in Phase 7 of this project's development, **after** the majority of the experimental corpus (18 real cases across Phases 2–3, plus the Phase 6 canonical-pipeline case) had already been generated and their aggregate outcomes already reviewed and reported (Phase 3's tally, Phase 4's baseline comparison, etc.). That is not what "pre-registered" means in the sense the phase title invokes — genuine pre-registration requires the classification scheme to be fixed *before* any result is observed, specifically to prevent the categories or their boundaries being shaped by what was found. Presenting this document as if it preceded those results would misrepresent the actual order of events, so it doesn't: this is a **retrospective formalization** of the schema, done honestly, not a claim of prospective pre-registration for data that already exists.

What this document *can* still do, legitimately:

1. Audit the existing corpus against a fixed schema and report gaps plainly (below).
2. Fix the one real gap the audit found (`environment_anomalies` had no dedicated field — see `src/terraveritas/models/experiment.py`).
3. Serve as the actual prospective schema for any case added from this point forward — which is exactly what "pre-registered" should mean for future data.

## The schema

Every field below maps to a concrete attribute on `RepairRecord` (`src/terraveritas/models/experiment.py`) — this is not a parallel or aspirational schema, it is what the existing data model already captures, plus the one addition made in this phase.

| Field | `RepairRecord` attribute(s) | Type |
|---|---|---|
| Case ID | `case_id` | `str` |
| Vulnerability type | `vulnerability_class` | `str` (always `S3_PUBLIC_ACCESS_EXPOSURE` in this corpus — the only invariant implemented) |
| Original configuration hash | `original_terraform_sha256` | `str` (SHA-256 of `original_terraform`) |
| Model identifier | `ai_model`, `model_version` | `str`, `str` |
| Raw response | `raw_ai_output` | `str`, unedited |
| Extracted repair | `extracted_terraform` | `str`, mechanically extracted (`experiments/extraction.py`) or, in one disclosed case shape, mechanically reassembled from a context-limited extraction plus an untouched resource — see `run_phase2_negative_case_experiment.py`'s case_b |
| Scanner before | `before_scan` | `ScanResult` |
| Scanner after | `after_scan` | `ScanResult` |
| Baseline classification | `scanner_baseline` | `ScannerOnlyBaseline \| None` — **added in Phase 6**, see gap analysis below |
| Plan before | `before_plan` | `PlanResult \| None` — **added in an earlier session pass (Prompt 14)**, see gap analysis below |
| Plan after | `after_plan` | `PlanResult \| None` |
| Invariant before | `before_invariant` | `InvariantResult \| None` |
| Invariant after | `after_invariant` | `InvariantResult \| None` |
| Differential | `differential` | `DifferentialResult` |
| Oracle verdict | `oracle_verdict.classification` | `Classification` |
| Oracle confidence | `oracle_verdict.confidence` | `Confidence` |
| Human label, if available | `human_label` | `HumanLabel \| None` — present as a field on every record; value is `None` on all 19 real records to date, since Phase 5's evaluation is still pending (see `docs/human_evaluation/`) |
| Environment anomalies | `environment_anomalies` | `list[str]` — **added in this phase**, see gap analysis below |

## Gap analysis against the existing corpus

Audited every real record under `datasets/experiments/*/records/*.json` (19 total) against the table above. Results, not assumed:

- **17 of 19 records** have `before_plan`/`after_plan`/`before_invariant`/`after_invariant` populated (full evidence). The **2 earliest** (`2026-09-02-pilot-s3exposure`, predating that schema addition) have only `before_plan_status`/`after_plan_status` as bare enum values — both were `plan_timeout`, so the missing detail wouldn't have changed anything evaluable, but the fuller evidence trail genuinely isn't there for those two.
- **1 of 19 records** (`phase6_case_a_genuine_fix`, generated in this same phase specifically to prove the new pipeline) has `scanner_baseline` populated natively. The other 18 do **not** carry it as part of their own stored record — it exists for them only in the separate retrospective analysis at `docs/scanner_only_baseline_comparison.json`, not inside each record. This is a real, disclosed gap: those 18 records are individually incomplete against this schema as now defined, even though the missing value is recoverable from the separate analysis file.
- **0 of 19 records** have a non-empty `environment_anomalies` list, because the field didn't exist until this phase. One genuine anomaly from earlier in the project (a subagent's `tool_uses=0` return on `case3_acl_and_policy`, original real-ai-pilot) was recorded, but under a non-standard `environment["anomaly"]` key, not this field. Not retroactively migrated — see below.
- **19 of 19 records** have every other field.

## Why existing records were not retroactively rewritten

Mutating already-written experiment evidence files to backfill new fields would blur "what was captured at generation time" against "what was reconstructed afterward" — the same reasoning that kept Phase 1's invariant fix from rewriting `case3_acl_and_policy`'s original record. The gaps above are disclosed, not hidden, and are recoverable from separate analysis where they matter (`scanner_only_baseline_comparison.json` for the baseline gap). Going forward, every new record produced via `scripts/run_experiment.py` / `experiments/pipeline.py` carries the full schema natively.

## The four standing rules, and where they're actually enforced

- **Never remove failed cases** / **never remove INCONCLUSIVE cases**: verified directly — every `manifest.json`'s `record_count` matches the number of files actually present in that experiment's `records/` directory (checked across all 6 experiment folders), and all 10 real `inconclusive` verdicts and the 1 `regression` verdict are present in the corpus, none filtered out of any report in this project. No case has ever been deleted after its result was known.
- **Never replace an AI output after seeing its evaluation result**: every `raw_ai_output` in every record is the file content saved to the scratchpad *before* `evaluate_repair` (or its predecessor scripts) were ever invoked against it — confirmed by the save-then-run ordering in every `scripts/run_*.py` file, and by there being exactly one record per case_id everywhere in the corpus (no `-001`, `-002` retry variants anywhere, which would be the signature of a discarded-and-regenerated attempt).
- **Never change the experiment corpus after observing results without recording the change**: this document *is* that record for the one schema change made after results existed — the `environment_anomalies` and `scanner_baseline` field additions, made in Phases 6–7, after 18 of 19 records' results were already known. Stated here, not silently absorbed into the schema as if it had always existed.
