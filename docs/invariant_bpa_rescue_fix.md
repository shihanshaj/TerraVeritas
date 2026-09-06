# Invariant fix: BPA/Object-Ownership rescue must apply even when content is unresolved

**Status: fixed in `src/terraveritas/invariants/s3_public_access.py`. No historical experiment record was modified — this document is an additive, read-only re-evaluation, not a correction applied retroactively to stored data.**

## The bug

The invariant's ACL and policy branches each have an independent, content-blind rescue: `ignore_public_acls=True` or `object_ownership=BucketOwnerEnforced` neutralizes the ACL vector regardless of what the ACL actually says; `restrict_public_buckets=True` neutralizes the policy vector regardless of what the policy actually says — both are real AWS Block Public Access enforcement mechanisms, not something this invariant infers.

Before this fix, both rescues were checked *only inside* the branch that runs when the relevant content (ACL grant / policy document) is actually resolved at plan time. When the content was unresolved instead, the function short-circuited straight to `*_neutralized = None` — discarding a rescue flag that was already fully known and `True`, for no reason connected to what that flag actually protects against.

## Reproduction

Two real, independently-generated AI repairs hit this exactly: `phase2_case_d_regression_attempt` (Claude Sonnet 5) and `phase3_case_d_regression_attempt` (Claude Haiku 4.5) — both started from an already-BPA-locked-down secure bucket (`restrict_public_buckets = true`, fully resolved) and added a new, legitimate, scoped cross-account bucket policy whose content ends up unresolved at plan time (once via a `data.aws_iam_policy_document` data source, once via a direct interpolation of the bucket's own `.arn` — both defer to apply-time because they depend on an unknown value). In both cases, TerraVeritas reported `INCONCLUSIVE` — "bucket policy content could not be evaluated" — for a repair that was very likely genuinely safe, given the BPA flag AWS itself enforces.

## Root cause and fix

Root cause: `ignore_public_acls`/`object_ownership`/`restrict_public_buckets` were read and checked *inside* each side's "content resolved" branch, never independently of it.

Fix: compute all three flags once, unconditionally, before either side's resolution check. Each side now checks its BPA/ownership rescue *first* — if it applies, the side is neutralized immediately, with no need to know the content at all. Only when the rescue does not apply does the function fall through to the existing unresolved-content gate (`*_neutralized = None`, never `True`).

## Methodology followed

1. Read the existing implementation (`s3_public_access.py`, current state before any edit).
2. Extracted the real plan JSON that reproduces this exactly from `phase2_case_d_regression_attempt`'s stored record into `fixtures/real_plans/s3_bpa_restrict_public_buckets_policy_unresolved_plan.json`.
3. Wrote 4 new tests *before* changing the implementation: 1 against the real captured plan above, 2 synthetic (the symmetric ACL-side rescue, via both `ignore_public_acls` and `BucketOwnerEnforced`), and 1 safety-preserving companion (no BPA resource at all + unresolved policy must still stay `UNKNOWN`, confirming the fix doesn't widen the rescue beyond what's actually declared).
4. Ran the 3 new positive tests against the *unfixed* code — all 3 failed with the exact reproduction (`UNKNOWN` where `PASS` was expected); the safety-preserving test already passed, confirming it wasn't testing the bug.
5. Implemented the fix described above.
6. Re-ran the same 4 tests — all pass.
7. Ran the full `tests/invariants/test_s3_public_access.py` file — 34/34 pass, including every pre-existing test (in particular the two tests added for the Phase 1 fix that specifically guard against an unresolved side ever producing a false `PASS` — those still pass unchanged, confirming this fix didn't reopen that gap).
8. Ran the full suite, `ruff`, and `mypy --strict` — 217/217 passing, clean.

## Effect on the historical corpus — what actually changes when re-evaluated under the new invariant

Every one of the 19 real experiment records was re-evaluated under the new invariant code, reading only the `raw_plan_json` already stored in each record — **no stored record file was read from, written to, or modified as part of producing this comparison.** 17 of 19 have full plan evidence to re-evaluate (`intent_explicit`, `minimal` predate that field entirely and are unaffected regardless — both are `plan_timeout`, with no BPA or policy resolution involved).

| Case | Original `after_invariant` | New `after_invariant` | Original oracle classification | New oracle classification |
|---|---|---|---|---|
| `phase2_case_d_regression_attempt` | `UNKNOWN` — "bucket policy content could not be evaluated at plan time" | **`PASS`** — "no unauthenticated-reachable ACL grant or bucket-policy statement found" | `inconclusive` (low confidence) | `inconclusive` (low confidence) — **same label, different reason** |
| `phase3_case_d_regression_attempt` | `UNKNOWN` — same reason | **`PASS`** — same reason | `inconclusive` | `inconclusive` — **same label, different reason** |

**Why the top-level classification label didn't change even though the invariant result did**: both fixtures' *before*-state was already `PASS` (a secure baseline bucket, by design — the whole point of these two cases was testing whether an unrelated feature request regresses an already-safe bucket). The oracle's decision table has no positive classification for "before=PASS, after=PASS" — it correctly returns `inconclusive`, reasoned as *"the invariant was already satisfied before the repair — there was nothing for this invariant to fix"*, which is categorically different from the original reason (*"insufficient evidence to determine whether the security property holds"*). The fix converts a **null result** (couldn't tell) into a **confirmed-safe result presented as a null classification** because there was nothing to fix in the first place — a real, meaningful change in what TerraVeritas actually knows, even though the one-word label a shallow diff would compare is unchanged. Anyone re-running Phase 8's aggregate counts (which only tally the top-level classification) would see no change in the 7/1/0/1/10 breakdown from that fact alone — which is exactly why this document reports the underlying invariant status, not just the classification, as the real measure of what changed.

**No other record changed at all** — verified by comparing `before_invariant`/`after_invariant` reason strings across the full 17, not just the classification enum. The other three inconclusive-for-invariant-reasons cases (`case3_acl_and_policy`, `phase2_case_e_inconclusive`, `phase3_case_e_inconclusive`) declare no BPA resource at all in the affected state, so the new rescue path is never reached for them — correctly unaffected, exactly as intended by a narrowly-scoped fix.

## What this document deliberately does not do

- It does not modify `docs/phase8_analysis.md` or `docs/phase9_scientific_claim_audit.md` — those remain an accurate historical record of the corpus as evaluated under the invariant version live at the time they were written. This document supersedes their specific claim about `phase2_case_d`/`phase3_case_d` being blocked by "a known, scoped, fixable gap" — it is now fixed — without silently editing that claim out of the historical documents.
- It does not touch any file under `datasets/experiments/` — every stored record's `oracle_verdict`, `before_invariant`, and `after_invariant` fields remain exactly as originally persisted at generation time, reflecting the invariant version that actually produced them.
- It does not run any new experiments — this is a re-evaluation of existing evidence under new code, not new data collection.
