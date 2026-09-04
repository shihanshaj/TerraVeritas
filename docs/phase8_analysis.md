# Phase 8: evidence-based analysis

All 11 numbers below were computed by re-running the invariant and oracle against the current codebase for every real record with full plan evidence (17 of 19), and using the originally-stored verdict for the 2 that predate full plan-JSON storage (both `plan_timeout`, a state unaffected by later invariant changes) — same method as Phases 4, 6, and 7. Nothing here is estimated or recalled from memory; every count was computed fresh from `datasets/experiments/*/records/*.json` for this phase.

**Sample size warning, stated up front**: n=19 total, and several of the categories below have n=0 or n=1. No percentage, rate, or proportion is reported anywhere in this document for that reason — a raw count of 1 out of 19 is not "5%" of anything generalizable, and treating it that way would be exactly the kind of misleading statistic this phase was told not to produce. Read every number below as "this many, out of this many, in this specific corpus" — not as an estimate of a rate that would hold on a larger or different sample.

## 1–6: Outcome counts

| # | Category | Count |
|---|---|---|
| 1 | Total experiment cases | **19** |
| 2 | Genuine fixes (`true_fix`) | **7** |
| 3 | Partial fixes (`partial_fix`) | **1** |
| 4 | Deceptive / insufficient fixes (`deceptive_fix`) | **0** |
| 5 | Regressions (`regression`) | **1** |
| 6 | Inconclusive outcomes (`inconclusive`) | **10** |

7 + 1 + 0 + 1 + 10 = 19. No case is missing, none excluded — matches the count audited in Phase 7.

`deceptive_fix` at n=0 is itself a finding, not an absence of one: three separate, deliberate attempts across Phases 2–3 were made to elicit it (from two different generating models), and none succeeded — see `docs/scanner_only_baseline_comparison.md` and the Phase 2/3 session record for why (a structural resource-identity mismatch in how Checkov attributes policy findings, plus good-faith models not producing subtly-wrong fixes on their own). This is a negative result worth stating exactly as such: **zero real evidence exists, in either direction, that TerraVeritas can detect a genuinely deceptive repair** — the classification logic is unit-tested against synthetic evidence only.

## 7–8: Scanner vs. TerraVeritas agreement

Using the **broad** scanner-only baseline (re-checks every Checkov rule that fires on an actual public-access grant, not just the one originally-reported rule — the narrow, single-rule baseline agrees with almost anything and isn't a meaningful comparison; see `docs/scanner_only_baseline_comparison.md`):

| # | | Count |
|---|---|---|
| 7 | Cases where scanner (broad) and TerraVeritas agree | **9 of 19** |
| 8 | Cases where they disagree | **10 of 19** |

(For reference, the narrow single-rule baseline agrees on 8 of 19 — not meaningfully different, and not a stronger comparison; it just accepts almost everything, so "agreement" there mostly means "TerraVeritas also didn't call it a clean true_fix," not that the two tools actually corroborated each other on a specific finding.)

## 9: Cases where the invariant provided evidence beyond the scanner

**One** case, unambiguously: `phase2_case_b_partial_fix`. Checkov's `CKV_AWS_70` still fails on the policy document text (`Principal = "*"` is untouched), but the repair also added a Block Public Access resource with `restrict_public_buckets = true`, which neutralizes any bucket policy at the AWS enforcement level regardless of its content. The invariant reasons over the whole resource graph; Checkov's rule only reads the policy document in isolation. TerraVeritas correctly reaches `true_fix`; the broad scanner baseline would have rejected a genuinely safe repair. This is verified, not asserted — the AWS Block Public Access semantics behind it were confirmed against AWS's own documentation during this invariant's original design.

**One further, contested case**: `negcase3_regression_unrelated_change` — TerraVeritas flagged `regression` where the broad baseline said accepted. But the underlying security invariant never changed (PASS before, PASS after); the divergence came from an unrelated Checkov lint finding (`CKV_AWS_300`, about multipart-upload abort settings) that has nothing to do with public access. This is real evidence *of something*, but not evidence the invariant *correctly* caught a security problem the scanner missed — it's the regression detector's own known imprecision (already flagged in Phases 2–4) firing on noise. Counting it as a genuine "beyond the scanner" win would overstate the evidence.

**So: 1 clean, verified instance out of 19 cases.** Not zero, but not more than that either — this does not support a claim that TerraVeritas routinely outperforms scanning.

## 10: Cases blocked by infrastructure limitations

**5 of 19**: `intent_explicit`, `minimal` (both `plan_timeout` — the original provider-network instability, from the earliest pilot before the filesystem mirror workaround existed in that run), `case2_policy_only`, `negcase2_deceptive_principal_condition`, `phase2_case_c_deceptive_attempt` (all `plan_provider_failure` — a repair used a Terraform `data` source, `aws_caller_identity`, requiring a live AWS STS call this sandboxed, non-applying evaluation model cannot make). This is an environment ceiling, not a defect in TerraVeritas's logic — confirmed in Phase 2's supplementary analysis, where the specific repair pattern in two of these cases was independently checked and found genuinely safe by both Checkov's real check code and the invariant's own logic, in isolation from the sandbox failure.

## 11: Cases blocked by invariant limitations

**5 of 19**: `case3_acl_and_policy`, `phase2_case_d_regression_attempt`, `phase2_case_e_inconclusive`, `phase3_case_d_regression_attempt`, `phase3_case_e_inconclusive`. These split into two different kinds of limitation, not one:

- **A known, scoped, fixable gap** (2 cases: `phase2_case_d`, `phase3_case_d`): the invariant's Phase 1 partial-evaluation fix checks an independent Block Public Access rescue only when the relevant content IS resolved — it never gets consulted when the policy itself is unresolved, even though `restrict_public_buckets=True` would rescue it regardless of content. Both underlying repairs are very likely actually safe; the tooling just can't confirm it yet. Flagged, not fixed, at the end of Phase 2/3 — still open.
- **A more fundamental, currently-unaddressed limitation** (3 cases: `case3_acl_and_policy`, `phase2_case_e`, `phase3_case_e`): a bucket policy whose content depends on the bucket's own computed `.arn` is genuinely unresolvable from Terraform's plan JSON in a create-action plan, and — unlike the cases above — there is no independent evidence (no safe ACL, no rescuing BPA flag) available to reach a verdict anyway. Phase 1 investigated and confirmed field-level reconstruction from the plan JSON is not possible for this pattern; closing this gap, if it's closeable at all, would need a different evidence source entirely (e.g. parsing the raw HCL policy expression directly), which has not been attempted.

5 (infrastructure) + 5 (invariant) = 10 = the full `inconclusive` count from section 6. Every inconclusive case is accounted for by exactly one of these two categories — none is unexplained.

## Overall reading

Genuine capability demonstrated on real data: `true_fix` (7), `partial_fix` (1, the first and only real instance), `regression` (1). Never demonstrated on real data: `deceptive_fix` (0, despite real attempts). More than half the corpus (10 of 19) ended `inconclusive` — evenly split between an environment ceiling this project cannot currently work around (sandboxed, non-applying evaluation cannot resolve live-AWS-dependent Terraform) and invariant gaps, one of which is scoped and fixable, the other of which is more fundamental. TerraVeritas's one clean, verified advantage over even a thorough scanner re-scan is real but singular (n=1) — not yet a demonstrated pattern.
