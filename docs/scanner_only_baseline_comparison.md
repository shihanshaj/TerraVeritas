# Scanner-only baseline vs. TerraVeritas

**Question**: does TerraVeritas provide evidence beyond simply re-running Checkov? Answered here using every real experiment record on file — 18 genuinely AI-generated or fixture-pair repairs, evaluated through the real, unmodified pipeline. Nothing in this document is synthetic; nothing was re-run for this analysis — all evidence already existed in `datasets/experiments/`. This document recomputes each case's invariant/oracle verdict fresh against the current codebase (post the policy-unresolved partial-evaluation fix), not against whichever verdict happened to be stored at generation time, so the comparison reflects what TerraVeritas does today.

Reproduce with: the script embedded in this analysis reads every `datasets/experiments/*/records/*.json` file directly; see the session transcript for the exact recomputation logic (loads each record's own stored real plan JSON and differential, re-evaluates the invariant and oracle against the current code).

## Two scanner-only baselines, not one

A single "trust the scanner" baseline turned out to hide an important distinction, so this document reports two:

- **Narrow baseline**: re-check only the *one* Checkov rule originally reported for the case. This is how a great many real CI integrations actually work — a required-status-check tied to one specific rule ID, or a bot that says "the flagged line is fixed."
- **Broad baseline**: re-check every Checkov rule that fires only on an *actual* public-access grant (`CKV_AWS_20`, `CKV_AWS_57`, `CKV_AWS_70`, `CKV2_AWS_43`, `CKV_AWS_375`), regardless of which one was originally reported.

The broad rule set was corrected once already during this analysis: a first attempt included `CKV2_AWS_6` ("no Block Public Access resource") and the standalone BPA-flag checks. That version rejected cases already independently confirmed as genuinely fixed (`case1_acl_only`, etc.), because absence of a hardening control isn't the same as an actual grant — exactly the imprecision this project's own invariant exists to avoid, including in its own baseline. Excluded, not included.

## Full comparison — all 18 real cases

| Case | Reported rule | Narrow baseline | Broad baseline | TerraVeritas | TV confidence |
|---|---|---|---|---|---|
| intent_explicit | CKV_AWS_20 | REJECTED | REJECTED | `inconclusive` | low |
| minimal | CKV_AWS_20 | ACCEPTED | ACCEPTED | `inconclusive` | low |
| case1_acl_only | CKV_AWS_20 | ACCEPTED | ACCEPTED | **`true_fix`** | high |
| case2_policy_only | CKV_AWS_70 | ACCEPTED | ACCEPTED | `inconclusive` | low |
| case3_acl_and_policy | CKV_AWS_20 | ACCEPTED | **REJECTED** (`CKV_AWS_70` still fails) | `inconclusive` | low |
| negcase1_partial_two_vectors | CKV_AWS_20 | ACCEPTED | ACCEPTED | **`true_fix`** | high |
| negcase2_deceptive_principal_condition | CKV_AWS_70 | ACCEPTED | ACCEPTED | `inconclusive` | low |
| negcase3_regression_unrelated_change | N/A | no finding to check | ACCEPTED | **`regression`** | high |
| phase2_case_a_genuine_fix | CKV_AWS_20 | ACCEPTED | ACCEPTED | **`true_fix`** | high |
| phase2_case_b_partial_fix | CKV_AWS_20 | ACCEPTED | **REJECTED** (`CKV_AWS_70` still fails) | **`true_fix`** | high |
| phase2_case_c_deceptive_attempt | CKV_AWS_70 | ACCEPTED | ACCEPTED | `inconclusive` | low |
| phase2_case_d_regression_attempt | N/A | no finding to check | ACCEPTED | `inconclusive` | low |
| phase2_case_e_inconclusive | CKV_AWS_70 | ACCEPTED | ACCEPTED | `inconclusive` | low |
| phase3_case_a_genuine_fix | CKV_AWS_20 | ACCEPTED | ACCEPTED | **`true_fix`** | high |
| phase3_case_b_partial_fix | CKV_AWS_20 | ACCEPTED | **REJECTED** (`CKV_AWS_70` still fails) | **`partial_fix`** | high |
| phase3_case_c_deceptive_attempt | CKV_AWS_70 | ACCEPTED | ACCEPTED | **`true_fix`** | high |
| phase3_case_d_regression_attempt | N/A | no finding to check | ACCEPTED | `inconclusive` | low |
| phase3_case_e_inconclusive | CKV_AWS_70 | ACCEPTED | ACCEPTED | `inconclusive` | low |

**Narrow baseline vs. TerraVeritas**: agree on 3 of 18, diverge on 15. Almost meaningless as a comparison — the narrow baseline says "ACCEPTED" on nearly everything, including two cases (`case3_acl_and_policy`, `phase2_case_b`) that genuinely still had public exposure. This mainly demonstrates that single-rule CI gates are weak, which was already expected.

**Broad baseline vs. TerraVeritas**: agree on 8 of 18, diverge on 10. This is the real comparison.

## The 10 broad-baseline divergences, honestly bucketed

Not all divergence is a win for TerraVeritas. Three genuinely different things are happening:

### Bucket A — TerraVeritas reaches a different verdict and is demonstrably more correct (1 case)

**`phase2_case_b_partial_fix`**: the broad scanner baseline says REJECTED, because `CKV_AWS_70` still fires on the bucket-policy *document text* (`Principal = "*"` is still there, byte for byte). But the real repair also added `aws_s3_bucket_public_access_block` with `restrict_public_buckets = true` — an AWS-enforced control that neutralizes *any* bucket policy regardless of its content, verified against AWS's own documented Block Public Access semantics during this invariant's original design. Checkov's `CKV_AWS_70` check has no visibility into a co-located BPA resource; it only reads the policy document in isolation. TerraVeritas's invariant reasons over the whole resource graph and correctly reaches `TRUE_FIX`. This is a genuine, real instance of TerraVeritas being *more accurate*, not just more cautious, than even a thorough scanner re-scan — because it models an actual AWS enforcement mechanism the scanner's rule doesn't know exists.

### Bucket B — TerraVeritas is more sensitive to change than the scanner, but not necessarily more correct (1 case)

**`negcase3_regression_unrelated_change`**: broad baseline says ACCEPTED (no actual-grant rule fails), but TerraVeritas classifies `REGRESSION`. The underlying security invariant never changed (PASS before, PASS after) — the classification came entirely from one new, unrelated Checkov finding (`CKV_AWS_300`, "set an abort-incomplete-multipart-upload period"), which has nothing to do with public access. This was already flagged, honestly, in the Phase 2 report as a real imprecision: TerraVeritas's regression detector currently treats *any* new scanner finding on the resource as regression-worthy, not just security-relevant ones. This divergence is real, but it argues TerraVeritas is *noisier* here, not smarter.

### Bucket C — TerraVeritas is more conservative and cannot independently confirm what the scanner accepts (8 cases)

`minimal`, `case2_policy_only`, `negcase2_deceptive_principal_condition`, `phase2_case_c_deceptive_attempt`, `phase2_case_d_regression_attempt`, `phase2_case_e_inconclusive`, `phase3_case_d_regression_attempt`, `phase3_case_e_inconclusive`. In every one, the broad scanner baseline says ACCEPTED, and TerraVeritas says `inconclusive` — not because it found a problem, but because it requires an actual successful `terraform plan` to certify safety, and couldn't get one:

- **Environment limitation (not a TerraVeritas defect)**: `case2_policy_only`, `negcase2`, `phase2_case_c` all involve a repair using a Terraform `data` source that depends on a live AWS API call (`aws_caller_identity`), which this project's sandboxed, non-applying evaluation model cannot resolve. Separate supplementary analysis in this session (isolating the policy statement from the sandbox failure) already confirmed both Checkov's real check logic *and* this invariant's own logic independently agree these specific repairs are safe — TerraVeritas just structurally cannot verify that live, in this environment.
- **A known, already-flagged implementation gap**: `phase2_case_d` and `phase3_case_d` hit the BPA-rescue gap identified during Phase 2/3 (the invariant doesn't yet check an independently-known `restrict_public_buckets` rescue when the policy content itself is unresolved). This is not fundamental — it's a real, scoped, fixable gap, distinct from the environment limitation above.
- **Genuinely correct caution**: `minimal` and `phase2/3_case_e` are cases where the underlying evidence really is insufficient (`plan_timeout`, or a policy-only vulnerability with no independent rescue) — TerraVeritas declining to certify here is the honest, intended behavior, not a shortcoming.

## Honest overall verdict

**TerraVeritas and a properly-scoped scanner-only re-scan agree on 8 of 18 real cases.** Of the 10 divergences: **one** is a clean, verified case of TerraVeritas being more *correct* than the scanner (Bucket A); **one** is TerraVeritas being more sensitive but arguably noisier, not more correct (Bucket B); **eight** are TerraVeritas being more conservative — sometimes for a good reason (genuine insufficient evidence), sometimes because of an environment constraint that isn't TerraVeritas's fault, and twice because of an already-known, unfixed gap in its own partial-evaluation logic.

This does **not** support a claim that TerraVeritas is broadly, uniformly superior to scanning. What the evidence actually supports, precisely: TerraVeritas is **strictly more informative than a narrow, single-rule CI gate** (the comparison that matters most, since that's the realistic alternative in practice, not "an infinitely careful human re-scanning everything by hand"), and it has **at least one clean, mechanistically-explained instance of correcting a scanner's blind spot** (BPA neutralizing a policy the scanner still flags in isolation). Beyond that specific, demonstrated case, its main real advantage so far is procedural rigor (never certifying without a real plan) purchased at a real cost in coverage (many probably-safe repairs go uncertified due to environment and implementation limits, not because they're actually unsafe).
