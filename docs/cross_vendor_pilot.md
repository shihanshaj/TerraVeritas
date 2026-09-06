# Cross-vendor pilot: Gemini vs. Claude, controlled

**Status: complete. First genuinely independent-vendor evidence in this project's dataset.**

## Why this matters

Every prior repair in this project — Phases 2, 3, and 6 — came from Anthropic (Claude Sonnet 5 or Haiku 4.5), disclosed honestly at every point as same-vendor evidence, not independent-source evidence (see Phase 3's session record and `docs/phase9_scientific_claim_audit.md`, which classified "the methodology generalizes beyond same-vendor comparison" as untested for exactly this reason). This pilot closes that specific gap with real data from a genuinely different lab: Google's Gemini, via a direct API call.

## Design — held constant, varied deliberately

| | Held constant | Varied |
|---|---|---|
| Vulnerable configuration | Identical fixtures (`fixtures/terraform/phase2_case_{a,b,e}_*`) | — |
| Prompt template | Byte-identical text to the corresponding Phase 2/3 case | — |
| Evaluation environment | `experiments.pipeline.evaluate_repair` — the same canonical, real pipeline (real Checkov, real Terraform plan via the provider mirror, the real invariant, the real oracle, the real scanner-only baseline) used for every other experiment in this project | — |
| Generating model | | **Gemini 3.6 Flash (Google)** instead of Claude |

Three cases, not a full re-run of the corpus — a deliberate small pilot, matching exactly what was asked for. Selected to mirror Phase 3's own case selection logic: A (single-vector, positive control), B (the context-limited case that produced the project's first real `PARTIAL_FIX`), E (the policy-only, idiomatic-`.arn` shape that Phase 1 confirmed is architecturally forced to stay `INCONCLUSIVE` regardless of the repair's quality).

## Getting access — worth recording honestly

No API key was available in the environment at the start of this priority (confirmed by re-checking — same result as Phase 3). The user obtained a real Gemini API key from Google AI Studio and provided it; it was stored in `.env` (already gitignored, verified via `git check-ignore` before use) rather than passed through as a repeated chat argument. One correction worth noting for accuracy: the key's format (`AQ.Ab8...`) didn't match the documented `AIzaSy...` prefix convention, and it would have been easy to wrongly tell the user it looked invalid — instead it was tested directly against the API (`GET /v1beta/models`), which confirmed it was genuinely live and working. Verify, don't assume, applied to the credential itself, not just the experiment.

## Results

| Case | Claude result (Phase 2/3) | Gemini result (this pilot) |
|---|---|---|
| A — genuine fix | `TRUE_FIX` (both Sonnet and Haiku) | **`TRUE_FIX`** — identical: `public-read` → `private`, nothing else touched |
| B — partial fix (context-limited) | Sonnet: `TRUE_FIX` (added a Block Public Access resource, incidentally neutralizing the hidden policy). Haiku: `PARTIAL_FIX` (fixed only the ACL, left the hidden policy genuinely exposed) | **`PARTIAL_FIX`** — replicates Haiku's outcome, not Sonnet's: fixed only the ACL, added no BPA resource, left the hidden policy resource in the after-state exactly as-is |
| E — inconclusive | `INCONCLUSIVE` (both models), each via `data.aws_caller_identity`, hitting this sandbox's no-live-AWS-credentials wall | **`INCONCLUSIVE`** — Gemini independently reached for the identical `data.aws_caller_identity` idiom to scope the principal to "the caller's own account," hitting the same wall |

## Why this is more than "one more data point"

Case B is the load-bearing result here. `PARTIAL_FIX` had exactly one real precedent before this pilot (Haiku, Phase 3) — a single instance was honestly reported as "the capability is proven to exist, not proven to be reliable or repeatable" (`docs/phase9_scientific_claim_audit.md`, claim 2). A second occurrence, under the identical controlled condition, from a *completely different vendor*, is a real, if still small, step toward that being a repeatable pattern rather than a one-off. Sonnet's `TRUE_FIX` result on the same fixture — via an unprompted defense-in-depth addition neither Haiku nor Gemini produced — now reads as the outlier of the three, not the norm.

Case E's replication is a different kind of finding: it's evidence that reaching for `aws_caller_identity` to scope a principal to "the deploying account" is a natural, cross-vendor idiom for this exact task, not a Claude-specific habit. That raises the practical importance of the underlying infrastructure limitation (this sandboxed, non-applying evaluation model cannot resolve any Terraform `data` source requiring a live AWS call) — it is not a rare edge case this project can deprioritize; two independent model families produced it on the first real attempt each.

## What this does not show

n=3 for one invariant, one prompt template, one vendor pair. This does not establish a rate, a percentage, or a generalizable claim about Gemini's behavior — it establishes that these three specific real outcomes replicate under a controlled design. No claim beyond that is made here, matching the same discipline `docs/phase9_scientific_claim_audit.md` already applied to the Sonnet/Haiku comparison.

## Reproducibility

`scripts/run_cross_vendor_pilot.py` runs the evaluation half of this end to end from the saved raw responses. The three raw Gemini responses themselves were captured via a one-off scratch script calling `generativelanguage.googleapis.com` directly (not committed to the repository, since it isn't part of the reusable pipeline — the responses it produced are the artifact that matters, and those are what's stored in `datasets/experiments/2026-09-06-cross-vendor-pilot-gemini/`). Regenerating fresh Gemini responses would require a valid `GEMINI_API_KEY` in `.env` (never committed) and would not necessarily reproduce byte-identical output, since model responses are not guaranteed deterministic — the stored raw responses are the authoritative record of what was actually evaluated.
