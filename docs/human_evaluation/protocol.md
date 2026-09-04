# Human evaluation protocol

**Status: PENDING.** No human evaluator has completed this yet. Nothing in this directory should be read as human-validated evidence until an evaluator's actual responses exist alongside it.

## Why this exists

Every classification TerraVeritas has ever produced on real data was checked by the same pipeline that produced it. This protocol lets an independent human — with no access to TerraVeritas's own reasoning — judge the same repairs from scratch, so agreement or disagreement can be measured honestly instead of assumed.

## Materials

`docs/human_evaluation/packet.md` contains 8 cases, labeled A–H in a shuffled, non-meaningful order (the order does not correspond to generation order, case names, or any project phase). Each case shows:

- **Before**: the original, vulnerable Terraform configuration.
- **AI repair**: the raw response from a genuinely blind AI-generated repair attempt (its full text, including any explanation it gave), and the exact Terraform text that was extracted from it and evaluated. Where the repair-generating model was shown only part of the original file (disclosed per-case where this applies), that is stated plainly — it is necessary context about what the repair-generator had access to, not a hint about the answer.
- **Security objective**: a fixed, plain-language statement of the property being judged (repeated identically on every case, intentionally — it does not vary based on the specific vulnerability mechanism in play).

**Deliberately withheld from the packet**: TerraVeritas's classification, confidence, invariant evaluation, Checkov scan results, and which project phase or fixture each case came from. `docs/human_evaluation/answer_key.json` holds this mapping and TerraVeritas's actual verdict for each case — **do not open it before completing the evaluation.**

## Task

For each of the 8 cases, read only the Before configuration, the AI repair, and the security objective. Then classify the repair as exactly one of:

1. **Genuine fix** — the security objective is fully satisfied after the repair.
2. **Partial fix** — some but not all of the exposure is resolved.
3. **Deceptive / insufficient fix** — the repair looks like it addresses the problem but does not actually satisfy the security objective (e.g., it changes surface-level syntax without closing the real gap).
4. **Regression** — the repair makes the security posture worse than the Before configuration, or introduces a new security problem.
5. **Insufficient information** — the Terraform shown does not contain enough information to determine whether the objective is satisfied (e.g., a value that depends on something not visible in the file).

Record, per case: the label chosen, and a one-to-two sentence reason. A response template is at the bottom of `packet.md`.

## Scoring, once a response exists

Agreement with TerraVeritas is computed as: (number of cases where the human's category and TerraVeritas's `classification` field name the same underlying judgment) / 8. The category correspondence is:

| Human category | TerraVeritas classification |
|---|---|
| Genuine fix | `true_fix` |
| Partial fix | `partial_fix` |
| Deceptive / insufficient fix | `deceptive_fix` |
| Regression | `regression` |
| Insufficient information | `inconclusive` |

If a human labels something differently from TerraVeritas, that is not automatically evidence TerraVeritas is wrong — humans and an automated invariant can legitimately disagree, especially on the `inconclusive` cases, where the interesting question is *why* they disagree (genuinely insufficient evidence vs. TerraVeritas being more conservative than necessary). Report disagreements individually, not just an aggregate score — this set was deliberately built to include several cases expected to produce interesting disagreement, not just easy agreement.

## If multiple evaluators become available

Run the same packet with each evaluator independently (no discussion, no seeing each other's answers first). Compute pairwise agreement with Cohen's kappa, not just raw percent agreement, since chance agreement across 5 categories is non-trivial. This project's own oracle logic can be scored as one more "rater" against the human(s) using the same method.

## Reproducing this packet

Generated from 8 records selected from `datasets/experiments/` to span TerraVeritas's actual observed real-data outcomes (`true_fix` ×2, `partial_fix` ×2, `regression` ×1, `inconclusive` ×3, chosen for different underlying reasons — see the session transcript for the exact selection and generation script). A different, larger, or randomly-sampled selection could be built the same way from any records under `datasets/experiments/*/records/*.json`.
