# Phase 9: scientific claim audit

Independent audit of the 7 specified claims, classified against the real evidence built in Phases 0–8 — no new experiments run for this phase; this is synthesis, not new data collection. Every count cited traces back to `docs/phase8_analysis.md` (n=19 real cases) or an earlier phase's specific finding, named explicitly rather than asserted from memory.

---

### 1. TerraVeritas can evaluate real AI-generated Terraform repairs.

**EXPERIMENTALLY DEMONSTRATED.**

19 real records, real Checkov scans, real `terraform plan` via the provider filesystem mirror, real invariant evaluation, real oracle classification — audited in Phase 6/7 to confirm zero synthetic `PlanResult`/`ScanResult` construction anywhere in the dataset. Most records are genuinely blind AI-generated repairs (Claude Sonnet 5 and Haiku 4.5, both Anthropic — see claim 6's caveat on generalization, and Phase 3's honest disclosure that no genuinely independent-vendor source was safely available in this environment). The mechanics of the claim — that the pipeline can take a real AI output and evaluate it end to end — is proven repeatedly, not once.

### 2. TerraVeritas can distinguish true fixes from partial fixes.

**EXPERIMENTALLY DEMONSTRATED, on a thin sample.**

The cleanest evidence is a paired comparison: the identical underlying vulnerability and context (`phase2_case_b` / `phase3_case_b`, ACL fixed but a hidden policy left untouched) produced `true_fix` from one model (which added a Block Public Access resource that happened to neutralize the hidden policy too) and a genuine, correctly-reasoned `partial_fix` from a different model (which did not) — with accurate "partial narrowing" evidence in the verdict (`acl_grants_public` resolved, `policy_grants_public` remains). This is real differentiation on real data, not synthetic. But it is exactly one instance of `partial_fix` in the whole corpus (n=1 of 19) — the capability is proven to exist, not proven to be reliable or repeatable across varied scenarios.

### 3. TerraVeritas can detect scanner-satisfying but semantically insecure repairs.

**UNTESTED** (with real evidence suggesting the current architecture may not be able to, for the most direct attack surface).

Zero real `deceptive_fix` classifications exist, despite three dedicated real attempts across two different generating models (`negcase2`, `phase2_case_c`, `phase3_case_c`). The classification logic itself is real code, covered by 11 synthetic unit tests — that part is an **implementation-level guarantee** (the decision function is correct given the inputs its tests supply), but that is a claim about the code, not about the capability. Separately, Phase 2's analysis found a real, structural reason this may be more than just bad luck: Checkov attributes a policy-based finding (`CKV_AWS_70`) to the *policy resource's own address*, not the bucket's, while every script in this project scopes the oracle's scanner-improvement check to the bucket's address — meaning the specific signal `deceptive_fix` depends on may be structurally invisible for this invariant's most obvious attack surface, independent of any repair's actual quality. That is suggestive negative evidence, not a direct empirical contradiction (no case exists where TerraVeritas was shown to have called a genuinely deceptive repair something else) — so it stays **UNTESTED**, not **CONTRADICTED**, but it is not a neutral untested claim either.

### 4. TerraVeritas provides evidence beyond scanner re-approval.

**EXPERIMENTALLY DEMONSTRATED as possible; NOT demonstrated as a reliable pattern.**

One real, verified case (`phase2_case_b_partial_fix`) where TerraVeritas reaches a more accurate verdict than even a thorough scanner re-scan, by reasoning about a Block Public Access resource Checkov's narrow rule can't see. That is real evidence the claim can be true. But of the 10 real cases where TerraVeritas and a properly-scoped scanner baseline disagree, only that one is a clean case of TerraVeritas adding *correct, new* evidence — a second candidate (`negcase3`'s `regression`) is contested, since the trigger was an unrelated lint finding rather than an actual security signal, and the remaining 8 divergences are TerraVeritas being more *conservative* (declining to certify what the scanner accepts), not more *informative*. n=1 clean instance out of 19 does not support a claim of general superiority — it supports a claim of demonstrated possibility.

### 5. The invariant design avoids circularity in practice.

**SUPPORTED HYPOTHESIS**, with an implementation-level guarantee underneath it.

That the invariant's logic was independently derived from AWS's own documented Block Public Access semantics, not copied from Checkov's rule source, is verifiable by direct inspection and was directly confirmed this session: Phase 2's analysis read Checkov's actual `S3AllowsAnyPrincipal` check source and compared it line-by-line against the invariant's own condition-disqualification logic, finding genuine, independent divergence (the invariant is *stricter* — it treats any wildcard character in a would-be-disqualifying condition value as non-disqualifying, where Checkov's regex-based check has real gaps). That's an implementation-level guarantee: the code does not derive its answers from the scanner's rule logic, by construction. Whether this actually *avoids circularity in practice* — i.e., produces genuinely independent, occasionally-diverging, correct verdicts on real cases, not just in principle — has exactly one clean empirical confirmation (`phase2_case_b`, claim 4). One real divergence, correctly resolved, is meaningful support; it is not enough real cases to call the general property demonstrated.

### 6. The methodology generalizes beyond S3.

**UNTESTED.**

One invariant is implemented: `S3_PUBLIC_ACCESS_EXPOSURE`. Zero of the other four originally-scoped invariants (IAM wildcard grants, security-group ingress, network reachability, storage encryption) have been designed, implemented, or tested against any real data. `CONTRIBUTING.md` already states this honestly as unstarted work. There is no evidence, positive or negative, about whether the differential-plus-invariant-plus-oracle pattern this project uses would work for a materially different kind of security property (e.g. one that isn't about "does a grant reach an unauthenticated principal").

### 7. Oracle verdicts agree with human judgment.

**UNTESTED.**

Phase 5 built real, usable evaluation materials (`docs/human_evaluation/`) — 8 blind cases, a protocol, an answer key withheld from the packet — but no human evaluator has completed it. The user was directly offered the chance to be that evaluator in this session and declined, choosing to leave it pending rather than have any label — real or fabricated — attached. Every one of the 19 real records has `human_label=None`. Zero data exists in either direction; this is not evidence of agreement or disagreement, it is the complete absence of the comparison.

---

## Summary table

| # | Claim | Classification |
|---|---|---|
| 1 | Can evaluate real AI-generated repairs | **EXPERIMENTALLY DEMONSTRATED** |
| 2 | Can distinguish true fixes from partial fixes | **EXPERIMENTALLY DEMONSTRATED** (n=1 partial_fix) |
| 3 | Can detect scanner-satisfying but insecure repairs | **UNTESTED** (structural reason to doubt, not confirmed either way) |
| 4 | Provides evidence beyond scanner re-approval | **EXPERIMENTALLY DEMONSTRATED as possible** (n=1 clean case, not a pattern) |
| 5 | Invariant design avoids circularity in practice | **SUPPORTED HYPOTHESIS** (implementation-level guarantee on design; n=1 empirical confirmation) |
| 6 | Methodology generalizes beyond S3 | **UNTESTED** |
| 7 | Oracle verdicts agree with human judgment | **UNTESTED** |

No claim above is classified as **CONTRADICTED** — nothing in the real evidence directly disproves any of the 7 claims as stated. But only two claims (1 and, more thinly, 2) rise to a level of evidence that would support confident, general statements in a paper or a release announcement. The rest are real but narrow (4, 5) or genuinely open (3, 6, 7). Presenting any of 3–7 as established capabilities would not be supported by what this project has actually shown.
