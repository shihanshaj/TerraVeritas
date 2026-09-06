# Two new invariants: IAM excessive privilege and network exposure

**Status: implemented, tested against real Terraform plans, and passing. No AI-repair experiments have been run against either yet — see "What this does not include" at the end.**

## Why this exists

Every real result this project has produced so far is about one invariant, `S3_PUBLIC_ACCESS_EXPOSURE`. Every claim about generalization has been `UNTESTED` in every audit this project has done of itself (see `docs/phase9_scientific_claim_audit.md`, claim 6). Two more invariants, in genuinely different security domains with genuinely different reasoning shapes, are the minimum needed before that claim can move past `UNTESTED`.

## Grounding — real AWS documentation, not invented definitions

**`IAM_EXCESSIVE_PRIVILEGE_EXPOSURE`** — AWS Config's own managed rule `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` (fetched and verified during design, not assumed from training data): a statement is "admin access" if and only if `Effect: Allow`, `Action: "*"` (the bare wildcard), and `Resource: "*"`. AWS's own cited COMPLIANT example uses `Action: "service:*"` over `Resource: "*"` — a service-scoped wildcard is explicitly *not* flagged by AWS's own rule, and this invariant makes the identical distinction rather than a broader "any wildcard is suspicious" heuristic of its own invention.

**`NETWORK_SENSITIVE_PORT_EXPOSURE`** — the union of two AWS Config managed rules' own default scope: `restricted-ssh` (port 22 open to `0.0.0.0/0`/`::/0`) and `restricted-common-ports` (its own default ports: 20, 21, 3306, 3389, open the same way). No port beyond what these two specific, cited rules already specify by default was added — a broader "commonly sensitive" list (5432, 1433, 27017, etc.) was deliberately left out rather than presented as AWS-endorsed when it would actually be this project's own judgment call.

## Why these two specifically — different reasoning shapes, not just different services

This was a real design constraint, not an afterthought: the whole point of adding a second and third invariant is to find out whether the *methodology* generalizes, which requires the new invariants to actually stress different parts of it.

- **S3** (existing): a multi-resource correlation problem. The security-relevant data is spread across up to four separate Terraform resources (bucket, ACL, policy, Block Public Access, ownership controls) that must be joined via the plan's static reference graph.
- **IAM** (new): single-resource-pair correlation, but with an inverted resolution characteristic. An inline `aws_iam_role_policy`'s own policy *content* resolves at plan time even when the reference that correlates it to its role does not — the opposite of S3's bucket-policy case, where the content is usually what's unresolved (because it interpolates the bucket's own computed `.arn`) while the correlating reference is comparatively easy to follow. Confirmed against a real captured plan, not assumed by analogy to S3.
- **Network** (new): no cross-resource correlation at all. The entire security-relevant state (`ingress` rules) lives as a list of nested blocks on one resource. The correctness challenge here is completely different: reading Terraform's *per-element* "known after apply" tracking inside a list-of-objects attribute, a mechanism nothing else in this project had exercised before.

Three invariants, three different failure modes to get right. That was the actual test of "is this a methodology."

## A real bug, caught the same way every prior real bug in this project was caught

Before any test was written for the network invariant, its logic was smoke-tested against real captured plans (both a vulnerable and a secure security group). Both returned `UNKNOWN`. The cause: Terraform's per-index unknown marker for a resolved list field is itself a list — `[False]` for one known element — which is truthy in Python even though it means "known." The first implementation's `if per_rule_unknown.get(field):` check treated every security group, vulnerable or not, as unresolved. Fixed with an explicit `_field_is_unresolved()` helper that distinguishes a bare `True` (whole field unknown) from a list of per-element booleans (only elements marked `True` are unknown), verified by re-running against the same two real plans before any unit test was written to lock the correct behavior in.

This is exactly the category of bug the S3 invariant's own history repeatedly demonstrates synthetic tests alone don't catch (see `docs/experiment_reproducibility.md` and this invariant's own predecessors' bug histories) — real execution against a real Terraform plan found it here too, on the first new invariant built after that lesson was already well-established in this project.

## Methodology followed for both invariants

1. Fetched and read the actual AWS Config documentation for the relevant managed rules before writing any code.
2. Built real Terraform fixtures (vulnerable + secure pair for each invariant) and ran a real `terraform plan` against each via the existing provider filesystem mirror — no new provider download was needed, since IAM and EC2/security-group resources are part of the same `hashicorp/aws` provider already mirrored for S3.
3. Inspected the real captured plan JSON directly before writing any evaluation logic, specifically to avoid assuming a schema by analogy to S3 — this is what surfaced both the favorable IAM characteristic (policy content resolves independently of the role reference) and the security-group per-index unknown-marker shape (including one additional probe fixture, not committed, built specifically to observe what an unresolved CIDR value's marker looks like).
4. Wrote the evaluator, smoke-tested it against the real captured plans, found and fixed the security-group bug above.
5. Extracted the real captured plans into `fixtures/real_plans/{iam,sg}_{vulnerable,secure}_create_plan.json` and wrote a full test suite for each invariant: real-plan regression tests plus synthetic tests covering the AWS-documented boundary cases (bare wildcard vs. service-scoped wildcard for IAM; sensitive vs. non-sensitive port, TCP vs. UDP, single CIDR vs. `0.0.0.0/0`, and the unresolved-content safety property for network) — 31 new tests total.
6. Both invariants populate `InvariantResult.related_resource_addresses` (the field added in the `DECEPTIVE_FIX` scoping fix) from day one — IAM's related set is the role plus every inline policy found; network's is just the security group itself, since there's nothing to correlate.
7. Ran the affected test files, then the complete suite, `ruff`, and `mypy --strict` (`src` only, matching this project's own established CI scope — a broader `mypy src tests` invocation surfaces pre-existing, unrelated typing looseness in test helper files across the project that predates this work and is out of scope here).

Full suite: 252/252 passing (was 221 before this addition — 31 new tests, 0 removed). Lint and strict mypy clean.

## Disclosed scope, stated plainly rather than discovered later

**IAM**: only `aws_iam_role` + directly-attached inline `aws_iam_role_policy`. Managed policies (`aws_iam_policy` + `aws_iam_role_policy_attachment`, requiring a second reference hop), `aws_iam_user_policy`/`aws_iam_group_policy` (same shape, different principal type), and `NotAction`/`NotResource` statements (inverted semantics, not implemented) are all real exposure paths this invariant does not evaluate — each would report PASS regardless of actual content.

**Network**: only the inline `ingress` block on `aws_security_group`. The newer, decoupled `aws_security_group_rule` / `aws_vpc_security_group_ingress_rule` resources are not evaluated. UDP-only rules to a sensitive port are not flagged, matching `restricted-common-ports`' own TCP-only scope exactly rather than extending past it.

Both mirror the S3 invariant's own founding discipline: start narrow, verify against real data, disclose exactly what's not covered — not attempt full coverage in one pass and risk getting the depth wrong everywhere at once.

## What this does not include

No AI-generated repair has been evaluated against either new invariant yet. Nothing in this document should be read as evidence that TerraVeritas's central capability (distinguishing a genuine fix from a deceptive or partial one) generalizes beyond S3 — only that the *invariant layer itself* can be built for a materially different security domain with the same rigor, which is a necessary precondition for that investigation, not the investigation itself. Running real, blind AI-repair experiments against IAM and network-exposure fixtures — the actual next step toward answering "is this a methodology" — has not been done in this pass.
