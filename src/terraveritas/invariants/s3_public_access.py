"""S3_PUBLIC_ACCESS_EXPOSURE invariant.

Full design (threat model, AWS mechanisms, adversarial review) was worked
out before any code — see project notes from that design pass. This module
implements exactly the pseudocode from that pass, using AWS's own
documented "meaning of public" algorithm for bucket policies (fetched and
verified against https://docs.aws.amazon.com/AmazonS3/latest/userguide/
access-control-block-public-access.html during design), not a scanner-rule
approximation of it.

Disclosed testing gap: this evaluator's tests use synthetic PlanResult
objects built to the exact `terraform show -json` schema verified in
Prompt 5 (resource_changes[].{address,type,name,provider_name,change:
{actions,after,after_unknown}}), not a live plan of a real aws_s3_bucket —
this sandbox cannot reliably download the AWS provider (see plan.py's
module docstring). The exact `after` key the AWS provider uses for a
bucket's own identifier (`id` vs `bucket`) is therefore NOT empirically
re-verified here; both are checked defensively. This should be confirmed
against a real plan before this invariant is relied on in an actual
evaluation run.

Disclosed scope gaps (see also the design review):
- Legacy inline `aws_s3_bucket.acl` / `aws_s3_bucket.policy` attributes
  (pre-v4 AWS provider) are not read. A bucket exposed only via those
  attributes will incorrectly evaluate as PASS (false PASS risk).
- S3 Access Points / Multi-Region Access Points are a separate exposure
  surface with their own "meaning of public" rules and are not evaluated
  at all. A repair that relocates exposure onto an access point will
  incorrectly evaluate as PASS (false PASS risk) — this is the one gap in
  this invariant that is NOT safe-direction-only.
- UNVERIFIED, genuinely unresolved (not safe-direction-only): a bucket
  with no ACL/policy/BPA/ownership resource declared at all evaluates as
  PASS, based only on the absence of a declared grant — this is NOT a
  verified claim about AWS's own implicit default BPA flag values for a
  freshly-created bucket. Two real attempts to confirm this against AWS's
  own S3 Block Public Access documentation (during the original design
  pass and again during a later audit) both found only the general
  statement "new buckets... don't allow public access", never a crisp
  confirmation of the actual BlockPublicAcls/IgnorePublicAcls/
  BlockPublicPolicy/RestrictPublicBuckets flag values Terraform's plan
  would show for a bucket where none of those resources are declared.
  Unlike the account-level-BPA gap above, this one is NOT known to be
  safe-direction-only: if AWS's real behavior in any scenario does not
  fully protect a bare bucket, this evaluates as a false PASS. Must be
  independently confirmed (e.g. a real `terraform plan` inspection, once
  this environment's provider-registry constraint is resolved — see
  terraform/plan.py) before this invariant is relied on for a bare-bucket
  case in an actual evaluation run.

Policy-unresolved partial evaluation (investigated and fixed against real
data — see datasets/experiments/2026-09-03-real-ai-pilot-s3exposure/records/
case3_acl_and_policy-000.json and fixtures/real_plans/): an idiomatic bucket
policy that interpolates the bucket's own `.arn` (e.g.
`Resource = "${aws_s3_bucket.data.arn}/*"`) is entirely unknown in a
create-action plan, since `arn` is AWS-computed and not known until apply.
This previously caused a blanket UNKNOWN for the whole bucket, discarding
even a fully-resolved, independently-conclusive ACL on the same resource.
Investigated and REJECTED: reconstructing the policy's Principal/Effect/
Action independently of Resource from Terraform's static configuration
graph. A real captured plan (see the fixture above) confirms
`configuration.root_module.resources[].expressions.policy` for a
`jsonencode(...)`-built policy collapses to a flat `{"references": [...]}`
list — Terraform's plan JSON does not preserve the internal structure of a
function-call argument, so there is no sub-key evidence to reconstruct.
This is not a limitation of this project's tooling; it is how Terraform's
`show -json` configuration section is defined, verified directly against
real output, not assumed. What IS implemented: the ACL side and the policy
side are evaluated independently. An unresolved side can still contribute a
FAIL (an unresolved policy can only make a bucket already publicly exposed
via its ACL MORE exposed, never less), but is never treated as evidence
toward PASS — reaching PASS requires both sides to be resolved and safe.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from terraveritas.models.invariant import InvariantResult, InvariantStatus
from terraveritas.models.plan import PlannedResourceChange, PlanResult, PlanStatus

INVARIANT_ID = "S3_PUBLIC_ACCESS_EXPOSURE"

ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
_PUBLIC_ACL_GRANTEE_URIS = {ALL_USERS_URI, AUTHENTICATED_USERS_URI}
_PUBLIC_CANNED_ACLS = {"public-read", "public-read-write"}

# "Sensitive action", within this invariant's own stated threat model
# (module docstring: read/write/list against the bucket's objects, or
# against the bucket's own security configuration), means any action whose
# VERB is get/put/delete/list against the s3: namespace, or a wildcard that
# subsumes them — not an enumeration of specific action NOUNS.
#
# Rejected: an allow-list of literal action names (the prior implementation,
# and the naive fix for the confirmed gap this replaces). S3's IAM action
# namespace is s3:<Verb><Noun> — GetObject, GetObjectAcl, GetBucketAcl,
# GetBucketPolicy, PutObject, PutObjectAcl, PutBucketPolicy, DeleteObject,
# DeleteBucket, ListBucket, ListBucketVersions, and more AWS may add later
# all matter for the SAME reason (they read, write, delete, or enumerate
# something about this bucket), and a name-by-name list can never keep up —
# this is exactly the "arbitrarily huge, still incomplete" list this
# project's own review explicitly rejected.
#
# Verb-prefix matching also naturally covers a POLICY-authored prefix
# wildcard like "s3:Get*" ("s3:get*".startswith("s3:get") is True) without
# any separate glob-matching logic.
#
# Boundary, disclosed not hidden: this also matches a small number of
# account-level actions that happen to share a verb (e.g.
# GetAccountPublicAccessBlock) — accepted as harmless in practice, since
# such an action would not realistically appear in a bucket policy's
# Action list, and the alternative (excluding it) would require an equally
# unmaintainable name-by-name exclusion list for the same reason the
# allow-list approach was rejected above. Also does not include verbs like
# Abort/Restore/Copy that don't cleanly map to read/write/delete/list of
# this bucket's own data or configuration — a deliberate, narrower scope,
# not an oversight.
_SENSITIVE_S3_ACTION_PREFIXES = ("s3:get", "s3:put", "s3:delete", "s3:list", "s3:*")
_UNIVERSAL_WILDCARD_ACTION = "*"
"""A bare "*" (as opposed to "s3:*") grants every action on every AWS
service — the single most severe possible Action value, and a second gap
found alongside the one above: the prior matcher recognized only the
s3:*-scoped wildcard, not this fully universal one."""

# AWS's own documented condition keys that can disqualify a bucket-policy
# statement from being "public", when used with a FIXED (non-wildcard)
# value. Verified against AWS S3 BPA docs during the design pass.
_DISQUALIFYING_CONDITION_KEYS = {
    "aws:PrincipalOrgID",
    "aws:SourceArn",
    "aws:SourceVpc",
    "aws:SourceVpce",
    "aws:SourceOwner",
    "aws:SourceAccount",
    "s3:DataAccessPointAccount",
}


class _Ambiguous(Exception):
    """Raised internally when a policy statement's condition can't be
    confidently classified as disqualifying or not — caught by the
    top-level evaluator and turned into InvariantStatus.UNKNOWN."""


def evaluate_s3_public_access_exposure(plan: PlanResult, bucket_address: str) -> InvariantResult:
    if plan.status != PlanStatus.PLAN_SUCCESS:
        return _unknown(bucket_address, f"plan did not succeed (status={plan.status.value})")

    bucket = _find_by_address(plan, "aws_s3_bucket", bucket_address)
    if bucket is None:
        return _unknown(bucket_address, "bucket not found in plan resource_changes")

    bucket_id = bucket.after.get("id") or bucket.after.get("bucket")
    if bucket_id is None:
        return _unknown(bucket_address, "could not resolve bucket identifier from plan")

    acl = _find_by_bucket(plan, "aws_s3_bucket_acl", bucket_id, bucket_address)
    policy = _find_by_bucket(plan, "aws_s3_bucket_policy", bucket_id, bucket_address)
    bpa = _find_by_bucket(
        plan, "aws_s3_bucket_public_access_block", bucket_id, bucket_address
    )
    ownership = _find_by_bucket(
        plan, "aws_s3_bucket_ownership_controls", bucket_id, bucket_address
    )

    evidence: dict[str, Any] = {
        "bucket_id": bucket_id,
        "acl_declared": acl is not None,
        "policy_declared": policy is not None,
        "bpa_declared": bpa is not None,
        "ownership_declared": ownership is not None,
    }

    # A plan-time-unresolved value for the actual grant content must never
    # be treated as evidence of safety — check after_unknown_keys before
    # reading the content at all, not after. Gates on "acl" only, not
    # "access_control_policy": confirmed against a real plan (configuration
    # section) that access_control_policy is a computed-only AWS API
    # response field, always listed as unknown regardless of whether the
    # user authored the canned `acl` string or an explicit grant block —
    # gating on it too made the invariant report UNKNOWN for the
    # overwhelmingly common canned-string case, including a bucket with a
    # literal, resolved `acl = "public-read"`. _acl_grants_public already
    # correctly treats an absent/unresolved access_control_policy as "no
    # explicit grants visible via that mechanism" (isinstance(..., list)),
    # which is the accurate reading when the user never authored it.
    #
    # ACL-unresolved and policy-unresolved are tracked SEPARATELY, not as a
    # single whole-bucket gate, and each side is evaluated independently
    # whenever it isn't unresolved. This is a deliberate, narrow partial
    # evaluation, not field-level JSON decomposition: a real captured plan
    # (fixtures/real_plans/, and datasets/experiments/.../case3_acl_and_policy)
    # confirmed that Terraform's `configuration.expressions.policy` collapses
    # an entire `jsonencode(...)` call into a flat `references` list with no
    # sub-key structure — there is no way to learn Principal/Effect/Action
    # independently of Resource from that source, so that approach was
    # investigated and rejected, not attempted. What IS safe: when one side
    # (e.g. a literal `acl = "public-read"`) is fully resolved and already
    # proves public exposure, an unresolved OTHER side cannot make that
    # bucket any safer — it can only mean the exposure is broader than shown.
    # An unresolved side is therefore allowed to contribute a FAIL, but is
    # NEVER treated as evidence toward PASS: `*_neutralized` is `None`
    # (not True) whenever its side is unresolved, and PASS is only reached
    # when BOTH sides are resolved and neither is neutralized-False.
    acl_unresolved = acl is not None and "acl" in acl.after_unknown_keys
    policy_unresolved = policy is not None and "policy" in policy.after_unknown_keys
    evidence["acl_unresolved_at_plan_time"] = acl_unresolved
    evidence["policy_unresolved_at_plan_time"] = policy_unresolved

    # BPA/Object-Ownership rescue checks come FIRST, before the unresolved
    # gates below, and are evaluated unconditionally. This is deliberate:
    # ignore_public_acls / BucketOwnerEnforced / restrict_public_buckets
    # neutralize their vector at the AWS enforcement layer regardless of
    # what the ACL/policy document itself says -- they don't require
    # reading that content at all. A prior version of this function checked
    # these only inside the "content is resolved" branch, so an unresolved
    # ACL or policy short-circuited straight to *_neutralized = None even
    # when one of these flags was already fully known and true. Found via
    # two real, independently-generated AI repairs that added a new,
    # unresolved policy on top of an already-BPA-locked-down bucket -- both
    # were very likely genuinely safe and were reported INCONCLUSIVE for a
    # reason that turned out to be fixable (see fixtures/real_plans/
    # s3_bpa_restrict_public_buckets_policy_unresolved_plan.json and
    # tests/invariants/test_s3_public_access.py's "BPA rescue" section).
    ignore_public_acls = _get_bool(bpa, "ignore_public_acls")
    object_ownership = _get_str(ownership, "rule", nested_key="object_ownership")
    restrict_public_buckets = _get_bool(bpa, "restrict_public_buckets")
    acl_rescued_by_bpa = object_ownership == "BucketOwnerEnforced" or ignore_public_acls is True
    policy_rescued_by_bpa = restrict_public_buckets is True

    # --- ACL side ---
    acl_neutralized: bool | None
    if acl_rescued_by_bpa:
        acl_neutralized = True
    elif acl_unresolved:
        acl_neutralized = None
    else:
        acl_grants_public = _acl_grants_public(acl)
        if acl_grants_public is None:
            # Ambiguous (redacted/unparseable), not unresolved-at-plan-time —
            # same safety treatment either way: never assume safe.
            acl_neutralized = None
        else:
            evidence["acl_grants_public"] = acl_grants_public
            # Absence of a Block Public Access / Object Ownership resource in
            # THIS config is informative, not unknown: it means this config
            # declares no such protection. (Whether an account-level BPA
            # setting outside this config might still protect the bucket is a
            # disclosed, safe-direction gap — see module docstring — never a
            # reason to return UNKNOWN here.)
            acl_neutralized = not acl_grants_public

    # --- Policy side ---
    policy_neutralized: bool | None
    if policy_rescued_by_bpa:
        policy_neutralized = True
    elif policy_unresolved:
        policy_neutralized = None
    else:
        try:
            policy_grants_public = _policy_grants_public(policy)
        except _Ambiguous:
            # Same treatment as unresolved: cannot confirm safety, but a
            # known violation on the other side still stands.
            policy_neutralized = None
        else:
            evidence["policy_grants_public"] = policy_grants_public
            policy_neutralized = not policy_grants_public

    violated: list[str] = []
    if acl_neutralized is False:
        violated.append("acl_grants_public")
    if policy_neutralized is False:
        violated.append("policy_grants_public")

    if violated:
        reason = f"bucket is publicly reachable via: {', '.join(violated)}"
        unresolved_sides = [
            label
            for label, flag in (("ACL", acl_unresolved), ("bucket policy", policy_unresolved))
            if flag
        ]
        if unresolved_sides:
            reason += (
                f" (note: {' and '.join(unresolved_sides)} content is also unresolved "
                "at plan time and was not evaluated — actual exposure may be broader "
                "than shown)"
            )
        return InvariantResult(
            invariant_id=INVARIANT_ID,
            resource_address=bucket_address,
            status=InvariantStatus.FAIL,
            violated_conditions=violated,
            reason=reason,
            evidence=evidence,
        )

    if acl_neutralized is None or policy_neutralized is None:
        unresolved_sides = [
            label
            for label, flag in (
                ("ACL", acl_neutralized is None),
                ("bucket policy", policy_neutralized is None),
            )
            if flag
        ]
        return _unknown(
            bucket_address,
            f"{' and '.join(unresolved_sides)} content could not be evaluated at plan "
            "time (known after apply), and no independent violation was found on the "
            "resolvable side(s)",
        )

    return InvariantResult(
        invariant_id=INVARIANT_ID,
        resource_address=bucket_address,
        status=InvariantStatus.PASS,
        violated_conditions=[],
        reason="no unauthenticated-reachable ACL grant or bucket-policy statement found",
        evidence=evidence,
    )


def _unknown(bucket_address: str, reason: str) -> InvariantResult:
    return InvariantResult(
        invariant_id=INVARIANT_ID,
        resource_address=bucket_address,
        status=InvariantStatus.UNKNOWN,
        violated_conditions=[],
        reason=reason,
        evidence={},
    )


def _find_by_address(
    plan: PlanResult, resource_type: str, address: str
) -> PlannedResourceChange | None:
    for rc in plan.resource_changes:
        if rc.resource_type == resource_type and rc.address == address:
            return rc
    return None


def _find_by_bucket(
    plan: PlanResult, resource_type: str, bucket_id: str, bucket_address: str
) -> PlannedResourceChange | None:
    """Correlates a dependent resource (ACL/policy/BPA/ownership) to its
    bucket. Two strategies, in order:

    1. Static reference graph (plan.raw_plan_json["configuration"]) —
       PRIMARY. Confirmed necessary against a real `terraform plan`, not
       assumed: a `create`-action plan (the only kind this project ever
       produces, since `apply` is never run) leaves a computed
       cross-reference like `bucket = aws_s3_bucket.data.id` entirely
       UNKNOWN in `after` — omitted from the resolved value, listed only
       in `after_unknown` — so a resolved-value join can never match for
       the overwhelmingly common case of referencing the bucket resource
       directly. This bug was found and fixed only once a real plan was
       produced end-to-end; every prior test used synthetic PlanResult
       objects where `after["bucket"]` was hand-set to a resolved string,
       which never exercised this failure mode. See fixtures/real_plans/
       for the real plan JSON that exposed it.
    2. Resolved-value join — FALLBACK, for the less common case of a
       literal, hardcoded bucket name string with no resource reference at
       all (nothing to look up in `configuration`).
    """
    by_reference = _find_by_bucket_reference(plan, resource_type, bucket_address)
    if by_reference is not None:
        return by_reference
    for rc in plan.resource_changes:
        if rc.resource_type != resource_type:
            continue
        if rc.after.get("bucket") == bucket_id:
            return rc
    return None


def _find_by_bucket_reference(
    plan: PlanResult, resource_type: str, bucket_address: str
) -> PlannedResourceChange | None:
    """Reads the plan's `configuration` section (unresolved expressions,
    always present regardless of whether values could be resolved) to find
    a resource of `resource_type` whose `bucket` argument references
    `bucket_address` — e.g. `expressions.bucket.references` containing
    `"aws_s3_bucket.data"` for `bucket = aws_s3_bucket.data.id`. Verified
    directly against real `terraform show -json` output, not assumed."""
    if plan.raw_plan_json is None:
        return None
    config_resources = (
        plan.raw_plan_json.get("configuration", {}).get("root_module", {}).get("resources", [])
    )
    matching_addresses: set[str] = set()
    for cfg in config_resources:
        if not isinstance(cfg, dict) or cfg.get("type") != resource_type:
            continue
        bucket_expr = cfg.get("expressions", {}).get("bucket", {})
        if not isinstance(bucket_expr, dict):
            continue
        references = bucket_expr.get("references", [])
        if isinstance(references, list) and bucket_address in references:
            address = cfg.get("address")
            if isinstance(address, str):
                matching_addresses.add(address)
    if not matching_addresses:
        return None
    for rc in plan.resource_changes:
        if rc.resource_type == resource_type and rc.address in matching_addresses:
            return rc
    return None


def _get_bool(rc: PlannedResourceChange | None, key: str) -> bool | None:
    if rc is None:
        return None
    value = rc.after.get(key)
    return value if isinstance(value, bool) else None


def _get_str(rc: PlannedResourceChange | None, key: str, *, nested_key: str) -> str | None:
    """Reads e.g. after["rule"][0]["object_ownership"] for
    aws_s3_bucket_ownership_controls, which nests `rule` as a block list."""
    if rc is None:
        return None
    rules = rc.after.get(key)
    if not isinstance(rules, list) or not rules:
        return None
    value = rules[0].get(nested_key) if isinstance(rules[0], dict) else None
    return value if isinstance(value, str) else None


def _acl_grants_public(acl: PlannedResourceChange | None) -> bool | None:
    """Returns None (ambiguous -> UNKNOWN) only if the ACL resource exists
    but its content can't be read; a bucket with no ACL resource at all is
    NOT ambiguous — it simply grants nothing."""
    if acl is None:
        return False

    canned = acl.after.get("acl")
    if isinstance(canned, str) and canned in _PUBLIC_CANNED_ACLS:
        return True
    # A recognized, non-public canned ACL (or none at all) — still need to
    # check for explicit grant blocks below in case one is present.

    policy_block = acl.after.get("access_control_policy")
    if isinstance(policy_block, list) and policy_block:
        grants = policy_block[0].get("grant") if isinstance(policy_block[0], dict) else None
        if isinstance(grants, list):
            for grant in grants:
                if not isinstance(grant, dict):
                    continue
                grantee = grant.get("grantee")
                grantee_list = grantee if isinstance(grantee, list) else [grantee]
                for g in grantee_list:
                    if isinstance(g, dict) and g.get("uri") in _PUBLIC_ACL_GRANTEE_URIS:
                        return True

    if isinstance(canned, str):
        return canned in _PUBLIC_CANNED_ACLS
    return False


def _policy_grants_public(policy: PlannedResourceChange | None) -> bool:
    if policy is None:
        return False

    raw = policy.after.get("policy")
    if not isinstance(raw, str):
        raise _Ambiguous("bucket policy value is missing or not a plain string (possibly redacted)")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _Ambiguous(f"bucket policy is not valid JSON: {exc}") from exc

    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue
        if "NotPrincipal" in statement:
            continue
        if not _principal_is_wildcard(statement.get("Principal")):
            continue
        if not _action_is_sensitive(statement.get("Action")):
            continue
        if _statement_disqualified_by_condition(statement.get("Condition")):
            continue
        return True
    return False


def _principal_is_wildcard(principal: Any) -> bool:
    """True if "*" is granted at all — including a multi-element AWS
    principal array that contains "*" alongside named principals. Under
    IAM's OR semantics for array-valued principals, a single "*" entry is
    sufficient to grant to everyone regardless of what else is listed."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws_val = principal.get("AWS")
        if aws_val == "*":
            return True
        if isinstance(aws_val, list) and "*" in aws_val:
            return True
    return False


def _action_is_sensitive(action: Any) -> bool:
    """Case-insensitive: AWS service/action name prefixes are not
    guaranteed distinct by case alone, and matching only the conventional
    lowercase form would miss an accidentally- or deliberately-recased
    action string. See _SENSITIVE_S3_ACTION_PREFIXES for what "sensitive"
    means here and why verb-prefix matching, not name enumeration, is the
    correct strategy for this invariant's threat model."""
    actions = action if isinstance(action, list) else [action]
    lower_prefixes = tuple(p.lower() for p in _SENSITIVE_S3_ACTION_PREFIXES)
    return any(
        isinstance(a, str)
        and (a.lower().startswith(lower_prefixes) or a == _UNIVERSAL_WILDCARD_ACTION)
        for a in actions
    )


def _statement_disqualified_by_condition(condition: Any) -> bool:
    """True if every condition block present uses a recognized disqualifying
    key with a fixed (non-wildcard) value. Raises _Ambiguous for anything
    this function can't confidently classify — never silently treated as
    either disqualifying or non-disqualifying."""
    if condition is None:
        return False
    if not isinstance(condition, dict):
        raise _Ambiguous("bucket policy Condition block has an unrecognized shape")

    # A key from the disqualifying list whose value turns out to be
    # wildcarded (or an IP range that isn't narrow) is a CONFIDENT "does not
    # disqualify" per AWS's own documented example (a Principal:* statement
    # conditioned on aws:SourceVpc="vpc-*" is explicitly still public) — not
    # ambiguous. Only a genuinely unrecognized key/shape is ambiguous, since
    # this function can't reason about semantics it doesn't know at all.
    disqualified = False
    for operator, kv in condition.items():
        if not isinstance(kv, dict):
            raise _Ambiguous(f"unrecognized Condition operator shape under {operator!r}")
        for key, value in kv.items():
            if key == "aws:SourceIp":
                if _cidr_is_narrow(value):
                    disqualified = True
                continue
            if key not in _DISQUALIFYING_CONDITION_KEYS:
                msg = f"unrecognized condition key {key!r}, not in the disqualifying list"
                raise _Ambiguous(msg)
            if _value_is_fixed(value):
                disqualified = True
    return disqualified


def _value_is_fixed(value: Any) -> bool:
    values = value if isinstance(value, list) else [value]
    return all(isinstance(v, str) and "*" not in v and "?" not in v for v in values)


def _cidr_is_narrow(value: Any) -> bool:
    values = value if isinstance(value, list) else [value]
    for v in values:
        if not isinstance(v, str):
            return False
        try:
            network = ipaddress.ip_network(v, strict=False)
        except ValueError:
            return False
        if network.version == 4 and network.prefixlen < 8:
            return False
        if network.version == 6 and network.prefixlen < 32:
            return False
    return True
