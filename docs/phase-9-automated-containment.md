# Phase 9 — Automated Containment

**Date:** 2026-08-16
**Objective:** Turn the Phase 8 handler from observer into responder, for
exactly one known finding type against exactly one known resource — not
"any HIGH finding → act."
**Status:** Complete. Since extended to recognize a second,
independently-verified trigger family (the Config-backed "block public
access" standards controls) and to notify a human on every actionable
outcome — see §11.
**Depends on:** [Phase 8 — The Incident Handler](phase-8-incident-handler.md),
[Phase 6 — Incident #2 (insecure S3 configuration)](phase-6-incident-02.md)

Handler: [lambda/incident_containment/containment_handler.py](../lambda/incident_containment/containment_handler.py).
Tests: [lambda/tests/test_containment_handler.py](../lambda/tests/test_containment_handler.py).
Terraform: [terraform/response/containment_lambda.tf](../terraform/response/containment_lambda.tf),
[terraform/response/containment_eventbridge.tf](../terraform/response/containment_eventbridge.tf).
Self-test: [detections/test-automated-containment.ps1](../detections/test-automated-containment.ps1).

---

## 1. The scope decision

Phase 7's "Next phase" note and the Phase 8 backlog item both described this
the same loose way: act on a finding instead of just logging it. Read
literally, the easiest version is "every HIGH/CRITICAL finding the alert
Lambda already sees → try to fix it." That's also the version that turns one
Lambda into the single most dangerous thing in the account — a function with
standing write access to an unbounded set of resources, triggered by
whatever Security Hub happens to import next.

This phase is deliberately the opposite shape:

```
known finding type  +  known lab resource  +  approved remediation  →  Lambda
```

Each of those three is a hard boundary, not a convention:

- **Known finding type(s)** — originally one ASFF `Types` value,
  `TTPs/Policy:S3-BucketAnonymousAccessGranted`. This is GuardDuty's native
  `Policy:S3/BucketAnonymousAccessGranted` as it actually renders once
  imported into Security Hub — verified against a real finding already
  present in this account, not guessed from documentation. The `/` inside
  `Policy:S3` becomes `-`, and the whole type is namespaced under `TTPs/`.
  §11 adds a second, independent match path (`Compliance.SecurityControlId`)
  for AWS Config-backed standards findings — a different ASFF field
  entirely, since GuardDuty and Security Hub's own standards controls
  identify "which thing fired" differently. Both paths are held to the same
  rule: nothing gets added without first being verified against a real
  finding, synthetic or live.
- **Known lab resource** — an explicit bucket-ARN allowlist
  (`containable_resource_arns`), defaulting to this lab's own INC-02 exercise
  bucket. Not a prefix. A finding against a bucket not on this exact list is
  logged and skipped, never acted on. This allowlist is shared by both
  trigger paths.
- **Approved remediation** — one idempotent call,
  `s3:PutBucketPublicAccessBlock` with all four settings `true`. Not a
  policy rewrite, not a delete, nothing that can destroy data. It restores
  the specific control Phase 6 hardened and these finding types report as
  missing — nothing more. §11's second trigger path deliberately reuses
  this exact same action rather than introducing a new one: `S3.1`, `S3.3`,
  and `S3.8` all check different facets of the same
  `PublicAccessBlockConfiguration` this call already sets, so widening *what
  triggers it* did not require widening *what it does* — a genuinely
  different proposition (a per-control remediation map) was considered and
  deliberately not built, since most other S3 controls (logging, TLS,
  cross-account policy) need distinct, unrelated actions that would each
  need their own verification and their own new IAM grant.

---

## 2. Architecture

As of §11, three EventBridge rules feed two Lambdas — still never a branch
inside an existing rule:

```
GuardDuty finding          AWS Config evaluation (S3-scoped)
      │                              │
      ▼                              ▼
Security Hub (import) ◄──────────────┘
      │
      ├───────────────────┬──────────────────────┐
      ▼                   ▼                       ▼
 alert rule         containment rule       standards containment rule
 (HIGH/CRITICAL,     (GuardDuty Types       (Compliance.SecurityControlId
  any type)           match only)            in {S3.1,S3.2,S3.3,S3.8})
      │                   │                       │
      ▼                   └───────────┬───────────┘
 incident_handler.py                  ▼
 (Phase 7/8 — logs,          containment_handler.py
  §11: + SNS notify)        (Phase 9 — examine → act,
                              §11: + SNS notify)
                                       │
                                ┌──────┴──────┐
                                ▼             ▼
                         allow-listed?   AUTO_CONTAIN_ENABLED?
                                │             │
                                └──────┬──────┘
                                       ▼ (only if both yes)
                           s3:PutBucketPublicAccessBlock
                                       │
                                       ▼
                             structured log line
                            (every branch, always)
                                       │
                                       ▼
                              SNS (§11 — the four
                              actionable outcomes)
```

The alert rule stays broad on purpose — it only logs (and, since §11,
notifies), so a wide net costs nothing. Both containment rules are scoped
down to exactly what this Lambda is built to act on — one via `Types`, one
via `Compliance.SecurityControlId`, since Security Hub identifies "which
thing fired" differently depending on whether a finding came from GuardDuty
or from a Config-backed standards control. The Lambda re-checks both match
conditions in code — defense in depth, same reasoning as the severity
re-filter in `incident_handler.py` (Phase 7 §3) — but a finding matching
neither rule never even reaches this Lambda's invocation count, which is a
stronger guarantee than a code-level check that could have a bug in it.

---

## 3. Two independent gates, not one

`enable_auto_containment` (a boolean) and `containable_resource_arns` (an
allowlist) are deliberately separate Terraform variables rather than one
combined "is this safe" flag:

| `enable_auto_containment` | `containable_resource_arns` | Result |
| --- | --- | --- |
| `false` | anything | Every check runs, every decision is logged, no API call is ever made |
| `true` | `[]` | The role has **no S3 permissions at all** (see §4) — physically cannot act on anything |
| `true` | `[bucket-arn]` | Acts only on that bucket, only for a known finding type |

Either gate alone being restrictive is not enough by design — both must agree
before anything is touched. The default is `false` / the lab's own INC-02
bucket, so a fresh `terraform apply` deploys in dry-run mode: the function
runs on every matching finding, examines the real resource, and logs exactly
what it *would* do, with no mutating call made. The intended operator
sequence is: deploy with the switch off, review a few
`would_contain_but_disabled` log lines, and only then flip
`enable_auto_containment = true` in `terraform.tfvars`.

---

## 4. IAM: the only write permission in the lab

Every other identity in this repo either reads, or writes only through
Terraform's own execution. `aws_iam_role.containment` is the one exception,
and its policy is scoped as tightly as the job allows:

```hcl
actions   = ["s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"]
resources = local.containable_resource_arns   # exact ARNs, never a wildcard
```

Worth stating explicitly: these are the real IAM action names, with
"Bucket" in them. The equivalent boto3/botocore *client method* names
(`get_public_access_block` / `put_public_access_block`) omit it — an easy,
invisible mismatch to introduce, since nothing catches a wrong action name
at plan time or deploy time, only at the moment a real request is evaluated
against the policy.

§11 adds one more, unrelated permission to this same role: `sns:Publish`,
scoped to exactly one topic ARN (`terraform/response/notifications.tf`) —
the first write permission this role holds that isn't an S3 call, needed so
it can notify a human on its own decisions rather than only logging them.

Three details worth calling out:

- **`GetBucketPublicAccessBlock` is granted alongside
  `PutBucketPublicAccessBlock`.** The handler's "examine resource" step
  (see the flow diagram above) calls `get_public_access_block` before ever
  considering a write, so a re-delivered EventBridge event (at-least-once
  delivery) produces `already_contained` instead of a second,
  indistinguishable `contained` log line. Without the read permission, that
  idempotency check itself would fail closed in the wrong way — as
  `examine_failed`, not as a clean skip.
- **The policy document has `count = length(...) > 0 ? 1 : 0`.** If an
  operator sets `containable_resource_arns = []`, the role gets *no S3
  statement attached at all*, not a policy with an empty `resources` list.
  Some providers reject an empty resource list outright, and an empty list
  is a confusing way to represent "nothing is allowed" even when accepted —
  no permissions attached is the unambiguous version.
- **The `sns:Publish` grant is scoped to one exact topic ARN, never a
  wildcard** — same posture as every other permission this role holds. It
  cannot publish to any topic but the one this stack created.

---

## 5. What the handler actually checks, in order

`_handle_one()` in `containment_handler.py` runs five checks per finding,
every one of them logged regardless of outcome:

1. **Type match** — `finding.Types` intersects `CONTAINABLE_FINDING_TYPES`
   **or** `finding.Compliance.SecurityControlId` is in
   `CONTAINABLE_SECURITY_CONTROL_IDS` (§11). Either is sufficient; this is
   two independent trigger families sharing one decision pipeline, not one
   family with an extra condition bolted on. Fails both → `skipped_unknown_type`.
2. **Resource present** — the finding carries an `AwsS3Bucket` resource.
   Deliberately *not* `Resources[0]`: a real GuardDuty S3 finding in this
   account lists the IAM principal that made the API call before the
   affected bucket, so indexing `[0]` would silently act on whichever
   resource happened to be listed first. Missing → `skipped_no_s3_resource`.
3. **Resource allow-listed** — the bucket ARN is in
   `CONTAINABLE_RESOURCE_ARNS`, checked as exact membership. Fails →
   `skipped_resource_not_allowlisted`.
4. **Already contained?** — `get_public_access_block` on the real bucket.
   All four settings already `true` → `already_contained`, no write
   attempted. This is also what makes a duplicate EventBridge delivery safe.
5. **Switch check** — `AUTO_CONTAIN_ENABLED`. Off → logs
   `would_contain_but_disabled` and stops. On → calls
   `put_public_access_block` with all four settings `true`, then logs
   `contained`.

Every branch, including the five skip/no-op outcomes, writes one structured
JSON line via `LOG.warning()` — finding ID, matched types, bucket ARN, the
live value of `AUTO_CONTAIN_ENABLED`, and a free-text detail. A containment
function that stays silent when it decides *not* to act is unauditable on
exactly the occasions that matter most for reviewing whether its judgment
was right — so every path through `_handle_one()` is equally visible in
CloudWatch Logs, not just the one that calls a mutating API.

§11 adds one more step after that log line, for four of these outcomes only
— `contained`, `would_contain_but_disabled`, `contain_failed`, and
`examine_failed` — an SNS publish to a human. The three `skipped_*` outcomes
and `already_contained` deliberately do not notify: those happen on every
finding Security Hub imports that isn't relevant here or that needed no
change, and paging a human for "nothing to see" would bury the outcomes
actually worth reading.

The handler never raises: every failure mode (a malformed finding, an S3 API
error on either the read or the write, or — since §11 — an SNS publish
failure) is caught, logged as its own named action (`examine_failed`,
`contain_failed`, `notify_failed`), and returned or continued past
per-finding, so one bad record in a batch can't take the rest of the batch
down with it, and a failed notification can never turn an already-decided
containment outcome into a crashed invocation.

An error is matched on its string error *code* (`exc.response["Error"]["Code"]`)
rather than a dynamically-generated exception class
(`_s3_client().exceptions.X`) — the string code is part of the AWS API
contract and stable across botocore versions; the generated exception
classes are not guaranteed to exist on every version bundled with a given
Lambda runtime. Matching on the stable thing avoids a fragile, hard-to-spot
dependency on exactly which botocore version happens to be deployed.

---

## 6. Delivery guarantees

Same DLQ pattern as the alert rule (Phase 7 §4), on its own queue:

```hcl
retry_policy {
  maximum_event_age_in_seconds = 3600
  maximum_retry_attempts       = 3
}
dead_letter_config {
  arn = aws_sqs_queue.containment_dlq.arn
}
```

A dropped containment event is a worse outcome here than a dropped alert
log line — it means a real exposure went uncontained with no record of why —
so the same three retries plus dead-letter-on-exhaustion applies, into a
dedicated `cloudsec-lab-s3-containment-dlq` rather than sharing the alert
Lambda's queue. A message landing there is always worth investigating; it
should be empty in steady state.

This queue covers EventBridge failing to *invoke* the Lambda at all. A
separate, function-level `dead_letter_config` on the Lambda resource itself
(sharing this same queue) covers the other failure mode — the function
being invoked successfully but erroring out after its own retries are
exhausted — which is a distinct path EventBridge's rule-level DLQ cannot
see, since from EventBridge's point of view the invocation succeeded.

---

## 7. Deployment

```hcl
# versions.tf
Phase = "7-9" # alerting (7), field extraction (8), containment (9)
```

Applied against the already-live `terraform/response/` stack — new resources
added alongside the existing alert pipeline, nothing in it touched. Current
live settings, read back via `terraform output`:

```
auto_containment_enabled         = true
containable_finding_types        = ["TTPs/Policy:S3-BucketAnonymousAccessGranted"]
containable_resource_arns        = ["arn:aws:s3:::cloudsec-lab-incident-02-<account-id>"]
containable_security_control_ids = ["S3.1", "S3.2", "S3.3", "S3.8"]
security_alerts_topic_arn        = "arn:aws:sns:us-east-1:<account-id>:cloudsec-lab-security-alerts"
```

`enable_auto_containment` stayed off through the initial deploy, and was
turned on only after each trigger path was independently verified — see
§11. §11 added these resources alongside what this phase originally
deployed, again without touching anything already there:

```
+ aws_cloudwatch_event_rule.s3_standards_containment[0]
+ aws_cloudwatch_event_target.containment_lambda_standards[0]
+ aws_lambda_permission.allow_eventbridge_containment_standards[0]
+ aws_sns_topic.security_alerts
+ aws_sns_topic_subscription.email
+ aws_iam_role_policy.containment_notify
+ aws_iam_role_policy.alert_notify
```

---

## 8. Testing

`lambda/tests/test_containment_handler.py` — originally 14 tests, independent
of any deployment (mocked S3 client, no network calls, the fake raising a
real `botocore.exceptions.ClientError` rather than a hand-rolled stand-in,
so a test asserting error handling actually proves it against the real
exception shape): the three skip conditions (unknown type, no S3 resource,
resource not allow-listed), the `Resources[0]`-is-not-assumed-to-be-the-bucket
regression case, the already-blocked no-op, examine/contain failure
handling, the disabled-switch path making no API call, the enabled path
calling `put_public_access_block` with all four settings, multi-finding
independence, and that every branch logs valid JSON. §11 added a fake SNS
client (same real-exception discipline) and cases covering the
`SecurityControlId` match path and that notification fires on exactly the
four actionable outcomes, never on a skip. `test_incident_handler.py`
(Phase 7/8's alert handler) gained the equivalent notify coverage for its
own, simpler, un-gated notify path. Combined suite, all passing:

```
$ python -m pytest lambda/tests/ -q
................................................                          [100%]
48 passed in 0.51s
```

[`detections/test-automated-containment.ps1`](../detections/test-automated-containment.ps1)
is the end-to-end counterpart, exercising the real path — a genuine
`PutPublicAccessBlock` precondition, a synthetic `BatchImportFindings`
finding, and a real wait on CloudWatch Logs — in three scenarios:

- **`Contain`** (default) — flips Block Public Access off on the real
  allow-listed bucket, imports a finding matching both the known type and
  the known resource, and verifies against the live S3 API that the Lambda
  restored it (or, with the switch off, that it correctly did *not* touch
  the bucket and logged the dry-run line instead).
- **`WrongResource`** — same finding type, against a bucket ARN that isn't
  on the allowlist. Proves the resource check, not just the type check.
- **`WrongType`** — the real bucket, but a finding type the EventBridge rule
  doesn't match. Expects *no invocation at all* — proves the rule itself is
  the first line of defense, not only the Lambda's internal logic.

---

## 9. Cost

- Containment Lambda: same free-tier math as the alert Lambda (Phase 7 §6) —
  $0.00 at lab invocation volume.
- One additional CloudWatch log group, 14-day retention: negligible.
- One additional SQS queue: free tier covers this volume indefinitely.
- No new always-on compute. The only resource this phase can ever modify
  (the INC-02 bucket's public access block) is a metadata flag, not billed
  storage or compute.
- §11's SNS topic: email delivery is free at any volume this lab produces
  (SNS's free tier is 1,000 email notifications/month, permanently, not a
  trial). The only recurring cost this phase added at all is whatever
  [Phase 4 §6](phase-4-detection-services.md#6-cost) already attributes to
  AWS Config, which §11's trigger depends on but which was turned on as part
  of [Incident 02's own remediation](../incidents/incident-02-s3.md#9-remediation-items),
  not by this phase.

---

## 10. Teardown

No separate teardown. `terraform destroy` in `terraform/response/` (Phase 7
§9) removes the containment Lambda, its role, its EventBridge rules, and its
DLQ along with everything else in that stack. If a `Contain`-scenario test
run is ever interrupted with `enable_auto_containment = false`, the INC-02
bucket is left with Block Public Access off until either the switch is
turned on and the rule re-fires, or it's restored manually:

```powershell
aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration `
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

---

## 11. Extension — a second trigger family, and notification

This phase closed two gaps that had sat open since it was first built: the
containment Lambda could only ever react to one GuardDuty finding type, and
nothing in this entire lab — alerting or containment — ever reached a human
directly. Both are closed here, without touching the narrow-by-design shape
§1 established.

### Where the second trigger came from

[Incident 02's own remediation items](../incidents/incident-02-s3.md#9-remediation-items)
had an open line: decide on AWS Config. Turning it on (scoped to
`AWS::S3::Bucket` only — [Phase 4 §6](phase-4-detection-services.md#6-cost))
gave Security Hub's standards controls something real to evaluate against for
the first time, and re-exposing the Incident 02 bucket produced a genuine,
live `S3.2` finding — not a synthetic one. That real finding is what
`containable_security_control_ids` is built from, the same discipline §1
used for the GuardDuty `Types` string: verified against something actually
observed in this account, never guessed from a control's name or
documentation.

### Why `S3.1`/`S3.3`/`S3.8` joined `S3.2`, and how each was verified

All four controls check different facets of the exact same
`PublicAccessBlockConfiguration` this Lambda's one remediation action
already sets — confirmed directly against AWS's own control catalog
(`aws securityhub describe-standards-controls`), not assumed from similar-
sounding names. That makes widening the *trigger* to all four safe without
widening the *action* at all.

Only `S3.2` was ever observed failing live. The other three were verified a
different, deliberately safer way: with the bucket's policy fully hardened
first (so no real public exposure was possible), `PutPublicAccessBlock` was
flipped off directly via the API, and a synthetic finding for each control
was injected via `securityhub batch-import-findings` — the same technique
`detections/test-*.ps1` already use to prove a code path without staging a
real attack. Each one produced a genuine `contained` log line and a real,
independently-verified `PutPublicAccessBlock` call. `S3.3` ("block public
write") specifically could not have been verified any other way: this lab's
own safety rules ([`terraform/incident-02/variables.tf`](../terraform/incident-02/variables.tf))
refuse to ever grant real public write access, since an openly writable
bucket is a genuine abuse and cost vector, not just a confidentiality one —
so its trigger condition is synthetic-verified by design, while its
remediation action is the same one already proven against `S3.2` and
`S3.1`.

The other seven controls in this standard's S3 family (`S3.5`, `S3.6`,
`S3.9`, `S3.12`, `S3.13`, `S3.19`, `S3.25`) are deliberately **not**
included — see "Next phase" below for why each would need its own,
separately-verified remediation action rather than reusing this one.

### Why two EventBridge rules, not one wider pattern

Security Hub identifies which control fired through two different ASFF
fields depending on the source: GuardDuty findings use `Types`; Config-
backed standards findings use `Compliance.SecurityControlId`. Matching both
in a single EventBridge rule would need an `$or` across two unrelated
fields; two small, separately-auditable rules pointed at the same Lambda
(§2) were simpler and kept each rule's own match condition legible on its
own, the same reasoning §2 already gave for not branching inside the alert
rule.

### Notification: the piece this pipeline was missing

Through this phase's original build, this entire pipeline only ever logged
— a human had to go looking in CloudWatch Logs to learn anything at all.
Both Lambdas now publish to one shared SNS topic
(`terraform/response/notifications.tf`): the containment handler on its
four actionable outcomes (§5), and the alert handler (Phase 7/8) on every
HIGH/CRITICAL finding it already logs, with no further gating of its own —
covering, deliberately, finding types that have no automated remedy at all,
such as Incident 01's denied-`iam:CreateAccessKey` pattern, if a detector
for it is ever built. "Notify a human" is treated as a complete, correct
response in its own right, not a placeholder for a future automated one.

### Verification

End to end, against the real account: AWS Config enabled and confirmed
recording (`AWS::S3::Bucket` only); a real `S3.2` finding observed, matched,
and contained; `S3.1`/`S3.3`/`S3.8` each verified via synthetic finding and
a real, confirmed `PutPublicAccessBlock` call; the bucket's final state
independently re-checked via `get-public-access-block` and a live anonymous
`curl` returning `403`, not just trusted from a log line; SNS delivery
confirmed via `AWS/SNS` CloudWatch metrics (`NumberOfNotificationsDelivered`
> 0, `NumberOfNotificationsFailed` = 0 across the entire test window) rather
than assumed from the absence of a `notify_failed` log line alone. Full
`lambda/tests/` suite green at 48/48 (§8).

---

## Next phase

The containment Lambda now acts on two independently-verified trigger
families (GuardDuty's anonymous-access finding, and the Config-backed
`S3.1`/`S3.2`/`S3.3`/`S3.8` "block public access" family) against exactly
one resource, and notifies a human on every actionable outcome — see §11.
The backlog items in [detections/README.md](../detections/README.md#backlog)
— a CloudTrail-driven rule that doesn't depend on Security Hub, denied-IAM-
action detectors, root account usage — are all still open, and none of them
currently has a containment path the way this phase's S3 findings do.

Two deliberate limits remain, not accidents:

- **Still one bucket.** Nothing here generalizes to "any bucket with this
  problem" — `containable_resource_arns` is still an explicit allowlist.
- **Still one remediation action.** The seven other S3 standards controls
  (`S3.5`, `S3.6`, `S3.9`, `S3.12`, `S3.13`, `S3.19`, `S3.25` — see §11) each
  need a genuinely different, unverified API call. Extending coverage to any
  of them means adding a new explicit match condition *and* a new,
  independently-verified remediation branch — never widening the existing
  action to cover a problem it doesn't actually fix, for the same reason
  this phase rejected "any HIGH finding → act" on day one.
