# Event-Source Security

A practitioner's reference for securing the event sources that trigger serverless workloads — SNS, SQS, EventBridge on AWS; Event Grid, Service Bus on Azure; Pub/Sub on GCP. The patterns here cover event-source resource policies, the cross-account event-source patterns, the "who can invoke this function" inventory problem, and the event-replay / dead-letter / poison-message patterns that affect both reliability and security.

This document covers the underweighted control in serverless security. Most teams audit the function IAM role and the API Gateway carefully; the event source (the SNS topic, the SQS queue, the EventBridge bus) gets the default resource policy and never gets revisited. A permissive event-source policy lets unintended principals invoke the function — which means the function's IAM role runs with attacker-controlled inputs.

For function IAM, see [lambda-functions-security.md](./lambda-functions-security.md) and [serverless-iam-patterns.md](./serverless-iam-patterns.md). For API Gateway specifically (one type of event source), see [api-gateway-security.md](./api-gateway-security.md).

---

## When to read this document

**If you operate Lambda / Functions / Cloud Functions and aren't sure what's invoking them** — read top to bottom.

**If you've found "who can call this function" hard to answer** — start with [The invoke-inventory problem](#the-invoke-inventory-problem).

**If you have cross-account event sources** — start with [Cross-account event patterns](#cross-account-event-patterns).

**If you are auditing event-source posture** — start with [Findings checklist](#findings-checklist).

---

## What an event source is

Anything that triggers a serverless function:

- **API Gateway:** HTTP requests reaching the function.
- **SNS:** Topic publication invokes subscribed functions.
- **SQS:** Queue message invokes the polling function.
- **EventBridge:** Rule match invokes the target function.
- **S3 Events:** Bucket events (PutObject, DeleteObject) invoke configured functions.
- **DynamoDB Streams:** Table changes invoke stream-processing functions.
- **CloudWatch / EventBridge Scheduled:** Time-based invocation.
- **Function URLs:** Direct HTTPS endpoint.
- **Custom invocation:** Other services calling `Lambda:Invoke` directly.

Each event source has its own policy model; each is a potential vector.

---

## The invoke-inventory problem

The basic question: "what can invoke this function?"

### Why it's hard to answer

For a given Lambda function:

- Event-source mappings (SNS / SQS / DynamoDB Streams / Kinesis) configured at the function level.
- EventBridge rules configured separately; the rule references the function as a target.
- API Gateway integrations configured separately; the gateway integrates with the function.
- S3 bucket event notifications configured at the bucket level.
- Direct `Lambda:Invoke` permission configured via the function's resource policy.
- Cross-account access via the function's resource policy.

There's no single query that returns "everything that can invoke this function." Each event-source type has its own configuration location.

### The inventory query

For each function, the inventory query needs to check:

```bash
# Event source mappings (SNS, SQS, DynamoDB, Kinesis)
aws lambda list-event-source-mappings --function-name FUNCTION

# Resource policy (who can call Lambda:Invoke directly)
aws lambda get-policy --function-name FUNCTION

# EventBridge rules targeting the function
aws events list-rule-names-by-target --target-arn arn:aws:lambda:...:function:FUNCTION

# API Gateway integrations
aws apigateway get-rest-apis  # then list integrations for each

# S3 bucket notifications
aws s3api get-bucket-notification-configuration --bucket BUCKET  # per bucket

# CloudWatch Logs subscription
aws logs describe-subscription-filters --destination-arn arn:aws:lambda:...:function:FUNCTION
```

Most CSPMs do this aggregation. Without a CSPM: a custom script that walks the configurations.

### The inventory output

For each function, an annotated list:

```
care-coordinator-event-processor:
  Event sources:
    - SQS: care-coordinator-events-queue (from same account)
    - EventBridge rule: clinical-events-rule (from same account)
    - API Gateway: /api/v1/coordination (via integration)
  Direct invokers (resource policy):
    - arn:aws:iam::ANALYTICS-ACCOUNT:role/analytics-job
  Cross-account:
    - One cross-account invoke from ANALYTICS account
```

Once the inventory exists, audit each line: is the invoker expected? authorized?

---

## SNS topic security

SNS topics fan out events to subscribers (including Lambda functions).

### The topic resource policy

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "s3.amazonaws.com"},
    "Action": "sns:Publish",
    "Resource": "arn:aws:sns:us-east-1:ACCOUNT:care-coordinator-events",
    "Condition": {
      "ArnLike": {"aws:SourceArn": "arn:aws:s3:::meridian-care-coordinator-prod-data"}
    }
  }, {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/care-coordinator-publisher-role"},
    "Action": "sns:Publish",
    "Resource": "arn:aws:sns:us-east-1:ACCOUNT:care-coordinator-events"
  }]
}
```

The policy specifies who can publish. The `SourceArn` condition prevents confused-deputy via S3.

### Common SNS anti-patterns

**The wildcard publisher:** `Principal: "*"` with no `Condition`. Anyone in any account can publish.

**The over-broad SourceAccount:** `Condition.StringEquals: aws:SourceAccount: "*"` (any account).

**The missing condition on cross-service triggers:** S3 sends to SNS; SNS doesn't verify the source bucket. An attacker with permission to send via S3 can trigger any subscribed function.

### Subscription filter

Subscribers can filter messages:

```yaml
subscription_filter:
  event_type:
    - care_coordination_started
    - care_coordination_updated
```

Only matching events reach the subscriber. Useful for noise reduction; also a security control (function only processes specific event types).

### Encryption

- **At rest:** SNS topics encrypt-at-rest with KMS. Use CMK for sensitive topics.
- **In transit:** SNS uses TLS by default; verify subscriber endpoints use HTTPS.

---

## SQS queue security

SQS queues are pulled by consumers (often Lambda).

### The queue resource policy

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/care-coordinator-publisher-role"},
    "Action": "sqs:SendMessage",
    "Resource": "arn:aws:sqs:us-east-1:ACCOUNT:care-coordinator-events-queue"
  }, {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/care-coordinator-consumer-role"},
    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
    "Resource": "arn:aws:sqs:us-east-1:ACCOUNT:care-coordinator-events-queue"
  }]
}
```

Distinct senders and consumers; each with specific actions.

### Dead-letter queue

DLQ for messages the function fails to process after N retries:

```yaml
RedrivePolicy:
  deadLetterTargetArn: arn:aws:sqs:us-east-1:ACCOUNT:care-coordinator-dlq
  maxReceiveCount: 3
```

After 3 failures, the message moves to DLQ. The DLQ has its own policy; access controlled.

### Poison-message handling

A message that consistently fails:

- Lambda invocation fails (exception).
- SQS marks the message visible again.
- Lambda fails again.
- After `maxReceiveCount`, message moves to DLQ.

The DLQ is monitored:

- Volume spike = investigation.
- Specific failing message = inspection (could be malformed input, malicious payload, or bug).

### Encryption

Like SNS: CMK encryption for sensitive queues.

---

## EventBridge security

EventBridge (formerly CloudWatch Events) routes events from many sources to many targets.

### Bus security

EventBridge has buses (default + custom). The bus resource policy controls who can put events:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT:root"},
    "Action": "events:PutEvents",
    "Resource": "arn:aws:events:us-east-1:ACCOUNT:event-bus/care-coordinator-bus"
  }]
}
```

For cross-account: explicit grants per other account.

### Rule security

Rules match events on patterns; invoke targets:

```yaml
rules:
  - name: clinical-event-rule
    event_pattern:
      source: ["care-coordinator"]
      detail-type: ["clinical_event"]
    targets:
      - arn: arn:aws:lambda:us-east-1:ACCOUNT:function:care-coordinator-clinical-processor
        role_arn: arn:aws:iam::ACCOUNT:role/eventbridge-invoke-lambda-role
```

The role specified for invocation needs `lambda:InvokeFunction` on the target. EventBridge uses this role; the target Lambda's role is what runs.

### EventBridge schema discovery

EventBridge can discover schemas for events. Useful for validation; ensure schemas are versioned.

### Anti-patterns

- **Default bus accepts any event from the account.** Custom bus for specific event types.
- **Rules with broad patterns** match more events than expected; target Lambda invoked unnecessarily.
- **Cross-account rules without verification:** the source-account check should be in the pattern.

---

## Cross-account event patterns

For events flowing between accounts.

### The pattern

Account A produces events; Account B consumes:

- Account A's bus has a rule with Account B's bus as the target.
- Account B's bus accepts events from Account A.
- Account B's rules route events to Lambda / SQS / etc.

### The authorization

- Account B's bus resource policy explicitly grants Account A.
- Account A's rule has permissions to put events on Account B's bus.
- Both layers enforced.

### The audit-trail

- Account A's CloudTrail: shows the rule firing.
- Account B's CloudTrail: shows the event landing on the bus.
- Cross-account correlation via SIEM.

### Common failure modes

- **Account B accepts events from "any account":** broader than intended.
- **Account A's rule sends to wrong account:** misconfigured target ARN.
- **Filtering not applied:** all events from Account A land on Account B's bus.

---

## The "who can invoke" inventory pattern

Operational discipline for ongoing visibility.

### Per-function inventory

Per the [The invoke-inventory problem](#the-invoke-inventory-problem) section. Run quarterly; per-function audit.

### Per-event-source inventory

For each event source (topic, queue, bus):

- Who can publish?
- What's subscribed / what's the target?
- Is the policy current?

### CSPM-driven inventory

Modern CSPMs (Wiz, Lacework, etc.) aggregate this. The pattern:

- Per-function inventory shown in the CSPM.
- Findings on overly-broad policies.
- Findings on unattended event sources.

For teams without a CSPM: scripted inventory; quarterly review.

### The "no orphan event source" baseline

Event sources without subscribers (orphan topics, queues with no consumer) accumulate. They have policies that might allow unintended publishing. Cleanup:

- Quarterly: list event sources with no active subscribers / consumers in N days.
- Verify with workload owner; decommission.

---

## Encryption for events

Events in transit and at rest.

### In transit

- All cloud-native event services use TLS in transit.
- Webhook subscriptions verify HTTPS.

### At rest

- SNS, SQS, EventBridge, Service Bus, Pub/Sub support encryption at rest.
- For sensitive events (PII, PHI): CMK encryption.
- Same KMS strategy as broader [../data-security/kms-strategy.md](../data-security/kms-strategy.md).

### Event-content sensitivity

- Events with PII / PHI: encryption at the source data level + transport encryption.
- Events with credentials / secrets: never in event payloads; reference IDs instead.
- Events with tenant data: tenant ID in metadata; payload encrypted with tenant-context.

---

## Worked example: Meridian Health's event-source posture

Meridian's Care Coordinator workload has ~30 event sources triggering ~50 Lambda functions.

### Inventory

Run quarterly via custom script + Wiz CSPM:

- Per-function: list of all event sources that can invoke.
- Per-event-source: policy + subscribers.
- Highlighted: orphan sources, broad policies, cross-account invokes.

### Care Coordinator's event topology

```
- API Gateway → 12 Lambda functions (HTTPS endpoints)
- SQS: care-coordinator-events-queue → care-coordinator-event-processor
- SNS: care-coordinator-clinical-events → 3 subscribed functions (notify, audit, analytics)
- EventBridge bus: care-coordinator-bus → 8 rules → 8 functions
- S3 events: 2 buckets → 2 functions (object-processing)
- DynamoDB Streams: 1 table → 1 function (cache invalidation)
```

### Per-source policies

All event sources have:

- Explicit publisher principal (no wildcards).
- Source-condition where applicable (SourceArn, SourceAccount).
- CMK encryption.
- DLQ for asynchronous patterns.

### Cross-account events

Three cross-account event flows:

1. From `meridian-analytics-prod` → care-coordinator analytics functions.
2. From partner integration accounts → care-coordinator partner-data ingestion.
3. Internal: cross-region replication via EventBridge.

Each has explicit bus policies; documented; quarterly reviewed.

### Findings opened during the event-source audit

- **ESRC-001** (5 SNS topics had `Principal: "*"` with no source-condition). Closed by per-topic tightening.
- **ESRC-002** (~10 functions' invoke inventory was incomplete; some event sources not catalogued). Closed by inventory script.
- **ESRC-003** (3 orphan SQS queues from deprecated workflows). Closed by decommission.
- **ESRC-004** (no DLQ on 5 production async functions). Closed by DLQ baseline.
- **ESRC-005** (EventBridge bus accepted events from any account in the org). Closed by explicit per-account grants.
- **ESRC-006** (event payloads contained PHI in some sources without encryption). Closed by application-layer encryption + CMK at rest.

---

## Anti-patterns

### 1. The wildcard SNS publisher

`Principal: "*"` with no `Condition`. Anyone can publish.

The fix: specific principal; source-condition if cross-service.

### 2. The unknown-invoker function

A function exists; nobody on the team knows what triggers it. Possibly long-deprecated; possibly malicious-trigger.

The fix: invoke inventory; per-quarter review; decommission orphans.

### 3. The orphan event source

SNS topic / SQS queue with no consumer. Policy might allow publishing; eventually it's used as part of an attack.

The fix: quarterly orphan-source cleanup.

### 4. The missing DLQ

Async function fails; message lost; no signal.

The fix: DLQ on every production async function.

### 5. The any-account-bus

EventBridge bus accepts events from any account. Cross-account misuse possible.

The fix: per-account explicit grants.

### 6. The PHI-in-event-payload

Event contains PHI without encryption. Anyone reading the topic / queue sees plaintext.

The fix: application-layer encryption of payload contents; CMK at rest.

### 7. The cross-service confused-deputy

S3 sends to SNS; SNS sends to Lambda. Without source conditions, an attacker with permission to publish to S3 could trigger arbitrary Lambdas.

The fix: source conditions on cross-service triggers.

### 8. The audit-trail gap

CloudTrail records the event triggering; but the trail might be in one account while the function is in another. Cross-account correlation needed.

The fix: SIEM correlation rule on cross-account event flows.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| ESRC-001 | SNS topic / SQS queue allows `Principal: "*"` | High | Specific principal; source-condition if cross-service | Security Eng + Platform Eng |
| ESRC-002 | Function invoke-inventory absent; unknown what triggers each function | High | Per-function inventory; quarterly review | Security Eng + Platform Eng |
| ESRC-003 | Orphan event sources (topics / queues with no consumers) | Medium | Quarterly orphan-source cleanup | Platform Eng + FinOps |
| ESRC-004 | DLQ absent on production async functions | High | DLQ baseline; alerting on volume | Platform Eng + SRE |
| ESRC-005 | EventBridge bus accepts events from any account in organization | Medium | Per-account explicit grants; least-privilege | Platform Eng + Security Eng |
| ESRC-006 | Event payloads contain PHI / PII without encryption | High | Application-layer encryption; CMK at rest | Application Eng + Security Eng |
| ESRC-007 | Cross-service trigger lacks source-condition | High | Add `SourceArn` / `SourceAccount` conditions on event-source policies | Security Eng |
| ESRC-008 | Cross-account event flow lacks audit-trail correlation | Medium | SIEM rule correlating CloudTrail events across accounts | Security Eng + SOC |
| ESRC-009 | Event-source encryption uses provider-managed key on sensitive payloads | Medium | CMK encryption per [../data-security/kms-strategy.md](../data-security/kms-strategy.md) | Security Eng |
| ESRC-010 | Subscription filter absent; function processes irrelevant events | Low | Subscription filter to narrow scope | Application Eng + Platform Eng |
| ESRC-011 | DLQ volume not alerted; poison-message patterns invisible | Medium | CloudWatch alarm on DLQ volume; SOC investigates | SOC + Platform Eng |
| ESRC-012 | EventBridge rules have over-broad event patterns; functions invoked unnecessarily | Low | Tighten event patterns; per-rule cost/security review | Application Eng + Platform Eng |
| ESRC-013 | Cross-account event sources accept events without verification of source-account | High | Source-account validation in event pattern or bus policy | Security Eng |
| ESRC-014 | Lambda resource policy allows broad `Lambda:Invoke` from `aws:Account` root | Medium | Specific principal ARNs; condition where appropriate | Security Eng + IAM Eng |
| ESRC-015 | Event-source policies hand-edited; drift from IaC | Medium | IaC for all event-source policies; admission gating | DevOps + Platform Eng |
| ESRC-016 | S3 bucket notifications configured ad-hoc; no inventory | Low | Per-bucket notification inventory; align with function inventory | Platform Eng |
| ESRC-017 | DynamoDB Streams enabled but no consumer; stream costs without benefit | Low | Quarterly review; disable unused streams | FinOps + Platform Eng |
| ESRC-018 | EventBridge schema validation absent; events with malformed schema reach consumers | Low | Schema discovery + validation; reject malformed events | Application Eng + Platform Eng |

---

## What this document is not

- **A complete SNS / SQS / EventBridge tutorial.** Vendor documentation covers operational depth.
- **An API Gateway reference.** API Gateway as event source is covered in [api-gateway-security.md](./api-gateway-security.md).
- **A Lambda function security reference.** Function-level security is in [lambda-functions-security.md](./lambda-functions-security.md).
- **A complete event-driven architecture guide.** Architectural patterns are out of scope; security patterns are covered.
