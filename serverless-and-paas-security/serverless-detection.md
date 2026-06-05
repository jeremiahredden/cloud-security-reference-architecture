# Serverless Detection

A practitioner's reference for detecting attacks on serverless workloads — Lambda, Azure Functions, GCP Cloud Functions, Cloud Run, App Engine — where the "host" you would normally instrument doesn't exist in a form you can run an agent on. The honest framing: serverless detection is detection-as-code, applied to platform-emitted signals (invocation logs, billing telemetry, IAM audit logs, request logs), with code-level instrumentation filling in the gaps the platform can't see.

This document closes a gap in the serverless folder: [lambda-functions-security.md](./lambda-functions-security.md) covers the function-level controls, [serverless-iam-patterns.md](./serverless-iam-patterns.md) covers the IAM design, [event-source-security.md](./event-source-security.md) covers triggering policies. This document covers detection — the signals that tell you a serverless workload is being misused, exploited, or has been compromised.

The reason serverless detection is its own document: the patterns from IaaS (EDR on the host, syscall instrumentation, network packet capture) don't translate. Replace them with: invocation telemetry, billing-as-signal, IAM-audit-as-signal, and code-emitted application telemetry. The detection writer who tries to translate "process injection" rules into serverless will burn weeks; the detection writer who starts from the platform signals and works outward will be productive in days.

---

## When to read this document

**If you are building a SOC capability for serverless workloads** — read top to bottom.

**If your team operates Lambda / Functions / Cloud Functions and isn't sure what to alert on** — start with [The detection catalogue](#the-detection-catalogue).

**If you are integrating serverless logs into a SIEM** — start with [Log ingestion architecture](#log-ingestion-architecture).

**If a serverless function was compromised and you want to know what forensic data exists** — start with [Forensics on serverless](#forensics-on-serverless).

---

## The serverless detection mental model

Why serverless detection is different.

### What you can't do

- **No host-based agent.** The runtime container is ephemeral and you have no shell into it.
- **No persistent network packet capture.** Per-invocation network traffic is brief; there is no NIDS sensor you can deploy adjacent to a Lambda.
- **No syscall instrumentation.** Falco, Tetragon, eBPF — none of these run inside a Lambda runtime.
- **No filesystem inspection.** The runtime filesystem is reset between cold starts; you can't scan it for persistence artifacts that aren't there.

### What you can do

- **Platform telemetry.** Every invocation generates structured platform logs: who triggered it, when, how long, with what role, with what outcome.
- **Audit trail.** Every configuration change to the function (code update, IAM role update, event source attach) lands in CloudTrail / Activity Log / Audit Log.
- **Billing telemetry.** Invocation count, duration, cost — all observable, all queryable, all useful as detection signal.
- **Application telemetry.** Code-emitted logs, traces, metrics — instrumented by the team, structured for detection.
- **Egress telemetry.** VPC Flow Logs (for VPC-attached functions), Cloud NAT logs, DNS query logs.
- **Event-source telemetry.** Who put a message on the SQS queue / EventBridge bus / Pub/Sub topic that triggered the function.

### The detection-source matrix

| Signal | Platform | Where to find it | Useful for |
| --- | --- | --- | --- |
| Invocation count, duration, errors | All four | CloudWatch / Application Insights / Cloud Logging | Volume anomaly, error spike, runaway invocations |
| Function configuration change | All four | CloudTrail / Activity Log / Audit Log | Backdoor injection, role escalation, event source poisoning |
| Function IAM role API calls | All four | CloudTrail / Activity Log / Audit Log | Detection of post-compromise activity (the role's API usage) |
| Event source put / publish | All four | Event-source service logs (SNS/SQS/EventBridge/Event Grid/Pub/Sub) | Detection of crafted-event poisoning |
| Egress network traffic (VPC-attached) | All four | VPC Flow Logs / NSG Flow Logs / VPC Flow Logs | C2 callback detection, data exfiltration |
| DNS queries | All four | Route 53 Resolver / Azure DNS / Cloud DNS audit | DGA detection, C2 callback |
| Cost / billing | All four | Cost Explorer / Cost Management / Billing | Cryptomining, cost-DoS |
| Code-emitted application logs | All four | Same as platform logs | Anything the application chooses to surface |

---

## Log ingestion architecture

How the signals reach your SIEM. Without this, none of the detections work.

### The shape

```
┌──────────────────────────────────────────────────────────────────┐
│                         Workload account / subscription          │
│  ┌────────┐                                                      │
│  │ Lambda │──────► CloudWatch Logs                               │
│  └────────┘                  │                                   │
│                              │                                   │
│  ┌────────┐                  │                                   │
│  │ Func   │──► App Insights ─┤                                   │
│  └────────┘                  │                                   │
│                              ▼                                   │
│              ┌─────────────────────────────────┐                 │
│              │  Per-account log destination    │                 │
│              │  (CW Logs, App Insights, etc.)  │                 │
│              └─────────────┬───────────────────┘                 │
│                            │                                     │
└────────────────────────────┼─────────────────────────────────────┘
                             │
                             │  Forwarder
                             │  (Kinesis Firehose / Event Hub / Pub/Sub)
                             │
                             ▼
              ┌──────────────────────────────────┐
              │   Central log lake (S3 / ADLS)   │
              │      + SIEM (Splunk / Sentinel   │
              │       / Chronicle / Elastic)     │
              └──────────────────────────────────┘
```

The pattern is the same as [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md); the serverless-specific notes:

### What to ship

- **Function invocation logs** (CloudWatch Logs, Application Insights, Cloud Logging) for every production function.
- **Platform audit logs** (CloudTrail, Activity Log, Audit Log) — these you ship anyway as the org baseline.
- **Event-source logs** — SNS / SQS / EventBridge data events (CloudTrail), Event Grid / Service Bus (Activity Log), Pub/Sub audit logs.
- **VPC Flow Logs** for VPC-attached functions.
- **Cost / billing exports** — daily, ingested into the same SIEM or a sibling lake for cost-anomaly detection.

### What not to ship

- Verbose application debug logs from healthy invocations — these will dominate cost and bury signal.
- The full body of every event that triggered every function — this can be sensitive (event payloads may contain PII) and is rarely useful at the SIEM layer.

The discipline: structured invocation logs and audit logs always; application-level logs filtered to warn / error / security-relevant.

### The "forward-selectively" pattern

The serverless log volume can be enormous (a 1000-RPS Lambda over a month produces hundreds of GB of CloudWatch Logs). Forwarding all of it to the SIEM is expensive.

The pattern, from [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md):
- Land everything in the cheap log lake (S3, ADLS, GCS).
- Forward filtered subsets to the SIEM (errors, security-relevant events, configuration changes).
- Query the lake from the SIEM for forensic investigations.

---

## The detection catalogue

The high-value detections for serverless workloads. Each detection lists: signal source, logic, severity, false-positive considerations, and what to do when it fires.

### 1. Function configuration change from unexpected principal

**Signal:** CloudTrail `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `PutFunctionConcurrency`, `AddPermission` API calls. Equivalents: Azure Activity Log `Microsoft.Web/sites/functions/write`, `Microsoft.Web/sites/config/write`. GCP Audit Log `cloudfunctions.functions.update`.

**Logic:**
- The expected principal is the CI/CD service role (e.g., `arn:aws:iam::<account>:role/github-actions-deploy`).
- Any other principal (a developer's IAM user, a Lambda role, a console session) updating a production function code or configuration is anomalous.

**Severity:** High. Configuration change is the most-common backdoor injection pattern: attacker compromises a developer role, swaps Lambda code, exfils via the function's IAM role.

**False positives:** Emergency hotfix where engineer used break-glass. Documented break-glass procedure should produce a parallel notification (Slack message, ticket) that the SOC correlates.

**Response:**
- Page security on-call.
- Pull the function code; compare to git HEAD.
- Pull CloudTrail for the principal that made the change; verify their session was legitimate.
- If unauthorized: revert; rotate credentials for the principal; investigate principal's other actions per [../cloud-detection-response/runbook-leaked-iam-key.md](../cloud-detection-response/runbook-leaked-iam-key.md).

### 2. Function IAM role assumed by unexpected service

**Signal:** CloudTrail `AssumeRole` events with `roleArn` matching a Lambda execution role and `userIdentity` not matching the Lambda service.

**Logic:**
- Lambda execution roles should only be assumed by `lambda.amazonaws.com` (or `edgelambda.amazonaws.com` for Lambda@Edge).
- An `AssumeRole` from `ec2.amazonaws.com`, `ecs-tasks.amazonaws.com`, or a human IAM user/role is a misuse / role-borrowing pattern.

**Severity:** High. Role-borrowing across services is a privilege-escalation pattern; the Lambda role is often more permissive than the borrower's intended scope.

**False positives:** Cross-account integration patterns. Document the legitimate cross-service / cross-account usage and add to the allowlist.

**Response:**
- Investigate the borrower principal's session.
- Determine what the borrower used the role for (CloudTrail filtered by `accessKeyId` from the AssumeRole response).
- If unauthorized: tighten the trust policy.

### 3. Invocation volume anomaly

**Signal:** CloudWatch `Invocations` metric (or equivalent) for a function, with baseline established from the prior 7 days.

**Logic:**
- Per-function baseline (mean + std deviation of invocations per minute).
- Alert when current rate exceeds baseline + N standard deviations (typically N=3–4).
- Or alert when current rate exceeds an absolute threshold for that function class.

**Severity:** Medium. High invocation volume can be: cryptomining via function exploitation, cost-DoS attack, runaway-loop bug, or legitimate traffic spike.

**False positives:** Sales / marketing events that drive traffic. Whitelist by ticket. Black-friday / similar predictable spikes get pre-staged alert tuning.

**Response:**
- Compare to ingress source (is there a corresponding API Gateway / Front Door / Load Balancer spike?).
- Check function logs for error patterns (loops emit recognizable patterns).
- Check function cost — is it a 10x cost spike?
- If unexplained: throttle the function (reduce reserved concurrency); investigate; root-cause.

### 4. Function error rate spike

**Signal:** CloudWatch `Errors` metric (or equivalent) for a function.

**Logic:**
- Baseline error rate per function.
- Alert when current rate exceeds baseline + N standard deviations and the rate is > 5% of total invocations.

**Severity:** Medium. Sudden error spike can be: exploitation attempt (payloads that trigger unhandled exceptions), broken dependency, deployment regression.

**False positives:** Deployments. Suppress alerts in the N minutes after a known deployment.

**Response:**
- Pull error log samples.
- Check for crafted-input patterns (oversized payloads, unusual characters).
- Coordinate with the team that owns the function.

### 5. Egress to unexpected destination

**Signal:** VPC Flow Logs from the subnet the VPC-attached function lives in, filtered by source IP matching the function's ENIs.

**Logic:**
- Per-function egress allowlist (the function should only call: AWS APIs, the internal database, the specific external API it integrates with).
- Alert on any egress to a destination not in the allowlist.

**Severity:** High. Function compromised, calling C2 or exfiltrating data.

**False positives:** New legitimate integration not yet added to the allowlist. Allowlist should be maintained by the team that owns the function, reviewed quarterly.

**Response:**
- Identify the destination (PassiveDNS / reverse lookup / threat-intel feed).
- Page security on-call.
- Isolate (set function concurrency to 0; remove egress security group rules).
- Forensic capture (function code in S3, CloudWatch Logs export, recent invocation logs).
- Engage IR per [../cloud-detection-response/runbook-leaked-iam-key.md](../cloud-detection-response/runbook-leaked-iam-key.md) if the function held credentials.

### 6. DNS query to known-bad domain or DGA pattern

**Signal:** Route 53 Resolver query logs (or Azure DNS, Cloud DNS) filtered by source IP matching function ENIs.

**Logic:**
- Threat-intel feed match (known-bad domains).
- DGA detection (high-entropy domain names, large fan-out of unique domains).

**Severity:** High. Same severity as egress-to-unexpected-destination; complementary signal.

**Response:** Same as #5.

### 7. Function role API call from unexpected geography

**Signal:** CloudTrail events with `userIdentity.arn` matching a Lambda execution role, filtered by `sourceIPAddress`.

**Logic:**
- Lambda execution roles call AWS APIs from AWS service IPs (the Lambda execution environment is inside AWS).
- An API call attributed to the function's role from an external IP indicates: temporary credentials were exfiltrated and used by an external attacker.

**Severity:** Critical. The function's credentials are in attacker hands.

**Response:** Treat as leaked IAM credentials per [../cloud-detection-response/runbook-leaked-iam-key.md](../cloud-detection-response/runbook-leaked-iam-key.md). Add a `aws:SourceIp` deny to the role's trust policy targeting non-AWS-service IPs; rotate the function code (forces new credentials in next cold start); investigate the credential exfil vector.

### 8. Function-cost anomaly

**Signal:** Cost Explorer / Cost Management daily cost export for the function's service (Lambda, Functions, Cloud Functions, Cloud Run).

**Logic:**
- Per-function-class daily cost baseline.
- Alert on > 2x baseline for any single day.

**Severity:** Medium → High depending on absolute dollar amount.

**False positives:** New deployment that materially increases function usage. Should be paired with engineering notification.

**Response:**
- Correlate with invocation volume anomaly.
- Investigate which function(s) are driving cost.
- Cryptomining is the worst-case scenario; runaway-loop bug is the most-common cause. Both deserve immediate attention.

### 9. Function permission change widening blast radius

**Signal:** CloudTrail `PutRolePolicy`, `AttachRolePolicy` for the function's role.

**Logic:**
- New permissions added to a function role outside the IaC pipeline.
- Or new permissions that match high-risk patterns: `iam:PassRole`, `kms:*`, `s3:*` on broad resource scopes, `secretsmanager:GetSecretValue` on broad resources.

**Severity:** High. Often a privilege-escalation step or a backdoor (attacker grants the compromised role more access).

**Response:** Same as #1.

### 10. Function resource-policy widening

**Signal:** CloudTrail `AddPermission` on a Lambda function (the function's resource policy).

**Logic:**
- `Principal: "*"` in the resource policy — the function is now callable by anyone.
- Or `Principal` matching an unexpected account / service.

**Severity:** High. The function is now invokable by an unintended caller.

**Response:**
- Remove the offending statement.
- Investigate the principal that made the change.

### 11. Application-emitted security event

**Signal:** Application-emitted log lines tagged with a security-event marker (e.g., a structured log field `securityEvent: true`).

**Logic:**
- The function code itself emits security-relevant events: authentication failure, authorization denial, anomalous input, fraud-detection rule trigger, etc.
- The SIEM ingests these as security signals.

**Severity:** Varies by event.

**Considerations:** Requires application teams to instrument. Pattern: a small library that wraps the team's logging framework with a `securityEvent()` helper that emits structured fields.

**Response:** Per the event type. The application owns the response definition.

### 12. Cold-start spike

**Signal:** CloudWatch `InitDuration` metric, or absence of warm-start invocations followed by sudden cold starts.

**Logic:**
- An attacker who wants their malicious code path to execute may force cold starts (e.g., by updating function configuration to invalidate warm containers).
- A spike in `InitDuration` events after a deployment that wasn't expected to require cold starts is anomalous.

**Severity:** Low to Medium. By itself this is a weak signal; correlate with #1 (configuration change) and #5 (egress).

**Response:** Investigate the configuration changes around the cold-start spike.

### 13. Cryptomining-pattern egress

**Signal:** Egress to known mining pool destinations (`*.mining-pool.com`, common Stratum protocol ports like 3333, 4444, 5555, 7777), or sustained outbound traffic to a single IP at a steady high rate.

**Logic:**
- Threat-intel feed of mining pool IPs / domains.
- Sustained outbound traffic at a function-uncharacteristic rate.

**Severity:** Critical. Pivot to [../cloud-detection-response/runbook-cryptomining.md](../cloud-detection-response/runbook-cryptomining.md).

### 14. Event-source poisoning

**Signal:** SQS / EventBridge / SNS / Pub/Sub put events from unexpected principals.

**Logic:**
- The event source has an expected set of writers (e.g., "the order-processing service writes to the orders queue").
- A `SendMessage` / `PutEvents` / `Publish` from an unexpected principal is anomalous.

**Severity:** High. Attacker is feeding crafted events into the function; the function will process them as legitimate.

**Response:**
- Tighten the event-source resource policy per [./event-source-security.md](./event-source-security.md).
- Investigate the writing principal.

### 15. Deprecated runtime in use

**Signal:** Lambda `ListFunctions` API output (or equivalents), filtered for runtimes near or past end-of-life.

**Logic:**
- AWS publishes runtime deprecation timelines; same for Azure / GCP.
- Functions running on a deprecated runtime are a posture finding (no longer patched).

**Severity:** Medium.

**Response:**
- Identify owning team.
- Open an upgrade ticket with deadline.
- Block new deployments to deprecated runtimes via CI gate.

### 16. Function deployed outside CI/CD

**Signal:** CloudTrail `UpdateFunctionCode` events from non-CI principals.

**Logic:**
- Production functions deploy from the CI service role only.
- Hand-deploy from a developer credential or console session is anomalous.

**Severity:** High. Even legitimate hand-deploys violate the audit-trail discipline; malicious hand-deploys are backdoors.

**Response:** Same as #1.

### 17. Function exposed via Function URL with no auth

**Signal:** CloudTrail `CreateFunctionUrlConfig` with `AuthType: NONE`.

**Logic:**
- New Function URL with no authentication; the function is now public.
- Could be legitimate (webhook receiver with code-level HMAC) or could be inadvertent / malicious.

**Severity:** Medium → High depending on the function's IAM role.

**Response:**
- Verify the function has code-level webhook validation; if not, page the owning team.
- Document the legitimate Function URLs; alert on new ones.

### 18. Function ENI count growing unbounded

**Signal:** EC2 `DescribeNetworkInterfaces` / VPC ENI count for VPC-attached functions.

**Logic:**
- VPC-attached Lambda creates ENIs in the target subnet; Lambda cleans them up.
- A bug or attack pattern can cause ENI leak; eventually the subnet runs out of IPs and other workloads can't get IPs.

**Severity:** Medium. Mostly an availability concern; can also indicate active enumeration / mass-invocation.

**Response:**
- Investigate the function's ENI lifecycle.
- Engage AWS Support if Lambda is failing to clean up.

---

## Forensics on serverless

When a function is compromised, what evidence exists and how to preserve it.

### The ephemerality problem

The runtime container of a serverless function is recycled after a brief idle period. By the time you're investigating, the runtime that ran the malicious invocation may be gone.

You're working with:
- The function code at the time of the incident (S3 / artifact registry).
- The invocation logs (CloudWatch / Application Insights / Cloud Logging).
- The audit trail (CloudTrail / Activity Log / Audit Log).
- Any state the function emitted to durable storage (DynamoDB writes, S3 uploads, queue messages).

You are NOT working with:
- The runtime memory at time of invocation.
- The runtime filesystem.
- The network packets seen by the runtime.

### The capture playbook

1. **Capture the function code as deployed at the time of the incident.**
   - Lambda: `aws lambda get-function --function-name <name>` returns a signed URL to the code package.
   - Azure Functions: download the function app's deployment package.
   - GCP: `gcloud functions describe <name>` returns the source location.
   - Save to evidence storage with hash and timestamp.

2. **Capture the function configuration as deployed at the time of the incident.**
   - Environment variables (sanitize before storage if they contain sensitive data).
   - IAM role / managed identity / service account.
   - Resource policy (Lambda) / trigger configuration.
   - Event sources.
   - Concurrency limits.

3. **Pull invocation logs for the relevant time window.**
   - CloudWatch Logs Insights query for the function's log group.
   - Application Insights query for the function app.
   - Cloud Logging query for the Cloud Function.
   - Export to evidence storage.

4. **Pull CloudTrail / Activity Log / Audit Log for the function's IAM role.**
   - Every API call the role made in the relevant window.
   - Cross-reference to identify what data the function touched.

5. **Pull the event-source data for triggering events.**
   - The SQS messages / EventBridge events / SNS notifications that triggered the suspect invocations.
   - Often available in CloudTrail data events if those are enabled, or in the event source's own retention.

6. **Capture VPC Flow Logs for VPC-attached functions** for the relevant window. Useful for confirming egress destinations.

7. **Snapshot the function's IAM role and trust policy.**
   - These may change during remediation; preserve the pre-remediation state.

### What's missing

The runtime memory and the unwritten / un-emitted application state at the moment of invocation. Serverless gives this up by design.

If your investigation needs runtime memory inspection, the function should not be serverless — it should be a container with eBPF / Falco / equivalent runtime instrumentation. This is part of the serverless trade-off discussed in [lambda-functions-security.md](./lambda-functions-security.md).

### The chain-of-custody discipline

- All evidence saved with timestamp and SHA-256 hash.
- All evidence storage immutable (S3 Object Lock; immutable storage tier in Azure / GCP).
- All retrievals logged.
- See [../threat-modeling-cloud/facilitation-guide.md](../threat-modeling-cloud/facilitation-guide.md) for finding-management discipline; see [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) for evidence-storage architecture.

---

## Detection-as-code: how rules ship

The pattern that makes the detection catalogue maintainable.

### The discipline

- Every detection rule lives in version control (the SIEM team's repo).
- Every rule has tests (synthetic input → expected fire / no-fire).
- Every rule is deployed via CI/CD to the SIEM.
- Every rule has an owner (the team responsible for response).
- Every rule has an MTTR target (how fast the SOC must triage).

### The rule template

```yaml
name: lambda-config-change-from-unexpected-principal
severity: high
owner: security-detection-team
runbook: runbooks/lambda-config-change.md
mttr_minutes: 15

logic: |
  source:cloudtrail
  AND (eventName:UpdateFunctionCode OR eventName:UpdateFunctionConfiguration)
  AND NOT userIdentity.arn:"arn:aws:iam::*:role/github-actions-deploy"
  AND NOT userIdentity.arn:"arn:aws:iam::*:role/break-glass-deploy"

tests:
  - description: Fires on developer IAM user updating function code
    input:
      eventName: UpdateFunctionCode
      userIdentity:
        arn: arn:aws:iam::123:user/alice
    expected: fire

  - description: Does not fire on CI deploy
    input:
      eventName: UpdateFunctionCode
      userIdentity:
        arn: arn:aws:iam::123:role/github-actions-deploy
    expected: no-fire
```

### Per-SIEM realization

- **Splunk:** Saved searches / correlation searches, version-controlled, deployed via Splunk REST API.
- **Microsoft Sentinel:** Analytics rules as ARM templates; deployed via Bicep / Terraform.
- **Chronicle:** YARA-L rules, version-controlled, deployed via Chronicle's API.
- **Elastic:** Detection rules as JSON, deployed via the detection-engine API.
- **Datadog:** Security rules as Terraform resources.

The choice is part of the SIEM-integration design ([../cloud-detection-response/siem-integration.md](../cloud-detection-response/siem-integration.md)); the discipline applies regardless.

---

## Worked example — Meridian Health serverless detection rollout (Q2 2026)

The Meridian platform team operates ~180 Lambda functions across the regulated-workloads and corporate accounts. Before this rollout, the only Lambda-specific detection was "GuardDuty findings flagged Lambda-related events." After: an 18-rule detection-as-code catalogue with documented response runbooks.

### The starting state

- GuardDuty enabled at the org level; Lambda Protection enabled.
- CloudWatch Logs from Lambda functions retained 30 days locally; not forwarded.
- CloudTrail forwarded to SIEM at the org level (good).
- No application-emitted security events.
- No per-function egress allowlists.
- No invocation-volume baselines.

### The six-week rollout

**Week 1 — log forwarding.**
Configured CloudWatch Logs subscription filters for production Lambda log groups; routed via Kinesis Firehose to the central S3 log lake (cheap retention) and Splunk (security-relevant filter only).

Filter: `{ $.level = "ERROR" || $.level = "WARN" || $.securityEvent = true }`

This dropped Lambda log volume into Splunk by ~98% while preserving the security-relevant signal.

**Week 2 — base detections from CloudTrail.**
Implemented detections #1, #2, #9, #10, #15, #16, #17 — all sourced from CloudTrail, all immediately useful, none requiring per-function tuning.

Within the first week of running: caught 3 functions deployed outside CI (legitimate but undocumented hotfixes; documented and brought into compliance), 1 function with `AuthType: NONE` Function URL (legitimate webhook, but lacking HMAC; remediated), and 2 deprecated-runtime functions.

**Week 3 — VPC Flow Logs and egress allowlists.**
For the 12 VPC-attached production functions, defined per-function egress allowlists (database IPs, AWS service endpoints, the specific external APIs each integrated with). Implemented detection #5.

Caught one function calling a long-deprecated AWS endpoint (no security issue, but indicated the SDK was outdated; updated).

**Week 4 — invocation-volume baselines.**
For the top 30 production functions by invocation volume: established 7-day baselines. Implemented detections #3, #4, #12, #18.

Tuned aggressively: anomaly threshold of baseline + 4σ in the first week, narrowed to baseline + 3σ after the first false-positive deluge.

**Week 5 — cost anomaly detection.**
Daily cost export to a Glue table; Athena query running daily, comparing to 30-day rolling baseline. Slack notification on > 2x baseline.

Caught one team experimenting with a model-inference Lambda that was 8x more expensive per invocation than expected; flagged the team; redesigned around batch processing.

**Week 6 — application security events and cryptomining detection.**
Wrote a small Python decorator (`@security_event`) that emits structured `securityEvent: true` log lines; rolled out to the 30 highest-criticality functions.

Detection #11 went live. Within two weeks: caught 4 authentication-failure spikes (3 from credential stuffing, 1 from a misconfigured client), all responded-to before customer impact.

Cryptomining detection (#13) went live. Drew on the threat-intel feed already maintained for the broader environment.

### Findings opened during the rollout

- **SVDT-001** (Lambda logs not shipping to SIEM). Closed by log subscription filters.
- **SVDT-002** (3 functions deployed outside CI). Closed by deployment-pipeline tightening; CI principal is the only one with PutFunction permission.
- **SVDT-003** (1 Function URL without HMAC validation). Closed by adding HMAC; documented as legitimate.
- **SVDT-004** (12 VPC-attached functions without egress allowlist). Closed by per-function security group tightening.
- **SVDT-005** (30 high-volume functions lacking baselines). Closed by baseline calculation and detection #3 / #4 / #18.
- **SVDT-006** (cost anomaly process absent for serverless). Closed by daily cost export + anomaly detection.
- **SVDT-007** (no application-emitted security events). Closed by the `@security_event` decorator rollout.

The 18-detection catalogue runs continuously. SOC handles ~5 alerts per week, ~80% triaged to "no action" in <10 minutes, ~15% requiring engineering follow-up, ~5% pivoting to IR. The "no action" rate has held below 90%; if it goes above, the rule is re-tuned.

---

## Anti-patterns

### 1. "We have GuardDuty, we're covered"

GuardDuty Lambda Protection catches a useful subset (suspicious DNS, anomalous behaviors), but it can't catch:
- Function-configuration backdoors.
- Deployment outside CI.
- Function URLs added with no auth.
- Cost-DoS / cryptomining (it surfaces some, misses the rest).
- Anything application-specific.

The fix: GuardDuty is the floor, not the ceiling. Layer detection-as-code on top.

### 2. The "log everything to SIEM" cost mistake

Shipping every Lambda log line to the SIEM produces unmanageable cost and buries signal. SIEM cost can equal cloud cost for high-volume serverless workloads.

The fix: forward selectively. Errors, warnings, security-flagged events to SIEM; everything to cheap lake; query lake from SIEM for forensics.

### 3. The "alert on every error" noise generator

Functions emit errors for many reasons; most are not security-relevant. Alerting on every error log produces hundreds of pages per day.

The fix: alert on error-rate anomaly, not on individual errors. Per-function error baselines.

### 4. The detection-without-runbook pattern

A detection fires. The SOC analyst has no idea what to do. The alert is dismissed. The next time it fires, it's dismissed again. The detection has been functionally disabled by neglect.

The fix: every detection has a runbook. Every runbook names the response steps. Every runbook is tested by a tabletop quarterly.

### 5. The "we'll instrument applications later" deferral

The platform-emitted signals catch some attacks; the application-emitted signals catch the rest. Skipping the application instrumentation cuts the detection coverage in half.

The fix: ship a security-event helper library; require its use in production functions; review during code review.

### 6. The single-function-egress allowlist that nobody maintains

Egress allowlists are useful only when current. If the allowlist hasn't been updated in a year and the function has grown a legitimate new integration, the detection fires on the legitimate integration and gets ignored.

The fix: per-function team owns the allowlist; quarterly review; CI check that the allowlist exists and isn't empty.

### 7. "We don't need cost-anomaly detection — billing alerts are enough"

Billing alerts fire when the bill has already been incurred. Cost-anomaly detection on daily exports catches the issue when it's still 1x the bill, not 30x.

The fix: daily cost export to the SIEM; anomaly detection on per-service daily cost.

### 8. The forensics-without-evidence-preservation pattern

A compromise happens; the SOC pulls the current function code; the engineering team has already pushed a fix; the malicious code is no longer available; the investigation stalls.

The fix: capture-the-function-code-and-config is step 1 of the IR runbook; happens before any remediation; evidence stored in immutable storage.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| SVDT-001 | Lambda / Functions / Cloud Functions logs not forwarded to SIEM | High | Subscription filters to SIEM ingestion pipeline; selective forwarding | Security Eng + Platform Eng |
| SVDT-002 | No detection for function configuration change from non-CI principal | High | Implement detection #1 with runbook | Detection Eng + SOC |
| SVDT-003 | No detection for unexpected role assumption / borrowing | High | Implement detection #2 with runbook | Detection Eng + SOC |
| SVDT-004 | No invocation-volume baseline / anomaly detection on production functions | Medium | Per-function baselines; detection #3 | Detection Eng + Platform Eng |
| SVDT-005 | No per-function egress allowlist; cannot detect data exfiltration | High | Egress allowlists; VPC Flow Logs analysis; detection #5 | Network Eng + Security Eng |
| SVDT-006 | No application-emitted security events from functions | Medium | Security-event helper library; team adoption | Security Eng + Application Eng |
| SVDT-007 | No cost-anomaly detection for serverless services | Medium | Daily cost export + anomaly detection | FinOps + Security Eng |
| SVDT-008 | No detection for resource-policy widening (e.g., Principal: *) | High | Implement detection #10 | Detection Eng + SOC |
| SVDT-009 | Forensic-capture step missing from serverless IR runbook | High | Add capture-code-and-config step before any remediation | IR + Detection Eng |
| SVDT-010 | Function deployed outside CI without alerting | High | Implement detection #16; CI-only deployment baseline | DevOps + Security Eng |
| SVDT-011 | Function URL with AuthType NONE created without ticket | Medium | Implement detection #17; require HMAC for webhook patterns | Application Eng + Security Eng |
| SVDT-012 | Deprecated-runtime functions not flagged for upgrade | Medium | Implement detection #15; CI gate on deploys to deprecated runtimes | DevOps + Security Eng |
| SVDT-013 | Function role permissions widened outside IaC | High | Implement detection #9; IaC-only permission changes | Security Eng + DevOps |
| SVDT-014 | DNS queries from VPC-attached functions not logged / analyzed | Medium | Route 53 Resolver query logs; detection #6 | Network Eng + Security Eng |
| SVDT-015 | Function role API calls from external IPs not detected | Critical | Implement detection #7; treat as leaked-credential per [../cloud-detection-response/runbook-leaked-iam-key.md](../cloud-detection-response/runbook-leaked-iam-key.md) | Detection Eng + SOC |
| SVDT-016 | Event-source-poisoning patterns not detected | High | Implement detection #14; tighten event-source resource policies per [./event-source-security.md](./event-source-security.md) | Detection Eng + Application Eng |
| SVDT-017 | Detection rules not version-controlled / not tested | Medium | Detection-as-code repo; CI tests per rule; deployment automation | Detection Eng |
| SVDT-018 | Detection runbooks missing or stale | High | Per-rule runbook; quarterly tabletop validation | IR + Detection Eng |

---

## Adoption checklist

- [ ] Function logs from production functions forwarded to SIEM (selectively).
- [ ] CloudTrail / Activity Log / Audit Log ingested into SIEM at org level.
- [ ] VPC Flow Logs from subnets hosting VPC-attached functions.
- [ ] Per-function egress allowlists documented and enforced.
- [ ] DNS query logs ingested for VPC-attached function subnets.
- [ ] Daily cost export from billing service to SIEM / lake.
- [ ] Per-function invocation-volume baselines computed.
- [ ] Detection-as-code repo for SIEM rules; CI for rule tests; automated deployment.
- [ ] All 18 catalogue detections implemented with per-rule runbook.
- [ ] Application security-event helper library; rollout to top-criticality functions.
- [ ] Forensic-capture step in IR runbook; tested via tabletop.
- [ ] Evidence storage immutable (S3 Object Lock or equivalent); chain-of-custody discipline.
- [ ] SOC team trained on serverless-specific response patterns.
- [ ] Quarterly tabletop on a serverless compromise scenario.
- [ ] Per-rule MTTR target; tracked monthly.
- [ ] Quarterly review of false-positive rate per rule; tune or remove.

---

## What this document is not

- **A SIEM-implementation guide.** [../cloud-detection-response/siem-integration.md](../cloud-detection-response/siem-integration.md) covers SIEM choices and integration patterns.
- **A general serverless reference.** [lambda-functions-security.md](./lambda-functions-security.md), [serverless-iam-patterns.md](./serverless-iam-patterns.md), [event-source-security.md](./event-source-security.md) cover the preventive controls.
- **A complete IR runbook.** The runbooks in [../cloud-detection-response/](../cloud-detection-response/) cover IR for specific incident classes (leaked IAM key, exposed storage, cryptomining, etc.); the patterns apply when serverless is the affected workload.
- **A threat-intelligence reference.** Threat-intel feed sourcing, evaluation, and consumption are adjacent and out of scope.
- **A GuardDuty / Defender / SCC manual.** Those services produce findings; this document treats them as one of several signal sources.
- **An application-security primer.** Code-level vulnerabilities in function code are out of scope; the sibling AppSec repo covers them.
