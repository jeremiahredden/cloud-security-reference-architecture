# Lambda / Functions / Cloud Functions Security

A practitioner's reference for securing serverless compute — AWS Lambda, Azure Functions, GCP Cloud Functions — side by side. The patterns here cover execution-role design, environment-variable handling (the secrets are never in env vars; the secrets manager is), VPC integration vs no-VPC, dead-letter queue patterns, the cold-start vs warm-start security implications, function URLs and when they are appropriate, and the operational discipline that prevents serverless from becoming an "everyone has a Lambda" sprawl.

This document opens the serverless-and-paas-security folder. Serverless security is mostly an IAM problem (deeper coverage in [serverless-iam-patterns.md](./serverless-iam-patterns.md)) and an event-source problem (deeper coverage in [event-source-security.md](./event-source-security.md)). This document covers the function-level controls that hold those other patterns together.

The honest framing: serverless is easier and harder than IaaS security simultaneously. Easier because the platform handles patching, OS hardening, runtime isolation. Harder because the controls move into IAM, event-source policies, and application code — places where standard security-engineering instincts apply less reliably. Many teams under-invest in serverless security because "it's just functions."

---

## When to read this document

**If you operate Lambda / Functions / Cloud Functions and aren't sure what the security baseline should be** — read top to bottom.

**If you have function URLs exposed and aren't sure when that's appropriate** — start with [Function URLs](#function-urls).

**If your functions have environment variables containing credentials** — start with [Environment variables and secrets](#environment-variables-and-secrets). This is the most common single mistake.

**If you are auditing serverless posture** — start with [Findings checklist](#findings-checklist).

---

## The function as a unit

The mental model.

### What a function is, security-wise

- A runtime environment with an attached IAM role.
- Triggered by an event source (API Gateway, EventBridge, SQS, etc.).
- Returns a result.
- Has limited lifetime (the invocation; possibly held warm across invocations).
- Has restricted control over its own environment.

### The attack surface

- **The IAM role:** what the function can do once it's running. Over-permissive = compromise = broad access.
- **The event source:** who can trigger the function. Permissive = anyone can invoke.
- **The code:** application-layer vulnerabilities.
- **The environment variables:** if they contain secrets, they're the attack surface.
- **The runtime / dependencies:** OS / language runtime / library vulnerabilities.

### What the platform handles

- OS patching, kernel updates.
- Runtime container isolation.
- Network-stack isolation between functions.
- Underlying compute provisioning.

### What the team handles

- IAM role design.
- Event-source policy design.
- Code security.
- Environment-variable hygiene.
- Function configuration (timeout, memory, concurrency).
- Logging, monitoring.

---

## Execution-role design

The single most-important serverless security control.

### Per-function roles (always)

Every function has its own IAM role. The role grants exactly what the function needs and nothing more.

Anti-pattern: one role shared across many functions ("the dev role"). The role accumulates permissions; each function inherits all of them; least-privilege is impossible.

Mature pattern: per-function role, named after the function (`care-coordinator-event-processor-role`).

### The minimum permissions baseline

Every function role needs:

- Permission to write CloudWatch / Application Insights / Cloud Logging logs.
- Permission to send X-Ray traces (if enabled).
- Permission to read the function's expected secrets / configurations.

Beyond this, the role grants only what the function actually does:

- Reads from S3 bucket X? `s3:GetObject` on bucket X.
- Writes to DynamoDB table Y? `dynamodb:PutItem` on table Y.
- Calls KMS? `kms:Decrypt` on specific keys.

### IAM Access Analyzer for function roles

AWS IAM Access Analyzer can analyze CloudTrail logs to suggest least-privilege policies:

```bash
aws accessanalyzer start-policy-generation \
  --policy-generation-details '{"principalArn": "arn:aws:iam::ACCOUNT:role/lambda-role"}' \
  --cloud-trail-details '{"trails": [{"cloudTrailArn": "arn:..."}], "accessRole": "arn:..."}'
```

The analyzer reads CloudTrail; identifies what the role actually used; generates a policy with only the used permissions.

For Azure: similar via Microsoft Sentinel / Defender for Cloud.
For GCP: IAM Recommender.

The pattern: deploy with broader role initially; run for 30 days; use the analyzer to suggest tighter role; deploy the tightening.

### Trust policy (who can assume the role)

The function's role is assumed by the Lambda / Functions / Cloud Functions service:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"aws:SourceAccount": "ACCOUNT"}
    }
  }]
}
```

The `SourceAccount` condition prevents cross-account "confused deputy" attacks via Lambda.

---

## Environment variables and secrets

The most common single mistake.

### Never put secrets in environment variables

Anti-pattern:

```python
import os
DB_PASSWORD = os.environ['DB_PASSWORD']
```

The environment variable is set in the function's configuration. The configuration is visible to anyone with `lambda:GetFunctionConfiguration`. Many roles have it.

The right pattern: fetch from Secrets Manager / Key Vault / Secret Manager at runtime:

```python
import boto3
import json

def get_secret():
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId='prod/care-coordinator/db')
    return json.loads(response['SecretString'])

# At invocation time:
secret = get_secret()
db_password = secret['password']
```

For performance: cache outside the handler (warm starts reuse it):

```python
import boto3
import json

# Module-level cache; persists across warm invocations
_cached_secret = None
_cached_at = 0

def get_secret():
    global _cached_secret, _cached_at
    import time
    if _cached_secret is None or time.time() - _cached_at > 300:  # 5 min TTL
        client = boto3.client('secretsmanager')
        response = client.get_secret_value(SecretId='prod/care-coordinator/db')
        _cached_secret = json.loads(response['SecretString'])
        _cached_at = time.time()
    return _cached_secret
```

### Encrypt-at-rest is not enough

Some teams encrypt environment variables at rest (Lambda supports CMK-encrypted env vars). This protects the at-rest storage but doesn't protect against principals with `GetFunctionConfiguration`.

The fix: don't put secrets in env vars at all. Use secrets manager.

### What env vars are appropriate for

- Configuration parameters (timeouts, feature flags, region names).
- Service names / endpoints.
- Non-sensitive defaults.

Anything that would be sensitive on stdout is too sensitive for env vars.

---

## VPC integration

When Lambda needs to access VPC resources (RDS, ElastiCache, internal services), it can be configured to attach to a VPC.

### When VPC attachment is needed

- Function accesses a database in a private subnet.
- Function accesses internal services in the VPC.
- Function should be subject to NetworkPolicy / Security Group constraints.

### When VPC attachment isn't needed

- Function only calls public APIs (AWS service APIs, third-party SaaS).
- Function operates entirely on AWS-managed services via their public endpoints (S3, DynamoDB, etc.).

### Performance implications

- **Cold-start latency** with VPC: ~10-30 seconds historically; now ~1 second with Lambda's improved VPC networking.
- **Warm-start latency**: minimal.

Modern VPC-Lambda is performant; the security benefit of network isolation is worth it for VPC-accessing functions.

### The VPC configuration

```yaml
VpcConfig:
  SecurityGroupIds:
    - sg-care-coordinator-lambda
  SubnetIds:
    - subnet-private-app-1a
    - subnet-private-app-1b
    - subnet-private-app-1c
```

Multi-AZ for resilience. Security group is purpose-built; egress to only required destinations.

### Egress from VPC-attached Lambda

VPC-attached functions don't have direct internet access. They need:

- NAT Gateway for internet egress.
- VPC endpoints for AWS services (avoid NAT for AWS API calls).
- PrivateLink for SaaS where supported.

Per [../network-security/egress-control.md](../network-security/egress-control.md), egress is controlled through the VPC's egress fabric, not directly from the function.

---

## Function URLs

A direct HTTPS endpoint for Lambda functions. Convenient for some use cases; dangerous if misunderstood.

### When function URLs are appropriate

- **Webhook receivers** (Stripe, GitHub, Twilio): the vendor needs a stable HTTPS endpoint.
- **Public APIs** when API Gateway is overkill: simple internet-facing endpoints with no advanced routing.
- **Internal services in a Zero Trust network**: with appropriate authentication.

### When function URLs are wrong

- **For HTTP-routing-heavy APIs**: use API Gateway.
- **For authenticated APIs requiring complex auth**: use API Gateway with a JWT authorizer.
- **For rate-limited APIs**: use API Gateway with throttling.
- **For "I want a quick way to expose this"**: this is the dangerous pattern; the URL becomes a public attack surface.

### The function URL security baseline

- **Authentication required.** `AuthType: AWS_IAM` (caller signs the request with IAM credentials) or `AuthType: NONE` only if the function does its own auth.
- **AuthType: NONE means the URL is public.** Anyone on the internet can invoke. The function's IAM role then has the blast radius.
- **CORS configured restrictively.** Allowed origins are specific, not `*`.
- **No sensitive operations behind unauthenticated URLs.**

For most use cases: API Gateway provides better controls and the cost difference is negligible.

References:
- [AWS Lambda Function URLs](https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html)

---

## Dead-letter queues and error handling

When a function fails, what happens?

### The DLQ pattern

A Dead Letter Queue receives failed invocations:

- After N retries, the failed event lands in the DLQ.
- Team monitors the DLQ; investigates failures.
- Without a DLQ, failed events are lost.

### Security-relevant DLQ patterns

- **Poison-message detection.** A specific event repeatedly fails; investigate (could be application bug; could be malicious payload).
- **Replay-from-DLQ.** After fixing a bug, the DLQ events can be re-processed.
- **DLQ retention.** Events in DLQ have a TTL; verify the TTL allows for investigation time.

### DLQ as security signal

A sudden spike in DLQ volume can indicate:

- Application bug.
- Malicious traffic (attacker probing for failure modes).
- Upstream issue (event source sending malformed messages).

Detection on DLQ volume changes is a useful SOC signal.

---

## Cold-start and warm-start security

Lambda's lifecycle has security implications.

### Cold start

- New execution environment.
- Imports executed; module-level code runs.
- Secret fetching often happens here.
- 100ms-1s of latency typical.

### Warm start

- Existing environment reused.
- Module-level state persists.
- Secret cache hits.
- Few ms of latency.

### Security implications

**State persistence across invocations.** Module-level variables persist. If one invocation pollutes them, subsequent invocations see the pollution.

```python
# Anti-pattern: mutable global state
context = {}

def handler(event, context_arg):
    # Reads / writes context globally
    # Subsequent invocations see the previous state
    pass
```

The fix: avoid mutable global state; or reset at the start of each invocation.

**Secret-cache TTL alignment.** If secrets rotate every 90 days but the cache TTL is 30 days, the function uses old credentials for up to 30 days after rotation.

The fix: cache TTL ≤ rotation cadence (or much shorter, e.g., 5 minutes).

**Concurrent invocations.** Lambda can run many concurrent invocations of the same function in separate environments. They don't share state; per-environment state is per-environment.

---

## Cross-cloud comparison

### AWS Lambda

- Runtime support: Python, Node, Java, Go, Ruby, .NET, custom runtimes via Docker.
- Maximum runtime: 15 minutes.
- Memory: 128 MB - 10 GB.
- Cold-start: usually < 1s.

### Azure Functions

- Runtime support: similar; also supports F#, PowerShell, TypeScript.
- Maximum runtime: 10 minutes (Consumption); 60 minutes (Premium); unlimited (Dedicated).
- Memory: 1.5 GB - 14 GB (Premium).
- Cold-start: longer than Lambda historically; improved.

### GCP Cloud Functions

- Runtime support: Python, Node, Go, Java, .NET, Ruby, PHP.
- Maximum runtime: 9 minutes (HTTP triggers); 60 minutes (Pub/Sub triggers).
- Memory: 128 MB - 32 GB.
- Cold-start: similar to Lambda.

The security patterns transfer across all three; the operational details differ.

---

## Worked example: Meridian Health's Lambda posture

Meridian uses Lambda for event-driven workloads: data-ingestion pipelines, periodic batch jobs, webhook receivers, and ad-hoc workflows. ~200 Lambda functions across production accounts.

### Function inventory and ownership

- Every function tagged with `Workload`, `Owner`, `Environment`.
- Inventory queryable via Resource Groups and Cost Explorer.
- Per-quarter owner review (the team's name on each function).

### Per-function role discipline

- Every function has its own IAM role.
- Role naming: `lambda-<function-name>-role`.
- Roles created via Terraform; no hand-created functions.
- Quarterly IAM Access Analyzer pass; tightening based on actual usage.

### Environment-variable hygiene

- No secrets in env vars (verified by automated scanning).
- Secrets fetched from Secrets Manager at runtime, cached for 5 minutes.
- Env vars contain only non-sensitive config.

### VPC integration

- Functions that access RDS / ElastiCache attach to VPC.
- Functions that only call AWS APIs don't attach.
- VPC-attached functions egress via NAT Gateway → Network Firewall.

### Function URLs

- Five production functions have Function URLs (all webhook receivers: Stripe, GitHub, etc.).
- All use AuthType: AWS_IAM with HMAC validation in code; or AuthType: NONE with cryptographic webhook validation.
- CORS restricted to specific known origins.
- No "ad-hoc API" Function URLs; those use API Gateway.

### DLQ pattern

- Production functions have a DLQ (SQS).
- DLQ retention: 14 days.
- CloudWatch alarm on DLQ message volume; SOC investigates spikes.

### Findings opened during the Lambda audit

- **LMBD-001** (~40 functions had broad IAM roles from a "dev role" pattern). Closed by per-function roles + IAM Access Analyzer.
- **LMBD-002** (database passwords in env vars on 15 functions). Closed by migration to Secrets Manager.
- **LMBD-003** (3 Function URLs with `AuthType: NONE` and no application-layer authentication). Closed by adding HMAC validation; one URL replaced with API Gateway.
- **LMBD-004** (VPC-attached functions had over-broad security groups). Closed by per-function security groups.
- **LMBD-005** (5 production functions had no DLQ; failures were silently dropped). Closed by DLQ baseline.
- **LMBD-006** (mutable global state in 8 functions; cross-invocation pollution possible). Closed by code review and fix.

---

## Anti-patterns

### 1. The shared "dev role" for all functions

One role used by 30+ functions. The role accumulates permissions; least-privilege impossible.

The fix: per-function role; quarterly Access Analyzer review.

### 2. The env-var secrets

Database passwords, API keys in environment variables. Anyone with `GetFunctionConfiguration` can read.

The fix: secrets in Secrets Manager; fetch at runtime with module-level caching.

### 3. The unauthenticated Function URL

`AuthType: NONE` on a production function. The URL is public; the function's IAM role is the blast radius.

The fix: authentication required; or HMAC validation for webhook-pattern; or move to API Gateway.

### 4. The over-broad VPC security group

VPC-attached function's security group allows broad egress / ingress. Lateral movement enabled if function is compromised.

The fix: per-function security group; specific egress to specific destinations.

### 5. The forgotten DLQ

Function failures are silent; the DLQ isn't configured; the team has no signal.

The fix: DLQ on every production function; alerting on DLQ volume.

### 6. The mutable global state

Module-level variables mutated across invocations. Cross-invocation pollution; specifically problematic for tenant-isolated workloads (one tenant's data leaks to another).

The fix: avoid mutable globals; reset at handler entry; tenant-context explicit per invocation.

### 7. The function-URL-as-API

Function URLs used to expose APIs. Lack of API Gateway features (rate limiting, request validation, WAF integration).

The fix: API Gateway for APIs; Function URLs for specific webhook-receiver patterns.

### 8. The deprecated-runtime-version

Functions running on Python 3.7 (deprecated). Security updates aren't applied; the runtime is end-of-life.

The fix: automated runtime-version monitoring; upgrade per quarter; deprecate functions on old runtimes.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| LMBD-001 | Shared IAM role across multiple functions; least-privilege impossible | High | Per-function role; IAM Access Analyzer pass per quarter | Security Eng + DevOps |
| LMBD-002 | Secrets in environment variables | High | Migrate to Secrets Manager; fetch at runtime with caching | Application Eng + Security Eng |
| LMBD-003 | Function URL with `AuthType: NONE` and no application-layer auth | High | Add authentication (IAM, HMAC, or migrate to API Gateway) | Application Eng + Security Eng |
| LMBD-004 | VPC-attached function has over-broad security group | Medium | Per-function security group; narrow egress | Platform Eng + Security Eng |
| LMBD-005 | Production functions lack DLQ; failures silent | Medium | DLQ baseline; alerting on volume | Platform Eng + SRE |
| LMBD-006 | Mutable global state in function code; cross-invocation pollution | High | Avoid mutable globals; tenant-context explicit | Application Eng + Security Eng |
| LMBD-007 | Function on deprecated runtime version | High | Automated monitoring; quarterly runtime upgrade | DevOps + Security Eng |
| LMBD-008 | No function-inventory ownership; functions accumulate without owners | Medium | Per-function `Owner` tag; quarterly review | Platform Eng + Engineering Lead |
| LMBD-009 | Function timeout set too high; resource exhaustion risk | Low | Tune to actual requirement; lowest reasonable value | DevOps + Application Eng |
| LMBD-010 | Function reserved concurrency unbounded; cost-DoS risk | Medium | Per-function concurrency limits | DevOps + FinOps |
| LMBD-011 | CloudWatch / Application Insights logs not consumed by SIEM | Medium | SIEM ingestion; detection rules on function patterns | Security Eng + SOC |
| LMBD-012 | Lambda environment-variable encryption uses provider-managed key | Low | Migrate to CMK for sensitive deployments | Security Eng |
| LMBD-013 | Function code in source control without secret scanning | High | Gitleaks / TruffleHog per [../secrets-and-keys/secret-detection.md](../secrets-and-keys/secret-detection.md) | DevOps + Security Eng |
| LMBD-014 | Function dependencies not scanned for vulnerabilities | Medium | Trivy / Snyk for layers and packages | DevOps + Security Eng |
| LMBD-015 | Function URL allows `*` in CORS | Medium | Restrict to specific origins; document approved set | Application Eng + Security Eng |
| LMBD-016 | Function deployed via hand-edit rather than IaC | Medium | IaC for all production functions; admission gate | DevOps |
| LMBD-017 | Function role's trust policy missing `aws:SourceAccount` condition | Low | Add condition; defense against confused-deputy | Security Eng + IAM Eng |
| LMBD-018 | Cross-account event-source invokes function without explicit policy | High | Function resource policy specifies allowed event-source ARNs per [event-source-security.md](./event-source-security.md) | Security Eng + DevOps |

---

## What this document is not

- **A serverless tutorial.** Working familiarity with Lambda / Functions / Cloud Functions is assumed.
- **A vendor comparison.** AWS / Azure / GCP serverless are mentioned; the choice belongs with broader cloud decisions.
- **An IAM deep dive.** [serverless-iam-patterns.md](./serverless-iam-patterns.md) covers IAM-specific patterns.
- **An event-source reference.** [event-source-security.md](./event-source-security.md) covers event-source policies.
