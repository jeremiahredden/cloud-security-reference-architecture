# Serverless IAM Patterns

A practitioner's reference for least-privilege IAM specifically for serverless workloads — per-function roles (always), the "no role attached to multiple functions" baseline, the role-inheritance-via-environment-variable anti-pattern, and the IAM Access Analyzer workflow applied to function roles. The patterns here are about IAM as the primary serverless security control, given that the platform handles most other concerns.

This document is the IAM-deep companion to [lambda-functions-security.md](./lambda-functions-security.md) and [event-source-security.md](./event-source-security.md). The IAM discipline is the load-bearing control in serverless; this document is where the patterns live.

The honest framing: a serverless workload with weak IAM is a serverless workload with strong attack surface. Other patterns (event-source policies, function code, API Gateway) compose on top of IAM; if IAM is wrong, the other patterns can't compensate.

---

## When to read this document

**If your serverless workloads share IAM roles across functions** — read top to bottom.

**If you've tried IAM Access Analyzer for function roles and aren't sure what to do with the output** — start with [The Access Analyzer workflow](#the-access-analyzer-workflow).

**If you have functions that read configuration including role-ARNs from environment variables** — start with [The role-inheritance-via-env-var anti-pattern](#the-role-inheritance-via-env-var-anti-pattern).

**If you are auditing serverless IAM** — start with [Findings checklist](#findings-checklist).

---

## Why serverless IAM is more sensitive than IaaS IAM

The point worth being explicit about.

### The trigger surface

- An EC2 instance is triggered by team action (boot it, run a job).
- A Lambda function is triggered by events. The event surface is wide: HTTP requests, queue messages, scheduled events, cross-account invokes.

A function with broad permissions runs on every trigger; the trigger surface is large.

### The compactness

- An EC2 instance role grants permissions to a long-running compute.
- A Lambda role grants the same permissions to a fast-spinning compute that can execute thousands of times per second.

Compromise of a Lambda role is a more compact privilege-escalation primitive because the execution rate is high and the trigger surface is wide.

### The forgetting

- An EC2 instance is visible (running, costing money).
- A Lambda function in the deployment is easy to forget.

Sprawl of forgotten functions with forgotten roles is the long-tail risk.

### The implication

Serverless IAM gets the same discipline as production IAM — per-function roles, least-privilege, audit. The "it's just a Lambda" framing produces incidents.

---

## Per-function role baseline

The non-negotiable.

### Why one role per function

- **Per-function least-privilege:** each function gets exactly what it needs.
- **Per-function audit:** CloudTrail shows which function did what (the role identifies the function).
- **Per-function rotation:** a role change affects one function.
- **Per-function deletion:** removing a function removes its role.
- **No "the role grew because someone needed it":** function A's needs don't expand function B's role.

### What shared roles produce

- The "dev role" or "lambda-default" pattern. Many functions use it.
- Permissions accumulate (every function's needs added).
- The blast radius of any one function's compromise is the union of all permissions.
- Audit trail is muddled (which function made this call?).

### Naming convention

```
lambda-<function-name>-role
lambda-care-coordinator-event-processor-role
lambda-care-coordinator-cleanup-role
```

The naming makes the function-role relationship obvious.

### IaC discipline

- Every function is defined in IaC.
- Every function's role is in the same IaC module.
- The role is created with the function.
- The role is deleted when the function is deleted.

Hand-created functions and hand-created roles drift; IaC prevents.

---

## The minimum-viable function policy

The baseline permissions for any function.

### Logging permissions

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ],
    "Resource": "arn:aws:logs:us-east-1:ACCOUNT:log-group:/aws/lambda/<function-name>:*"
  }]
}
```

Restricted to the function's own log group. Not `logs:*` or `Resource: *`.

### X-Ray (if enabled)

```json
{
  "Effect": "Allow",
  "Action": [
    "xray:PutTraceSegments",
    "xray:PutTelemetryRecords"
  ],
  "Resource": "*"
}
```

X-Ray APIs don't support resource-level restrictions; `*` is the only option.

### VPC ENI permissions (if VPC-attached)

```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:CreateNetworkInterface",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DeleteNetworkInterface",
    "ec2:AssignPrivateIpAddresses",
    "ec2:UnassignPrivateIpAddresses"
  ],
  "Resource": "*"
}
```

VPC ENI permissions also don't support resource-level restrictions for most operations; `*` is necessary.

### KMS (for decrypting env vars / fetching secrets)

```json
{
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": "arn:aws:kms:us-east-1:ACCOUNT:key/SPECIFIC-CMK-ID"
}
```

Specific KMS key; not `*`.

### What the baseline does NOT include

- S3 actions (specific buckets only; on-demand).
- DynamoDB actions (specific tables only).
- Secrets Manager actions (specific secrets only).
- Network actions beyond VPC ENI.
- IAM actions of any kind (no `iam:*`).
- KMS actions beyond `Decrypt` on specific keys.

---

## Action and resource scoping

The granular pattern.

### Specific actions

For S3: `s3:GetObject` if read-only, `s3:GetObject` + `s3:PutObject` if write. Not `s3:*`.

For DynamoDB: `dynamodb:GetItem` + `dynamodb:Query`. Not `dynamodb:*`.

For SQS: `sqs:ReceiveMessage` + `sqs:DeleteMessage` for consumers; `sqs:SendMessage` for producers. Not `sqs:*`.

### Specific resources

For S3: `arn:aws:s3:::specific-bucket/*` (specific bucket); or `arn:aws:s3:::specific-bucket/prefix/*` (specific prefix). Not `arn:aws:s3:::*`.

For DynamoDB: specific table ARN. Not `*`.

For KMS: specific key ARN.

### Condition keys

For added scoping:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::care-coordinator-data/*",
  "Condition": {
    "StringEquals": {
      "aws:RequestedRegion": "us-east-1",
      "s3:DataAccessPointAccount": "ACCOUNT"
    }
  }
}
```

Conditions narrow further: same region, specific account access points, etc.

---

## The Access Analyzer workflow

The practical pattern for tightening roles based on actual usage.

### Step 1: deploy with broader policy

Initial deployment: the role has the permissions you think the function needs. Often slightly broader (uncertain at design time).

### Step 2: run for 30 days

The function executes; CloudTrail records every action. After 30 days: actual usage is visible.

### Step 3: invoke Access Analyzer

```bash
aws accessanalyzer start-policy-generation \
  --policy-generation-details '{"principalArn": "arn:aws:iam::ACCOUNT:role/lambda-care-coordinator-event-processor-role"}' \
  --cloud-trail-details '{"trails": [{"cloudTrailArn": "arn:..."}], "accessRole": "arn:..."}'
```

Analyzer reads CloudTrail; identifies actions actually used by the role; generates a policy.

### Step 4: review the generated policy

The generated policy might be:

- **Tighter than the deployed:** the function used less than was granted. Adopt the tighter version.
- **Same as deployed:** the deployment was already tight. No change.
- **Broader than deployed:** something's wrong (Analyzer found more uses than the deployment allowed; possibly a misread).

For most cases: the generated policy is tighter; adopt it.

### Step 5: deploy the tightening

- Test in dev / staging.
- Deploy to production.
- Monitor for new permission-denied errors (indicates the analyzer missed a usage).

### Step 6: quarterly cadence

Repeat for all functions quarterly. Permissions tighten over time as usage stabilizes.

References:
- [IAM Access Analyzer Policy Generation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html)

---

## The role-inheritance-via-env-var anti-pattern

A subtle but important anti-pattern.

### The pattern

Function code reads a role ARN from an environment variable and assumes it:

```python
import boto3

def handler(event, context):
    # The role ARN is in an env var
    role_arn = os.environ['ASSUMED_ROLE_ARN']
    
    sts = boto3.client('sts')
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName='function-call')
    
    # Now use the assumed role's credentials
    s3 = boto3.client('s3',
        aws_access_key_id=assumed['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
        aws_session_token=assumed['Credentials']['SessionToken']
    )
```

### Why this is bad

- The function's actual permissions are the assumed role's, not the function's role.
- IAM audit on the function role is misleading; the function does things its role doesn't directly grant.
- Misconfiguration of the env var = different role assumed.
- Modifying the env var (via Lambda permissions) = privilege escalation.

### The fix

The function's role should grant what the function needs. No env-var-driven role assumption.

If cross-account access is genuinely needed:

- Specify the target role in code (not env var).
- The function's role has `sts:AssumeRole` on that specific role ARN.
- Use a constant role ARN, not configurable.

### When this anti-pattern emerges

- Multi-tenant patterns where "each tenant has its own role; function assumes it."
- Cross-account ETL where "the source account's role is configured."
- The "we'll make it flexible" pattern.

For multi-tenant: per-tenant function (or per-tenant function configuration); not env-var role.

For cross-account: hardcoded; reviewed.

---

## The trust policy

Who can assume the function's role.

### The standard trust policy

```json
{
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

The `SourceAccount` condition prevents cross-account confused-deputy.

### What goes wrong without SourceAccount

If Lambda in account X is misconfigured to call Lambda in account Y (a rare but possible misconfig), and the role's trust policy doesn't restrict to account Y, an attacker who controls account X can invoke Y's function. Adding `SourceAccount: ACCOUNT-Y` prevents.

### Custom invokers

For functions invoked by specific cross-account principals:

```json
{
  "Principal": {
    "AWS": [
      "arn:aws:iam::ANALYTICS-ACCOUNT:role/analytics-invoke-role"
    ]
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "ArnEquals": {
      "aws:SourceArn": "arn:aws:iam::ANALYTICS-ACCOUNT:role/analytics-invoke-role"
    }
  }
}
```

Explicit principal; ArnEquals condition.

---

## Function-resource policies vs IAM-role policies

The distinction.

### The function role policy

What the function can do (S3, DynamoDB, etc.). Attached to the role.

### The function resource policy

Who can invoke the function. Attached to the function:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "apigateway.amazonaws.com"},
    "Action": "lambda:InvokeFunction",
    "Resource": "arn:aws:lambda:us-east-1:ACCOUNT:function:care-coordinator-event-processor",
    "Condition": {
      "ArnLike": {"aws:SourceArn": "arn:aws:execute-api:us-east-1:ACCOUNT:API-ID/*"}
    }
  }]
}
```

API Gateway can invoke this function from this specific API.

### Per-event-source resource policy entries

- API Gateway: per-API resource policy entry.
- SNS: SNS service + SourceArn (specific topic).
- SQS: typically configured via event source mapping (uses execution role of the queue's reader; or function role).
- EventBridge: EventBridge service + SourceArn (specific rule).

Each event source adds a resource policy entry. The inventory of invokers comes from this policy.

---

## Worked example: Meridian Health's serverless IAM

Meridian's serverless workloads follow per-function role + Access Analyzer tightening.

### Per-function roles

- 200+ Lambda functions; ~200 IAM roles.
- Naming convention: `lambda-<env>-<workload>-<function>-role`.
- Created via Terraform; deleted with function.

### Quarterly Access Analyzer pass

- Every quarter: run Access Analyzer against function roles.
- Generated policies reviewed; tightenings deployed.
- 80%+ of roles tightened over time.

### Cross-account access patterns

- A few functions need cross-account access (analytics, partner integrations).
- Each cross-account is documented: source account, target role, business justification.
- ExternalId on each assume-role; quarterly review.

### The role-inheritance-via-env-var ban

- Code review checks for env-var role ARNs.
- Detection rule in CI for the pattern.
- Findings opened on legacy functions; remediation tracked.

### Findings opened during the IAM audit

- **SVIAM-001** (30 functions shared a "lambda-dev-role"). Closed by per-function migration.
- **SVIAM-002** (no Access Analyzer cadence; roles drifted from actual usage). Closed by quarterly pass.
- **SVIAM-003** (5 functions had env-var-driven role assumption). Closed by hardcoding the cross-account role; tightening function's role.
- **SVIAM-004** (function trust policies lacked SourceAccount condition). Closed by Terraform template addition.
- **SVIAM-005** (no separation between "what function can do" and "what can invoke function"; resource policies missing). Closed by per-function resource policies for each invoker.
- **SVIAM-006** (KMS Decrypt granted to `*` instead of specific keys). Closed by per-CMK scoping.

---

## Anti-patterns

### 1. The shared "lambda-default" role

One role used by many functions. Permissions accumulate.

The fix: per-function roles; IaC discipline.

### 2. The role-from-env-var

Function reads role ARN from env var; assumes it. Misconfig = different role; lockdown bypassed.

The fix: hardcode the cross-account role; tighten function's own role.

### 3. The wildcard actions

`s3:*` or `dynamodb:*` or `lambda:*`. Function has every operation; least-privilege impossible.

The fix: specific actions per function; Access Analyzer tightening.

### 4. The wildcard resources

`Resource: "*"` instead of specific ARNs. Function can act on any resource of the action type.

The fix: specific ARNs; Access Analyzer.

### 5. The missing trust-policy condition

Trust policy lacks `SourceAccount`. Cross-account confused-deputy possible.

The fix: SourceAccount condition; or specific ArnEquals.

### 6. The resource-policy-without-source-condition

Function's resource policy says "API Gateway can invoke" without specifying which API. Any API Gateway in the account can invoke.

The fix: SourceArn condition specifying the specific API.

### 7. The no-Access-Analyzer-discipline

Function roles were generated by guesses. Actual usage is much narrower; the policy isn't tightened over time.

The fix: quarterly Access Analyzer pass.

### 8. The "deploy with admin and we'll tighten later"

Function deployed with admin-level role "temporarily." The tightening never happens.

The fix: deploy with specific permissions from day one; don't accept "we'll tighten later" as a path.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| SVIAM-001 | Shared IAM role across multiple Lambda functions | High | Per-function roles; IaC-managed; named by function | Security Eng + DevOps |
| SVIAM-002 | No Access Analyzer cadence; roles drift from usage | Medium | Quarterly Access Analyzer pass; deploy generated policies | Security Eng + IAM Eng |
| SVIAM-003 | Function code assumes role from environment variable | High | Hardcode cross-account roles; tighten function's own role | Application Eng + Security Eng |
| SVIAM-004 | Function trust policy lacks `aws:SourceAccount` condition | Medium | Add condition; defense against confused-deputy | Security Eng |
| SVIAM-005 | Function resource policies missing; cross-service invokers not constrained | High | Per-function resource policies with SourceArn conditions per invoker | Security Eng |
| SVIAM-006 | Function role has `kms:Decrypt` on `*` instead of specific keys | High | Per-CMK scoping; specific ARNs | Security Eng |
| SVIAM-007 | Function role has wildcard actions (e.g., `s3:*`, `dynamodb:*`) | High | Specific actions; Access Analyzer-driven tightening | Security Eng + Application Eng |
| SVIAM-008 | Function role has wildcard resources (`Resource: "*"`) | High | Specific ARNs; Access Analyzer-driven tightening | Security Eng + Application Eng |
| SVIAM-009 | Function deployed with admin role "temporarily" | High | Specific permissions from day one; admin roles forbidden by SCP | Security Eng + DevOps |
| SVIAM-010 | Function role missing logging permissions; CloudWatch unable to log | Low | Add minimum logging permissions to log group | DevOps |
| SVIAM-011 | Function role's permissions audit absent | Medium | Quarterly audit of function-role permissions | Security Eng |
| SVIAM-012 | Cross-account function invocation without ExternalId; confused-deputy possible | Medium | ExternalId in trust policies; documented | Security Eng + IAM Eng |
| SVIAM-013 | Function code uses access keys instead of IAM-bound role | High | Use the role; remove access keys; OIDC if external trigger | Application Eng + Security Eng |
| SVIAM-014 | Function role deleted but function not deleted | Low | Cascade delete in IaC; orphan-function detection | DevOps |
| SVIAM-015 | Function role permission usage not tracked; over-grants persist | Medium | Permission usage metrics; tracker | Security Eng |
| SVIAM-016 | IAM Access Analyzer findings not consumed by SOC | Low | Analyzer findings to SIEM; alerting | Security Eng + SOC |
| SVIAM-017 | Function resource policy allows `aws:Account` root invoke | Medium | Specific principals; condition on SourceArn | Security Eng |
| SVIAM-018 | New function deployment without IAM review | Medium | IaC gate; code review includes IAM | DevOps + Security Eng |

---

## What this document is not

- **A complete IAM policy reference.** AWS IAM documentation covers the depth.
- **A Lambda-specific feature reference.** Vendor docs cover.
- **A serverless tutorial.** Working familiarity assumed.
- **An Access Analyzer deep dive.** Tool-specific operational depth lives with vendor docs.
