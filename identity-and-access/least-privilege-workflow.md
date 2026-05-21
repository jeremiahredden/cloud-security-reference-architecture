# Least Privilege Workflow

A practitioner's reference for the iterative workflow that takes an AWS IAM role from "over-privileged because we did not know what it needed" to "scoped to the specific actions and resources actually in use" — the CloudTrail → IAM Access Analyzer → policy generation → review → tighten loop. The document is structured as a runbook because every team I have worked with runs this work quarterly, and the value comes from the workflow being repeatable rather than from a one-time tightening pass.

The companion documents are [workload-identity.md](./workload-identity.md) (for the credentials that the roles materialize) and [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) (for the SCP layer that bounds what any role in the Organization can do, regardless of policy).

---

## Why least privilege is a workflow

The most common failure mode in IAM design is treating least privilege as a destination — a state the role reaches once and stays at — rather than as a workflow that runs continuously. The destination framing produces three predictable failures:

1. **Roles that were tight at creation drift as the application evolves.** A role created for a Lambda function that read from one S3 bucket becomes the role for a Lambda function that reads from four S3 buckets and writes to two DynamoDB tables. The original IAM policy was not updated; instead, the engineer added a `*` action when the first new permission was needed. By month six, the role has `s3:*` and `dynamodb:*` because every change widened the policy.

2. **Roles that were created with broad policies "until we know what we need" never get tightened.** The engineer's intent was to tighten later; the later never comes because there is no scheduled review and no detection that the role is still broad. Six months pass; the role is still `*:*` on the action and `*` on the resource; an incident reveals the breadth.

3. **Roles drift in a direction that no single change would justify.** Each change to the policy is locally reasonable ("we need this action to make the new feature work"); the cumulative breadth is not reasonable but no review surfaces it because the reviewers only see one change at a time.

The workflow framing treats least privilege as a recurring activity, not a one-time event. The role is tightened, the application changes, the role drifts wider, the workflow runs again and tightens it again. The runbook below is structured so the workflow takes one engineer-day per quarter per workload account; the cost is modest enough that it actually happens.

The strongest pattern is to run the workflow on a schedule (quarterly is the right cadence for most environments) and to make the workflow's output a list of pull requests rather than a list of tickets. PRs are reviewed and merged or rejected in the normal engineering flow; tickets accumulate in a queue.

---

## The mental model

AWS IAM has four layers of authorization, evaluated together for every API call:

```
                                AWS API Call
                                      │
                                      ▼
                          ┌───────────────────────┐
                          │                       │
                          │   Is the call allowed │
                          │   under ALL of:       │
                          │                       │
                          │   1. SCP attached to  │
                          │      the OU?          │
                          │                       │
                          │   2. Permission       │
                          │      Boundary on the  │
                          │      principal?       │
                          │                       │
                          │   3. Identity policy  │
                          │      attached to the  │
                          │      principal?       │
                          │                       │
                          │   4. Resource policy  │
                          │      on the target    │
                          │      resource?        │
                          │                       │
                          │   (Cross-account also │
                          │    requires Allow in  │
                          │    both accounts)     │
                          │                       │
                          └───────────────────────┘
                                      │
                          ┌───────────┴───────────┐
                          ▼                       ▼
                      ALLOWED                 DENIED
                  (default-deny if            (default if
                   not explicitly allowed     any explicit
                   in any layer)              Deny anywhere)
```

The least-privilege workflow operates primarily on layer 3 (the identity policy). The outer layers (SCP, Permission Boundary) are guardrails that cap what the identity policy can grant; the inner layer (resource policy) is set per-resource by the resource's owner. The identity policy is the policy whose breadth the team actually controls and whose breadth the workflow tightens.

The four layers compose multiplicatively. A principal can take action A if and only if A is permitted by the SCP *and* by the Permission Boundary *and* by the identity policy *and* (for cross-account / cross-service operations) by the resource policy. A `Deny` in any layer blocks the action. This means tightening any one layer makes the system stricter; loosening any one layer does not necessarily make the system more permissive (because another layer may still deny).

References:
- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [Permission Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)

---

## When to read this document

**If you are tightening an existing role you suspect is over-privileged** — start with [Step 1 — Establish the baseline](#step-1--establish-the-baseline). Run the procedure once on the role; do not try to fix every role at once.

**If you are designing a new role** — skip to [Designing new roles](#designing-new-roles). The least-privilege-by-construction pattern is cheaper than retrofitting.

**If you are setting up the quarterly review program** — start with [The quarterly review cadence](#the-quarterly-review-cadence).

**If you are auditing an environment's least-privilege posture** — start with [Findings checklist](#findings-checklist).

---

## The IAM Access Analyzer toolkit

AWS IAM Access Analyzer provides three distinct analyzers as of 2026, plus a policy-generation feature. The workflow uses all four.

### External access analyzer

Identifies resources in the account (or Organization) that are accessible from outside the trust zone. "Outside" means another AWS account, an AWS service, a federated identity, or the public internet. Findings include:
- S3 buckets with policies that allow external AWS accounts.
- IAM roles whose trust policies allow external principals.
- KMS keys with key policies that allow external principals.
- Secrets Manager / SQS / SNS resources with resource policies that allow external access.

Use this analyzer to catch the unintentional external access — a bucket that was made temporarily public for a migration and was never re-closed, a cross-account role with a trust policy that names the entire other account, an SNS topic with a wildcard principal.

### Unused access analyzer

Identifies IAM users, roles, access keys, and permissions that have not been used recently. "Recently" is configurable (default 90 days). Findings include:
- IAM users with no console or programmatic activity in the period.
- IAM roles never assumed in the period.
- Access keys never used in the period.
- Permissions granted to a role but never exercised in the period.

The unused-permissions findings are the key input to the tightening workflow. The analyzer tells you which actions on which resources a role actually used; the actions and resources it did not use can be removed from the policy.

### Custom policy checks

Allows the team to define policy-checks as code: "this role should not have `*` in any action," "this role should not allow access to PHI buckets," "this role should not allow `iam:PassRole`." Findings appear when a new or modified policy violates a check. Use this to enforce organizational standards on IAM policy text.

### Policy generation

Generates an IAM policy from CloudTrail history. The pattern: select a role, select a time range (default 90 days, max 365), and IAM Access Analyzer reads the role's CloudTrail events and synthesizes a policy that grants exactly the actions and resources the role used. The generated policy is a tight baseline that can be reviewed and adopted as the role's new policy.

This is the single highest-leverage feature in IAM Access Analyzer for the tightening workflow. The generated policy is the starting point for the new policy text; the engineer reviews it, removes anything they do not want to encode permanently (e.g., one-off operations that should not be part of the role), and adopts it.

References:
- [IAM Access Analyzer findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Generate policies based on access activity](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_generate-policy.html)

---

## The runbook

The runbook below is structured as a numbered sequence. Run it once per role per quarter (or more frequently for high-privilege roles).

### Step 1 — Establish the baseline

Before tightening, capture the role's current state. Three artifacts:

1. **The current policy.** Export the role's attached policies and inline policies as a single document.

```bash
ROLE_NAME=PatientApiRole

# Inline policies.
aws iam list-role-policies --role-name "$ROLE_NAME" \
  --output json | jq -r '.PolicyNames[]' | \
  while read policy; do
    aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$policy" \
      --output json > "current-${policy}.json"
  done

# Attached managed policies.
aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --output json | jq -r '.AttachedPolicies[] | .PolicyArn' | \
  while read arn; do
    version=$(aws iam get-policy --policy-arn "$arn" \
      --output json | jq -r '.Policy.DefaultVersionId')
    aws iam get-policy-version --policy-arn "$arn" --version-id "$version" \
      --output json > "current-managed-$(basename $arn).json"
  done
```

2. **The role's CloudTrail history.** This is what IAM Access Analyzer's policy generation will read. Confirm the role has been active in the time range you intend to use (at least 30 days, preferably 90).

3. **The role's trust policy.** The trust policy is separate from the permissions policy; both need review.

```bash
aws iam get-role --role-name "$ROLE_NAME" \
  --output json | jq '.Role.AssumeRolePolicyDocument' > "trust-policy.json"
```

The baseline captures the current state. Subsequent steps compare against it.

### Step 2 — Run policy generation

Use IAM Access Analyzer's policy generation against the role.

```bash
# Start the policy generation job. The job runs asynchronously.
aws accessanalyzer start-policy-generation \
  --policy-generation-details "principalArn=arn:aws:iam::123456789012:role/$ROLE_NAME" \
  --cloud-trail-details "trails=[{cloudTrailArn=arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail,regions=[us-east-1,us-west-2]}],accessRole=arn:aws:iam::123456789012:role/AccessAnalyzerCloudTrailRole,startTime=2026-02-21T00:00:00Z"
```

The job typically completes in 15-60 minutes for a moderately-active role. Retrieve the result:

```bash
JOB_ID=<from-start-output>
aws accessanalyzer get-generated-policy --job-id "$JOB_ID" \
  --output json > "generated-policy-${ROLE_NAME}.json"
```

The output is a generated policy that grants exactly the actions and resources the role used in the time range.

### Step 3 — Review the generated policy

The generated policy is a starting point, not a final answer. Review checklist:

- **Are all the actions in the policy ones the role *should* be doing?** Sometimes the role exercised an action that it should not have (e.g., a debug action that someone left in production). Remove those from the policy and investigate why the role exercised them.
- **Are all the resources in the policy ones the role *should* be accessing?** A role that accessed bucket A and bucket B but should only have access to bucket A had a misuse; the new policy should grant only bucket A.
- **Are there actions the role *should* be doing in the future that are not in the generated policy?** A role that has not exercised an action in the time range, but is intended to exercise it in the future (a scheduled monthly action that did not run during the period), needs the action added.
- **Are there one-off actions that should not be encoded permanently?** A role that was used to perform a one-off migration in the time range will have the migration's actions in its generated policy; those should be removed if the migration is not a recurring operation.

The review takes 15-60 minutes per role for an engineer who knows the workload.

### Step 4 — Compare to the current policy

Diff the generated policy against the current policy. The differences fall into three categories:

| Category | What it means | Action |
| --- | --- | --- |
| **In current, not in generated** | Permissions the role has but did not use | Likely candidates for removal. Verify they are not for upcoming features. |
| **In generated, not in current** | Permissions the role used but does not explicitly have | Often means the role had a broader permission (`*`) that covered this; the generated policy is more specific. |
| **In both, same** | Permissions the role both has and uses | Keep. |

The first category is the value. Most over-privileged roles have a long list of "permissions held but not used" that the generated policy lets you remove safely.

### Step 5 — Tighten the trust policy

The trust policy is often more permissive than necessary. Common issues:

- **Trust policy names the entire other account** (`arn:aws:iam::123456789012:root`) rather than a specific role in the other account. Tighten to a specific role.
- **Trust policy lacks `ExternalId` for third-party access.** If the trust is for a third-party SaaS, add an `ExternalId` condition.
- **Trust policy lacks MFA for human assume.** For roles assumed by humans (rather than by services), add a `Bool` condition on `aws:MultiFactorAuthPresent`.
- **Trust policy allows the AWS service principal as a wildcard** (e.g., `"Service": "ec2.amazonaws.com"` when only one specific instance should assume). Add a condition on `aws:SourceArn` to scope to specific instances or instance profiles.

### Step 6 — Test the new policy

Before applying the new policy to production, test it. Three patterns:

1. **IAM Policy Simulator.** AWS provides a simulator that evaluates whether a given policy would allow or deny specific API calls. Useful for verifying that the new policy still allows operations the role needs.

```bash
aws iam simulate-custom-policy \
  --policy-input-list "$(cat new-policy.json)" \
  --action-names "s3:GetObject" "s3:PutObject" "dynamodb:Query" \
  --resource-arns "arn:aws:s3:::meridian-phi-bucket/*" "arn:aws:dynamodb:*:*:table/patient-records"
```

2. **Shadow mode.** Apply the new policy in a staging environment first. Run the workload against the staging environment for a week; observe whether any API calls fail with `AccessDenied`.

3. **Production canary.** If staging coverage is incomplete, apply the new policy to a single workload instance in production while the others run with the old policy. Monitor CloudTrail for `AccessDenied` errors from the canary; if none appear for the canary period (typically 1 week), roll out to the remaining workloads.

### Step 7 — Apply the new policy

Apply via the team's normal IaC pipeline (Terraform, CloudFormation, etc.). The policy change should be a pull request, reviewed and approved like any other code change. The PR description should reference:
- The role being tightened.
- The previous policy and the new policy (or a link to the diff).
- The IAM Access Analyzer job ID for traceability.
- The test method (simulator, shadow mode, canary).
- The roll-back plan if the policy turns out to be too tight.

### Step 8 — Monitor for AccessDenied errors

For the first 30 days after the policy change, monitor CloudTrail for `AccessDenied` errors from the role.

```sql
-- Athena query against CloudTrail logs.
SELECT eventTime, eventName, errorCode, errorMessage, resources, userIdentity.arn
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%PatientApiRole%'
  AND errorCode = 'AccessDenied'
  AND eventTime > current_timestamp - interval '7' day
ORDER BY eventTime DESC
LIMIT 100;
```

If the role hits `AccessDenied` for an action it should have, add the action back to the policy. If the role hits `AccessDenied` for an action that the policy correctly excludes, the work is to fix the application (not the policy).

### Step 9 — Document and schedule the next run

The output of one cycle is the input of the next:

- Update the role's documentation with the new policy text and the rationale.
- Record the time range used for the policy generation.
- Schedule the next quarterly review for the role.

The documentation is important. A role that has been tightened without documentation looks indistinguishable from a role that was always tight; the next engineer to look at it has no context for why the policy is what it is. Brief documentation ("Tightened on 2026-05-21 using CloudTrail data from 2026-02-21 to 2026-05-21; PR #1247") is enough.

---

## Permission Boundaries

Permission Boundaries are the layer that caps what a principal's identity policy can grant. They are particularly valuable for:

1. **Developer self-service.** Developers can create IAM roles for their workloads, but the roles cannot exceed what the Permission Boundary allows. This lets the platform team allow self-service without granting developers the authority to escalate privileges.

2. **Service-creation roles.** A role used by a CloudFormation stack or Terraform pipeline that creates other roles. The Permission Boundary on the service-creation role ensures the created roles cannot exceed a known scope.

### The mental model

```
       SCP at OU                  (outer cap, set by the platform team)
            │
            ▼
       Permission Boundary        (cap per principal, set by the platform team)
            │
            ▼
       Identity Policy            (grant, set by the role's author)
            │
            ▼
       Effective Permissions      (the intersection of all three)
```

### A worked Permission Boundary

A Permission Boundary for a "developer can create any role for any workload" pattern:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowMostServicesExceptDangerous",
      "Effect": "Allow",
      "NotAction": [
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:DeleteUser",
        "iam:UpdateAccountPasswordPolicy",
        "organizations:*",
        "account:*",
        "billing:*",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:DeleteAlias",
        "sso-admin:*",
        "identitystore:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyResourceWildcardOnSensitiveServices",
      "Effect": "Deny",
      "Action": [
        "s3:*",
        "dynamodb:*",
        "rds:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {"aws:ResourceTag/Sensitive": "true"}
      }
    },
    {
      "Sid": "RequirePermissionBoundaryOnCreatedRoles",
      "Effect": "Deny",
      "Action": [
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/DeveloperPermissionsBoundary"
        }
      }
    }
  ]
}
```

The third statement is critical: it requires that any role the developer creates *also* has this Permission Boundary attached. Without this, a developer with `iam:CreateRole` could create a role without a boundary, attach broader permissions to the new role, assume the new role, and escalate. The recursive boundary closes the escalation path.

### Where Permission Boundaries belong

Permission Boundaries belong on:
- Developer roles in non-production accounts where engineers have IAM permissions.
- Service-creation roles that create other roles (CloudFormation execution roles, Terraform CI roles).
- Cross-account roles assumed by external parties (third-party SaaS, vendor consultants).

Permission Boundaries are usually overkill for:
- Lambda execution roles, EKS pod roles, ECS task roles — these are workload roles with narrow scope; the identity policy already does the scoping.
- Roles assumed only by humans through IAM Identity Center — the permission set already does the scoping at the Identity Center layer.

References:
- [Permission Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [Delegating IAM permission management](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries-delegate.html)

---

## Designing new roles

The retrofitting workflow above is for existing over-privileged roles. New roles should be built tight from the start.

The pattern for new roles:

1. **Start with the operations the role will perform.** Write them out in plain English: "this role will read from these specific S3 prefixes, write to these specific DynamoDB tables, and decrypt with this specific KMS key."

2. **Translate to IAM actions and resources.** For each operation, identify the specific IAM action (`s3:GetObject`, `dynamodb:Query`, `kms:Decrypt`) and the specific resource (the bucket ARN, the table ARN, the key ARN).

3. **Write the policy.** No `*` on actions; no `*` on resources without a condition. Use AWS-managed policies sparingly — they are convenient and almost always too broad.

4. **Run the policy through `iam:SimulatePrincipalPolicy`.** Verify the policy allows the intended operations.

5. **Run the policy through IAM Access Analyzer's policy validation.** The validator catches common mistakes (missing fields, deprecated actions, formatting errors) and surfaces warnings about overly-permissive statements.

6. **Deploy and observe.** For the first 30 days after the role is in use, monitor for `AccessDenied` errors. Tighten or loosen as needed.

The starting-tight pattern is much cheaper than the starting-broad-and-tightening pattern, but it requires more design effort up-front. The trade-off is worth it for any role that will exist for more than a few months.

---

## The quarterly review cadence

The recurring review is what keeps least privilege a workflow rather than a one-time pass. The cadence:

**Quarterly per workload.** Each workload account has one or more IAM roles that are the primary identities for its services. Run the workflow on each of those roles once per quarter. For most workloads, this is 3-8 roles per account per quarter, which is one engineer-day per workload.

**Triggered on policy changes.** Any pull request that modifies an IAM policy should trigger the IAM Access Analyzer's policy validation. The validation runs in CI; the PR fails if the validation reports new findings.

**Triggered on Access Analyzer findings.** External-access findings and unused-access findings should be reviewed weekly. Findings that are valid get sprint assignments; findings that are false positives get explicit exception documentation.

**Annual full sweep.** Once per year, the platform team runs the workflow against every role in the Organization (or every role in the highest-privilege accounts). The annual sweep catches roles that have not been touched in regular quarterly reviews — typically utility roles, legacy roles from migrations, third-party SaaS access roles.

The cadence's value compounds. After two years of quarterly reviews, the Organization's IAM posture is materially tighter than it would be without the discipline; after five years, the difference is measured in incident frequency.

---

## Worked example: Meridian Health's quarterly review

Meridian Health (the fictional regulated SaaS) runs the quarterly review across all production accounts. The Q2 2026 review for the `meridian-prod-phi-store` account:

**Roles reviewed:** 7 roles (PatientApiRole, PHIIngestionLambdaRole, BackupServiceRole, AnalyticsExportRole, AuditReadRole, IncidentResponseRole, BreakGlassRole).

**Findings:**
- PatientApiRole: 32% of its statements were unused in the 90-day window. The generated policy was 18 statements instead of the current 26. PR merged.
- PHIIngestionLambdaRole: All statements used. No changes.
- BackupServiceRole: The role had `s3:*` on a bucket where it actually only used `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`. Tightened. PR merged.
- AnalyticsExportRole: Had unused `dynamodb:*` from a deprecated feature. The deprecated feature was confirmed; PR merged removing the unused permissions.
- AuditReadRole: All statements used. The role's purpose is broad read access, which the team accepted as the intended scope.
- IncidentResponseRole: Had unused destructive permissions (`s3:DeleteObject`, `rds:DeleteDBInstance`) that the team decided to keep for emergency response purposes. Documented as an intentional exception with the rationale.
- BreakGlassRole: Reviewed but not tightened; the break-glass role is intentionally broad and its protection is the alarm on its use, not the scope of its permissions.

**Effort:** Approximately 4 engineer-hours for one platform-engineer who was familiar with the workloads.

**Outcome:** Three roles tightened; one role's broad permissions documented as intentional; net policy-statement count across the account dropped by ~18%.

The Q3 2026 review repeats the workflow. Some roles will have drifted since Q2 (especially PatientApiRole, which is actively developed); some will be unchanged. The drift is the value — without the quarterly review, the drift accumulates indefinitely.

---

## Findings checklist

Findings IDs use the `LPV-` prefix (least privilege).

| ID | Finding | Severity | Remediation |
| --- | --- | --- | --- |
| LPV-001 | Role has `*` on action | High | Use IAM Access Analyzer policy generation; replace `*` with specific actions. |
| LPV-002 | Role has `*` on resource without conditioning | High | Add resource ARNs or condition the wildcard. |
| LPV-003 | Trust policy names entire account, not specific role | Medium | Tighten trust to specific role ARN. |
| LPV-004 | Cross-account trust policy lacks ExternalId for third-party | Medium | Add ExternalId condition. |
| LPV-005 | Trust policy allows any AWS service principal of given type | Medium | Add `aws:SourceArn` condition. |
| LPV-006 | Role has `iam:PassRole` to `*` resource | High | Scope PassRole to specific role ARNs. |
| LPV-007 | Role attaches AWS-managed policy that is broader than needed | Medium | Replace with custom policy from Access Analyzer generation. |
| LPV-008 | Role has unused permissions (90-day window) | Low to High | Run Access Analyzer; remove unused permissions per generation. |
| LPV-009 | Developer can create IAM roles without Permission Boundary | High | Add Permission Boundary enforcement to the developer role. |
| LPV-010 | External-access finding in Access Analyzer not reviewed | Variable | Review weekly; remediate or document exception. |
| LPV-011 | Policy validation findings ignored | Medium | Run validation in CI; fail PRs with new findings. |
| LPV-012 | Role has not been reviewed in last 6 months | Medium | Schedule for next quarterly review. |
| LPV-013 | Resource policy on shared resource is overly permissive | High | Tighten resource policy to specific principals. |
| LPV-014 | `iam:PutRolePolicy` granted to non-platform principal | Critical | Move IAM authoring to the platform team or to IaC pipelines. |
| LPV-015 | Role's last-used data shows no usage in > 180 days | Medium | Confirm consumer; consider deletion. |

---

## Anti-patterns

**Anti-pattern 1: The "we will tighten it later" deferral.** A new role is created with broad permissions; the engineer commits to tightening later; later never comes. Corrective: tighten on creation, not later. The starting-broad approach is structurally worse than the starting-tight approach.

**Anti-pattern 2: The AWS-managed-policy reflex.** When a role needs S3 access, attach `AmazonS3FullAccess` from the managed policy library. Failure mode: the role has access to every S3 bucket in the account. Corrective: AWS-managed policies are starting points, not destinations. Replace with custom policies as soon as the role's specific needs are known.

**Anti-pattern 3: The "shared role across workloads" pattern.** A single IAM role attached to multiple Lambda functions, ECS tasks, or EKS deployments. Failure mode: the role's permissions are the union of every consumer's needs; a compromise of any consumer leaks the full union. Corrective: per-workload roles.

**Anti-pattern 4: The `*` on every action because typing the actions is tedious.** Engineers' time is valuable, and writing `s3:GetObject` plus `s3:PutObject` plus `s3:ListBucket` is more effort than `s3:*`. Failure mode: the convenience compounds into systemic over-permission. Corrective: use IAM Access Analyzer's policy generation; the tool does the typing.

**Anti-pattern 5: The unreviewed external-access findings.** IAM Access Analyzer emits external-access findings; nobody reviews them. Failure mode: a misconfigured bucket policy that grants external access goes unnoticed until an incident reveals it. Corrective: review the findings weekly; the review can take 15-30 minutes per week and surfaces issues that would otherwise become incidents.

**Anti-pattern 6: The "PassRole to everything" pattern.** A role has `iam:PassRole` on `*`. Failure mode: the role can pass any role to any service, allowing privilege escalation by passing a higher-privileged role to a service the attacker controls. Corrective: scope PassRole to specific role ARNs.

**Anti-pattern 7: The "skip validation in CI" shortcut.** IAM policy changes are merged without running policy validation in CI. Failure mode: typos in policy text, missing fields, or deprecated actions produce policies that do not behave as expected; problems surface in production. Corrective: validation is a CI gate; PRs fail when validation reports new findings.

**Anti-pattern 8: The break-glass-as-daily-driver.** The break-glass role is broad on purpose; some engineers use it for routine operations because it is the easiest path. Failure mode: the protection on break-glass (alarms on use) generates so many alerts that the alerts are ignored; when a real break-glass use happens, it is buried in noise. Corrective: enforce that break-glass is exceptional; the use alarm should be high-priority and the use itself should require an incident-ticket reference.

---

## Further reading

- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Generate IAM policies based on access activity](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_generate-policy.html)
- [Permission Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [IAM policy simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
- This repo:
  - [workload-identity.md](./workload-identity.md) — the role-creation patterns this workflow tightens.
  - [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) — the SCP layer that bounds what any tightened role can do.
  - [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) — the CloudTrail architecture that feeds the policy generation.
