# IAM Anti-Patterns

A practitioner's catalogue of the IAM patterns I always rip out — the configurations that look reasonable in a small environment, age badly, and become privilege-escalation primitives by year two. Each entry names the pattern, names why it appears (because it solved a real problem at the time), describes the failure mode, and prescribes the replacement.

This is the closing document in the identity-and-access folder. It cross-references back to [workforce-identity.md](./workforce-identity.md), [workload-identity.md](./workload-identity.md), [federation-patterns.md](./federation-patterns.md), [just-in-time-access.md](./just-in-time-access.md), [least-privilege-workflow.md](./least-privilege-workflow.md), and [service-account-hygiene.md](./service-account-hygiene.md). It exists because the same set of bad patterns recur across nearly every environment I review; documenting them in one place is more useful than scattering the warnings.

The honest framing: most of these aren't wrong because the engineer who wrote them was careless. They're wrong because the engineer who wrote them was solving a real problem (the broker integration needed access; the script needed credentials; the audit needed read-only access "to everything") and didn't think about the lifecycle. Six months later the situation has shifted; the pattern hasn't. Anti-patterns are debt; this document is the inventory and the payoff plan.

---

## When to read this document

**If you're auditing IAM posture and want a list of patterns to look for** — read top to bottom.

**If you've inherited an IAM environment that's "fine" but smells off** — start with [The structural anti-patterns](#the-structural-anti-patterns).

**If you're reviewing a specific IAM policy / trust policy** — scan [The policy-level anti-patterns](#the-policy-level-anti-patterns).

**If you want a checklist for remediation** — see [The remediation order](#the-remediation-order).

---

## The structural anti-patterns

The architecture-level patterns.

### 1. IAM users for human access in 2026

**The pattern:** AWS IAM users (with passwords, with access keys) used for human sign-in.

**Why it exists:** the easiest path on day one. "Just create an IAM user." Predates Identity Center for many environments.

**Why it's wrong:**
- Bypasses IdP conditional access (the IAM user isn't in the IdP).
- MFA enforcement is per-IAM-user, not policy-driven.
- Deprovisioning depends on someone remembering to delete the user.
- No central audit of who has access across N accounts.

**The replacement:**
- AWS IAM Identity Center federated to the corporate IdP per [workforce-identity.md](./workforce-identity.md).
- SCP blocks new IAM user creation per [workforce-identity.md](./workforce-identity.md).
- Existing IAM users migrated; deleted post-migration.

**Documented exceptions:**
- AWS service users (CodeCommit, etc.) where IAM user is required by the service.
- Break-glass account (sealed credentials, quarterly tested).

### 2. Service principals / service accounts with long-lived credentials when workload identity is available

**The pattern:** GCP service account with a JSON key file; Azure service principal with a client secret; AWS IAM user with an access key — used by a workload that could authenticate via the cloud's workload-identity mechanism.

**Why it exists:** workload identity is per-workload-specific (IRSA for EKS, managed identity for Azure VMs, etc.); easier to just hand the workload a credential file.

**Why it's wrong:**
- Long-lived credentials are exfiltratable.
- Rotation is operational overhead; often skipped.
- Compromise has no expiration.

**The replacement:**
- AWS: IRSA for EKS, Pod Identity for EKS (newer), execution roles for Lambda, instance profiles for EC2. Per [workload-identity.md](./workload-identity.md).
- Azure: managed identity (system or user-assigned), federated identity credential for external workloads.
- GCP: attached service account for GCP workloads, Workload Identity Federation for external workloads.

**Documented exceptions:**
- External workloads that don't yet support OIDC federation; wrap credentials in secrets manager, rotate frequently.

### 3. SCP / IAM-policy gaps in the management account

**The pattern:** the AWS management account ("organization root") is treated as just another account with full permissions. Standing-admin in the management account.

**Why it exists:** the management account is where AWS Organizations and the org-level Service Control Policies live; admin access feels appropriate.

**Why it's wrong:**
- Compromise of the management account = total org takeover.
- Standing admin in the management account = high-blast-radius credential.
- The management account often hosts billing / payment-method credentials.

**The replacement:**
- Zero workloads in the management account; only org-level governance (SCPs, AWS Organizations).
- Standing-admin count in the management account = 0 (only break-glass).
- All admin access JIT-elevated per [just-in-time-access.md](./just-in-time-access.md).
- Per-principal MFA + phishing-resistant factor.
- SCP at the org level denies the management account's principals from performing workload actions (defense in depth against accidental workload placement).

### 4. Per-account silos without org-level controls

**The pattern:** an AWS Organization exists but the SCPs are minimal / empty; per-account governance is delegated entirely to the account owner.

**Why it exists:** "we want to give teams autonomy."

**Why it's wrong:**
- Some controls must be org-level (root user MFA, region restrictions, denying account-level CloudTrail disable).
- Per-account hygiene varies; the worst account becomes the attack surface.
- No defense-in-depth against compromised account principals.

**The replacement:**
- Baseline SCP set at the org root per [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md).
- Per-OU SCPs for specific workload categories.
- Org-level guardrails non-negotiable; per-account autonomy on what they additionally enable.

### 5. Cross-account access via long-lived access keys

**The pattern:** account A's resources accessed from account B by storing an IAM access key from account A in account B's secrets manager.

**Why it exists:** historical; before role assumption was the obvious pattern.

**Why it's wrong:**
- Long-lived credentials; rotation overhead.
- The access key in account B's secrets manager is the bearer-token equivalent of the IAM user in account A.

**The replacement:**
- AssumeRole across accounts; the role in account A has a trust policy permitting the calling principal in account B.
- Per-call short-lived credentials.
- The trust relationship is the audit trail.

### 6. Federation to multiple IdPs without consolidation

**The pattern:** AWS Identity Center federated to Okta; some accounts have direct SAML to Entra ID; one account has direct SAML to Auth0.

**Why it exists:** organic growth; mergers; each new federation set up by whoever needed it that quarter.

**Why it's wrong:**
- Multiple IdP-to-cloud trust relationships; multiple potential compromise paths.
- Conditional access policies differ per IdP; some accounts have weak controls.
- Audit complexity.

**The replacement:**
- One IdP as the source of truth.
- All cloud federation through that IdP.
- Migration of legacy federations to the consolidated path.

---

## The policy-level anti-patterns

The patterns visible in IAM policy JSON.

### 7. `Resource: "*"` with broad Action

**The pattern:**
```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
```

**Why it exists:** "the team needs to work with S3"; resource-scoping seemed like over-engineering.

**Why it's wrong:**
- Grants access to every S3 bucket; future-buckets included.
- A compromised principal with this policy has full S3 access in the account, including buckets for unrelated workloads.

**The replacement:**
```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
  "Resource": [
    "arn:aws:s3:::specific-bucket-name",
    "arn:aws:s3:::specific-bucket-name/*"
  ]
}
```

Use IAM Access Analyzer to identify roles using this pattern; tighten based on actual usage per [least-privilege-workflow.md](./least-privilege-workflow.md).

### 8. `Principal: "*"` in trust policies

**The pattern:**
```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "sts:AssumeRole"
}
```

**Why it exists:** "we'll narrow it later"; or pasted from a tutorial.

**Why it's wrong:**
- The role can be assumed by literally anyone with an AWS account.
- Combined with any meaningful permissions, this is a full-access backdoor.

**The replacement:**
```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::AAAAAAAAAAAA:root" },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": { "sts:ExternalId": "specific-shared-secret" }
  }
}
```

Or for cross-account from a specific role:
```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::AAAAAAAAAAAA:role/specific-role" },
  "Action": "sts:AssumeRole"
}
```

### 9. Missing `aws:SourceAccount` / `aws:SourceArn` on service-principal trust

**The pattern:**
```json
{
  "Effect": "Allow",
  "Principal": { "Service": "events.amazonaws.com" },
  "Action": "sts:AssumeRole"
}
```

**Why it exists:** the AWS console wizard generates this; the team doesn't know to add the condition.

**Why it's wrong:**
- Any EventBridge in any AWS account can assume this role (confused-deputy class).

**The replacement:**
```json
{
  "Effect": "Allow",
  "Principal": { "Service": "events.amazonaws.com" },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "ACCOUNT-ID"
    },
    "ArnLike": {
      "aws:SourceArn": "arn:aws:events:REGION:ACCOUNT-ID:rule/specific-rule-name"
    }
  }
}
```

### 10. `iam:PassRole` with `Resource: "*"`

**The pattern:**
```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "*"
}
```

**Why it exists:** the policy author needed PassRole for one service; gave it everywhere because narrowing was tedious.

**Why it's wrong:**
- The principal can pass *any* role to *any* service.
- Combined with the ability to create resources (e.g., create EC2 instances): privilege-escalation primitive — pass a high-privilege role to a new EC2 instance, gain access via the instance.

**The replacement:**
- Restrict the resource: `Resource: "arn:aws:iam::*:role/specific-role-name"` or specific role list.
- Add `Condition: { StringEquals: { iam:PassedToService: "service.amazonaws.com" } }`.

### 11. AssumeRole chains that erase the original caller

**The pattern:** principal A assumes role B which assumes role C. CloudTrail shows role C's actions attributed to the assumed-role session. The original principal A is obscured.

**Why it exists:** chained role assumption is sometimes necessary for cross-account / cross-organization access.

**Why it's wrong:**
- The audit trail breaks at the AssumeRole; "who actually did this" requires correlating session timing across CloudTrail events.
- Compromise of role C is harder to attribute back to the originating principal.

**The mitigations:**
- Use `sts:SourceIdentity` to preserve a string identifying the original caller through the chain.
- Restrict role-chaining via SCP where possible.
- Cross-system audit correlation in SIEM.

### 12. Wildcard resource ARNs in trust policies

**The pattern:**
```json
{
  "Principal": { "AWS": "arn:aws:iam::*:role/some-role-name" }
}
```

**Why it exists:** the team wanted to trust roles across multiple accounts; wildcarded the account ID.

**Why it's wrong:**
- Any AWS account can create a role with the matching name and use it.
- Effectively trusts the universe.

**The replacement:**
- Explicit account list.
- Or `aws:PrincipalOrgID` condition to scope to your AWS Organization.
```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "*" },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": { "aws:PrincipalOrgID": "o-xxxxxxxxxx" }
  }
}
```

### 13. `NotResource` / `NotAction` constructs without testing

**The pattern:**
```json
{
  "Effect": "Allow",
  "NotAction": "iam:*",
  "Resource": "*"
}
```

**Why it exists:** "block IAM, allow everything else."

**Why it's wrong:**
- `NotAction` matches "actions other than the listed ones." For Allow, it grants everything except those actions.
- Future AWS services (with new actions) are automatically granted.
- The grant is broader than the author intended.

**The replacement:**
- Allow-listing the specific actions needed, not subtracting.
- Explicit deny for actions you want to forbid, in a separate Deny statement.

### 14. Conditions that match nothing

**The pattern:**
```json
{
  "Effect": "Deny",
  "Action": "s3:GetObject",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": { "aws:RequestTag/SecretMaster": "true" }
  }
}
```

**Why it exists:** the team meant to require a tag; got the condition operator wrong.

**Why it's wrong:**
- `aws:RequestTag` only applies to API calls that include a tag in the request. GetObject doesn't tag. The condition is always-true → the Deny always fires → S3 GetObject is denied for everything.

**The fix:**
- Test policies in IAM Policy Simulator before deploying.
- Use IAM Access Analyzer policy validation.
- Per-policy unit tests for non-trivial Conditions.

---

## The lifecycle anti-patterns

The patterns around how IAM evolves over time.

### 15. Policies that grew over time without periodic review

**The pattern:** an IAM policy attached to a role accumulates permissions as new use cases emerge. Quarterly addition; never subtraction. By year three, the policy grants more than the workload uses.

**Why it exists:** the path of least resistance is "add the permission and move on."

**Why it's wrong:**
- The role's blast radius grows.
- A compromise has more attacker-useful permissions than necessary.
- The policy is unreadable; nobody knows what's actually used.

**The replacement:**
- Per [least-privilege-workflow.md](./least-privilege-workflow.md): quarterly review using IAM Access Analyzer's used-permissions analysis.
- Tighten based on actual usage.
- Per-PR review notes which permissions are added and why.

### 16. Standing-admin "for emergencies"

**The pattern:** "Alice has Admin standing because she might need it during incidents."

**Why it exists:** the on-call doesn't have time to elevate.

**Why it's wrong:**
- 99% of the time, Alice doesn't need Admin. Her credential is a perpetual high-value target.
- Compromise of Alice's session = perpetual Admin compromise.

**The replacement:**
- JIT elevation per [just-in-time-access.md](./just-in-time-access.md). The on-call elevates in 5 seconds; the elevation is logged; the elevation expires.
- Break-glass account for situations where JIT itself is unavailable (sealed credentials).

### 17. Orphan IAM users / roles / service accounts

**The pattern:** principals exist for workloads that no longer exist. Nobody cleaned them up at decommissioning.

**Why it exists:** decommissioning is unglamorous; nobody checks.

**Why it's wrong:**
- Orphan principals with long-lived credentials are attractive compromise targets.
- The audit-finding pattern: "this access key hasn't been used in 18 months" — yet it's still active.

**The replacement:**
- Per [service-account-hygiene.md](./service-account-hygiene.md): per-account ownership; renewal-date workflow; disable on lapse.

### 18. SCPs / Org Policies in audit / monitor mode forever

**The pattern:** the team deploys SCPs in "audit-only" mode for testing. The audit-only mode persists; the SCP never enforces.

**Why it exists:** caution about breaking things; the testing phase is open-ended.

**Why it's wrong:**
- The protection isn't actually deployed.
- Posture review may show "SCPs in place" without checking enforcement.

**The replacement:**
- Time-bound the audit phase (2 weeks); enforce by deadline.
- Verify enforcement with synthetic tests.
- Per-quarter review of any SCP / policy still in audit-only mode.

---

## The role-design anti-patterns

The patterns specific to how roles are scoped.

### 19. One role per environment, not per workload

**The pattern:** a single "prod-app-role" used by every production application.

**Why it exists:** ops team finds it easier to manage one role.

**Why it's wrong:**
- Role's permissions are the union of every app's needs.
- Compromise of any app = compromise of the role = access to every app's resources.

**The replacement:**
- Per-workload role.
- Higher role count is a feature (granular blast radius), not a bug.

### 20. The "developer" role with PowerUser

**The pattern:** developers in production have PowerUser. Justified by "they need to debug."

**Why it exists:** developers complained about access friction during incidents.

**Why it's wrong:**
- PowerUser includes most write actions. Developers can modify production.
- The audit trail loses meaning ("the developer modified the database" — was that intentional?).

**The replacement:**
- Developer role in production: ReadOnly + specific actions (e.g., CloudWatch Logs read).
- Elevation to write via JIT for change windows.
- Manual production changes through a documented runbook + JIT.

### 21. The "audit" role with `*` permissions

**The pattern:** an "auditor" role with `Action: "*"` on `Resource: "*"`. Justified by "audits need to see everything."

**Why it exists:** the auditor wanted breadth.

**Why it's wrong:**
- `*` on Action includes write actions. The "auditor" can modify what they're auditing.
- Compromise of the auditor account = full account compromise.

**The replacement:**
- `ReadOnlyAccess` (AWS managed policy) for the auditor.
- `SecurityAudit` (more restrictive) where ReadOnly is too broad.
- Specific Deny statements for any read action that shouldn't be in scope.

### 22. The "break-glass" role used for routine work

**The pattern:** the break-glass account / role is used by the ops team for daily work because JIT is friction.

**Why it exists:** JIT was slow or flaky.

**Why it's wrong:**
- Break-glass = standing-admin without the JIT discipline.
- Defeats the entire JIT investment.
- Hides the actual access patterns (audit looks at JIT logs; the activity isn't there).

**The replacement:**
- Fix the JIT system so break-glass isn't tempting.
- Alert on break-glass use; investigate every instance.
- Disable break-glass between scheduled tests; re-enable only for actual incidents.

---

## The remediation order

When you find these anti-patterns in an inherited environment, the order to fix them.

### Tier 1 — Compromise-multiplier patterns (fix first)

1. **`Principal: "*"`** in trust policies — Critical, immediate triage.
2. **`Resource: "*"` with broad Action** on production roles — High.
3. **Standing-admin in management account** — High.
4. **Missing `aws:SourceAccount` / `aws:SourceArn` on service-principal trusts** — High.
5. **`iam:PassRole` with `Resource: "*"`** — High.

### Tier 2 — Credential-lifecycle patterns

6. **Long-lived credentials when workload identity is available** — High.
7. **IAM users for human access** — High; large project but high payoff.
8. **Orphan IAM users / roles / service accounts** — Medium.
9. **SCPs in audit-only mode forever** — Medium.

### Tier 3 — Audit and posture patterns

10. **Standing-admin "for emergencies"** — Medium; depends on JIT availability.
11. **Federation to multiple IdPs** — Medium; large project.
12. **Policies that grew over time** — Medium; ongoing tightening.
13. **Per-environment role (instead of per-workload)** — Medium; refactor over time.

### Tier 4 — Quality-of-life patterns

14. **The `developer` role with PowerUser** — Low-Medium.
15. **The `audit` role with `*` permissions** — Low-Medium.
16. **The `break-glass` role used for routine work** — Medium (workflow problem more than IAM problem).
17. **AssumeRole chains** — Low; mostly an audit-clarity issue.
18. **`NotAction` / `NotResource` constructs** — Low; case-by-case review.

The remediation order isn't strict; some Tier 1 patterns block Tier 2 work, and the right sequence depends on the environment. But "compromise-multipliers first" is the rule of thumb.

---

## Worked example — Meridian Health IAM cleanup (Q1 2026)

Meridian conducted an IAM audit using this catalogue as the checklist. Result snapshot.

### The audit (week 1-2)

Used custom scripts + AWS Access Analyzer + Wiz CSPM to enumerate patterns across 12 AWS accounts, 4 Azure subscriptions, 6 GCP projects.

Findings categorized by anti-pattern:

- **Wildcard principals (#8):** 3 trust policies. All in non-production accounts (test artifacts that never got cleaned up).
- **Resource: "*" with broad Action (#7):** 47 IAM policies in production.
- **Missing SourceAccount/SourceArn (#9):** 18 service-principal trust policies.
- **iam:PassRole with Resource: "*" (#10):** 5 policies.
- **Long-lived credentials when workload identity available (#2):** 80 IAM users (parallel track to the kill-the-IAM-user campaign).
- **Standing-admin in management account (#3):** 12 standing-admin principals (per the workforce-identity rollout, all migrated to JIT).
- **Policies that grew over time (#15):** ~150 policies showed permissions never used per Access Analyzer.

### The remediation (weeks 3-12)

Followed the tier ordering above.

**Tier 1:** all wildcard-principal trusts and broad-action policies addressed first. Three weeks; ~30 PRs.

**Tier 2:** workload-identity migration (parallel to other identity work). Eight weeks; ongoing.

**Tier 3:** standing-admin migration done as part of the JIT rollout per [just-in-time-access.md](./just-in-time-access.md).

**Tier 4:** scheduled into the per-quarter access review process.

### Findings opened during the cleanup

- **IAM-001** (3 trust policies with `Principal: "*"`). Closed.
- **IAM-002** (47 production policies with broad Action + Resource: "*"). Closed by per-policy tightening with Access Analyzer.
- **IAM-003** (18 service-principal trusts missing SourceAccount / SourceArn). Closed.
- **IAM-004** (5 policies with iam:PassRole + Resource: "*"). Closed.
- **IAM-005** (~150 policies showed unused permissions). Tightening campaign ongoing.

The campaign cost ~2 FTE-quarters. Maintenance ongoing: per-quarter access review process.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| IAM-AP-001 | IAM users for human access | High | Migrate to federated sign-in per [workforce-identity.md](./workforce-identity.md) | Identity + Security Eng |
| IAM-AP-002 | Long-lived service credentials when workload identity is available | High | Migrate to workload identity per [workload-identity.md](./workload-identity.md) | Platform Eng + Security Eng |
| IAM-AP-003 | Standing-admin in management account | High | JIT per [just-in-time-access.md](./just-in-time-access.md); standing-admin = 0 | Identity + Security Eng |
| IAM-AP-004 | Per-account silos without org-level SCPs | High | Baseline SCP set at org root per [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) | Cloud Foundation + Security Eng |
| IAM-AP-005 | Cross-account access via long-lived access keys | High | AssumeRole pattern; cross-account trust policy | Security Eng + Platform Eng |
| IAM-AP-006 | Federation to multiple IdPs | Medium | Consolidate to one IdP; migrate legacy federations | Identity + Security Eng |
| IAM-AP-007 | `Resource: "*"` with broad Action | High | Per-resource scoping based on Access Analyzer usage | Security Eng + Service Owners |
| IAM-AP-008 | `Principal: "*"` in trust policies | Critical | Explicit principal; or PrincipalOrgID condition | Security Eng |
| IAM-AP-009 | Missing aws:SourceAccount / aws:SourceArn on service-principal trust | High | Add conditions to all service-principal trusts | Security Eng |
| IAM-AP-010 | iam:PassRole with Resource: "*" | High | Per-role resource scoping; iam:PassedToService condition | Security Eng |
| IAM-AP-011 | AssumeRole chains erasing original caller | Medium | sts:SourceIdentity preservation; restrict chaining where possible | Security Eng |
| IAM-AP-012 | Wildcard resource ARNs in trust policies | High | Explicit account list; or aws:PrincipalOrgID | Security Eng |
| IAM-AP-013 | NotResource / NotAction constructs | Medium | Convert to allow-listing | Security Eng |
| IAM-AP-014 | Conditions that match nothing (always-true / always-false) | High | IAM Policy Simulator testing; per-policy unit tests | Security Eng |
| IAM-AP-015 | Policies that grew over time without periodic review | Medium | Quarterly Access Analyzer review per [least-privilege-workflow.md](./least-privilege-workflow.md) | Security Eng + Service Owners |
| IAM-AP-016 | Standing-admin "for emergencies" | High | JIT per [just-in-time-access.md](./just-in-time-access.md); break-glass for JIT unavailable | Identity + Security Eng |
| IAM-AP-017 | Orphan IAM users / roles / service accounts | Medium | Per [service-account-hygiene.md](./service-account-hygiene.md): ownership, renewal, cleanup | Security Eng + Owners |
| IAM-AP-018 | SCPs / Org Policies in audit / monitor mode forever | Medium | Time-bound audit; enforce by deadline; synthetic test | Cloud Foundation + Security Eng |
| IAM-AP-019 | One role per environment, not per workload | Medium | Per-workload roles; granular blast radius | Security Eng + Service Owners |
| IAM-AP-020 | Developer role with PowerUser in production | Medium | ReadOnly + specific actions; JIT for writes | Security Eng + Engineering |
| IAM-AP-021 | Audit / SecurityAudit role with `*` permissions | High | ReadOnlyAccess / SecurityAudit managed policies; specific Deny statements | Security Eng + Audit |
| IAM-AP-022 | Break-glass used for routine work | High | Fix JIT friction; alert on break-glass use; investigate every instance | Identity + Security Eng |

---

## Adoption checklist

- [ ] Per-anti-pattern audit script; per-platform enumeration.
- [ ] Findings categorized by tier; remediation prioritized by tier.
- [ ] Tier 1 findings addressed first (compromise multipliers).
- [ ] Tier 2 findings (credential lifecycle) addressed as separate workstreams (kill-IAM-users, workload-identity migration).
- [ ] Tier 3 findings (audit and posture) addressed in per-quarter access review.
- [ ] Tier 4 findings (quality-of-life) addressed in ongoing tightening.
- [ ] CI gate: new policies checked against the anti-pattern catalogue (e.g., Checkov, custom OPA rules).
- [ ] Quarterly review of new policies merged; spot-check for anti-pattern reintroduction.
- [ ] Per-platform CSPM (Wiz, Prisma, etc.) tuned to surface these patterns.
- [ ] SCP at org root preventing Tier 1 anti-patterns (e.g., deny IAM-user creation, deny trust policies with `Principal: "*"`).
- [ ] Per-team training: the anti-pattern catalogue is part of the onboarding for cloud engineers.

---

## What this document is not

- **An IAM-policy reference.** AWS / Azure / GCP documentation cover the policy grammar.
- **A complete IAM design.** [workforce-identity.md](./workforce-identity.md), [workload-identity.md](./workload-identity.md), [federation-patterns.md](./federation-patterns.md), [just-in-time-access.md](./just-in-time-access.md), [service-account-hygiene.md](./service-account-hygiene.md), [least-privilege-workflow.md](./least-privilege-workflow.md) cover the broader architecture.
- **A CSPM tool reference.** Wiz, Prisma, Lacework, and others surface these patterns; tool choice is procurement decision.
- **An exhaustive anti-pattern list.** Cloud IAM has more failure modes than this list; the document focuses on the recurring ones I've removed in real environments.
- **A policy-validation library reference.** IAM Access Analyzer, Checkov, Conftest, and others can codify these checks.
