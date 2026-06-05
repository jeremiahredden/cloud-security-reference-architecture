# Workforce Identity

A practitioner's reference for workforce identity in cloud environments — the architecture that decides which employees, contractors, and partners can sign into AWS / Azure / GCP / SaaS apps, under what conditions, with what privileges, and how that decision is audited. Workforce identity is *the* trust root for almost every cloud security control; the rest of the security architecture stands on whatever the workforce-identity model permits.

This document opens a triad with [workload-identity.md](./workload-identity.md) and [federation-patterns.md](./federation-patterns.md). Workforce identity is "humans signing into cloud accounts and apps." Workload identity is "services authenticating to cloud APIs without a human in the loop." Federation patterns is the SAML / OIDC / SCIM mechanics that connect identity providers to consumers. They're independent topics that share infrastructure.

The honest framing: the workforce-identity decisions of 2018 — "we'll add AWS users with long-lived passwords for now, federate later" — are still active in many environments in 2026. Federation in 2026 isn't a project, it's a posture baseline. Conditional-access, MFA-with-phishing-resistant-factors, device-trust signals, PIM / JIT for privileged access — these are the floor. This document describes the floor.

---

## When to read this document

**If you're designing the IdP-to-cloud trust model for a new tenant or organization** — read top to bottom.

**If you have IAM users with passwords across your AWS accounts and you want to retire them** — start with [The kill-the-IAM-user playbook](#the-kill-the-iam-user-playbook).

**If you need to set up conditional access policies that actually fire** — start with [Conditional access](#conditional-access).

**If you're auditing workforce-identity posture** — start with [Findings checklist](#findings-checklist).

---

## The workforce-identity mental model

What "workforce identity" decides.

### The decision flow

```
1. Employee starts (HRIS = source of truth)
        │
        ▼
2. Identity provisioned in central IdP (Entra ID / Okta / Google Workspace)
        │
        ▼
3. Group memberships assigned (per role / per team / per project)
        │
        ▼
4. IdP-to-cloud trust enforced:
        - SAML / OIDC federation to AWS / Azure / GCP
        - SCIM provisioning for users that need cloud-native identity
        │
        ▼
5. Per-cloud authorization (IAM roles, RBAC role assignments,
   resource-level permissions) — gated by group membership
        │
        ▼
6. Per-session enforcement:
        - MFA (phishing-resistant factor)
        - Device trust (managed / patched / enrolled)
        - Conditional access (network, time, risk score)
        │
        ▼
7. Audit trail: every sign-in, every API call, traceable to the human
        │
        ▼
8. Employee leaves → HRIS triggers deprovisioning → all access revoked
```

If any of these steps is weak, the whole posture is weak. The investment is in *all* of them, not just one.

### The three trust roots

Most teams settle on one IdP per organization:

- **Microsoft Entra ID** (formerly Azure AD): native to Azure, strong identity-governance product (Entra ID Governance), the dominant choice for organizations on Microsoft 365.
- **Okta**: cross-vendor, deep app catalog, strong federation tooling. Common in organizations with a mix of cloud providers.
- **Google Workspace** (Cloud Identity): native to GCP, simpler than Entra / Okta, the natural choice for organizations on Google Workspace.

The choice between them is mostly determined by the productivity-suite decision. The pattern is the same across all three: source-of-truth in HRIS → sync into IdP → federate to cloud / SaaS.

### What the IdP owns

- The user record (account, attributes).
- The credentials (password, MFA factors).
- The session (active-session tracking).
- The authentication enforcement (MFA challenge, password policy, conditional access).

### What the cloud / SaaS owns

- The authorization model (what the user can do once authenticated).
- The user-attribute-to-permission mapping (groups → roles).
- The audit trail of post-auth actions.

The boundary matters because every workforce-identity incident I've worked with traces back to a confused boundary: either the IdP was treated as the authorization source (groups granted permissions without the cloud-side mapping being audited) or the cloud was treated as the authentication source (cloud-native users with passwords that bypass the IdP).

---

## The IdP-to-cloud trust patterns

How the cloud trusts the IdP.

### AWS — IAM Identity Center (formerly AWS SSO)

The recommended pattern for AWS workforce access.

```
Entra ID / Okta / Google Workspace
        │
        │  SAML 2.0 federation (with SCIM for provisioning)
        ▼
AWS IAM Identity Center
        │
        │  Permission Sets assigned to AWS Account + Group pairs
        │
        ▼
AWS Account → assume Identity Center role on sign-in
```

**Properties:**
- One IdP integration per AWS Organization, not per account.
- Permission Sets define what a group can do in a specific account.
- Users sign in at a per-organization URL (`<org>.awsapps.com/start`) and pick an account-role to assume.
- AWS CLI: `aws sso login` provides credentials.

**The setup, abbreviated:**

1. Enable AWS IAM Identity Center in the management account.
2. Configure the external IdP (SAML metadata exchange + SCIM token for user/group provisioning).
3. Define Permission Sets (IAM policies templated; e.g., `ReadOnlyAccess`, `PowerUserAccess`, `BillingReader`).
4. Assign per-account: `Group + Permission Set + Account = Access`.

**Anti-pattern to avoid:** assigning IAM users (the legacy ones) instead of going through Identity Center. IAM users bypass conditional access, MFA-enforcement, session-policy controls.

### Azure — Entra ID natively

Azure's IdP is Entra ID; subscriptions trust Entra ID by default. No additional federation needed.

The pattern:
- Entra ID groups assigned to Azure RBAC roles at subscription / resource group / resource scope.
- Conditional access policies (Entra ID feature) gate the sign-in.
- PIM for just-in-time elevation to privileged roles (more in [just-in-time-access.md](./just-in-time-access.md)).

**If Entra ID is not the corporate IdP:** Entra ID can be the federated-to identity (Okta or Google Workspace as IdP, Entra ID as relying party). This is common but less common than Entra-native; the federation adds complexity that should be justified.

### GCP — Workforce Identity Federation or Cloud Identity

Two paths:

**Cloud Identity (the simpler option):**
- Cloud Identity is GCP's equivalent of a directory.
- Sync users from Google Workspace, Active Directory (via GCDS), or Okta.
- Groups in Cloud Identity assigned to GCP IAM roles.

**Workforce Identity Federation (the federated option):**
- The corporate IdP is the source; GCP federates to it.
- Users authenticate at the IdP; obtain short-lived GCP credentials via STS.
- Groups in the IdP map to GCP IAM via attribute conditions.

Workforce Identity Federation is the modern pattern for organizations whose IdP isn't Google Workspace. It avoids creating a parallel directory.

### SaaS apps — SAML or OIDC

For non-cloud-provider apps (Snowflake, dbt Cloud, Looker, Datadog, etc.), the pattern is:
- SAML or OIDC from the corporate IdP.
- SCIM provisioning where supported.
- Group-to-role mapping in the app.

The mechanics are in [federation-patterns.md](./federation-patterns.md).

---

## Conditional access

The policy layer that decides "this sign-in is allowed under these conditions."

### What conditional access evaluates

- **User / group:** which user is signing in.
- **Device:** managed / unmanaged; compliant / non-compliant; enrolled / not enrolled.
- **Location:** network IP, named locations, country.
- **Application:** which app the user is signing into.
- **Risk:** IdP-computed sign-in risk (impossible travel, unfamiliar device, leaked credentials).
- **Time:** business hours, weekday vs weekend.

### What conditional access decides

- **Allow.**
- **Allow with conditions:** require MFA, require compliant device, require approved client app, require session lifetime cap.
- **Block.**

### The baseline policy set

Every workforce-identity deployment should ship at least:

1. **MFA required for all users.** No app exempt. Some apps (very old SaaS) may not support modern MFA — they get a high-friction policy (one-time-passcode on every sign-in, narrow access).

2. **Phishing-resistant MFA required for privileged roles.** FIDO2 / WebAuthn / Yubikey for the user-set that has Admin / PowerUser / KMS Admin / SCP Admin in any cloud. Phone-based MFA is acceptable for the average user; it is not acceptable for privileged users in 2026.

3. **Block legacy authentication.** Basic auth, IMAP-on-Outlook, ActiveSync from un-managed devices. These bypass conditional access.

4. **Require compliant device for sensitive apps.** Production AWS console, GCP console, Snowflake admin role, source code repos. The "compliant device" definition is set in MDM (Intune / Jamf / Workspace ONE).

5. **Geofence as appropriate.** If your workforce is US-and-EU only, deny sign-ins from countries that aren't either. Be careful with travel; have an exception process.

6. **Risk-based step-up.** IdP signals an elevated sign-in risk; require additional verification (re-MFA, device-bound MFA, password reset). Microsoft Entra Identity Protection, Okta Behavior Detection, and Google's risk signals all support this.

### The "policy is theater" failure mode

Conditional access policies are deployed in "report-only" mode for testing. The team forgets to switch them to "enforce." The dashboard says "policy: configured" — and the policy isn't actually firing. Verify enforcement with synthetic-account tests; document the verification in the per-quarter access review.

### The break-glass account

Conditional access policies can lock out the entire workforce if misconfigured. The break-glass account is the exception:
- A dedicated account (not used for daily work) with Global Administrator / equivalent.
- Excluded from conditional access policies (with a documented exception statement).
- Credentials stored offline (a sealed envelope in a fireproof safe; password manager with hardware token; etc.).
- Tested quarterly: sign in, verify access works, rotate credentials, re-seal.

The break-glass is the "we just locked everyone out" recovery path. Don't skip it. Don't share the credentials. Don't let "we'll test the break-glass next month" become a permanent backlog item.

---

## PIM / JIT for privileged access

Standing-administrator access is the highest-impact compromise vector. Just-in-time elevation reduces standing access to near-zero.

The full pattern is in [just-in-time-access.md](./just-in-time-access.md). The summary for workforce-identity context:

### The principle

- Day-to-day access uses non-privileged accounts (developer, contributor, viewer).
- Privileged access (Admin, Owner, Security Manager) is elevated *for a session*, with approval, with audit, and the elevation expires.

### Per-platform

- **Microsoft:** Entra ID Privileged Identity Management (PIM) for Azure / Microsoft roles. Approval workflow, time-bound elevation, audit log.
- **AWS:** IAM Identity Center session policies + custom elevation tooling (or AWS's emerging PIM features). Many teams use Aponia or Teleport for AWS-side JIT.
- **GCP:** GCP Just-in-Time Access (formerly Just-in-Time Privileged Access). Approval workflow, time-bound role grants.
- **SaaS / Snowflake / etc.:** depends on the app. Most have an admin role and assume-role pattern; layered tools (Aponia, Sym, Indent) standardize the request / approval flow.

### The baseline

- Standing administrator access in any cloud / app: zero.
- Elevation duration: ≤ 8 hours, typically 1-2.
- Approval: required for production-impact roles, auto-approved for lower-impact.
- Audit: every elevation logged with requester, approver, role, duration, justification.

---

## Device trust

The signal that distinguishes "Alice on her managed laptop" from "Alice's credentials, used by someone on a random device."

### What device trust verifies

- Device is enrolled in MDM (Intune, Jamf, Workspace ONE, etc.).
- Device is compliant with corporate baselines (disk encrypted, screen lock, OS patched, EDR running).
- Device is in the expected device class (laptop vs personal phone).

### How the IdP gets the signal

- **Entra ID + Intune:** native; Entra ID reads the Intune compliance attribute.
- **Okta + EDR:** Okta Identity Engine integrates with CrowdStrike, SentinelOne, etc. The EDR vendor's device-trust signal is read at sign-in.
- **Google Workspace + Endpoint:** Google Workspace's endpoint management product provides the signal.
- **Custom:** the device-trust signal can come from anywhere; the IdP needs to be able to read it.

### The tiered access pattern

The maturity model:

1. **No device trust.** Anyone with credentials can sign in. (The starting state for most environments.)
2. **MDM-managed devices only.** Only enrolled devices can sign in. Bring-your-own-device patterns are deferred.
3. **Compliant devices only.** Enrolled + compliant. Lapsed-patch devices get blocked / step-up.
4. **Tiered access:** managed devices full access; BYOD limited access (web-only, no clipboard, no download).

Most organizations sit at #2 or #3 in 2026; #4 is the maturity target.

### BYOD

BYOD without device trust is the equivalent of "your contractor's home laptop has the same access as your laptop." The patterns:

- **No BYOD:** corporate-issued devices only. Simplest; not feasible everywhere.
- **BYOD with MDM:** the user enrolls their personal device; corporate has a foothold (separate work profile in Android, configuration profile in iOS, Workspace ONE in BYOD mode).
- **BYOD with attested device + restricted scope:** the user runs an attestation app (Cloudflare WARP, Okta Verify) that signals "this device meets minimum criteria"; the IdP grants restricted-scope access (web-only, narrow app list).

The trade-off is operational complexity vs user experience. Pick the pattern that fits your workforce.

---

## SCIM provisioning

Auto-provisioning users into cloud / SaaS based on IdP group membership.

### What SCIM solves

- Manual user creation in N apps for every new hire.
- Manual user deactivation in N apps for every departure.
- Stale users across apps that nobody remembers to clean up.

### The pattern

```
HRIS (Workday / BambooHR / etc.)
        │
        │ employee data sync
        ▼
IdP (Entra ID / Okta)  ◄────  group memberships updated based on role / team
        │
        │  SCIM 2.0 push
        ▼
App (AWS IAM Identity Center / Snowflake / dbt Cloud / etc.)
        │
        │  user provisioned, attribute-mapped, group-mapped
        ▼
Authorization in app (group → role mapping)
```

### What to provision via SCIM

- All cloud-provider sign-in surfaces (AWS Identity Center, Azure native, GCP Cloud Identity).
- All major SaaS apps (Snowflake, dbt Cloud, Looker, Datadog, GitHub Enterprise, Slack, etc.).
- The CI/CD platform (where SaaS).

### What can't be SCIM-provisioned

- Apps without SCIM support. The fallback is "just-in-time provisioning" (the app creates the user record on first SAML sign-in). Less complete deprovisioning; the user record stays after departure.
- Legacy / custom apps. Custom provisioning via scripts.

### Quarterly SCIM hygiene

- **Reconciliation:** does the user list in each app match the IdP's expected list?
- **Orphan accounts:** accounts in apps without matching IdP users. These are the residue of failed deprovisioning.
- **Provisioning lag:** does a new hire have access on day one or day five? Should be day one.

---

## The kill-the-IAM-user playbook

The single highest-impact workforce-identity cleanup in many AWS environments.

### The problem

IAM users (the cloud-native AWS account-user) bypass:
- IdP MFA enforcement (each user has their own MFA factor, often not phishing-resistant).
- Conditional access (IAM users sign in via console with username + password; conditional access lives in the IdP).
- SCIM deprovisioning (IAM users don't sync to the IdP).
- Centralized audit (you have to enumerate IAM users in N accounts to know who has access).

### The replacement: Identity Center

- Federate to Identity Center.
- Migrate users from IAM-user to Identity Center user.
- Migrate IAM users' attached policies into Permission Sets.
- Block IAM-user creation via SCP.

### The migration

1. **Inventory.** `aws iam list-users` across every account. Categorize: human users, service accounts (some teams mis-use IAM users for workloads — those get migrated to roles per [workload-identity.md](./workload-identity.md)).

2. **Group humans by role.** Translate IAM-user permissions into Permission Sets.

3. **Per-user migration.**
   - Provision the user in Identity Center with appropriate group membership.
   - Inform the user of the new sign-in URL.
   - Disable the IAM user (don't delete yet; keep for rollback window).
   - After confirmed transition: delete the IAM user.

4. **Block creation.** SCP at the organization root:
```json
{
  "Sid": "DenyIAMUserCreation",
  "Effect": "Deny",
  "Action": ["iam:CreateUser", "iam:CreateLoginProfile", "iam:CreateAccessKey"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/break-glass-admin",
        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*"
      ]
    }
  }
}
```

The SCP blocks new IAM users for everyone except the break-glass and Identity Center reserved roles.

### The exceptions

- **Programmatic-only "users" that are actually service accounts.** Migrate to roles; see [workload-identity.md](./workload-identity.md). Not exceptions; mis-categorized.
- **Cross-account access keys held by external services.** Migrate to OIDC federation where the service supports it; otherwise wrap in Secrets Manager with rotation.
- **AWS-internal service users (e.g., a CodeCommit user).** Maintained as IAM users by AWS service requirement; document each one; quarterly review.

### Aftermath

- IAM-user count in production = 0 (or the documented exceptions).
- AWS-side authentication flows through Identity Center → IdP.
- IdP-side conditional access fires for every sign-in.
- Departures handled via IdP deprovisioning; no orphan IAM users.

---

## Worked example — Meridian Health workforce-identity rollout (Q1-Q2 2026)

The Meridian platform team consolidated workforce identity over six months. Snapshot:

### Starting state

- Okta as the corporate IdP (~1,200 employees, ~80 contractors).
- AWS: ~400 IAM users with passwords across 12 AWS accounts. ~50 federated via legacy SAML directly to specific accounts. No Identity Center.
- Azure: Entra ID synchronized from Okta via SCIM. ~600 users in Entra ID; conditional access policies in "report-only" mode for six months.
- GCP: Cloud Identity synchronized from Okta. ~300 users.
- Snowflake / dbt / Looker / Datadog: each federated via SAML to Okta; SCIM where supported.
- MFA: enforced via Okta for "all users" — but legacy SAML AWS bypass meant ~50 users were exempt. Many MFA factors were SMS or push-notification (phishing-vulnerable).
- No PIM / JIT; standing-admin in every cloud and SaaS app.
- Conditional access policies in Entra ID present but unenforced.

### Q1 — Identity Center migration and policy enforcement

**Weeks 1-2:** Stood up AWS IAM Identity Center in the management account. Federated to Okta. Defined ~15 Permission Sets (ReadOnly, PowerUser, BillingReader, KMSAdmin, SCPAdmin, etc.).

**Weeks 3-6:** Migrated humans off IAM users. Identified 80 IAM users that were actually service accounts and migrated them to roles (parallel track). Migrated the 320 actual humans to Identity Center. Documented the four exceptions (AWS CodeCommit users for legacy repos).

**Weeks 7-8:** Deployed the IAM-user-creation SCP. Verified by attempting to create an IAM user from a high-privilege session (denied; SCP fired).

**Weeks 9-10:** Switched Entra ID conditional access policies from report-only to enforce. Verified with synthetic accounts that policies fire as expected.

**Weeks 11-12:** Rolled out FIDO2 / YubiKey for the ~80 users with privileged roles. Required phishing-resistant MFA for admin-tier sign-ins. The non-privileged user population kept push-notification MFA for now.

### Q2 — PIM / JIT, device trust, BYOD policy

**Weeks 13-14:** Stood up Entra ID PIM for Azure roles. All standing-Owner assignments converted to PIM-eligible. Default elevation duration: 4 hours. Approval workflow: Security Eng for production-impact roles, auto-approve for read-only.

**Weeks 15-16:** Aponia deployed for AWS-side JIT. Identity Center Permission Sets for non-routine access (PowerUser on production accounts) became Aponia-gated.

**Weeks 17-18:** Device-trust signal added to conditional access. Required compliant device for AWS console sign-in, Azure console sign-in, GCP console sign-in. Compliance defined in Intune.

**Weeks 19-20:** BYOD policy formalized. Two tiers: full-access on managed devices, web-only-narrow-scope on attested BYOD.

**Weeks 21-24:** Quarterly access review process stood up. SCIM-reconciliation script runs monthly. Per-app SCIM verification (orphan accounts, provisioning lag).

### Findings opened during the rollout

- **WFI-001** (~400 AWS IAM users bypass IdP conditional access). Closed by Identity Center migration.
- **WFI-002** (Conditional access policies in report-only mode for six months). Closed by enforcement; verified by synthetic test.
- **WFI-003** (No PIM / JIT for privileged roles). Closed by PIM + Aponia.
- **WFI-004** (Privileged users on push-notification MFA). Closed by FIDO2 rollout.
- **WFI-005** (No device-trust signal in conditional access). Closed by Intune integration.
- **WFI-006** (BYOD users have full access; no scope restriction). Closed by tiered policy.
- **WFI-007** (No quarterly SCIM reconciliation). Closed by monthly script + quarterly process.

The rollout cost ~3 FTE-quarters of engineering. Maintenance cost: ~0.25 FTE per quarter for ongoing operation.

---

## Anti-patterns

### 1. IAM users for human access in 2026

The thing the kill-the-IAM-user playbook exists to fix. IAM users with passwords are an architectural debt; pay it down.

### 2. Conditional access policies in permanent report-only mode

Report-only mode is for testing. "We'll switch it to enforce next sprint" becomes "we'll switch it to enforce next quarter" and policies that are present but not enforced are theater.

The fix: time-bound the report-only mode (two weeks); enforce by deadline; document any policy that genuinely needs to stay in report-only with the reason.

### 3. Phone-based MFA for privileged users

SMS and phone-call MFA are phishing-vulnerable in 2026. SIM-swap attacks against high-value individuals have been documented for years. Push-notification MFA is better but still vulnerable to push-bombing.

The fix: phishing-resistant MFA (FIDO2 / WebAuthn / YubiKey) for privileged users. Mass-rollout of FIDO2 for the entire workforce is the next stage.

### 4. The forever-Global-Administrator

Standing Global-Administrator-in-Entra-ID or root-account-access-in-AWS for "convenience." Compromise = total takeover.

The fix: PIM / JIT. Standing-admin count = 1 (the break-glass; tested quarterly).

### 5. SCIM-without-deprovisioning

SCIM creates accounts; SCIM should also deactivate accounts on offboarding. Many SCIM integrations are configured for provisioning but not deprovisioning (or use "soft deprovisioning" that disables sign-in but leaves the user record).

The fix: verify SCIM deprovisioning fires; reconciliation script monthly; per-app audit of orphans.

### 6. The cloud-side groups parallel to IdP groups

The team creates groups in AWS Identity Center / Snowflake / etc. that parallel groups in the IdP. Now there are two sources of truth; they drift.

The fix: IdP-side groups; SCIM-pushed to apps; per-app group-to-role mapping in IaC.

### 7. "We have MFA, we're fine"

MFA is necessary, not sufficient. Without device trust, conditional access, and PIM / JIT, MFA is one of several signals — and the others are missing.

The fix: layer the controls; review the maturity model per quarter; don't stop at MFA.

### 8. The contractor-as-employee identity

Contractors and partners are treated as full-fledged employees in the IdP. They inherit the same access as employees. Departure (contractor offboarding) is less rigorous; orphan accounts accumulate.

The fix: separate guest-user / external-user pool; restricted scope; explicit expiration dates; monthly review.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| WFI-001 | IAM users (or equivalent cloud-native users) for human access; bypass IdP conditional access | High | Migrate to federated sign-in (Identity Center / Entra ID / Cloud Identity); SCP block new IAM users | Identity + Security Eng |
| WFI-002 | Conditional access policies in permanent report-only mode | High | Time-bound report-only; enforce by deadline; verify with synthetic tests | Identity + Security Eng |
| WFI-003 | Standing administrator access in production cloud / SaaS | High | PIM / JIT pattern per [just-in-time-access.md](./just-in-time-access.md) | Identity + Security Eng |
| WFI-004 | Privileged users on phone / SMS / push MFA | High | Phishing-resistant MFA (FIDO2 / WebAuthn) for privileged roles | Identity + Security Eng |
| WFI-005 | No device-trust signal in conditional access | Medium | MDM integration; compliant-device requirement for sensitive apps | Identity + IT |
| WFI-006 | BYOD users have full-access scope | Medium | Tiered policy; BYOD scoped to web-only / narrow apps | Identity + IT |
| WFI-007 | No quarterly SCIM reconciliation | Medium | Monthly reconciliation script; per-app audit; orphan-account cleanup | Identity |
| WFI-008 | Legacy authentication (basic auth, IMAP) not blocked | High | Conditional access block legacy auth | Identity + Security Eng |
| WFI-009 | Apps not behind IdP federation | Medium | Migrate to SAML / OIDC; SCIM where supported per [federation-patterns.md](./federation-patterns.md) | Identity + App Owners |
| WFI-010 | Break-glass account untested in > 90 days | Medium | Quarterly tabletop; verify sign-in works; rotate credentials | Identity + Security Eng |
| WFI-011 | Conditional access exceptions not documented / reviewed | Medium | Per-exception ticket; quarterly review; remove stale exceptions | Identity + Security Eng |
| WFI-012 | No risk-based step-up authentication | Medium | Enable Identity Protection / Behavior Detection; step-up policy | Identity + Security Eng |
| WFI-013 | HRIS-to-IdP sync not active; manual user creation | Medium | HRIS-to-IdP sync via SCIM or HRIS-native integration | HR + Identity |
| WFI-014 | No geofencing or unusual-location alerting | Low | Conditional access geofence; SIEM alert on impossible travel | Identity + Detection Eng |
| WFI-015 | Contractors / partners treated as employees in IdP | Medium | Separate guest user pool; restricted scope; expiration dates | Identity + HR |
| WFI-016 | App-side groups drift from IdP groups | Medium | IdP-side groups as source; SCIM push; IaC for group-role mapping | Identity + App Owners |
| WFI-017 | No audit trail correlating cross-system sign-ins | Medium | SIEM ingestion of IdP + cloud + app sign-in logs; cross-system correlation | Detection Eng + Identity |
| WFI-018 | New-hire access provisioning takes > 24 hours | Low | HRIS-to-IdP automation; day-one access target | HR + Identity |

---

## Adoption checklist

- [ ] Identify the corporate IdP (Entra ID / Okta / Google Workspace) and confirm it as the workforce-identity trust root.
- [ ] HRIS-to-IdP sync configured; new-hire access on day one.
- [ ] AWS: IAM Identity Center deployed; federated to IdP; Permission Sets defined; IAM users migrated; SCP blocks new IAM users.
- [ ] Azure: Entra ID groups assigned to RBAC roles via IaC; PIM enabled for privileged roles.
- [ ] GCP: Workforce Identity Federation or Cloud Identity sync configured; groups mapped to GCP IAM roles.
- [ ] SaaS apps: SAML / OIDC federation; SCIM provisioning where supported; per-app group-to-role mapping.
- [ ] Conditional access policies enforced (not report-only): MFA-required, compliant-device-required-for-sensitive-apps, block-legacy-auth.
- [ ] Phishing-resistant MFA (FIDO2 / WebAuthn) for privileged users.
- [ ] PIM / JIT for privileged roles; standing-admin count = 0 (excluding break-glass).
- [ ] Device-trust signal from MDM consumed by conditional access.
- [ ] BYOD policy tiered; BYOD without managed device gets restricted scope.
- [ ] Break-glass account documented and tested quarterly.
- [ ] Monthly SCIM reconciliation; orphan-account cleanup.
- [ ] Quarterly access review; per-user, per-app, per-role.
- [ ] Conditional access exceptions tracked; quarterly review.
- [ ] Risk-based step-up authentication enabled.
- [ ] Contractor / partner pool separate; restricted scope; expiration dates.
- [ ] SIEM ingestion: IdP sign-in logs, cloud sign-in logs, SaaS sign-in logs; cross-system correlation.

---

## What this document is not

- **A complete IdP administration guide.** Entra ID, Okta, Google Workspace each have their own administrative depth; vendor documentation covers it better.
- **A workload-identity guide.** [workload-identity.md](./workload-identity.md) covers service-to-cloud authentication.
- **A federation-mechanics reference.** [federation-patterns.md](./federation-patterns.md) covers SAML / OIDC / SCIM in depth.
- **A JIT / PIM deep dive.** [just-in-time-access.md](./just-in-time-access.md) covers JIT in depth.
- **A privileged-access-management product comparison.** PAM tools (CyberArk, BeyondTrust, etc.) overlap with PIM / JIT; the choice is vendor-dependent.
- **An identity-governance reference.** Lifecycle management, access certification, segregation-of-duties — these are adjacent to workforce identity and live in identity-governance platforms (SailPoint, Saviynt, Entra Governance, Okta Identity Governance).
