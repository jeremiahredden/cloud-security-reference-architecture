# Just-in-Time Access

A practitioner's reference for JIT / PIM patterns in cloud environments — the architectures that take standing administrator access from "everyone with the role 24/7" to "the role is elevated for a session, with approval, with audit, and the elevation expires." JIT is the single most-effective control for reducing the blast radius of privileged-account compromise; it's also one of the most-under-implemented in 2026.

This document complements [workforce-identity.md](./workforce-identity.md) (the IdP-side trust root) and [federation-patterns.md](./federation-patterns.md) (the SAML / OIDC mechanics). JIT is the pattern that sits atop the federated identity, modulating who has which permissions when.

The honest framing: every cloud-security incident report I've read where the headline is "an attacker compromised an administrator credential" would have been narrower in blast radius — usually substantially — if the administrator's standing access had been an elevatable, approvable, time-bound role rather than a perpetual one. The trade-off is one approval click per session. The compromise reduction is one tier of severity.

---

## When to read this document

**If you have standing administrator access in any cloud / SaaS app** — read top to bottom.

**If you've implemented JIT but the elevation duration is "24 hours" and the approval is auto-approve** — start with [JIT done wrong](#jit-done-wrong).

**If you're evaluating JIT vendors (Aponia, Sym, Indent, Teleport, etc.)** — start with [Vendor patterns](#vendor-patterns).

**If you're integrating JIT with break-glass** — start with [JIT and break-glass](#jit-and-break-glass).

---

## The JIT mental model

The principle and its consequences.

### The principle

```
Without JIT:                               With JIT:
                                           
Alice has Admin role 24/7.                 Alice is JIT-eligible for Admin.
                                           
Alice does her job daily as Admin.         Alice does her job as Developer (low priv).
                                           When she needs Admin:
A compromise of Alice's session                1. Request elevation.
= Admin compromise.                            2. Approver approves (or auto-approves).
                                               3. Alice is Admin for 2 hours.
                                               4. Elevation expires.
                                           
                                           A compromise of Alice's session
                                           = Developer compromise (unless attacker
                                             also triggers + survives the JIT flow).
```

### The trade-offs

**You gain:**
- Reduced standing-admin attack surface (close to zero, in mature deployments).
- Audit trail for every privileged action (who, when, why, approved-by).
- Forcing function for "is this admin access actually needed."

**You give up:**
- A click of friction per elevation.
- Engineering investment in the JIT pipeline (or vendor cost).
- A new failure mode (the JIT system itself can be down).

The 2026 consensus: the trade-off is overwhelmingly worth it for any role with material production impact.

### What gets JIT-gated

Not every role. The discrimination:

**Strong candidates for JIT (gate aggressively):**
- AWS PowerUser / Admin in production.
- Azure Owner / Contributor in production.
- GCP Project Owner / Editor.
- KMS / Key Vault Admin.
- IAM / Identity Manager.
- SCP / Org Policy Manager.
- Snowflake ACCOUNTADMIN, SECURITYADMIN, USERADMIN.
- Production database admin (rdsadmin, etc.).

**Marginal candidates (consider JIT, often configured as lower-friction):**
- Read-only roles for sensitive data (PHI read).
- Service-now-tier admin for HRIS, ticketing systems.

**Poor candidates for JIT (overhead exceeds benefit):**
- Daily-use developer roles.
- Generic-employee SaaS sign-ins (Slack, etc.).
- Build / CI pipeline access (use workload identity instead per [workload-identity.md](./workload-identity.md)).

---

## The JIT flow

What an elevation looks like end-to-end.

### The standard flow

```
1. User requests elevation
   ├── Via chat (Slack bot)
   ├── Via web UI (JIT tool's portal)
   ├── Via CLI (JIT tool's CLI)
   │
2. Request includes:
   ├── Role to elevate to (e.g., aws-prod-PowerUser)
   ├── Duration (e.g., 2 hours)
   ├── Justification (free text or ticket link)
   │
3. Approval gate
   ├── Auto-approve (low-risk roles, low-friction)
   ├── Approver notification (Slack / email / pager)
   ├── Approver reviews + approves
   │
4. Elevation enacted
   ├── IAM / RBAC role assignment created
   ├── Or temporary credentials issued
   │
5. User receives credentials / can now sign in with role
   │
6. User performs work
   │
7. Time expires (or user releases)
   ├── Role assignment removed
   ├── Credentials revoked
   │
8. Audit trail captured
   └── Who, when, why, approver, action-taken
```

### Per-platform realizations

#### AWS — IAM Identity Center + custom elevation

AWS doesn't have a first-party PIM equivalent in 2026 (Identity Center has session policies but not full JIT workflow). The patterns:

- **Custom Lambda + Step Functions:** the team builds a JIT pipeline. Request triggers Lambda; Step Function manages approval; on approval, Lambda creates the Permission Set assignment; expiration triggers removal. Engineering-heavy but full control.
- **Aponia / Sym / Indent:** SaaS JIT vendors that integrate with Identity Center. Reduce engineering load.
- **Teleport:** self-hosted access platform with JIT for AWS, K8s, databases.
- **Kion / Tamr / etc.:** cloud-management platforms that include JIT alongside other features.

The pattern: Identity Center holds the user-to-Permission-Set assignment; JIT tool adds / removes the assignment for the elevation duration.

#### Azure — Entra ID PIM

First-party JIT for Azure roles. The mature option.

```
Azure role assignment types:
├── Active: standing access (the legacy mode)
└── Eligible: PIM-gated, requires activation
```

PIM features:
- Per-role activation duration (default 4 hours, max 24).
- Per-role approval requirement (none, role-specific approver, group of approvers).
- Per-role MFA-on-activation requirement.
- Per-role justification requirement.
- Per-role ticket-system integration (require ticket number).
- Audit log of every activation.

Setup pattern: every Azure role assignment for production should be Eligible, not Active. Active is reserved for break-glass.

#### GCP — Just-in-Time Privileged Access (GCP PIM)

GCP's first-party JIT product (2024+ GA).

Features comparable to Entra ID PIM:
- Per-role activation duration.
- Per-role approval flow.
- Per-role justification.
- Audit logging.

Pattern: every Project Owner / Project Editor / Folder Admin role in production should go through GCP JIT.

#### Snowflake — Role-based with custom elevation

Snowflake has no first-party JIT product. Patterns:

- **Aponia / Sym:** SaaS integrators that manage Snowflake role grants on a JIT basis.
- **Custom:** a small service that issues `GRANT ROLE` to a user for a session, then `REVOKE ROLE` on expiration.

The mechanics are simple (Snowflake roles are easy to grant/revoke); the operational discipline is the work.

#### Generic SaaS — SCIM-based group management

For apps that don't have a native JIT product:
- The app has a group-to-role mapping (e.g., Slack #admins channel for "admin" access).
- JIT tool adds the user to the elevated group at activation; removes at expiration.
- SCIM provisions the change to the app.

Latency: SCIM sync delays mean the elevation may take 1-5 minutes to fully propagate. Document the expectation.

---

## Approval patterns

The variations and when each is appropriate.

### Auto-approve

The request is auto-approved if it meets predefined criteria. Used for low-risk elevations.

**Criteria might include:**
- Role is read-only or low-impact.
- Requester is in a pre-approved group.
- Duration is short (≤ 1 hour).
- Justification provided.

**When auto-approve is right:**
- Read-only audit roles where elevation is for compliance work.
- Developer access to staging environments.
- The vast majority of routine elevations in mature environments.

**When auto-approve is wrong:**
- Production admin roles.
- Roles with credential-management or data-deletion permissions.
- Cross-account or cross-tenant roles.

### Single-approver

One human approves. Typical for routine privileged elevations.

**Approver options:**
- The user's manager.
- A rotating on-call security engineer.
- A designated approver per role.

**Anti-pattern:** the approver is "anyone in the security team's channel." First-come-first-served approvals are theater (anyone bothering to look approves; nobody verifies).

**Fix:** specific approver(s) per role, listed in the JIT tool, paged when a request arrives.

### Multi-approver / Quorum

Two or more approvers required. For highest-impact roles.

**When to require:**
- Production-tier roles with destructive permissions (KMS key deletion, S3 bucket deletion, IAM admin).
- Cross-account role assumption to all-accounts.
- Roles that can read PHI / regulated data at scale.

**The friction is the feature.** Multi-approval is rare; when it happens, it gets attention.

### Approval-with-time-window

Approval is given for a future time window, not immediately. Use case: planned maintenance windows. Reduces "I forgot to approve" failures during scheduled work.

### Just-in-time + just-enough

Some JIT tools support narrowing the elevation scope at request time. Example: "I need PowerUser on `prod-account-A` for 2 hours" rather than "I need PowerUser everywhere." The tool grants only the requested scope.

The discipline: requests with narrower scope get faster approval. Wide-scope requests get more scrutiny.

---

## Duration patterns

How long is the elevation good for.

### The tiers

| Duration | When | Example |
| --- | --- | --- |
| 15 minutes | Quick task, very-high-privilege role | "I need to disable a specific KMS key now" |
| 1 hour | Short task | "Investigating an alert; need PowerUser to query" |
| 2-4 hours | Routine task | "Deploying a manual change; need Admin" |
| 8 hours | Full-day project | "Refactoring an IAM policy; need to iterate" |
| 24 hours | Maximum for routine elevation | Rare; should justify |

### Why short is better

- Short elevation = narrow attack window. If credentials are stolen mid-session, they're useful for less time.
- Short elevation = forcing function. Long elevation drifts toward standing access.
- Short elevation = audit clarity. "What did Alice do during her 2pm-4pm elevation" is a tight question.

### The "I just need to re-elevate" pattern

Users complain that 2-hour elevations require re-requesting. The right answer is usually:
- The work didn't actually need elevated access for the full duration; the user was idle in the elevated session.
- The work needed a different access path (e.g., the change should go through CI, not manual elevation).
- The duration is genuinely too short for this class of work; adjust the per-role default.

The wrong answer is "let me extend the default to 24 hours." That undoes most of the JIT benefit.

### Maximum duration

Per-role maximum cap. No elevation exceeds the cap, regardless of approver consent. Caps prevent the "I'll be honest, I need this until next Tuesday" requests.

---

## Audit and detection

What gets logged, what gets watched.

### What gets logged

Every elevation event:
- Requester (identity).
- Role.
- Duration.
- Justification.
- Approver(s).
- Approval timestamp.
- Activation timestamp.
- Deactivation timestamp.
- Approver justification (if rejected or modified).

### What gets watched

Detection rules to deploy:

- **Elevation without ticket** (when ticket is required by role policy).
- **Elevation outside business hours** for production roles.
- **Elevation by a user who hasn't activated in > 90 days** (could be a credential-takeover).
- **Approval from an approver who hasn't approved in > 90 days** (could be a credential takeover of the approver).
- **Failed activation attempts** (someone trying to elevate to a role they aren't eligible for).
- **Mass elevation in a short window** (script-driven elevation, possibly malicious).
- **Activation immediately followed by high-impact actions** (elevation → KMS key deletion within 1 minute = page).

### Cross-system correlation

The JIT system's audit log is one source; the cloud's CloudTrail / Activity Log / Audit Log is the other. Correlate:

- JIT log: "Alice elevated to aws-prod-PowerUser at 14:00."
- CloudTrail: "session arn:aws:sts::123:assumed-role/aws-prod-PowerUser/alice@meridian.com did X, Y, Z between 14:00 and 16:00."

Together: "what did Alice do during her elevation."

Without cross-correlation, the CloudTrail trail shows the role's actions but not why the user was elevated.

---

## JIT and break-glass

The reverse pattern.

### What break-glass is

The standing-access exception to JIT. A dedicated account / role with always-on permissions, used only when JIT can't be used (the JIT system is down, or the JIT system itself needs maintenance).

### Why break-glass exists

- The JIT system is a single point of failure. If it's down, no elevations are possible.
- The JIT system's own administration needs elevated access; can't be JIT-gated.
- Some emergency scenarios are too time-critical for the JIT flow.

### The discipline

- Break-glass accounts are dedicated; not used for daily work.
- Credentials are stored offline (sealed envelope, hardware token, etc.).
- Break-glass use is the highest-severity audit event; pages the security team.
- Tested quarterly (synthetic break-glass; verify the path works).
- Break-glass exception in conditional access policy is documented; quarterly reviewed.

### Anti-pattern: break-glass becomes the daily-use path

The team finds that JIT is slow, friction-laden, sometimes broken — and starts using break-glass for routine work. The break-glass account becomes the standing-admin path; the JIT system becomes vestigial.

The fix: monitor break-glass use; alert on any use (not just failures); track the trend; if it's increasing, fix the JIT system rather than accepting the bypass.

---

## Vendor patterns

The market in 2026.

### First-party (cloud-provider)

| Cloud | Product | Notes |
| --- | --- | --- |
| Azure | Entra ID PIM | Mature; widely used; standard pattern |
| GCP | Just-in-Time Privileged Access | GA; growing adoption |
| AWS | Identity Center session policies + no full PIM | Gap; custom or third-party fills it |

### Third-party

| Vendor | Strength | Notes |
| --- | --- | --- |
| Aponia | AWS-focused | Slack-native UX; good for AWS-heavy shops |
| Sym | Multi-cloud | Workflow-engine model; flexible |
| Indent | Multi-cloud + SaaS | Strong SaaS support |
| Teleport | Self-hosted | All-in-one access platform; AWS, K8s, DB, etc. |
| Britive | Multi-cloud + SaaS | CIEM-adjacent |
| CyberArk | Enterprise | PAM heritage; deep features |
| Saviynt | Enterprise | IGA + JIT |

The choice depends on:
- Which clouds and SaaS apps need coverage.
- Whether SaaS-hosted JIT is acceptable (regulatory considerations).
- Existing PAM / IGA investments.
- Engineering capacity for self-hosted alternatives.

### Self-built

Some teams build JIT from scratch. Pattern:
- Slack bot for requests.
- Lambda / Step Function for orchestration.
- DynamoDB / Postgres for state.
- Cloud-side role assignment via SDK.

Engineering cost: 1-2 quarters for a basic version; ongoing maintenance.

When self-built is right: highly customized requirements; no acceptable vendor; engineering capacity available.
When self-built is wrong: standard requirements that the vendors handle; limited engineering capacity.

---

## JIT done wrong

The failure modes.

### Wrong-1: Auto-approve everywhere

Every role is auto-approve. The JIT system creates a thin audit trail but doesn't actually constrain access. Functionally equivalent to standing access.

The fix: per-role approval policy; production roles require human approval.

### Wrong-2: 24-hour default duration

Defaults to 24-hour elevation; users never explicitly shorten. After a week, everyone has been elevated for the full day.

The fix: per-role default that matches the typical workload; 2-4 hours for most production roles; nudge users toward shorter on each elevation.

### Wrong-3: One approver, always available

"Approve all JIT requests" is in the bot's auto-approve list under a different name. The "approver" is a bot. Audit trail shows approvals; reality is auto-approve.

The fix: human approval for production roles; verify by spot-checking the approver-action distribution.

### Wrong-4: JIT-on-paper, standing-in-practice

The team configures JIT but leaves the standing role assignment intact "for backup." Users sign in with the standing role; the JIT system is unused.

The fix: remove the standing assignment; the JIT path is the only path; break-glass is the exception.

### Wrong-5: Approval is the same person as the requester

Self-approval (or co-worker rubber-stamp). The approval is theater.

The fix: approval requires segregation; the requester cannot be the approver; document the approver role.

### Wrong-6: No expiration enforcement

The JIT tool grants the role; the elevation expires; the tool fails to remove the role assignment. The user retains the role indefinitely.

The fix: per-elevation cron / reconciliation; the tool verifies removal happened.

### Wrong-7: JIT lifecycle disconnected from offboarding

User leaves; SCIM deprovisions the IdP account; the user's pending JIT elevations and JIT-eligibility don't get cleaned up. Orphaned elevations.

The fix: offboarding flow includes JIT cleanup; reconciliation script catches gaps.

---

## Worked example — Meridian Health JIT rollout (Q1 2026)

Meridian deployed JIT across AWS, Azure, GCP, and Snowflake in one quarter.

### Starting state

- ~80 users with standing PowerUser / Admin in AWS production accounts.
- ~40 users with standing Owner in Azure subscriptions.
- ~25 users with Project Owner in GCP production projects.
- ~15 users with ACCOUNTADMIN in Snowflake.
- No JIT in any system.
- Standing-admin compromise concern raised in last quarterly security review.

### Week 1-2 — Selection and design

Selected:
- Entra ID PIM for Azure (first-party).
- GCP JIT for GCP (first-party, recently GA).
- Aponia for AWS (Slack-native; team preferred over Sym/Indent).
- Custom Snowflake JIT (small Lambda; Aponia didn't yet support Snowflake natively).

Designed the per-role policy:
- Production AWS PowerUser: 2-hour default, single-approver from security on-call, MFA required at activation.
- Production AWS Admin: 1-hour default, two approvers, MFA + justification required.
- KMS Admin (all clouds): 30-minute default, two approvers, ticket reference required.
- Azure Production Owner: 2-hour default, single-approver, MFA.
- GCP Project Owner: 2-hour default, single-approver, MFA.
- Snowflake ACCOUNTADMIN: 1-hour default, single-approver, justification.

### Week 3-4 — Deployment

Configured each system per the policy. Did a phased deployment:
- Cohort 1: security-team members (could troubleshoot themselves).
- Cohort 2: engineering platform team.
- Cohort 3: application teams.

Each cohort had 1-week to adapt; helpdesk channel for issues.

### Week 5-6 — Standing-access removal

After cohort 3 adapted: removed standing-admin assignments. The JIT path became the only path. Break-glass accounts (one per cloud, sealed-envelope credentials) were exempted.

### Week 7-8 — Detection and ongoing

- SIEM rule: any break-glass account use pages security.
- SIEM rule: any activation outside business hours for production roles.
- SIEM rule: activation immediately followed by destructive actions.
- Weekly review: who's elevating, to what, for how long; identify outliers.
- Per-quarter review: roles still in JIT scope; new roles to add; over-broad scopes.

### Findings opened during the rollout

- **JIT-001** (80 users with standing AWS PowerUser). Closed by Aponia + standing removal.
- **JIT-002** (40 users with standing Azure Owner). Closed by PIM-eligible conversion.
- **JIT-003** (25 users with standing GCP Project Owner). Closed by GCP JIT conversion.
- **JIT-004** (15 users with standing Snowflake ACCOUNTADMIN). Closed by custom Snowflake JIT.
- **JIT-005** (No break-glass account documented per cloud). Closed by per-cloud break-glass setup + quarterly test.
- **JIT-006** (No detection on break-glass use). Closed by SIEM rule.
- **JIT-007** (No detection on activation-followed-by-destructive-action). Closed by correlated rule.

The quarter cost ~1.5 FTE of security + platform engineering. Ongoing maintenance: ~0.1 FTE / quarter.

After 6 months in production: ~6,000 elevations processed; mean activation duration 47 minutes (well under the policy max); zero break-glass uses; zero standing-admin re-creations.

---

## Anti-patterns

### 1. JIT-on-paper, standing-in-practice

Standing assignments left in place "for backup." Users default to the standing path.

The fix: remove standing assignments; JIT is the only path.

### 2. Auto-approve for production roles

Production-tier elevation auto-approves. The audit trail looks impressive; the access decision wasn't actually made.

The fix: per-role policy; human approval for production-impact roles.

### 3. 24-hour default elevations

Users never re-elevate because the elevation is good for a day. Functionally equivalent to standing access.

The fix: per-role default matched to typical workload; 2-4 hours for most production roles.

### 4. Single permanent approver

One person is the approver for everything. They approve in their sleep. Compromise of the approver = approval of all elevations.

The fix: rotating approver (on-call rotation); approver-quorum for high-impact roles; spot-check the approver's actions monthly.

### 5. JIT tool runs as a standing-admin itself

The JIT tool needs to grant / revoke roles; it has the cloud-side permissions to do so; those permissions are standing. The JIT tool's own credentials are now the standing-admin path.

The fix: JIT tool's permissions are scoped narrowly (only the roles it manages); audit on the JIT tool's API calls; rotate JIT tool credentials regularly.

### 6. Break-glass account used for routine work

Friction in JIT drives users to break-glass as a workaround.

The fix: monitor break-glass use; alert on every use; fix the JIT friction rather than tolerating the bypass.

### 7. Elevation without justification

Justification field is optional or accepts "work" as the answer. The audit trail is uninformative.

The fix: per-role policy requiring meaningful justification; ticket reference for high-impact roles; spot-check the justifications.

### 8. Cross-cloud elevation without coordinated detection

JIT in AWS, JIT in Azure, JIT in GCP — each with its own audit trail. A user elevated in all three simultaneously isn't flagged because no system sees the combined picture.

The fix: SIEM ingests all JIT audit logs; cross-system correlation; alert on multi-cloud elevation by single user.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| JIT-001 | Standing administrator access in production cloud | High | JIT-eligible conversion; remove standing assignment | Identity + Security Eng |
| JIT-002 | Auto-approve for production-impact roles | High | Per-role human approval; segregation of requester / approver | Identity + Security Eng |
| JIT-003 | Elevation duration > 4 hours by default for production roles | Medium | Reduce default; per-role tuning | Identity |
| JIT-004 | No break-glass account documented per cloud | High | Per-cloud break-glass with sealed credentials; quarterly test | Identity + Security Eng |
| JIT-005 | Break-glass use not detected / alerted | High | SIEM rule on any break-glass use | Detection Eng + SOC |
| JIT-006 | JIT tool runs with standing-admin permissions on cloud | Medium | Scope tool's permissions narrowly; audit on tool API calls | Identity + Security Eng |
| JIT-007 | Single permanent approver for elevations | Medium | Rotating approver; quorum for high-impact roles | Identity + Security Eng |
| JIT-008 | Elevation without justification field enforced | Low | Per-role policy requiring meaningful justification | Identity |
| JIT-009 | No detection on activation-immediately-followed-by-destructive-action | High | Correlated rule on elevation + KMS deletion / IAM modification / etc. | Detection Eng + SOC |
| JIT-010 | No cross-system audit-log correlation across cloud JIT systems | Medium | SIEM ingestion of all JIT logs; cross-system query | Detection Eng |
| JIT-011 | Elevations not enforced to expire (cleanup failure) | High | Reconciliation script verifies role removal; alert on stuck elevations | Identity + Security Eng |
| JIT-012 | Offboarding doesn't clean up JIT eligibility | Medium | Offboarding checklist includes JIT cleanup; reconciliation catches gaps | Identity + HR |
| JIT-013 | Approver action distribution suggests rubber-stamp pattern | Medium | Monthly spot-check; targeted training; rotation if needed | Security Eng + Identity |
| JIT-014 | No JIT for SaaS apps (Snowflake, etc.) | Medium | Extend JIT to SaaS via SCIM-group-based pattern | Identity + Security Eng |
| JIT-015 | JIT elevation outside business hours not specifically alerted | Low | SIEM rule on after-hours elevation for production roles | Detection Eng + SOC |
| JIT-016 | Activation requires MFA but not phishing-resistant factor | Medium | Per-role policy requiring WebAuthn / FIDO2 for highest-impact roles | Identity + Security Eng |
| JIT-017 | Mass-elevation (script-driven) pattern not detected | Medium | SIEM rule on > N elevations in T minutes by single user | Detection Eng |
| JIT-018 | Per-quarter review of JIT scope / policy not happening | Low | Quarterly process; documentation of changes | Identity + Security Eng |

---

## Adoption checklist

- [ ] Identify roles in scope for JIT (production cloud admins, KMS admins, etc.).
- [ ] Select JIT tooling per cloud / app (first-party where possible; vendor / self-built otherwise).
- [ ] Per-role policy: duration, approver, MFA, justification.
- [ ] Phased rollout: security team → platform team → application teams.
- [ ] Remove standing-admin assignments after rollout cohort adapts.
- [ ] Break-glass account per cloud; sealed credentials; quarterly test.
- [ ] SIEM ingestion of all JIT audit logs.
- [ ] SIEM rules: break-glass use, activation-then-destructive-action, after-hours elevation, mass elevation.
- [ ] Cross-system correlation: multi-cloud elevations by single user.
- [ ] Reconciliation script: stuck elevations cleanup.
- [ ] Offboarding flow includes JIT cleanup.
- [ ] Quarterly review of JIT scope, policy, and approver distribution.
- [ ] Approver action spot-check monthly; identify rubber-stamp patterns.
- [ ] Per-role MFA-on-activation requirement; phishing-resistant for highest-impact.
- [ ] JIT tool's own credentials rotated regularly; tool's permissions scoped narrowly.
- [ ] Per-role policy reviewed annually; tune defaults based on actual usage.

---

## What this document is not

- **A PIM / JIT product comparison.** Aponia, Sym, Indent, Teleport, etc. all work; the choice depends on your stack.
- **A complete IAM design.** [workforce-identity.md](./workforce-identity.md) covers the broader workforce-identity architecture.
- **A workload-identity guide.** [workload-identity.md](./workload-identity.md) covers service-to-cloud authentication.
- **A federation-mechanics reference.** [federation-patterns.md](./federation-patterns.md) covers SAML / OIDC / SCIM.
- **A PAM (Privileged Access Management) deep-dive.** PAM tools (CyberArk, BeyondTrust) overlap with PIM / JIT; some teams use both.
- **A complete identity-governance reference.** Access certification, recertification, segregation-of-duties analysis live in IGA platforms (SailPoint, Saviynt, Entra Governance, Okta Identity Governance).
