# Rotation Patterns

A practitioner's reference for secret rotation in cloud environments — rotation cadence, the rotate-without-downtime pattern (dual-credential rotation), AWS Secrets Manager rotation Lambdas, Azure Key Vault rotation, the "verify the new credential works *before* invalidating the old one" baseline, and the rotation-runbook structure that catches silent rotation failures.

This document is about rotating *static secrets* — credentials that need to change periodically because the secret-as-credential model demands it. For dynamic credentials (Vault's database engine, IAM auth, OIDC federation), rotation is implicit (every credential is short-lived). The patterns here apply to the residual secrets that survived the elimination playbook in [kill-the-static-secret.md](./kill-the-static-secret.md).

For the secrets-manager features that enable rotation, see [secrets-manager-patterns.md](./secrets-manager-patterns.md). For the Vault dynamic-credential alternative that obviates rotation, see [vault-patterns.md](./vault-patterns.md). For detection of secrets that should have rotated but didn't, see [secret-detection.md](./secret-detection.md).

---

## When to read this document

**If your secrets rotate annually because that's what compliance asked for** — read top to bottom. Rotation cadence and rotation discipline are different problems; this document covers both.

**If you've automated rotation and the rotation job sometimes silently fails** — start with [The verify-before-invalidate pattern](#the-verify-before-invalidate-pattern). The pattern eliminates silent rotation failures by making them loud.

**If you operate a workload with thousands of secrets** — start with [Rotation at scale](#rotation-at-scale). The patterns differ from rotating a handful of secrets.

**If you are auditing rotation posture** — start with [Findings checklist](#findings-checklist). Most environments have unrotated secrets, mis-rotated secrets, and rotation jobs that haven't successfully run in months.

---

## Why rotation matters (and where it doesn't)

The premise: a static secret leaks. The leak vector might be:

- An engineer commits the secret to a public repo.
- A backup of a configuration file leaks.
- A compromised endpoint exposes the secret store.
- A compromised CI environment leaks the secret.
- A vendor (whose API key it is) discloses the secret in their breach.

Rotation bounds the damage window. A secret rotated every 90 days has a maximum exposure window of 90 days from any single leak event.

For dynamic credentials — credentials that are issued fresh on every use, with short TTLs — rotation is implicit. There is nothing to rotate; every credential is already new.

For static secrets — long-lived credentials stored somewhere — rotation is the structural mitigation against the unknown leak. The cadence depends on the secret's blast radius and the threat model.

### When rotation is essential

- **High-privilege credentials.** Database admin passwords, cloud-IAM access keys, root CA private keys. These deserve aggressive rotation (30–90 days).
- **Credentials in environments with high turnover.** Engineers leaving the company; CI environments with many contributors; shared infrastructure.
- **Compliance-mandated rotation.** PCI-DSS requires periodic credential rotation; HIPAA-derived contracts often do; FedRAMP requires.

### When rotation is theater

- **Internal-only secrets with no external exposure.** A credential used only by one application within one VPC, where the secret is fetched via IAM-restricted Secrets Manager. The threat model doesn't include leak vectors that rotation would mitigate.
- **Application-API keys consumed by trusted partners with their own rotation discipline.** Rotation creates coordination overhead without commensurate benefit.

The discipline: **rotate the credentials that matter; don't burn cycles rotating credentials where the threat model doesn't justify it.**

---

## Rotation cadence

The cadence is a security trade-off, not a fixed answer.

| Credential class | Recommended cadence |
| --- | --- |
| Database admin / root credentials | 30–90 days |
| Cloud-IAM access keys (residual; should be migrated to OIDC per [kill-the-static-secret.md](./kill-the-static-secret.md)) | 30–90 days |
| Application-to-database (where IAM auth not available) | 90 days |
| Third-party API keys (Datadog, PagerDuty, etc.) | Quarterly to annual |
| Per-tenant API keys (issued to customers) | Annual, with customer notification |
| Internal-service shared secrets | 90 days (or move to dynamic credentials) |
| PKI signing keys (intermediate CA) | Multi-year (with proper key-ceremony) |

The pattern: more sensitive credentials rotate more often. The cost of more-frequent rotation is more chances for rotation to break; the benefit is shorter leak-exposure windows.

### Compliance-mandated cadences

- **PCI-DSS 4.0** requires keys protecting cardholder data to be rotated; the cadence is risk-based but typically annual minimum.
- **HIPAA** does not specify a cadence but requires "periodic" review.
- **FedRAMP** requires rotation per the relevant NIST controls; varies by control.
- **SOC 2** auditors typically expect documented rotation cadence with evidence.

Document the cadence; evidence the rotation; the audit story writes itself.

### The "rotate on event" pattern

Beyond scheduled rotation, **event-driven rotation** is the discipline of rotating on specific events:

- An engineer who had access leaves the company.
- A credential is suspected of leaking (detected by secret scanning).
- A vendor discloses a breach.
- A compromised system is investigated.

Event-driven rotation is the response; scheduled rotation is the baseline.

---

## The verify-before-invalidate pattern

The most important rotation pattern. The discipline that prevents silent rotation failures.

### The failure mode it prevents

The naive rotation:

1. Generate a new credential.
2. Replace the old credential with the new in the secret store.
3. Invalidate the old credential at the source (database, API, etc.).
4. Hope the application picks up the new credential.

The failure: between step 2 and step 4, the application is still using the old credential (cached); after step 3, the application breaks. The team learns about the failure when users complain.

### The verify-before-invalidate sequence

1. **Generate a new credential.** The new credential is created at the source (database, API) but the old credential is *still valid*.
2. **Store the new credential in the secrets store.** The application's next fetch will get the new value. The old credential remains valid.
3. **Verify the new credential works.** Connect using the new credential; perform a representative operation; confirm success.
4. **Wait for propagation.** Give applications time to fetch the new credential (one cache TTL, plus margin).
5. **Invalidate the old credential.** Now safe; everyone is using the new.
6. **Verify nothing breaks.** Monitor application health; if anything was still using the old credential, it now breaks loudly.

The pattern adds time to rotation (steps 4–6) but eliminates silent failures.

### AWS Secrets Manager rotation Lambda pattern

AWS Secrets Manager rotation supports this natively via the four-step Lambda contract:

- **`createSecret`** — generate the new credential; store as `AWSPENDING` version.
- **`setSecret`** — apply the new credential at the source (e.g., update the database password).
- **`testSecret`** — verify the new credential works.
- **`finishSecret`** — move `AWSPENDING` to `AWSCURRENT`; old `AWSCURRENT` becomes `AWSPREVIOUS`.

The Lambda runs the four steps in sequence. If any step fails, the rotation halts; the old credential remains valid; the team is alerted.

For supported databases (RDS Postgres / MySQL / MariaDB / SQL Server / Oracle, Redshift, DocumentDB), AWS provides reference Lambdas. For other secrets, the team writes the Lambda.

### Azure Key Vault rotation

Azure supports auto-rotation for some secret types (storage account keys, managed identity, certificates from supported CAs). For application-managed secrets, the pattern is similar:

- Event Grid notification on rotation needed.
- Function App handles the rotation.
- Verify-before-invalidate via Key Vault's version model (new version added; old version disabled only after verification).

### Manual rotation runbook

For secrets that can't be auto-rotated, the manual runbook follows the same pattern:

1. **Pre-rotation:** verify the new credential will be deployable; confirm consumer applications have refresh logic; schedule the rotation window.
2. **Generate** the new credential.
3. **Store** the new credential in the secret store as a new version.
4. **Verify** the new credential works (out-of-band test).
5. **Wait** for application refresh (or trigger refresh manually).
6. **Invalidate** the old credential.
7. **Monitor** for failures.

Document the runbook per credential type. Update when the procedure changes.

References:
- [AWS Secrets Manager rotation Lambda](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)
- [Azure Key Vault key rotation](https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation)
- [GCP Secret Manager rotation](https://cloud.google.com/secret-manager/docs/rotation-recommendations)

---

## The dual-credential rotation pattern

For credentials that cannot tolerate the verify-and-wait pattern (e.g., a session-token shared secret used by many services simultaneously), the dual-credential pattern.

### How it works

The downstream system (the consumer of the credential) accepts *two* credentials simultaneously:

- **Current credential.** The credential applications are using now.
- **Next credential.** A credential that applications will rotate to.

Rotation:

1. Generate the next credential.
2. Activate it on the downstream system (now both work).
3. Migrate consumers to the next credential.
4. Verify all consumers have migrated.
5. Deactivate the original credential.

The benefit: at every moment, at least one credential is valid; no gap in service.

### When it applies

- **API keys** where consumers may not refresh in lock-step.
- **JWT signing keys** where issued tokens are still valid for their TTL.
- **HMAC shared secrets** in legacy integrations.

### When it does not apply

- **Database passwords.** Database accepts one password at a time.
- **TLS certificates.** Certificate replacement is verify-before-invalidate.
- **Cloud IAM access keys.** Two keys can coexist (AWS allows two active access keys); migrate consumers; deactivate the old. AWS access-key rotation natively supports this pattern.

---

## Rotation at scale

For environments with hundreds or thousands of secrets, rotation as a per-secret manual task doesn't scale.

### The scheduled rotation queue

A central scheduler:

- **Knows the rotation cadence** for every secret (from tags or rotation config).
- **Queues rotations** by due-date.
- **Triggers rotation** on schedule (rotation Lambda, Function App, or equivalent).
- **Monitors completion** and alerts on failures.

For AWS: Secrets Manager's built-in scheduling handles this. For Azure / GCP: Event Grid / Cloud Scheduler + Functions.

### Rotation as code

Rotation procedures should be version-controlled:

- Lambda function code in Git.
- Configuration (which secret rotates how often, which Lambda handles it) in IaC.
- Changes go through PR review.

This avoids the "rotation worked, but no one knows why or how" failure mode.

### Failure handling at scale

When rotation fails:

- **Immediate alert** to the secret's owner (per tagging discipline in [secrets-manager-patterns.md](./secrets-manager-patterns.md)).
- **Old credential remains valid** (verify-before-invalidate); no immediate breakage.
- **Investigation and fix** within SLA.
- **Re-run** after fix.

The rotation failure should be loud (paging, ticket auto-creation) but not break operations.

### Rotation observability

A dashboard:

- **Rotation success rate per environment** (trending).
- **Time since last rotation per secret** (overdue alerts).
- **Failed rotations** (current; investigate).
- **Rotations queued for next 7 days** (capacity planning).

The metric drives behavior; without it, rotation health is invisible.

---

## Worked example: Meridian Health's rotation discipline

Meridian operates rotation on the residual static secrets after the elimination playbook removed ~80% of the original credential count.

### What rotates

- **Database master passwords** (where IAM auth isn't supported for the engine version): 90-day automatic rotation via Secrets Manager Lambda.
- **Third-party API keys** (Datadog, PagerDuty, Snyk, GitHub deploy keys for CI): quarterly manual rotation following runbook.
- **Per-tenant API keys** issued by Meridian to customers: annual rotation with 60-day customer notification.
- **Internal service shared secrets** (the few that haven't migrated to dynamic credentials): 90-day automatic rotation.
- **PKI intermediate CA** (Vault PKI): 18-month rotation with planned re-issuance of dependent certificates.

### The verify-before-invalidate enforcement

Every rotation Lambda follows the four-step Secrets Manager contract. Each step is logged; rotation failures alert the security team.

Example: the Aurora cluster's master password rotation Lambda:

1. **`createSecret`:** generate a new 32-character password; store as `AWSPENDING`.
2. **`setSecret`:** use the existing master credential to set the new password on the Aurora cluster.
3. **`testSecret`:** connect to Aurora with the new password; perform a representative SELECT; confirm.
4. **`finishSecret`:** move `AWSPENDING` to `AWSCURRENT`.

If `testSecret` fails (most commonly because Aurora's password change is still propagating), Secrets Manager retries with backoff. After exhausted retries, the rotation is marked failed; old credential remains valid; team is alerted.

### Manual runbook structure

The runbook for each manually-rotated credential includes:

- **Pre-rotation checklist:** verify consumer health, confirm pre-rotation backup of the secret, schedule the window.
- **Rotation steps:** generate, store, verify, propagate, invalidate.
- **Rollback procedure:** if rotation fails after invalidation, revert to the previous version (Secrets Manager `AWSPREVIOUS`).
- **Post-rotation verification:** monitor application health for 24 hours.

Runbooks are in source control; updated when procedures change.

### Failure-handling pattern

When a rotation Lambda fails:

- **CloudWatch alarm** on Lambda error rate triggers.
- **PagerDuty incident** auto-created.
- **Security team on-call** investigates within 30 minutes.
- **Old credential** remains valid; application is unaffected.
- **Fix and re-run** within SLA (usually same business day).

If the failure is not addressed in 7 days (the credential is now overdue for rotation), the SLA escalates.

### Rotation observability

Meridian's CloudWatch dashboard shows:

- Number of rotations succeeded in the last 7 days.
- Number of failures.
- Time since last rotation per secret class.
- Overdue rotations (secrets past their rotation cadence + grace period).

The dashboard is reviewed weekly by the security team.

### Findings opened during the rotation audit

- **ROT-001** (Aurora master password had not rotated in 14 months; rotation Lambda had been failing silently). Closed by fixing the Lambda; one-time manual rotation; alerting on Lambda failures.
- **ROT-002** (Datadog API key rotation was annual but the runbook had been lost). Closed by re-documenting; ticket auto-created on rotation due date.
- **ROT-003** (per-tenant API keys had no rotation schedule). Closed by establishing annual cadence with customer notification.
- **ROT-004** (PKI intermediate CA had been issued 5 years ago; rotation was overdue). Closed by planned re-issuance project (multi-quarter due to dependent certificate planning).
- **ROT-005** (no observability on rotation success rate; failures were invisible). Closed by the dashboard + alerting.

---

## Anti-patterns

### 1. The rotation Lambda that never runs

Rotation is configured but the Lambda has been failing silently for months. Nobody notices because there's no monitoring on the rotation job. The credential ages indefinitely.

The fix: monitoring + alerting on rotation success / failure. Loud failures, not silent.

### 2. The rotate-without-verify

The rotation pattern is: generate, store, invalidate old. No verification step. Consumers break; the team scrambles to roll back.

The fix: verify-before-invalidate. Always.

### 3. The compliance-driven rotation theater

The team rotates every 365 days because "compliance says so." The rotation provides no actual security improvement because the credential's threat model doesn't include leaks that rotation would catch.

The fix: rotate the credentials that matter (high-privilege, frequently-exposed); document why others don't rotate.

### 4. The rotation that breaks the runbook

A rotation runs on schedule. The application breaks because it doesn't refresh from Secrets Manager (cached the credential without invalidation). The runbook documents a procedure but the runtime doesn't follow it.

The fix: applications use the cache-with-invalidation pattern; SDK helpers handle refresh.

### 5. The rollback-impossible rotation

A credential rotated; the old credential is destroyed. The new credential turns out to be broken. The team has no way to recover; the only option is to issue a third credential and reconfigure consumers.

The fix: keep previous version (Secrets Manager `AWSPREVIOUS`, Azure Key Vault disabled-but-not-deleted, GCP Secret Manager disabled-but-not-destroyed versions) for a recovery window.

### 6. The forgotten manual rotation

A credential requires manual rotation. The procedure is in a wiki. The engineer who knew it has left. The credential ages indefinitely because nobody knows how to rotate it.

The fix: rotation procedures in source-controlled runbooks; rotation triggers create tickets; new engineers learn during onboarding.

### 7. The dual-credential without cleanup

The dual-credential rotation runs successfully. Both credentials are valid. The team forgets to deactivate the old credential. Six months later, two valid credentials exist; the rotation gave no security benefit.

The fix: dual-credential pattern includes the deactivation step; verify deactivation in the runbook.

### 8. The rotation cadence by guess

Each team picks its own rotation cadence based on intuition. Some rotate quarterly; some annually; some never. No documented rationale.

The fix: document cadence per credential class based on threat model + compliance; enforce via CSPM (find credentials older than their class's cadence).

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| ROT-001 | Secret has not rotated within its documented cadence | High | Investigate rotation failure; manual rotation; fix automation | Security Eng + Workload Owner |
| ROT-002 | Rotation Lambda failures are not monitored | High | CloudWatch / Function App / Cloud Function alerting on rotation errors | Platform Eng + SOC |
| ROT-003 | Rotation does not include verify-before-invalidate step | High | Migrate to four-step pattern (create, set, test, finish) | Platform Eng + Workload Owner |
| ROT-004 | Manual rotation runbook missing or out of date | Medium | Source-control runbooks; update on procedure changes | Security Eng |
| ROT-005 | Rotation observability dashboard absent | Medium | Build dashboard: success rate, time-since-last-rotation, overdue secrets | Security Eng + Observability |
| ROT-006 | Application caches credential without refresh-on-auth-failure | High | Cache wrapper invalidates on auth error; explicit refresh API | Workload Owner |
| ROT-007 | Previous version of secret destroyed; rollback impossible | Medium | Keep previous version for recovery window (default 30 days) | Security Eng |
| ROT-008 | Dual-credential rotation: old credential not deactivated after migration | Medium | Runbook includes deactivation step; verify in audit | Security Eng + Workload Owner |
| ROT-009 | Rotation cadence undocumented or inconsistent across teams | Low | Document per credential class; CSPM enforces | Security Eng |
| ROT-010 | High-privilege credentials rotate less frequently than risk-based cadence | High | Tighten cadence for high-privilege (database admin, cloud IAM, root CA) | Security Eng + Compliance |
| ROT-011 | Per-tenant API keys lack rotation schedule | Medium | Establish annual cadence; customer notification process | Customer Eng + Security Eng |
| ROT-012 | Rotation triggers no ticket / notification; engineers don't know to act | Medium | Auto-create tickets on manual-rotation due dates | Security Eng + Platform Eng |
| ROT-013 | Rotation failure SLAs not defined or not enforced | Medium | SLA per credential class; escalation on overdue rotation | Security Eng |
| ROT-014 | PKI key rotation overdue; certificate trust chain weak | High | Planned re-issuance project; coordinate dependent certificates | Security Eng + Platform Eng |
| ROT-015 | Compliance-driven rotation on credentials where it provides no security benefit | Low | Document risk-based cadence; align with compliance via documentation | Security Eng + Compliance |
| ROT-016 | Rotation Lambda has broader IAM than needed (e.g., admin on entire database) | Medium | Tighten Lambda IAM to rotation-specific privileges only | Security Eng + IAM Eng |
| ROT-017 | Rotation procedure differs between dev and prod; staging rotation untested | Medium | Same procedure across environments; test in staging | Platform Eng + Security Eng |
| ROT-018 | Rotation logs not consumed by SIEM; rotation anomalies invisible | Medium | SIEM rule on rotation events; alert on unusual patterns | Security Eng + SOC |

---

## What this document is not

- **A rotation-tool comparison.** AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Vault are named; the patterns transfer.
- **A complete PKI reference.** Certificate rotation is mentioned; the deeper PKI patterns belong with [vault-patterns.md](./vault-patterns.md) PKI engine and with cert-manager / acme-client docs.
- **A compliance-clause guide.** PCI / HIPAA / FedRAMP rotation-specific language is summarized; [../compliance-and-control-mapping/](../compliance-and-control-mapping/) is the destination for the row-by-row mapping.
- **A complete rotation-as-code framework.** Patterns are described; tooling (rotation orchestrators, dependency-aware rotation systems) is environment-specific.
