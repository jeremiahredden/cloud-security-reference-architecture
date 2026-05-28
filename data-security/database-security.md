# Database Security

A practitioner's reference for hardening managed cloud databases — RDS / Aurora on AWS, Azure SQL / Cosmos DB on Azure, Cloud SQL / Spanner on GCP. The patterns here cover network exposure, encryption, IAM database authentication, audit logging, the connection-pooling and Secrets-Manager-as-credential pattern, and the no-public-endpoint baseline that is the single highest-leverage database control.

This document is about *managed* databases. Self-managed databases on EC2 / VMs inherit the same patterns plus the operational burden of patching, replication, and backup management. The cloud-native managed offerings (Aurora, Cloud SQL, Azure SQL, Cosmos DB, DynamoDB, Spanner) handle the operational burden; the security configuration is what teams own.

For the encryption decisions (CMK vs provider-managed), see [byok-hyok-cmk.md](./byok-hyok-cmk.md). For the KMS hierarchy that databases consume, see [kms-strategy.md](./kms-strategy.md). For backup-specific hardening, see [backup-and-data-residency.md](./backup-and-data-residency.md).

---

## When to read this document

**If you are landing a new database for a production workload** — read top to bottom. The decisions here (public vs private endpoint, IAM auth vs password, audit log destination) are made implicitly when nobody addresses them; making them explicitly is the discipline.

**If you have inherited a database with a public endpoint** — start with [The no-public-endpoint baseline](#the-no-public-endpoint-baseline). The migration is bounded; the security improvement is meaningful.

**If you are auditing database posture** — start with [Findings checklist](#findings-checklist). The most common findings (public endpoint, weak authentication, no audit logging, encryption mismatch) are universal in environments that haven't done the work.

**If you are setting up database access for a workload** — start with [Authentication patterns](#authentication-patterns) and [Connection management](#connection-management). The pattern is IAM-native where supported, Secrets-Manager-broker where it is not, never hardcoded.

---

## The no-public-endpoint baseline

The single most important database control: production databases should not be reachable from the internet.

### What "no public endpoint" means

- **AWS RDS / Aurora:** `PubliclyAccessible: false` at creation. Subnets in the DB subnet group are private subnets only. Security group allows ingress only from application-tier security groups.
- **Azure SQL:** `Public network access: Disabled`. Connections via Private Endpoint or VNet service endpoint only.
- **Cloud SQL:** `private_network` set to the VPC; no `authorized_networks` for public IPs. Public IP not assigned (or assigned and behind a firewall denying `0.0.0.0/0`).
- **Cosmos DB / DynamoDB:** Private Endpoint / VPC endpoint; no public access through resource-level firewall.

### How to enforce organization-wide

The most effective enforcement is at the policy layer:

- **AWS SCP** denies `rds:CreateDBInstance` / `rds:CreateDBCluster` with `PubliclyAccessible: true` for non-public-data accounts.
- **Azure Policy** `[Preview]: Public network access on Azure SQL Database should be disabled` at the Management Group level.
- **GCP Organization Policy** `sql.restrictPublicIp` denies Cloud SQL instances with public IPs.

Workloads that need to connect from outside their VPC use a bastion (Session Manager / Azure Bastion / IAP) or PrivateLink rather than a public endpoint.

### The "but we need to connect from anywhere" pushback

The objection: "developers need to connect from their laptops; CI runners need access; on-prem services need to reach the database."

The responses:

- **Developer access:** via Session Manager / Azure Bastion / IAP tunneling to a database client EC2 / VM. The developer authenticates to the cloud; the cloud authenticates to the database.
- **CI runner access:** the CI runner should be in the VPC (self-hosted runner) or use a temporary egress channel via the bastion pattern.
- **On-prem access:** Direct Connect / ExpressRoute / Cloud Interconnect for production; the on-prem network reaches the database via private connectivity.

The "we need it to be public" pushback is almost always solvable with one of these patterns. Public endpoints exist because they were the path of least resistance at creation time, not because the workload genuinely needs them.

### When public endpoints are legitimate

Rare cases:

- **Multi-tenant SaaS databases where customers connect from anywhere.** These are still hardened with strict IP allowlists (per customer); end-to-end TLS; IAM-equivalent or strong password auth. The endpoint is technically public; the access surface is tight.
- **Public-data datasets (open research data, public reference tables).** Read-only; no PII; minimal value to attackers.

Document the exception; audit quarterly.

References:
- [AWS RDS publicly accessible](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RDS_Fea_Regions_DB-eng.Feature.PubliclyAccessible.html)
- [Azure SQL public network access](https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings)
- [Cloud SQL private IP](https://cloud.google.com/sql/docs/mysql/private-ip)

---

## Authentication patterns

Three patterns for database authentication, in order of preference.

### 1. IAM database authentication (where supported)

Cloud-native IAM principals authenticate directly to the database. The cloud provider's IAM is the source of truth; the database trusts the cloud-IAM token.

- **AWS RDS / Aurora (MySQL, PostgreSQL):** `aws_iam_authentication=true`. Application calls `rds.generate_db_auth_token`; uses the token as the password; expires after 15 minutes.
- **Azure SQL:** Azure AD Authentication. Application uses Managed Identity to obtain a token; uses the token to authenticate.
- **Cloud SQL (MySQL, PostgreSQL):** IAM database authentication via service accounts and the Cloud SQL Auth Proxy.
- **DynamoDB / Cosmos DB:** native IAM (no separate database authentication; the cloud IAM is the access control).

The benefits:

- No passwords stored anywhere.
- Credentials are short-lived (15 min for RDS; configurable for others).
- Rotation is automatic (every token is fresh).
- Audit trail is rich (CloudTrail / Activity Log / Audit Log captures the token-issuance event).
- Compromise of an IAM principal is bounded by IAM, not by a leaked password.

The cost:

- Per-connection authentication is more expensive (token-issuance overhead).
- Some legacy database tooling does not support IAM auth; requires adapter.
- High-throughput applications need to cache tokens carefully.

### 2. Secrets Manager / Key Vault broker (when IAM auth is not supported)

For databases that don't support IAM auth (e.g., Microsoft SQL Server on RDS, older database engines):

- Database password is stored in Secrets Manager / Key Vault / Secret Manager.
- Application IAM grants permission to fetch the specific secret.
- Application retrieves the password at startup or per-connection.
- Secret rotation is automated (Secrets Manager Rotation Lambda or equivalent).

The benefits:

- Password is not in `.env` files, not in IaC, not in source code.
- Rotation is automated.
- Access to the password is audited (Secrets Manager logs the GetSecretValue calls).
- Compromise of a connection-string-in-disk is harder.

The cost:

- One additional dependency in the connection path.
- Rotation must be tested; silent rotation failures break workloads.
- Secret retrieval adds latency on connection establishment.

### 3. Hardcoded passwords (never)

The pattern that should not exist:

- Password in `.env` files committed to source control.
- Password in IaC template variables (Terraform `tfvars`, CloudFormation parameters).
- Password in container environment variables baked into the image.
- Password in a CI/CD pipeline secret.

These patterns leak. The leaks are some of the most common breach vectors in cloud incidents.

The fix: every static password is a migration target to IAM auth or Secrets Manager.

### The authentication migration sequence

For environments with hardcoded passwords:

1. **Inventory.** Find every database connection string in the environment. Scan source code, IaC, container images, CI configurations.
2. **Migrate to Secrets Manager broker.** Move passwords to Secrets Manager; application reads at startup. This is the lower-effort migration; works for any database engine.
3. **Where supported, migrate to IAM auth.** Eliminate the password entirely.
4. **Enforce.** SCP / Azure Policy / Org Policy that prevents database creation without IAM auth or rotation-enabled passwords.

The migration takes weeks for a typical environment; the steady state is dramatically improved.

---

## Encryption

Database encryption has two dimensions: at-rest and in-transit.

### Encryption at rest

- **AWS RDS / Aurora:** `StorageEncrypted: true` at creation. Cannot be changed after creation. CMK is the right choice for regulated workloads (per [byok-hyok-cmk.md](./byok-hyok-cmk.md)).
- **Azure SQL:** Transparent Data Encryption (TDE) is enabled by default. Customer-managed key via Key Vault supported.
- **Cloud SQL:** Encrypted at rest by default. CMEK via Cloud KMS supported.
- **Cosmos DB / DynamoDB:** Encrypted at rest by default. CMEK / CMK supported.

The discipline:

- **Encryption enabled at creation** (cannot be added later for RDS without snapshot+restore).
- **CMK for regulated data** (not the default AWS / provider-managed key).
- **Key rotation per the CMK strategy** ([kms-strategy.md](./kms-strategy.md)).
- **Backup encryption uses the same CMK** (or a backup-specific CMK; the encryption must apply to backups, not just live data).

### Encryption in transit

- **TLS required** for all database connections.
- **TLS 1.2 minimum**; TLS 1.3 where supported.
- **Certificate validation enabled** in clients (the most common mistake is `sslmode=require` instead of `sslmode=verify-full`).
- **Cipher suite restrictions** for high-assurance environments.

The cloud-native databases enforce TLS by default in 2026; older configurations may not. Audit.

### The encryption mismatch failure

A common failure mode: the database is encrypted with a CMK; the application code does not validate the server's TLS certificate; an attacker performs a MITM attack between the application and the database; the application accepts the attacker's certificate; the database connection is intercepted; the encryption at rest is bypassed at the network layer.

The fix: TLS validation is mandatory; the application's database client is configured to verify the server's certificate against a known CA bundle.

---

## Audit logging

Every production database should produce comprehensive audit logs. The patterns:

### What to log

- **Connection events.** Who connected, from what source, at what time.
- **Authentication events.** Successful and failed authentications.
- **Schema changes.** DDL (CREATE, ALTER, DROP) operations.
- **Privilege changes.** GRANT / REVOKE / role membership changes.
- **Data access on sensitive tables.** SELECT / UPDATE / DELETE on PII / PHI / cardholder tables.

The first four are universally valuable; the last is high-volume and selective (full SELECT logging on a busy table can produce TB of logs per day).

### Cloud-native audit configurations

- **AWS RDS / Aurora:** Database Activity Streams (Aurora) ships every database operation to Kinesis Data Streams. Cheaper alternative: enable engine-native auditing (Postgres `pgaudit`, MySQL audit log plugin) and ship to CloudWatch Logs.
- **Azure SQL:** Auditing to Log Analytics workspace or Storage Account. Built-in; enable per database or at the server level.
- **Cloud SQL:** Cloud Audit Logs (Admin Activity for config; Data Access for queries — Data Access logs can be very high volume).
- **DynamoDB / Cosmos DB:** Cloud-native audit via CloudTrail data events / Diagnostic settings.

### Ship to centralized log archive

Per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md):

- Database audit logs ship to the central log archive.
- Retention per the workload's regulatory requirement (HIPAA: 6 years minimum; PCI: 1 year hot + 1 year cold typical).
- SIEM detection rules look for: failed login bursts, unusual query patterns, schema changes by unexpected principals, off-hours queries from production application accounts.

### The selective-logging discipline

Full audit logging is expensive. The pattern:

- **Always log:** connections, auth events, DDL, privilege changes.
- **Conditionally log:** queries on sensitive tables (per compliance requirement).
- **Never log:** application-layer queries on non-sensitive operational tables (the volume is overwhelming).

Document the selection. Re-evaluate when compliance scope changes.

---

## Connection management

How applications connect to databases at scale.

### Connection pooling

- **At the application layer:** the application's database driver maintains a pool of connections.
- **At the cloud layer:** RDS Proxy, Azure SQL connection pooling, Cloud SQL Auth Proxy.

The patterns:

- **RDS Proxy** (AWS) — managed connection pooler in front of RDS / Aurora. Reduces connection overhead, supports failover, integrates with Secrets Manager and IAM auth.
- **PgBouncer / ProxySQL** (self-managed) — open-source pooler, deployed in the VPC. More flexibility, more operational burden.
- **Cloud SQL Auth Proxy** — sidecar / agent that brokers connections; handles IAM auth and TLS.

The recommendation: cloud-native pooler (RDS Proxy, Cloud SQL Auth Proxy) for production workloads at scale. Self-managed when specific pooler features are required.

### Credentials retrieval

- **At connection time:** application fetches credentials from Secrets Manager / Key Vault / Secret Manager.
- **Cached locally:** with a TTL aligned to the credential lifetime (e.g., 5-minute cache for credentials that rotate hourly).
- **Refreshed on auth failure:** if a connection fails with auth error, refresh credentials and retry once.

The pattern handles the rotation-window failure where a credential rotates between the application's retrieval and use.

### Per-application database accounts

Each application should have its own database user (and IAM role / managed identity if using IAM auth). The discipline:

- Application `app-care-coordinator` uses database user `care_coordinator_app`.
- Read-only reporting workload `report-care-coordinator` uses database user `care_coordinator_readonly`.
- Admin access uses a separate human-identified account (named after the engineer, not "admin").
- Schema migrations use a migrator account with elevated DDL privileges.

The benefits:

- Per-application audit (which application ran this query).
- Per-application privilege scoping (the reporting workload cannot DELETE).
- Per-application credential rotation (rotate the reporting credential without affecting the application).

The shared `admin` or `app_user` account is an anti-pattern; per-application accounts make audit and access control real.

---

## Database firewalling and network ACLs

Beyond the security group / NSG / firewall rule layer, some databases support additional network filtering at the database service.

### AWS RDS / Aurora

- Security group is the primary control.
- Database parameter groups can restrict `pg_hba.conf` (PostgreSQL) or equivalent connection-rule files.
- IAM authentication for fine-grained access.

### Azure SQL

- **Firewall rules** at the server and database level — allow specific source IPs.
- **VNet rules** — allow connections from specific VNets via service endpoints.
- **Private Endpoint** — the connection is via private IP only.

The pattern: Private Endpoint is the strong control; firewall rules are the legacy control. Use Private Endpoint for new deployments.

### Cloud SQL

- **Authorized networks** — IP allowlist for public IP connections (rare).
- **Private IP** — connection via VPC peering.
- **SSL certificates** for client authentication (additional layer beyond network).

### Cosmos DB / DynamoDB

- **Firewall rules** and **Private Endpoint / VPC endpoint** are the controls.
- IAM is the primary access control.

---

## Backup security

Brief here; full treatment in [backup-and-data-residency.md](./backup-and-data-residency.md).

The patterns that intersect with database security specifically:

- **Backup encryption** uses the same CMK as the live database (or a backup-specific CMK in the same key class).
- **Backup retention** per regulatory requirement.
- **Cross-region replication** for DR; replica uses CMK in the destination region.
- **Immutability** for ransomware resilience (S3 Object Lock for snapshots, Azure immutable blob storage, GCS bucket lock).
- **Restore testing** — quarterly restore from backup to a non-production environment.

A backup that has not been tested has not been backed up.

---

## Worked example: Meridian Health's database posture

Meridian's Care Coordinator workload uses Aurora PostgreSQL with IAM database authentication, RDS Proxy, and full audit logging.

### The Aurora cluster

- **`care-coordinator-prod-aurora-pg`** — Aurora PostgreSQL 15.
- **Multi-AZ deployment** across three AZs (per [../network-security/vpc-vnet-design.md](../network-security/vpc-vnet-design.md)).
- **`PubliclyAccessible: false`** — private subnets only; security group allows ingress from the application tier SG only.
- **Storage encryption:** SSE with `cmk-care-coordinator-prod-phi` (per [kms-strategy.md](./kms-strategy.md)).
- **Backup encryption:** same CMK.
- **Backup retention:** 35 days (RDS automated); 7 years (regulatory) via daily snapshot copies to a separate retention account with S3 Object Lock.
- **Cross-region replica** in `us-west-2` for DR (read replica, asynchronous).

### Authentication

- **IAM authentication enabled.** Application uses RDS Proxy + IAM token.
- **No password user.** The `postgres` admin role has IAM auth enabled; password is generated random and stored in Secrets Manager for emergency-only use.
- **Per-application database users:**
  - `care_coordinator_app` — application read/write to operational tables.
  - `care_coordinator_readonly` — read-only access for the reporting workload.
  - `care_coordinator_migrator` — schema migration access for the CI/CD pipeline.

### RDS Proxy

- **Sits in front of the Aurora cluster.** Application connects to the proxy endpoint; proxy handles connection pooling and IAM token refresh.
- **Integrated with Secrets Manager** for the emergency-only `postgres` user.
- **Integrated with IAM** for application users.
- **Provides failover support** — proxy holds the connection during Aurora failover, reconnecting to the new primary transparently.

### Audit logging

- **`pgaudit` enabled** in the parameter group. Logs:
  - All DDL operations.
  - All ROLE changes.
  - All operations on tables tagged `audit_full` (the PII / PHI tables).
- **CloudWatch Logs export** of PostgreSQL log group; shipped to the central archive.
- **SIEM detection rules** for: failed login bursts, off-hours migrator-user activity, DDL by unexpected principals, large bulk operations on PHI tables.

### Network architecture

- Aurora endpoint resolves to the private IP in the data subnet.
- Application connects via RDS Proxy in the application VPC.
- No public endpoint; no internet egress required by the database.

### The migration story

Meridian's first Care Coordinator database deployment in 2024 had:

- Public endpoint (the team thought it was needed for the analytics pipeline).
- Password authentication; password in CI variables.
- Self-managed connection pooling; no rotation.
- Minimal audit logging.

The migration over 4 sprints:

- **Sprint 1:** disable public endpoint; migrate analytics pipeline to use a read replica in the analytics VPC via PrivateLink.
- **Sprint 2:** migrate password to Secrets Manager; enable rotation.
- **Sprint 3:** enable IAM database authentication; migrate application to use IAM tokens via RDS Proxy.
- **Sprint 4:** enable comprehensive audit logging; build SIEM detection rules.

The post-migration posture is what's described above.

### Findings opened during the database audit

- **DB-001** (Aurora cluster had `PubliclyAccessible: true`). Closed.
- **DB-002** (database password was in CI environment variables). Closed.
- **DB-003** (no IAM database authentication). Closed.
- **DB-004** (no audit logging beyond default RDS logs). Closed.
- **DB-005** (shared `app_user` for all applications; no per-application audit). Closed.
- **DB-006** (no SCP preventing public-endpoint database creation). Closed by adding SCP at the workload OU.
- **DB-007** (backup retention was 7 days; regulatory required 7 years). Closed by the cross-account snapshot retention pattern.

---

## Anti-patterns

### 1. The publicly-accessible production database

The dominant anti-pattern. RDS / Cloud SQL / Azure SQL configured with public endpoint "for convenience." Anyone on the internet can attempt to connect; the only barriers are the security group's IP allowlist and the database password.

The fix: private endpoint baseline; SCP / policy enforcement; bastion patterns for legitimate access needs.

### 2. The password in source control

`config.py` has `DB_PASSWORD = "..."`. The file is in the application repo. Anyone with repo read access has the production database password.

The fix: passwords in Secrets Manager / Key Vault; application retrieves at startup; secret scanning in CI to prevent reintroduction.

### 3. The password in CI environment variables

The CI system has `PROD_DB_PASSWORD` set as a secret variable. Every CI run has access. Compromised CI = compromised production database.

The fix: CI workflows use OIDC federation to obtain temporary IAM credentials; the temporary credentials authenticate to the database via IAM auth; no static password in CI.

### 4. The shared application database user

Three applications share `app_user`. Audit logs cannot distinguish which application performed which query. Privilege scoping cannot be per-application.

The fix: per-application database user; per-application credential rotation; per-application audit attribution.

### 5. The TLS-required-but-not-validated

Application connects with `sslmode=require`; the certificate is not validated; MITM attacks succeed. The encryption is theater.

The fix: `sslmode=verify-full`; application bundles or trusts the cloud provider's CA chain; certificate pinning where appropriate.

### 6. The forgotten audit logging

Audit logging was enabled at database creation. The logs ship to CloudWatch / Log Analytics / Cloud Logging — but no SIEM rule reads them. Detection signal exists but is not consumed.

The fix: SIEM detection rules consume audit logs; alerts on specific patterns; periodic review of rule coverage.

### 7. The untested backup

Backups are running. Nobody has tested restoring from one. When a real failure happens, the team discovers the backups are missing critical tables, or use an incompatible engine version, or the restore takes 18 hours.

The fix: quarterly restore test to a non-production environment. Document the restore time. Update the runbook.

### 8. The encryption-not-at-creation regret

Database was created without encryption ("we'll add it later"). Now there's terabytes of unencrypted data. Adding encryption requires snapshot + restore + cutover; the operation is multi-hour and requires a maintenance window.

The fix: encryption enabled at creation, always. SCP enforces.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| DB-001 | Production database has public endpoint | High | Migrate to private endpoint; SCP enforces; bastion patterns for legitimate access | Platform Eng + Security Eng |
| DB-002 | Database password in source control or `.env` files | High | Move to Secrets Manager / Key Vault; secret scanning in CI | Workload Owner + Security Eng |
| DB-003 | Database password in CI environment variables | High | OIDC federation; CI uses IAM database auth via temporary credentials | DevOps + Security Eng |
| DB-004 | No IAM database authentication where supported | Medium | Migrate to IAM auth (RDS / Cloud SQL / Azure SQL Azure AD) | Platform Eng + Workload Owner |
| DB-005 | Shared database user across applications | Medium | Per-application database users; per-application credentials and audit | Workload Owner + Security Eng |
| DB-006 | No SCP / policy preventing public-endpoint database creation | High | Add policy at the OU level | Platform Eng + Security Eng |
| DB-007 | Database not encrypted at rest | High | Snapshot + restore with encryption enabled; SCP prevents non-encrypted creation | Platform Eng + Security Eng |
| DB-008 | Database encrypted with provider-managed key for regulated data | High | Migrate to CMK | Security Eng + Workload Owner |
| DB-009 | TLS not enforced or not validated | High | TLS required; client validates certificate (`sslmode=verify-full`) | Workload Owner + Security Eng |
| DB-010 | No audit logging configured | High | Enable engine-native audit (`pgaudit`, audit_log plugin, Azure Auditing); ship to central archive | Platform Eng + Security Eng |
| DB-011 | Audit logs exist but not consumed by SIEM | Medium | Build SIEM detection rules; alert on patterns | Security Eng + SOC |
| DB-012 | Backup retention shorter than regulatory requirement | High | Cross-account snapshot retention with required period | Platform Eng + Compliance |
| DB-013 | Backups never tested for restoration | High | Quarterly restore test to non-production; document restore time | SRE + Platform Eng |
| DB-014 | Connection pooling not in place; database hits connection limits | Medium | RDS Proxy / Cloud SQL Auth Proxy / Azure SQL pooling | Platform Eng + Workload Owner |
| DB-015 | Schema migrations use the application user; over-privileged | Low | Separate migrator user with DDL privileges; application user has DML only | Workload Owner + DBA |
| DB-016 | Read-replica access uses the production write user; unnecessary risk | Low | Separate read-only user; read replicas use it | Workload Owner + DBA |
| DB-017 | No alerting on failed authentication bursts | Medium | SIEM rule on failed-auth threshold; SOC paged | Security Eng + SOC |
| DB-018 | Cross-region read replica uses different CMK class than primary | Low | Replica uses CMK in destination region; key policies match | Platform Eng + Security Eng |

---

## What this document is not

- **A database engine reference.** PostgreSQL, MySQL, SQL Server, Oracle, DynamoDB, Cosmos DB tuning and operation belong with the vendor docs.
- **A query-performance reference.** Index design, query optimization, partitioning are out of scope.
- **A NoSQL deep dive.** DynamoDB, Cosmos DB, Cloud Firestore patterns are mentioned but not detailed; the security patterns transfer; the operational patterns differ.
- **A data-platform reference.** Snowflake, BigQuery, Redshift, Databricks security are their own large topics; the IAM and encryption patterns transfer but the data-platform-specific controls are separate.
