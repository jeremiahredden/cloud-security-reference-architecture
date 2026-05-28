# Vault Patterns

A practitioner's reference for HashiCorp Vault when it is the right answer — dynamic database credentials, dynamic cloud-provider credentials, the PKI engine for internal mTLS, the transit engine for application-layer encryption. The patterns here cover the deployment shape (Vault on Kubernetes; Vault on cloud VMs; Vault Enterprise vs OSS), the auth-method choice tree, the engines that justify Vault's operational cost, and the integration patterns that keep Vault from becoming a single point of failure for the workloads that depend on it.

This document is **not** about whether to use Vault. That decision belongs to [secrets-manager-patterns.md](./secrets-manager-patterns.md), which is opinionated about defaulting to the cloud-native option. This document is about *when Vault is the right tool* — for the specific capabilities that the cloud-native services don't provide.

The honest framing: Vault in 2026 is a powerful tool that is over-adopted. Many organizations adopt Vault because a vendor or consultant recommended it, then discover the operational cost is higher than the cloud-native alternative would have been. The deciding factor: does the team need *dynamic credential issuance* (Vault's killer feature), *internal PKI at scale* (the PKI engine), or *multi-cloud unification* (Vault as the unifier)? If yes, Vault is the right tool. If the team only needs to store passwords and API keys, the cloud-native secrets manager is simpler.

---

## When to read this document

**If you have Vault already and want to use it well** — read top to bottom.

**If you are considering Vault** — read [When Vault is the right answer](#when-vault-is-the-right-answer) first. The decision should be made deliberately, not by default.

**If you operate Vault and the team finds it hard to use** — start with [Common Vault failure modes](#common-vault-failure-modes). Most Vault pain traces to one or two design choices that are fixable.

**If you are deploying Vault on Kubernetes** — start with [Vault on Kubernetes patterns](#vault-on-kubernetes-patterns). The deployment shape choice is consequential.

---

## When Vault is the right answer

The specific capabilities that justify Vault over cloud-native secrets management.

### 1. Dynamic database credentials

Vault's **database secrets engine** issues short-lived database credentials on demand. The pattern:

- Vault is configured with an admin credential to a database (e.g., PostgreSQL).
- Application calls Vault: "give me a credential for the `app_role` role."
- Vault creates a new database user with the role's privileges; returns the credential.
- The credential has a TTL (e.g., 1 hour).
- After TTL expires, Vault revokes the database user.

The benefits:

- No long-lived database passwords anywhere.
- Per-application credentials are unique (per-call, not per-application).
- Compromise of one credential is bounded by TTL.
- Audit trail: every credential issuance is logged by Vault.

The cost:

- Database user creation overhead per credential (modest but real).
- Vault must have the database admin credential to create users.
- Database connection-pooling layers must understand short-lived credentials.

**This is Vault's killer feature.** The cloud-native services don't offer equivalent dynamic-credential issuance for databases.

### 2. Dynamic cloud-provider credentials

Vault's **AWS / Azure / GCP secrets engines** issue short-lived cloud credentials:

- Application calls Vault: "give me AWS credentials with `S3ReadOnly`."
- Vault assumes an IAM role (or creates a temporary user) and returns credentials.
- Credentials are valid for a TTL.

This is similar in concept to IAM role assumption (which AWS supports natively), so the use case is narrower:

- **For multi-cloud applications** where the application needs credentials for multiple clouds, Vault is a unified API.
- **For on-prem or non-cloud-hosted applications** that need cloud credentials, Vault can be the broker (no native cloud IAM available).
- **For dynamic credentials with complex authorization** (e.g., issue credentials to a specific S3 bucket based on application state), Vault's flexibility is useful.

For applications running on the cloud's own compute, the cloud's native IAM (IRSA, Workload Identity, Managed Identity) is simpler and usually preferred.

### 3. Internal PKI

Vault's **PKI secrets engine** is a certificate authority that issues short-lived certificates:

- Configure Vault as a root or intermediate CA.
- Applications request certificates: "give me a cert for `app.internal.meridian.com` with 24-hour TTL."
- Vault signs the cert and returns it.
- Applications use the cert; renew before TTL.

The use cases:

- **Internal mTLS between services** without paying for public CA-signed certs.
- **Service-mesh integration** (Istio, Consul Connect, Linkerd) — Vault can be the CA.
- **Short-lived certificates** for high-assurance internal services.

Vault PKI is mature; for organizations running internal mTLS at scale, it is the default choice.

### 4. Transit (encryption-as-a-service)

Vault's **transit secrets engine** provides encryption operations without the application managing keys:

- Application calls Vault: "encrypt this payload with the `payment-data` key."
- Vault encrypts; returns ciphertext.
- Vault never returns the key itself; the key never leaves Vault.

The use case: application-layer encryption where the application needs to encrypt / decrypt but shouldn't hold the key. Conceptually similar to AWS KMS `Encrypt` / `Decrypt` APIs; Vault adds key versioning, derived keys, and convergent encryption that KMS doesn't.

For most workloads: cloud KMS is sufficient. Transit is useful when the application needs Vault's specific patterns.

### 5. The unifier in multi-cloud environments

For organizations running workloads across AWS, Azure, and GCP, Vault can be the single secrets-management API. Applications target Vault; Vault is configured with the cloud-specific backends.

The benefit: one API across clouds. The cost: Vault operational overhead, Vault as a critical dependency.

For most multi-cloud environments, the per-cloud-native secrets manager is acceptable. Vault as unifier is appropriate when the team wants to avoid cloud-specific integration code in every application.

---

## Vault deployment shape

The Vault operational architecture.

### HA cluster topology

Vault production deployments are HA clusters:

- **3 or 5 nodes** in a Raft cluster (Raft is Vault's built-in consensus).
- **Cross-AZ deployment** for resilience.
- **Single leader** at a time; followers proxy writes to the leader.
- **Performance Standbys** (Enterprise) can serve reads.

The 5-node cluster tolerates 2 simultaneous failures; the 3-node tolerates 1. For most production workloads, 3 nodes is sufficient.

### Storage backend

Vault Open Source uses **integrated storage** (Raft) by default. The cluster's storage is built into Vault; no external dependency.

Vault Enterprise supports additional backends (Consul as classic option; cloud-native storage in some patterns).

For 2026 deployments: integrated Raft is the right default. External storage backends are legacy choices.

### Auto-unseal

Vault encrypts its storage with a master key. On startup, Vault is "sealed" — it cannot decrypt storage until the master key is reconstructed (historically from key shards held by humans).

**Auto-unseal** uses a cloud KMS to manage the master key:

- AWS KMS auto-unseal: Vault unseals using an AWS KMS key.
- Azure Key Vault auto-unseal.
- GCP Cloud KMS auto-unseal.

The benefit: no human intervention required for cluster startup or restart. Critical for production HA.

The trade-off: the cloud KMS is a dependency for Vault unsealing. If the KMS is unreachable, Vault can't unseal. In practice, this is acceptable; the cloud KMS is itself highly available.

### Open Source vs Enterprise

Vault has tiers:

- **Open Source:** the core engine; sufficient for most use cases.
- **Vault Enterprise:** adds HSM auto-unseal, namespaces (multi-tenancy), DR replication, performance replication, FIPS 140-2 compliance, additional auth methods.

For most teams: Open Source is sufficient. Enterprise is justified when specific features (namespaces, performance replication, HSM auto-unseal) are required.

Note: HashiCorp's licensing changed in 2023 (Business Source License rather than open source). Enterprise customers and existing OSS users are unaffected for ongoing use; new OSS adoption requires understanding the license.

References:
- [Vault Architecture](https://developer.hashicorp.com/vault/docs/internals/architecture)
- [Vault HA with Raft](https://developer.hashicorp.com/vault/docs/concepts/integrated-storage)

---

## Auth methods

Vault uses **auth methods** to authenticate clients. The choice depends on the client.

### AppRole (the workhorse)

**AppRole** authenticates applications via two credentials: a Role ID (durable) and a Secret ID (often short-lived).

- The application presents (Role ID, Secret ID); Vault validates; returns a Vault token.
- The Vault token is used for subsequent API calls.
- Secret IDs can be wrapped (one-time-use; Vault gives a wrapping token that must be unwrapped within a window).

Best for: applications without cloud-native identity (legacy apps; on-prem); CI pipelines (with wrapped Secret IDs).

### Kubernetes auth

**Kubernetes auth** uses the cluster's service account tokens:

- Application pod's service account token is presented to Vault.
- Vault validates the token with the Kubernetes API server.
- Vault issues a token bound to the validated service account.

Best for: Kubernetes-hosted applications. Cleaner than AppRole because the credential is the cluster-native identity.

### AWS / Azure / GCP auth

**Cloud-native auth** uses the cloud provider's identity:

- AWS auth: application uses STS signed identity; Vault validates with AWS STS.
- Azure auth: application uses Managed Identity token; Vault validates with Entra ID.
- GCP auth: application uses GCP IAM identity; Vault validates with GCP IAM.

Best for: applications running on cloud-native compute; aligns Vault auth with cloud identity.

### LDAP / OIDC / userpass

For human users:

- **LDAP / Active Directory:** for enterprise environments with LDAP-backed identity.
- **OIDC:** for SSO-backed authentication (Okta, Auth0, Entra ID).
- **userpass:** Vault-local users; appropriate only for emergency-break-glass or small teams.

### TLS certificates

**TLS auth** uses client certificates for authentication.

Best for: machine-to-machine where mTLS is already in place (often paired with the PKI engine).

### The auth-method matrix

| Client type | Recommended auth method |
| --- | --- |
| Kubernetes pod | Kubernetes auth |
| EC2 instance / AWS Lambda | AWS auth |
| Azure VM / Function | Azure auth |
| GCE / Cloud Run / Cloud Function | GCP auth |
| Legacy application | AppRole |
| CI pipeline | AppRole with wrapped Secret IDs (or OIDC if supported) |
| Human user via CLI | OIDC (SSO-integrated) |
| Service-mesh integration | TLS auth with PKI engine |

### Policies

Vault policies are HCL documents that grant permissions:

```hcl
# Example policy
path "secret/data/prod/care-coordinator/*" {
  capabilities = ["read"]
}

path "database/creds/care-coordinator-app" {
  capabilities = ["read"]
}
```

Policies attach to tokens (which come from auth methods). Each auth method's role specifies which policies the issued token gets.

The discipline:

- **Per-application policies** with narrow path access.
- **No wildcards** that grant broader access than intended.
- **Periodic policy review** as workloads evolve.

---

## Vault on Kubernetes patterns

Vault is commonly deployed on Kubernetes. Three patterns:

### Pattern 1: Vault running in the cluster

Vault pods run in the cluster they serve. Storage uses persistent volumes; HA across pods.

Pros:

- Single deployment artifact (Helm chart).
- Auto-unseal via cloud KMS works seamlessly.
- Easy to scale.

Cons:

- Vault is a critical dependency of the cluster; cluster failure can affect Vault.
- Vault upgrade requires cluster discipline.

Best for: small-to-medium environments where Vault primarily serves the cluster's applications.

### Pattern 2: Vault running outside the cluster, serving multiple clusters

Vault is deployed on dedicated VMs (or in a dedicated cluster); applications across multiple Kubernetes clusters use it.

Pros:

- Independent from any single Kubernetes cluster.
- Can serve non-Kubernetes workloads too.
- Operational independence.

Cons:

- Two deployment patterns to maintain (Vault separately from Kubernetes).
- Network connectivity between clusters and Vault is a dependency.

Best for: organizations with multiple clusters or hybrid Kubernetes / non-Kubernetes environments.

### Pattern 3: Vault Agent Injector

Regardless of where Vault runs, the **Vault Agent Injector** is a Kubernetes mutating webhook:

- Pod is annotated with Vault Agent annotations.
- The webhook injects a Vault Agent sidecar (or init container).
- The sidecar authenticates to Vault and writes secrets to a shared volume.
- The application reads secrets from the shared volume.

The benefit: applications need no Vault-specific code. The sidecar handles authentication, secret retrieval, and refresh.

Most Kubernetes Vault deployments use the Agent Injector. The pattern is well-established and minimizes application code changes.

References:
- [Vault on Kubernetes](https://developer.hashicorp.com/vault/docs/platform/k8s)
- [Vault Agent Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector)

---

## The dynamic-database-credential pattern (deep dive)

Vault's killer feature, worth the dedicated treatment.

### The configuration

```bash
# Configure the database connection
vault write database/config/care-coordinator-db \
    plugin_name=postgresql-database-plugin \
    allowed_roles="care-coordinator-app,care-coordinator-readonly,care-coordinator-migrator" \
    connection_url="postgresql://{{username}}:{{password}}@db.example.com:5432/postgres?sslmode=verify-full" \
    username="vault_admin" \
    password="..."  # the admin credential Vault uses

# Define a role
vault write database/roles/care-coordinator-app \
    db_name=care-coordinator-db \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
                         GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"
```

### Application usage

```python
import hvac

vault = hvac.Client(url='https://vault.internal.meridian.com')
vault.auth.kubernetes.login(role='care-coordinator-app',
                            jwt=open('/var/run/secrets/kubernetes.io/serviceaccount/token').read())

# Get a dynamic database credential
creds = vault.secrets.database.generate_credentials(name='care-coordinator-app')
db_user = creds['data']['username']
db_pass = creds['data']['password']

# Use the credential
conn = psycopg2.connect(
    host='db.example.com',
    user=db_user,
    password=db_pass,
    sslmode='verify-full',
)
```

The credential is valid for 1 hour; Vault revokes the database user when the lease expires.

### The lease-renewal pattern

For long-running connections, the application should renew the lease before expiration:

```python
# Renew the lease (extends TTL)
vault.sys.renew_lease(lease_id=creds['lease_id'])
```

The Vault Agent Injector handles lease renewal automatically; for direct API integration, the application is responsible.

### What this eliminates

- Database passwords in any configuration file.
- Database password rotation as a manual process.
- Shared database credentials across multiple application instances.
- The audit-trail gap of "which app instance ran this query" (every Vault-issued credential is unique).

### What this costs

- Database user creation overhead (PostgreSQL handles this well; some databases struggle).
- Vault as a critical-path dependency for new application instances starting.
- Connection-pooling complexity (the pool must handle credential refresh).
- Database user proliferation (Vault creates a user per credential issuance; cleanup is via lease revocation).

For high-throughput applications, the database may have hundreds of Vault-created users at any moment. This is normal; the database handles it.

---

## Common Vault failure modes

The patterns that go wrong in Vault deployments.

### 1. The under-resourced Vault cluster

Vault is deployed with minimal resources; under load, it falls behind on auth requests; application timeouts occur.

The fix: Vault needs real CPU and memory. Size based on auth-request rate. Performance Standbys (Enterprise) for read-heavy workloads.

### 2. The Vault sealed-and-no-one-knows-how-to-unseal

Auto-unseal wasn't configured. The cluster restarts; Vault is sealed; no one on call knows the unseal procedure.

The fix: auto-unseal with cloud KMS. Document the unseal procedure for emergency manual unseal.

### 3. The Vault upgrade that broke everything

Vault was upgraded without a tested procedure. Existing tokens were invalidated; auth methods misconfigured; downtime.

The fix: tested upgrade procedure in a staging Vault first; rolling upgrade in production with single-leader-aware operations.

### 4. The expanded policy

A policy was granted "broad now, narrow later." The narrowing never happened. The application has access to far more than it needs.

The fix: narrow at grant time; quarterly policy review.

### 5. The Vault-as-SPOF

Every workload requires Vault to start (for dynamic credentials). Vault outage = full environment outage.

The fix: Vault Agent caches credentials; applications tolerate short Vault outages within the cache window. For critical workloads, the database credential is cached for the connection-pool lifetime.

### 6. The audit-log absent

Vault audit logs are not enabled or not shipped. Detection has no signal from Vault.

The fix: audit device configured; logs ship to central archive; SIEM rules consume.

### 7. The forgotten lease cleanup

Vault is configured to issue dynamic credentials. Leases are not being revoked (auto-revocation requires lease management). Database has thousands of orphan users.

The fix: lease revocation is automatic for properly-configured Vault; verify the configuration; periodic database user audit catches drift.

### 8. The recovery-key disaster

Vault's recovery keys (for emergency unseal) were never properly distributed. The single person who has them leaves. Recovery is now impossible.

The fix: recovery keys distributed to multiple custodians; tested via tabletop exercise; documented in the runbook.

---

## Worked example: Meridian Health's Vault deployment

Meridian operates Vault in the shared services account for cross-account dynamic credential issuance, particularly for database access.

### The deployment

- **Vault Enterprise cluster** (3 nodes) in `meridian-secrets-broker` account, `us-east-1`.
- **Raft storage** with cloud-KMS auto-unseal (AWS KMS).
- **Performance Standbys** in `us-west-2` for read-heavy workload distribution.
- **DR replication** to `us-west-2` for disaster recovery.

### What Meridian uses Vault for

- **Dynamic database credentials** for the Aurora clusters. Per-application roles; 1-hour TTL.
- **PKI engine** for internal service mTLS (the Istio service mesh's intermediate CA is Vault-backed).
- **Transform engine** for tokenization (per [../data-security/tokenization-patterns.md](../data-security/tokenization-patterns.md)).
- **KV v2 secrets engine** for some workloads that need versioned secret storage with Vault's specific patterns.

Meridian does **not** use Vault for:

- Most static secrets (those live in AWS Secrets Manager per [secrets-manager-patterns.md](./secrets-manager-patterns.md)).
- Cloud-provider credentials (cloud-native IAM and IRSA / Workload Identity handle this).
- General-purpose secret storage where Secrets Manager is sufficient.

### Auth methods in use

- **Kubernetes auth** for EKS pods.
- **AWS auth** for EC2 instances and Lambda functions.
- **AppRole** for legacy applications and CI pipelines.
- **OIDC** (with Okta) for human operators.

### The Vault Agent Injector pattern

EKS pods that need Vault secrets are annotated:

```yaml
metadata:
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: "care-coordinator-app"
    vault.hashicorp.com/agent-inject-secret-db-creds: "database/creds/care-coordinator-app"
    vault.hashicorp.com/agent-inject-template-db-creds: |
      {{- with secret "database/creds/care-coordinator-app" -}}
      {
        "host": "db.example.com",
        "user": "{{ .Data.username }}",
        "password": "{{ .Data.password }}"
      }
      {{- end -}}
```

The Vault Agent Injector adds a sidecar; secrets are written to `/vault/secrets/db-creds`; the application reads from there.

### Findings opened during the Vault audit

- **VLT-001** (Vault cluster was 3-node but without DR replication; regional failure would have lost Vault). Closed by enabling DR replication to us-west-2.
- **VLT-002** (Vault audit logs were on but not centrally shipped). Closed by syslog audit device shipping to the central log archive.
- **VLT-003** (some applications had broad `secret/*` policies). Closed by narrowing to per-application paths.
- **VLT-004** (recovery keys were held by one person). Closed by distributing to 5 custodians (3-of-5 quorum required).
- **VLT-005** (database engine was issuing creds but lease revocation was misconfigured; thousands of orphan PostgreSQL users existed). Closed by fixing the lease-revocation configuration; one-time cleanup of orphan users.

---

## Anti-patterns

### 1. The "Vault for everything" overuse

The team uses Vault for static secrets that Secrets Manager would handle natively. The operational cost of Vault is paid for use cases that don't justify it.

The fix: cloud-native for static secrets; Vault for dynamic credentials and the engines that Vault specifically provides.

### 2. The Vault without auto-unseal

Manual unseal is required on every restart. Production HA is compromised; on-call has to perform unseal during incidents.

The fix: auto-unseal with cloud KMS.

### 3. The Vault upgrade without testing

Vault upgraded in production without prior testing in staging. Compatibility issue surfaces; production is degraded.

The fix: tested upgrade procedure in staging; rolling upgrade in production; documented rollback.

### 4. The catch-all policy

A policy grants access to `secret/*`. Every secret in the KV engine is accessible. Least-privilege is broken.

The fix: per-application policy with narrow paths; policy review on each application onboarding.

### 5. The Vault as build-time dependency

The application's container image includes a Vault Agent that authenticates at build time and bakes the secret into the image. Vault's lease management is bypassed; the secret is now static.

The fix: Vault Agent runs at runtime, not at build. Secrets are fetched fresh on container start.

### 6. The Performance Standby misconfiguration

Performance Standbys (Enterprise) are configured but not actually receiving read traffic. Reads still go to the leader; the standby is idle.

The fix: configure clients (or load balancers) to route reads to standbys; verify with metrics.

### 7. The forgotten transit-engine key rotation

Transit engine encrypts data with a key. The key has versions. The team never rotates; old data is encrypted with old key versions; key revocation impact is unclear.

The fix: schedule periodic transit-key rotation; re-encryption is automated for performance-critical data.

### 8. The Vault token in plaintext logs

The application logs the Vault token it received. Anyone with log access can use the token to call Vault.

The fix: never log Vault tokens; redact in logging frameworks.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| VLT-001 | Vault cluster lacks DR replication; regional failure would lose Vault | High | Enable DR replication; tested failover | Platform Eng + SRE |
| VLT-002 | Vault audit logs not centrally shipped | High | Configure audit device; ship to central log archive | Platform Eng + Security Eng |
| VLT-003 | Vault policies use wildcards (`secret/*`); over-broad access | Medium | Per-application policies with narrow paths | Security Eng |
| VLT-004 | Vault recovery keys held by single person; recovery is fragile | High | Distribute keys to multiple custodians (m-of-n); tabletop exercise | Platform Eng + Security Eng |
| VLT-005 | Database engine lease revocation misconfigured; orphan database users accumulate | Medium | Fix lease config; one-time cleanup; verify revocation in normal operation | Platform Eng + DBA |
| VLT-006 | Manual unseal required; production HA compromised | High | Enable cloud-KMS auto-unseal | Platform Eng + Security Eng |
| VLT-007 | Vault upgrade procedure untested | High | Test in staging; document rollback; rolling upgrade procedure | Platform Eng + SRE |
| VLT-008 | Vault used for use cases where cloud-native secrets manager is sufficient | Low | Migrate static secrets to cloud-native; Vault for dynamic / PKI / transit | Architecture + Security Eng |
| VLT-009 | Vault Agent runs at build time, baking secrets into images | High | Vault Agent runs at runtime; secrets fetched on container start | Workload Owner + Platform Eng |
| VLT-010 | Performance Standbys configured but not receiving read traffic | Low | Configure clients to route reads to standbys; verify with metrics | Platform Eng |
| VLT-011 | Transit-engine keys never rotated | Medium | Schedule rotation; document re-encryption procedure for older data | Security Eng |
| VLT-012 | Vault tokens logged or echoed by applications | High | Redact tokens in logs; verify with detection on log archive | Workload Owner + Security Eng |
| VLT-013 | Vault deployed in a cluster it serves; cascading failure risk | Medium | Consider Vault outside-cluster for critical environments | Platform Eng + Architecture |
| VLT-014 | Vault not sized for actual load; auth latency degrades under spikes | Medium | Capacity-plan Vault; scale up or add Performance Standbys | Platform Eng + SRE |
| VLT-015 | Vault Agent Injector annotations inconsistent; some pods authenticate directly to Vault | Low | Standardize on Agent Injector for Kubernetes; document the pattern | Platform Eng |
| VLT-016 | AppRole Secret IDs not wrapped; static distribution risk | Medium | Use wrapped Secret IDs with one-time unwrap | Security Eng |
| VLT-017 | Cross-cluster Vault access via long-lived service-account tokens | Medium | Per-cluster auth method config; service-account-scoped roles | Platform Eng + Cluster Owner |
| VLT-018 | Vault metrics not consumed by SIEM; abnormal auth patterns not detected | Medium | Ship Vault metrics + audit logs to SIEM; build detection rules | Security Eng + SOC |

---

## What this document is not

- **A complete Vault administration guide.** HashiCorp's documentation is authoritative; this document covers the patterns that matter for cloud-security architecture decisions.
- **A Consul integration reference.** Vault works well with Consul; the integration is out of scope for this folder.
- **A Vault performance-tuning guide.** Capacity planning, latency optimization, scaling patterns are operational concerns covered in HashiCorp's documentation.
- **An evaluation of OpenBao or other Vault forks.** The BSL license change in 2023 led to OpenBao (an OSS fork); the patterns transfer but the operational community is smaller.
