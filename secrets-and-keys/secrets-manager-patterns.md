# Secrets Manager Patterns

A practitioner's reference for cloud-native secrets management — AWS Secrets Manager, Azure Key Vault (secrets feature), GCP Secret Manager. The patterns here cover resource-policy design, Kubernetes integration patterns (External Secrets Operator, CSI Secret Driver, native injection), versioning and rotation hooks, cross-account / cross-region access, the cost characteristics that matter for high-volume access, and the patterns that keep the secrets manager from becoming a single point of failure for the workloads that depend on it.

This document picks up where [kill-the-static-secret.md](./kill-the-static-secret.md) leaves off. After federation has eliminated as many secrets as possible, the residual secrets (third-party API tokens, legacy database passwords, per-tenant API keys) need a managed home. The cloud-native secrets manager is the right default for almost every team; Vault ([vault-patterns.md](./vault-patterns.md)) is the right answer for organizations that already operate it well.

For rotation specifically, see [rotation-patterns.md](./rotation-patterns.md). For the encryption that protects the secret store, see [envelope-encryption.md](./envelope-encryption.md). For preventing secrets from leaking into source control, see [secret-detection.md](./secret-detection.md).

---

## When to read this document

**If you are choosing between AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, and HashiCorp Vault** — read [The cloud-native vs Vault decision](#the-cloud-native-vs-vault-decision) first.

**If you are integrating secrets with Kubernetes** — start with [Kubernetes integration patterns](#kubernetes-integration-patterns). The three patterns (External Secrets Operator, CSI Secret Driver, native injection) have different operational characteristics; the choice matters.

**If your secrets manager has become a high-cost line item** — start with [Cost characteristics and patterns](#cost-characteristics-and-patterns). The default access patterns are not cost-optimal at scale.

**If you are auditing secrets-manager posture** — start with [Findings checklist](#findings-checklist). The most common findings (over-broad resource policies, no rotation, missing audit logs, no cross-account discipline) are universal.

---

## The cloud-native vs Vault decision

Most teams should default to the cloud-native secrets manager. Vault is the right answer for a narrower set of cases.

| Pattern | Best when | Avoid when |
| --- | --- | --- |
| **AWS Secrets Manager** | AWS-centric environments; IAM is the identity substrate; deep integration with RDS, ECS, Lambda matters. | Multi-cloud with strict cross-cloud secret-sharing needs. |
| **Azure Key Vault** | Azure-centric; Entra ID identity substrate; secrets + certificates + keys in one service. | Heavy non-Microsoft tooling. |
| **GCP Secret Manager** | GCP-centric; service-account identity substrate; simpler than Vault. | Need dynamic credential issuance. |
| **HashiCorp Vault** | Already-operating-Vault organizations; dynamic-credential needs (Vault DB engine, Vault cloud engines); PKI / transit engine needs; multi-cloud where Vault is the unifier. | Single-cloud environments where the cloud-native option suffices. |

The strongest recommendation: **cloud-native unless you specifically need what Vault offers**. The operational cost of running Vault is meaningful (at minimum 1 platform engineer dedicated to it; HA cluster operation; backup and DR; auth-method configuration). For a team that doesn't have that engineering investment available, cloud-native is the safer choice.

For a team that already operates Vault well: continue with it. Migration from Vault to cloud-native is mostly an unnecessary churn unless Vault is causing specific problems.

For details on Vault itself, see [vault-patterns.md](./vault-patterns.md).

---

## Resource-policy design

The cloud-native secrets managers use the cloud's IAM model. Resource policies on individual secrets are the access-control primitive.

### AWS Secrets Manager resource policy

A secret's resource policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowApplicationAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/care-coordinator-app-role"},
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {"aws:SourceVpc": "vpc-XXX"}
      }
    },
    {
      "Sid": "DenyCrossAccountByDefault",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "secretsmanager:*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {"aws:PrincipalAccount": "ACCOUNT"}
      }
    }
  ]
}
```

The discipline:

- **Specific principals** (the application role), not `Principal: AWS: ACCOUNT:root`.
- **Specific actions** (`GetSecretValue`, `DescribeSecret`), not `secretsmanager:*`.
- **Condition keys** for context (`aws:SourceVpc` to require the call from the application's VPC).
- **Deny statements** for cross-account access by default (only specific cross-account principals granted via explicit allows above the deny).

### Azure Key Vault access policies and RBAC

Azure Key Vault has two access models:

- **Access policies** (legacy) — Vault-level grants per principal with specific permissions.
- **Azure RBAC** (preferred in 2026) — standard Azure role assignments scoped to the Vault, secret, or key.

The pattern with RBAC:

- Application's managed identity gets the `Key Vault Secrets User` role on the specific Vault.
- For secret-specific scoping, the role is assigned at the secret level (where supported).
- Network rules on the Vault restrict access to specific VNets (via Service Endpoints) or Private Endpoint.

### GCP Secret Manager IAM

Secret Manager uses standard GCP IAM:

- Per-secret IAM bindings; not per-Vault (the unit of grant is the secret).
- `roles/secretmanager.secretAccessor` for read.
- `roles/secretmanager.secretVersionManager` for create / disable / destroy.
- Conditional IAM with attribute conditions (e.g., source VPC).

The per-secret IAM granularity makes scoping precise; the cost is per-secret IAM management at scale.

### Principles common to all three

- **Least-privilege per consumer.** Each application has access to its own secrets only.
- **No cross-team secret sharing without policy.** Shared secrets are an anti-pattern; if multiple applications need similar data, they get separate secrets.
- **Audit-trail at the secret level.** Every retrieval is logged with the principal and the timestamp.
- **Version-aware access.** Where supported, grants can be scoped to specific versions of the secret.

---

## Kubernetes integration patterns

The three patterns for getting cloud-native secrets into Kubernetes pods.

### Pattern 1: External Secrets Operator

The **External Secrets Operator (ESO)** is a Kubernetes operator that syncs secrets from external secrets managers to native Kubernetes secrets.

How it works:

- Engineer defines an `ExternalSecret` resource that references an external secret (e.g., `secretsmanager:prod/db/password`).
- ESO fetches the secret from the cloud secrets manager.
- ESO creates a native Kubernetes `Secret` with the value.
- Pod mounts the Kubernetes secret as usual (file or environment variable).

Trade-offs:

- **Pros:** familiar pattern (pods consume native Kubernetes secrets); refresh on a schedule; supports many backends.
- **Cons:** secrets exist briefly as native Kubernetes secrets (visible to anyone with namespace access); refresh interval determines staleness; one more operator to maintain.

Best fit: Kubernetes environments where the team is comfortable with the operator pattern and the brief on-disk presence of secrets is acceptable.

### Pattern 2: CSI Secret Driver

The **Secrets Store CSI Driver** mounts secrets from external secret stores into pods via the CSI (Container Storage Interface).

How it works:

- Engineer defines a `SecretProviderClass` resource that references external secrets.
- Pod uses a CSI volume of type `secrets-store.csi.k8s.io`.
- At pod start, the driver fetches secrets from the external store and mounts them as files in the pod's filesystem.
- Optional: sync secrets to native Kubernetes secrets (similar to ESO).

Trade-offs:

- **Pros:** secrets are mounted directly into the pod (no intermediate Kubernetes Secret object); supports many providers (AWS, Azure, GCP, Vault); cleaner audit trail (pod restarts trigger fresh secret fetch).
- **Cons:** secret refresh requires pod restart (unless using sync-to-Kubernetes-secret mode, which negates the benefit); CSI driver is one more component to operate.

Best fit: production workloads where the secrets-as-files pattern is acceptable and the team wants to avoid intermediate Kubernetes Secret objects.

### Pattern 3: native injection / sidecar

Some secrets managers offer native injection patterns:

- **AWS Secrets Manager + Lambda Extensions / ECS task definitions:** the secret is injected directly by the AWS runtime; the pod / task reads it from a specific environment variable or extension.
- **HashiCorp Vault Agent Injector:** Vault's mutating webhook injects a sidecar that authenticates to Vault and writes secrets to a shared volume.
- **Azure Key Vault Secrets Store CSI:** the CSI driver path applies (above).

Trade-offs:

- **Pros:** secrets never exist as Kubernetes Secrets; tight integration with the secrets manager's auth model.
- **Cons:** vendor-specific; refresh patterns are tool-specific.

Best fit: workloads with specific tight-integration needs; Vault-heavy environments using Vault Agent Injector.

### The cross-tool decision

For most teams:

- **External Secrets Operator** is the easiest entry point — works with multiple backends, familiar pattern, mature community.
- **CSI Secret Driver** is the right answer when you want to avoid intermediate Kubernetes Secrets.
- **Vendor-specific injection** for tight integration in single-cloud Vault-heavy environments.

References:
- [External Secrets Operator](https://external-secrets.io/)
- [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)
- [Vault Agent Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector)

---

## Versioning and rotation hooks

The cloud-native secrets managers support version-aware access patterns.

### Versioning model

- **AWS Secrets Manager:** versions identified by `VersionId` (UUID) and `VersionStage` (e.g., `AWSCURRENT`, `AWSPREVIOUS`, `AWSPENDING`). Default access returns `AWSCURRENT`.
- **Azure Key Vault:** versions identified by version GUID in the URI. Default access returns the latest enabled version.
- **GCP Secret Manager:** versions are numbered (1, 2, 3, ...). Default access uses the `latest` alias.

### The dual-credential rotation pattern

The pattern most relevant to integration:

1. **New version created** (rotation).
2. **`AWSPENDING` stage** marks the new version as pending.
3. **Validation** — application tests the new version works.
4. **`AWSCURRENT` stage** moves to the new version.
5. **`AWSPREVIOUS` stage** still references the old version for rollback.

The application:

- Reads `AWSCURRENT` on connection failure (forces refresh).
- May read `AWSPREVIOUS` as a fallback if `AWSCURRENT` fails authentication (the rotation may not have fully propagated to the downstream system).

For deep rotation patterns, see [rotation-patterns.md](./rotation-patterns.md).

### Version pinning vs latest

The default pattern is to use the "latest" version (`AWSCURRENT`, latest enabled, `latest`). The trade-off:

- **Latest:** application gets the rotated value automatically; rotation works without code changes; if a bad version is published, all consumers break.
- **Pinned:** application uses a specific version; rotation requires application change; if a bad version is published, only re-pinned consumers are affected.

For most production secrets: latest. For specific high-impact secrets (root CA private key, master encryption key): consider pinning with explicit upgrade procedures.

---

## Cross-account and cross-region access

The patterns for multi-account / multi-region secret access.

### Cross-account access (AWS)

Two patterns:

**Resource policy + IAM:** the secret in account A has a resource policy granting account B's role. Account B's IAM also grants `secretsmanager:GetSecretValue` on the secret's ARN. Both layers required.

**Secrets replicated to multiple accounts:** for secrets that need to be accessed by many accounts, replicate the secret to consumer accounts. Each account has a local copy; cross-account API calls are eliminated.

The choice:

- **Resource policy** for occasional cross-account access; preserves single-source-of-truth.
- **Replicated secrets** for high-volume cross-account access; lower latency, higher cost.

### Cross-region access

**AWS Secrets Manager replication:** native cross-region replication. A secret in `us-east-1` can be configured to replicate to `us-west-2`. Both copies are queryable in their respective regions; updates to the primary propagate to replicas.

**Azure Key Vault geo-replication:** Premium SKU supports cross-region geo-replication for HSM-backed Vaults.

**GCP Secret Manager replication:** multi-region secrets support automatic replication.

The pattern: enable replication for any secret consumed by workloads in multiple regions. Eliminates cross-region API calls and provides region-failover support.

---

## Cost characteristics and patterns

The pricing models differ; cost can become meaningful at scale.

### AWS Secrets Manager pricing

- **Per secret per month:** $0.40
- **Per 10,000 API calls:** $0.05

For a workload with 100 secrets and 1M API calls per month: ~$40 (secrets) + $5 (API) = $45/month. Modest.

For a workload with 10 secrets and 100M API calls per month: ~$4 + $500 = $504/month. The API cost dominates.

### Azure Key Vault pricing

- **Per 10,000 standard operations:** $0.03 (Standard tier)
- **Per 10,000 HSM operations:** higher

API cost is the dominant variable; secret count is essentially free.

### GCP Secret Manager pricing

- **Per active secret version per month:** $0.06
- **Per 10,000 API operations:** $0.03

Comparable structure to Azure; cost-effective for moderate-volume use.

### High-volume access patterns

For workloads that access secrets at high frequency (e.g., per-request secret retrieval), the API cost dominates. Two patterns reduce it:

**Client-side caching.** The application caches the secret for a TTL (e.g., 5 minutes). Subsequent reads hit the cache. The cache invalidates on auth failure (forcing a fresh fetch).

```python
import time
import boto3

class CachedSecret:
    def __init__(self, secret_id, ttl_seconds=300):
        self.client = boto3.client('secretsmanager')
        self.secret_id = secret_id
        self.ttl = ttl_seconds
        self.cached_value = None
        self.cached_at = 0

    def get(self):
        now = time.time()
        if self.cached_value is None or (now - self.cached_at) > self.ttl:
            response = self.client.get_secret_value(SecretId=self.secret_id)
            self.cached_value = response['SecretString']
            self.cached_at = now
        return self.cached_value

    def refresh(self):
        self.cached_value = None
        return self.get()
```

The TTL trade: longer TTL reduces cost; reduces freshness on rotation. 5 minutes is a common balance.

**AWS Parameters and Secrets Lambda Extension.** For Lambda functions specifically, an extension caches secrets in the Lambda environment. Reduces per-invocation API calls without per-function caching code.

**Sidecar caching in Kubernetes.** A sidecar fetches the secret and exposes it on localhost; the application reads from localhost without an API call.

### The cost vs availability trade

Aggressive caching reduces cost but creates staleness:

- A rotated secret is stale in the cache until TTL expires.
- A revoked secret is still usable from cache until TTL expires.
- A secrets-manager outage is invisible to applications still in their TTL window (a benefit, not a cost).

The TTL is a security trade-off. Aligning TTL with rotation frequency (rotate every 7 days → TTL of hours) keeps staleness bounded.

---

## Worked example: Meridian Health's secrets-manager posture

Meridian uses AWS Secrets Manager as the primary secrets store, with External Secrets Operator integration for Kubernetes workloads and per-workload-account secret isolation.

### The architecture

- Each workload account has its own Secrets Manager secrets.
- Secrets are tagged with `Workload`, `Environment`, `DataSensitivity`, `Owner`, `RotationCadence`.
- Resource policies grant access to the specific application IAM role from the workload's VPC.
- Cross-account access is rare; when needed, explicit resource policy + IAM grant.

### Kubernetes integration

Meridian's EKS clusters use External Secrets Operator:

- ClusterSecretStore configured per cluster with IRSA-backed access to Secrets Manager.
- ExternalSecret resources reference specific Secrets Manager secrets.
- Refresh interval: 1 hour (balance between cost and staleness).
- Kubernetes secrets are created in the workload's namespace; pods consume via standard mount or environment-variable patterns.

### Caching pattern

For high-volume workloads, in-process caching with 5-minute TTL is the standard. The cache invalidates on auth failure; rotation propagates within 5 minutes worst-case.

### The Datadog API key example

Meridian's Datadog integration needs the API key in every workload. The pattern:

- One Datadog API key per environment (prod, staging, dev).
- Stored in the network-account's Secrets Manager.
- Resource policy grants every workload account in the environment.
- ExternalSecret in each cluster references the network-account secret via cross-account IAM.
- Rotation: quarterly; coordinated with Datadog's API key management.

### Findings opened during the secrets-manager audit

- **SMP-001** (some secrets had no rotation enabled). Closed by enabling rotation on every secret (manual rotation where automated isn't supported; automated where Secrets Manager Rotation Lambdas exist).
- **SMP-002** (cross-account access was via account-root grants instead of specific roles). Closed by tightening resource policies.
- **SMP-003** (no tagging on secrets; cross-cutting inventory unclear). Closed by mandatory tag policy.
- **SMP-004** (Kubernetes secrets were created by hand `kubectl create secret` patterns; not synced from Secrets Manager). Closed by ESO migration; the hand-created secrets were rotated and replaced with synced versions.
- **SMP-005** (high-volume workloads were making per-request API calls; cost was significant). Closed by client-side caching with 5-minute TTL.

---

## Anti-patterns

### 1. The "all secrets in one Vault" centralization

The team puts every secret in one Secrets Manager region in one account. Cross-account access requires many resource-policy grants; cross-region requires manual replication; the central Vault is a single point of failure.

The fix: per-workload-account secrets; cross-account only when needed; replication where multi-region is required.

### 2. The over-broad resource policy

The secret's resource policy grants `Principal: AWS: ACCOUNT:root` with `Action: secretsmanager:GetSecretValue`. Any IAM principal in the account can read the secret. The least-privilege model is broken.

The fix: specific role ARNs; specific actions; condition keys for context.

### 3. The forgotten rotation

A secret was created. Rotation was not configured. Two years later, the credential is older than industry guidance recommends.

The fix: rotation enabled at creation; CSPM detects rotation-disabled secrets.

### 4. The Kubernetes secret bypass

The team uses Secrets Manager but operators are creating Kubernetes secrets via `kubectl create secret` for "quick" needs. The Kubernetes secrets are not tracked in Secrets Manager; not rotated; not audited.

The fix: SCP / OPA Gatekeeper policies that block direct Kubernetes secret creation in production namespaces; all secrets sync from Secrets Manager via ESO / CSI.

### 5. The cache-without-invalidation

The application caches secrets for hours. Rotation happens; the application keeps using the old credential; downstream system rejects the call; the application logs auth failures but doesn't refresh.

The fix: cache invalidation on auth failure; explicit refresh API in the cached-secret wrapper.

### 6. The audit-log absent

Secrets Manager produces CloudTrail events for every access. The team has not enabled them or has not consumed them.

The fix: CloudTrail captures Secrets Manager events; SIEM rules alert on unusual patterns (access from unexpected principals, access spikes, off-hours access).

### 7. The "delete the secret" recovery

A secret is deleted to "start fresh." Secrets Manager has a 7–30 day recovery window. The team realizes they need the old value after the window closes; recovery is impossible.

The fix: never delete a secret; rotate or disable. If deletion is truly needed, set the recovery window to maximum (30 days) and explicitly cancel before it expires only after verifying nothing depends on the old value.

### 8. The cross-region secret without replication

The workload runs in us-east-1 and us-west-2. The secret exists only in us-east-1. The us-west-2 workload incurs cross-region API call latency and cost.

The fix: enable cross-region replication for multi-region secrets.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| SMP-001 | Secrets exist without rotation enabled | High | Enable rotation per secret; automated where supported, manual runbook otherwise | Security Eng + Workload Owner |
| SMP-002 | Resource policy uses over-broad principal (`ACCOUNT:root`) | High | Specific role ARNs; condition keys for VPC / source IP | Security Eng |
| SMP-003 | Secrets lack tags (Workload, Environment, DataSensitivity, Owner, RotationCadence) | Low | Add tag baseline; CSPM enforces | Security Eng + Workload Owner |
| SMP-004 | Kubernetes Secrets created via `kubectl` bypassing the secrets manager | High | OPA / Gatekeeper policies block direct creation; ESO / CSI is the only path | Platform Eng + Cluster Owner |
| SMP-005 | High-volume workloads make per-request API calls; cost is significant | Medium | Client-side caching with TTL; Lambda extensions where applicable | Workload Owner + FinOps |
| SMP-006 | Cache lacks invalidation on auth failure; rotation breaks consumers | Medium | Cache wrapper invalidates on auth failure; explicit refresh API | Workload Owner |
| SMP-007 | Cross-account access via account-root grants | High | Specific principal ARNs in resource policies | Security Eng + IAM Eng |
| SMP-008 | No CloudTrail / Activity Log / Audit Log consumption of secrets-manager events | Medium | SIEM rules on access patterns; alert on anomalies | Security Eng + SOC |
| SMP-009 | Secrets deleted instead of rotated; recovery impossible after window | Medium | Disable instead of delete; rotate when value should change | Workload Owner + Security Eng |
| SMP-010 | Multi-region workload uses single-region secret | Low | Enable cross-region replication | Platform Eng |
| SMP-011 | Resource policy missing cross-account-deny default | Medium | Add `Deny` for `aws:PrincipalAccount != ACCOUNT` unless explicit allow above | Security Eng |
| SMP-012 | Secrets older than rotation cadence; "rotation" enabled but never ran | High | Investigate rotation Lambda failures; alert on rotation-job failures | Security Eng + Platform Eng |
| SMP-013 | Kubernetes ESO refresh interval too long; staleness affects rotation propagation | Medium | Align refresh interval with rotation frequency / acceptable staleness | Platform Eng + Workload Owner |
| SMP-014 | ESO ClusterSecretStore IAM grants over-broad access to all secrets | Medium | Per-namespace SecretStore with scoped IAM | Platform Eng + Cluster Owner |
| SMP-015 | Secrets in source control or `.env` files alongside Secrets Manager usage | High | Migrate to Secrets Manager; secret scanning per [secret-detection.md](./secret-detection.md) | Workload Owner + Security Eng |
| SMP-016 | High-impact secrets pinned to version but rotation breaks consumers | Low | Document version-pinning vs latest decision; rotation procedure for pinned secrets | Security Eng |
| SMP-017 | Replicated secret has different IAM in replica region; cross-region access pattern fails | Medium | Align IAM across regions | Platform Eng + Security Eng |
| SMP-018 | Secret naming convention absent; inventory by name is impossible | Low | Adopt naming convention (e.g., `{env}/{workload}/{purpose}`); enforce via SCP / OPA | Security Eng + Platform Eng |

---

## What this document is not

- **A complete Secrets Manager / Key Vault administration reference.** AWS, Azure, GCP documentation cover the depth.
- **A Vault deep dive.** Vault patterns live in [vault-patterns.md](./vault-patterns.md).
- **A rotation deep dive.** Rotation patterns live in [rotation-patterns.md](./rotation-patterns.md).
- **A complete Kubernetes secrets reference.** ESO, CSI Secret Driver, and native injection are covered as the cloud-native integration patterns; Kubernetes-native sealed-secrets and other tools are mentioned as alternatives.
