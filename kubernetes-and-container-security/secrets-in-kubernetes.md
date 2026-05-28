# Secrets in Kubernetes

A practitioner's reference for handling secrets in Kubernetes — why etcd-stored Secrets are not secret without KMS envelope encryption, the External Secrets Operator and CSI Secret Driver patterns, SOPS, sealed-secrets, and the workload-identity-to-secrets-manager pattern that obviates Kubernetes Secrets entirely. The patterns here are about getting secret material into pods correctly, with the discipline that almost every common pattern is wrong in some subtle way.

This document is the Kubernetes-specific extension of [../secrets-and-keys/](../secrets-and-keys/). The broader patterns (cloud-native secrets managers, Vault, rotation, envelope encryption, kill-the-static-secret) all apply; this document covers what's distinct about delivering secrets into Kubernetes pods.

For the static-secret reduction that obviates many of these patterns, see [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md). For the secrets manager that secrets sync from, see [../secrets-and-keys/secrets-manager-patterns.md](../secrets-and-keys/secrets-manager-patterns.md).

---

## When to read this document

**If your pods consume Kubernetes Secrets directly** — read top to bottom. The pattern is widely deployed and broadly wrong; the alternatives are mature.

**If you use ExternalSecretsOperator** — start with [The External Secrets Operator pattern](#the-external-secrets-operator-pattern). The pattern is solid but has its own pitfalls.

**If you use SOPS or sealed-secrets** — start with [SOPS and sealed-secrets patterns](#sops-and-sealed-secrets-patterns). Both are operationally workable but neither is the right primary pattern in 2026.

**If you are auditing Kubernetes-secrets posture** — start with [Findings checklist](#findings-checklist).

---

## Why etcd-stored Secrets are not secret

The default Kubernetes Secret pattern:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: care-coordinator
type: Opaque
data:
  password: cGFzc3dvcmQxMjM=    # base64-encoded
```

The widely misunderstood properties:

- **Base64 is encoding, not encryption.** Anyone reading the Secret object reads the secret.
- **Secrets are stored in etcd.** Compromise of etcd compromises every secret.
- **By default, etcd encrypts at rest with provider-managed keys.** Better than plaintext; not "customer-controlled."
- **Anyone with RBAC `get` on Secrets can read the value.** ServiceAccounts, users, namespace admins — anyone with the permission gets plaintext.

The improvement patterns:

1. **KMS envelope encryption** for etcd (per [eks-aks-gke-baselines.md §Etcd encryption](./eks-aks-gke-baselines.md#etcd-encryption)).
2. **External Secrets Operator** to sync from cloud secrets manager into Kubernetes Secrets.
3. **CSI Secret Driver** to mount secrets from cloud secrets manager directly (no Kubernetes Secret created).
4. **Workload identity to secrets manager** — pods fetch secrets directly via their cloud IAM identity (the most-leveraged pattern).

Each pattern addresses a different aspect; the right choice depends on the threat model.

---

## The four patterns

### Pattern 1: native Kubernetes Secrets with KMS envelope

The minimum baseline. Etcd encrypted with a customer-managed key:

- Secrets created as standard Kubernetes Secret objects.
- Etcd encryption at rest uses a CMK.
- Compromise of etcd is now bounded by the CMK's access control.

Limitations:

- Secrets still visible to anyone with RBAC `get`.
- No rotation discipline (Kubernetes Secrets don't auto-rotate).
- Secret value lives in etcd indefinitely; if compromised, all-time exposure.

Best for: clusters not yet integrated with a cloud secrets manager; a stopgap, not a destination.

### Pattern 2: External Secrets Operator (ESO)

The pattern that's widely adopted in 2026:

- ExternalSecret resource references a cloud secret.
- ESO fetches from the secrets manager; creates a native Kubernetes Secret.
- Pods consume the Kubernetes Secret as usual.
- ESO refreshes the Kubernetes Secret on a schedule.

Trade-offs:

- **Pros:** familiar pattern (pods consume native Kubernetes Secrets); refresh from upstream secret rotation.
- **Cons:** secrets still exist as native Kubernetes Secrets (visible with RBAC `get`); refresh interval determines staleness.

Best for: most teams; a solid default.

### Pattern 3: CSI Secret Driver

The pattern that avoids intermediate Kubernetes Secrets:

- SecretProviderClass resource references cloud secrets.
- Pod uses a CSI volume of type `secrets-store.csi.k8s.io`.
- At pod start, the driver fetches from the cloud secrets manager and mounts files into the pod.
- The Kubernetes Secret object is optionally created (for backwards compatibility); typically not.

Trade-offs:

- **Pros:** secrets mounted directly into the pod, never visible as Kubernetes Secrets; cleaner audit trail.
- **Cons:** refresh requires pod restart (without sync-to-K8s-secret); one more component to operate.

Best for: production workloads where avoiding the intermediate Kubernetes Secret is valuable.

### Pattern 4: workload identity to secrets manager

The pattern that obviates Kubernetes Secrets entirely:

- Pod uses workload identity (IRSA, AKS WI, GKE WI) to authenticate to the cloud secrets manager.
- Pod fetches secret at startup or as needed; in-memory only.
- No Kubernetes Secret, no CSI mount.

Trade-offs:

- **Pros:** secret never appears in Kubernetes; no etcd exposure; per-pod audit trail.
- **Cons:** application code must integrate with the secrets manager SDK; no automatic refresh.

Best for: new workloads designed for this pattern; applications where the secrets-manager SDK integration is acceptable.

### The decision

| Workload type | Recommended pattern |
| --- | --- |
| Legacy workload that expects environment-variable or file-based secrets | ESO or CSI |
| New workload that can integrate with secrets-manager SDK | Workload identity + direct fetch |
| Workload with strict no-etcd-secret requirement | CSI (no Kubernetes Secret created) |
| Workload in transition from native Secrets | Pattern 1 → Pattern 2 → Pattern 3 / 4 |

For most teams: ESO as the default, with workload identity + direct fetch for new applications and CSI for high-assurance cases.

---

## The External Secrets Operator pattern

The dominant pattern in 2026. Worth understanding deeply.

### Installation

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace
```

ESO runs as a Deployment in its own namespace. It reconciles ExternalSecret resources across the cluster.

### Configuration: SecretStore / ClusterSecretStore

Where ESO fetches secrets from:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: care-coordinator
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
```

The SecretStore uses IRSA (the `external-secrets-sa` service account in the namespace has an IAM role that grants `secretsmanager:GetSecretValue`).

A ClusterSecretStore is cluster-scoped (any namespace can reference it):

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-secrets-manager
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
            namespace: external-secrets
```

The cluster-scoped pattern requires careful IAM scoping: the central service account potentially has access to all secrets the team uses; per-namespace SecretStores are tighter.

### ExternalSecret resource

The mapping from cloud secret to Kubernetes Secret:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
  namespace: care-coordinator
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: care-coordinator-db-credentials
    creationPolicy: Owner
  data:
    - secretKey: username
      remoteRef:
        key: prod/care-coordinator/db
        property: username
    - secretKey: password
      remoteRef:
        key: prod/care-coordinator/db
        property: password
```

ESO:

- Fetches `prod/care-coordinator/db` from Secrets Manager every hour.
- Extracts `username` and `password` JSON fields.
- Creates / updates a Kubernetes Secret named `care-coordinator-db-credentials` with those values.

The pod consumes the Kubernetes Secret normally:

```yaml
env:
  - name: DB_USER
    valueFrom:
      secretKeyRef:
        name: care-coordinator-db-credentials
        key: username
  - name: DB_PASS
    valueFrom:
      secretKeyRef:
        name: care-coordinator-db-credentials
        key: password
```

### Refresh discipline

The `refreshInterval` matters:

- **Short (5–15 min):** rotation propagates quickly; more API calls to the secrets manager.
- **Long (1 hour+):** fewer API calls; longer staleness window after rotation.

For rotating secrets (per [../secrets-and-keys/rotation-patterns.md](../secrets-and-keys/rotation-patterns.md)): align refresh with rotation cadence + acceptable staleness.

For non-rotating secrets (third-party API keys with annual rotation): 1-hour refresh is fine.

### ESO pitfalls

- **Cluster-wide IAM that's too broad.** The ESO service account has access to all secrets it might need; tighten per-namespace.
- **Refresh latency vs rotation.** A 1-hour refresh means rotation takes up to 1 hour to propagate; applications using cached credentials may fail in the window.
- **Secret value visible in Kubernetes Secret.** The pattern doesn't eliminate the Kubernetes Secret; it syncs from a better source. RBAC on the namespace Secret matters.

References:
- [External Secrets Operator](https://external-secrets.io/)

---

## CSI Secret Driver pattern

The pattern that avoids the intermediate Kubernetes Secret.

### Installation

```bash
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system

# Provider plugin (AWS, Azure, GCP, Vault)
helm install csi-secrets-store-provider-aws secrets-store-csi-driver/secrets-store-csi-driver-provider-aws \
  --namespace kube-system
```

### SecretProviderClass

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: care-coordinator-db
  namespace: care-coordinator
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "prod/care-coordinator/db"
        objectType: "secretsmanager"
        jmesPath:
          - path: "username"
            objectAlias: "db-username"
          - path: "password"
            objectAlias: "db-password"
```

### Pod consumption

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: care-coordinator-supervisor
spec:
  serviceAccountName: care-coordinator-supervisor-sa
  containers:
    - name: app
      image: meridian-registry.local/care-coordinator-supervisor:v2.4.1@sha256:abc123
      volumeMounts:
        - name: secrets
          mountPath: /mnt/secrets
          readOnly: true
  volumes:
    - name: secrets
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: care-coordinator-db
```

The pod mounts `/mnt/secrets/db-username` and `/mnt/secrets/db-password` as files. The values come directly from Secrets Manager via the CSI driver.

### Refresh behavior

CSI Secret Driver's refresh is more limited than ESO:

- **Default:** secrets fetched at pod start; no refresh during pod lifetime.
- **Periodic sync** (optional): syncs to a Kubernetes Secret on a schedule; pod restarts to consume new values.

For rotation: the pod restart is the propagation mechanism. Acceptable for many workloads; problematic for stateful workloads where restart is expensive.

### When CSI beats ESO

- **No intermediate Kubernetes Secret.** Audit trail is cleaner; RBAC exposure is removed.
- **Cleaner ephemeral semantics.** Secrets exist only while the pod runs; gone when pod terminates.

When ESO beats CSI:

- **Refresh without restart.** ESO can update the Kubernetes Secret without restarting the pod; the application reads the updated value on next access.
- **Familiar pattern.** Pods consume native Kubernetes Secrets (the most-documented Kubernetes pattern).

### The hybrid

Some deployments use both: ESO for most secrets (refresh-without-restart is valuable); CSI for high-assurance secrets where the intermediate Kubernetes Secret is unacceptable.

References:
- [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)

---

## SOPS and sealed-secrets patterns

Two alternative patterns; widely deployed but not the right primary pattern in 2026.

### SOPS (Secrets OPerationS)

SOPS encrypts secret files on disk (in source control). The pattern:

- Engineer encrypts a YAML file containing Kubernetes Secret manifest with SOPS using a KMS key.
- The encrypted file lives in source control.
- At deploy time, ArgoCD / Flux / Helm decrypts via SOPS and applies the resulting Kubernetes Secret to the cluster.

```yaml
# secrets.enc.yaml (in source control)
apiVersion: v1
kind: Secret
metadata:
  name: database-password
data:
  password: ENC[AES256_GCM,data:abc...,iv:def...,tag:ghi...,type:str]
sops:
  kms:
    - arn: arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID
  encrypted_regex: ^(data|stringData)$
```

Trade-offs:

- **Pros:** secrets in source control (auditable, version-controlled); decryption gated by KMS access.
- **Cons:** the secret value lives in encrypted form in source control (potentially forever if not removed); rotation requires updating source control; key escrow problem (lost KMS key = lost secrets).

Best for: GitOps-heavy organizations that want secrets-in-Git with the encryption-at-rest property; not the right primary pattern for most.

### sealed-secrets (Bitnami)

Similar concept but Kubernetes-native:

- Cluster runs the sealed-secrets controller.
- Engineer uses the `kubeseal` CLI to encrypt a Secret manifest with the cluster's public key.
- The encrypted SealedSecret resource is committed to source control.
- The controller decrypts using the cluster's private key when the SealedSecret is applied.

Trade-offs:

- **Pros:** GitOps-friendly; no external KMS dependency (the cluster manages the key).
- **Cons:** the cluster's private key is a single point of failure; recovery is hard if lost; per-cluster encryption (secrets encrypted for cluster A can't decrypt in cluster B).

Best for: simpler GitOps environments without cloud KMS integration; not the right primary pattern for production.

### Why these aren't the right primary pattern

Both SOPS and sealed-secrets address the "secrets in Git" problem. The cloud-native pattern (cloud secrets manager + ESO / CSI / workload identity) solves the same problem better:

- Secrets don't live in Git at all.
- Secrets-manager integration with cloud IAM is direct.
- Rotation discipline is built into the secrets manager.
- Audit trail is from the secrets manager.

For new deployments: prefer cloud-native. For existing SOPS / sealed-secrets deployments: migration is bounded; payoff is real.

References:
- [SOPS](https://github.com/getsops/sops)
- [Bitnami sealed-secrets](https://github.com/bitnami-labs/sealed-secrets)

---

## The workload-identity-to-secrets-manager pattern

The pattern that obviates Kubernetes Secrets entirely. Best practice for new workloads.

### How it works

1. Pod uses workload identity (IRSA, AKS WI, GKE WI) to authenticate to the cloud.
2. Pod's application code uses the cloud SDK to fetch the secret directly.
3. Secret lives in pod memory; never in Kubernetes etcd; never as a file mount.
4. Secret can be refreshed dynamically by the application (e.g., on auth failure).

### Example: AWS Secrets Manager from a pod

```python
import boto3
import json

def get_db_credentials():
    sm = boto3.client('secretsmanager', region_name='us-east-1')
    # boto3 uses the pod's IRSA-provided credentials automatically
    response = sm.get_secret_value(SecretId='prod/care-coordinator/db')
    return json.loads(response['SecretString'])

# At application startup
creds = get_db_credentials()
conn = psycopg2.connect(
    host='db.example.com',
    user=creds['username'],
    password=creds['password'],
)
```

The pod's service account is annotated with the IRSA role; the role has `secretsmanager:GetSecretValue` on the specific secret.

### Caching

For high-volume access, in-process caching (per [../secrets-and-keys/secrets-manager-patterns.md §Cost characteristics](../secrets-and-keys/secrets-manager-patterns.md#cost-characteristics-and-patterns)):

```python
import time

class CachedSecret:
    def __init__(self, secret_id, ttl_seconds=300):
        self.sm = boto3.client('secretsmanager')
        self.secret_id = secret_id
        self.ttl = ttl_seconds
        self.cached_value = None
        self.cached_at = 0

    def get(self):
        now = time.time()
        if self.cached_value is None or (now - self.cached_at) > self.ttl:
            response = self.sm.get_secret_value(SecretId=self.secret_id)
            self.cached_value = json.loads(response['SecretString'])
            self.cached_at = now
        return self.cached_value
```

### Trade-offs

Pros:

- No Kubernetes Secret; no etcd exposure.
- Per-pod audit trail in CloudTrail / Audit Log.
- Refresh on auth failure or rotation propagation.
- Compromise of etcd doesn't compromise secrets.

Cons:

- Application code change required (SDK integration).
- No automatic refresh without code; cache invalidation discipline matters.
- The cloud SDK becomes a runtime dependency.

For new workloads: this is the right pattern. For existing workloads: migration is per-application; ESO or CSI may be the transitional step.

---

## Worked example: Meridian Health's Kubernetes-secrets posture

Meridian's secrets posture in Kubernetes spans three patterns based on workload age:

### Pattern allocation by workload

- **New workloads (2024+):** workload identity to secrets manager. Application code uses AWS SDK with IRSA.
- **Legacy workloads (pre-2024):** ESO. Sync from Secrets Manager to Kubernetes Secret; pod consumes the Kubernetes Secret.
- **High-assurance workloads (clinical data):** CSI Secret Driver. No intermediate Kubernetes Secret.

The trend: new workloads use direct integration; the legacy ESO pool shrinks as workloads are modernized.

### ESO configuration

Per-namespace SecretStore (not cluster-scoped). Each workload account has its own ESO ServiceAccount with narrow IAM scope:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: care-coordinator-secrets
  namespace: care-coordinator
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: care-coordinator-eso-sa
```

The `care-coordinator-eso-sa` service account's IAM role grants `secretsmanager:GetSecretValue` on `prod/care-coordinator/*` only — scoped to the workload's secrets.

### Refresh discipline

- **Database credentials (90-day rotation):** 15-minute refresh.
- **Third-party API keys (quarterly rotation):** 1-hour refresh.
- **TLS certificates (mTLS, rotation by mesh):** handled by Vault PKI via mesh, not ESO.

### Etcd encryption

Per [eks-aks-gke-baselines.md](./eks-aks-gke-baselines.md), every cluster has etcd encrypted with the cluster's PHI CMK. Even Kubernetes Secrets (the ones created by ESO) are envelope-encrypted in etcd.

### The migration plan

Pre-2024: 100% native Kubernetes Secrets, no encryption beyond defaults.

Q1 2024: ESO deployment across all clusters; sync from Secrets Manager.

Q2 2024: etcd encryption with CMK on all clusters.

Q3 2024+: new workloads use workload identity directly. Migration of high-assurance workloads to CSI Secret Driver.

Current state: ~50 workloads on direct SDK integration; ~30 on ESO; ~10 on CSI.

### Findings opened during the Kubernetes-secrets audit

- **K8SEC-001** (workloads consumed native Kubernetes Secrets without integration to Secrets Manager). Closed by ESO deployment.
- **K8SEC-002** (etcd encryption was provider-managed default; compliance asked for customer-managed). Closed by CMK migration.
- **K8SEC-003** (ESO ClusterSecretStore granted broad IAM; per-namespace tightening absent). Closed by per-namespace SecretStores.
- **K8SEC-004** (refresh interval was 6 hours; rotation propagation was too slow). Closed by aligning with rotation cadences.
- **K8SEC-005** (new applications used ESO when direct integration was feasible). Closed by guidance to use workload identity directly.
- **K8SEC-006** (high-assurance clinical workloads kept Kubernetes Secrets visible via RBAC). Closed by migration to CSI Secret Driver.

---

## Anti-patterns

### 1. The base64-as-encryption misunderstanding

The team believes that base64-encoded values in Kubernetes Secrets are "encrypted." Engineers commit base64-encoded passwords to source control "because they're encrypted."

The fix: education + secret-scanning. Base64 is encoding, not encryption.

### 2. The default-encryption-only etcd

Etcd is encrypted by the cloud provider's default key. Compliance audit asks who controls the encryption key; the answer is "the cloud provider."

The fix: CMK-encrypted etcd per [eks-aks-gke-baselines.md §Etcd encryption](./eks-aks-gke-baselines.md#etcd-encryption).

### 3. The ClusterSecretStore IAM-too-broad

A ClusterSecretStore is used cluster-wide; its IAM has access to all secrets the team uses across namespaces. A compromised ESO controller can fetch any secret.

The fix: per-namespace SecretStore with namespace-scoped IAM; cluster-scoped only for genuinely-shared secrets.

### 4. The forever-1-hour-refresh

ESO is configured with 1-hour refresh. A high-frequency-rotating credential (15-minute rotation) is stale for up to 1 hour after rotation; applications fail intermittently.

The fix: refresh interval aligned with rotation frequency.

### 5. The CSI-without-restart-discipline

CSI Secret Driver mounts secrets at pod start. The team rotates a credential; pods continue running with stale credentials; no refresh.

The fix: rotation triggers a pod restart (via Deployment annotation change or similar); OR migrate to ESO for refresh-without-restart workloads.

### 6. The kubeseal-as-source-of-truth

The team uses sealed-secrets. The cluster's private key is the only decryption mechanism. The cluster has to be restored; the key is lost; secrets are unrecoverable.

The fix: key backup discipline; consider migration to cloud-native secrets manager.

### 7. The cluster-admin reads all secrets

A cluster-admin role exists for engineers' break-glass access. The role can `get` any Secret. Secrets stored in Kubernetes (ESO or native) are visible to anyone with cluster-admin.

The fix: minimize cluster-admin use; audit cluster-admin actions; migrate critical secrets to CSI or workload-identity patterns where Kubernetes-RBAC doesn't expose the values.

### 8. The Helm-rendered-secret

The team uses Helm charts; secrets are passed as values; Helm renders them into Kubernetes Secret manifests. Helm values files (sometimes committed to source) contain plaintext secrets.

The fix: don't pass secrets through Helm values; integrate via ESO / CSI / workload identity; secrets-manager-provider Helm chart features for sourcing values.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| K8SEC-001 | Pods consume native Kubernetes Secrets without secrets-manager integration | High | Deploy ESO (or CSI / direct integration) per workload type | Platform Eng + Workload Owner |
| K8SEC-002 | Etcd encryption uses provider-managed default key | High | Migrate to customer-managed key per [eks-aks-gke-baselines.md](./eks-aks-gke-baselines.md) | Platform Eng + Security Eng |
| K8SEC-003 | ClusterSecretStore IAM grants broad access; per-namespace tightening absent | High | Per-namespace SecretStore with namespace-scoped IAM | Platform Eng + Security Eng |
| K8SEC-004 | ESO refresh interval longer than rotation cadence; staleness window too long | Medium | Align refresh with rotation frequency | Platform Eng + Workload Owner |
| K8SEC-005 | New applications use intermediate-secret pattern when direct integration is feasible | Low | Guidance for new applications to use workload-identity-to-secrets-manager pattern | Architecture + Workload Owner |
| K8SEC-006 | High-assurance workloads keep Kubernetes Secrets visible via RBAC | Medium | Migration to CSI Secret Driver; no intermediate Kubernetes Secret | Platform Eng + Workload Owner |
| K8SEC-007 | Cluster-admin role has secret-read access; audit trail of access incomplete | Medium | Restrict cluster-admin; CloudTrail / audit log of secret-reads; SIEM rules | Security Eng + IAM Eng |
| K8SEC-008 | Helm values files contain plaintext secrets | High | Migrate to secrets-manager integration; remove plaintext from values | DevOps + Workload Owner |
| K8SEC-009 | sealed-secrets cluster private key not backed up; recovery impossible | High | Key backup discipline; documented recovery procedure | Platform Eng + SRE |
| K8SEC-010 | SOPS-encrypted secrets in source control without rotation discipline | Medium | Rotate secrets; if SOPS retained, rotate KMS key periodically | DevOps + Security Eng |
| K8SEC-011 | Kubernetes Secret object naming inconsistent; inventory difficult | Low | Naming convention (e.g., `<workload>-<purpose>`); enforce via OPA | Platform Eng |
| K8SEC-012 | ESO ServiceAccount lacks audit on secret-fetch operations | Medium | CloudTrail / Activity Log captures Secrets Manager events; SIEM | Security Eng + SOC |
| K8SEC-013 | Application code doesn't cache secrets; per-request API calls; cost issue | Low | In-process caching with TTL aligned to rotation | Workload Owner + FinOps |
| K8SEC-014 | Pods use the cluster's `default` ServiceAccount for secrets access | Medium | Per-workload ServiceAccount; IRSA-scoped to specific secrets | Platform Eng + Workload Owner |
| K8SEC-015 | Cross-namespace Kubernetes Secrets shared; tenancy isolation broken | High | Per-namespace secrets; explicit ESO / CSI for cross-namespace use | Security Eng + Platform Eng |
| K8SEC-016 | Pods inject secrets via ConfigMap (mistake; ConfigMap is plaintext) | High | Migrate to Secret + ESO / CSI; ConfigMap for non-sensitive config only | Workload Owner |
| K8SEC-017 | Secret in environment variable; logged in process listings, error messages | Medium | Mount as file rather than env var where possible; redact in logs | Workload Owner |
| K8SEC-018 | Image baked with secrets via Dockerfile ARG | High | Secrets at runtime via ESO / CSI / direct integration; never bake | DevOps + Workload Owner |

---

## What this document is not

- **A complete ESO administration reference.** External Secrets Operator documentation covers the depth.
- **A CSI Secret Driver reference.** CSI Secret Driver documentation covers provider-specific configuration.
- **A SOPS / sealed-secrets tutorial.** Both are workable but not the primary pattern in 2026.
- **A secrets-management reference.** Broader secrets-management patterns live in [../secrets-and-keys/](../secrets-and-keys/).
