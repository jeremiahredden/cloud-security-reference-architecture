# EKS / AKS / GKE Baselines

A practitioner's reference for the cluster-level security baseline across the three major managed Kubernetes services — AWS EKS, Azure AKS, GCP GKE. The patterns here cover cluster authentication (IRSA, Workload Identity, AKS workload identity), control-plane access (public vs private endpoints), node-group hardening, audit log configuration, automatic upgrades, and the four detective controls every cluster should have. AWS-first depth with Azure and GCP equivalents.

This document opens the kubernetes-and-container-security folder. The cluster baseline is the load-bearing first decision; everything else in this folder (pod security, network policies, admission control, runtime, image supply chain) sits on top of a properly-baseline-d cluster. A team that gets the baseline wrong builds the rest on sand.

For the workload identity patterns this baseline enables, see [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md) and [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md). For the in-cluster patterns, see [pod-security.md](./pod-security.md), [network-policies.md](./network-policies.md), [admission-control.md](./admission-control.md), and [image-supply-chain.md](./image-supply-chain.md).

---

## When to read this document

**If you are standing up a new EKS / AKS / GKE cluster** — read top to bottom. The decisions here propagate through the cluster's lifetime; getting them right at creation is much cheaper than retrofitting.

**If you have inherited a cluster and you're not sure what it's configured with** — start with [The baseline checklist](#the-baseline-checklist). Most inherited clusters miss several baseline items; the inventory is fast.

**If you are auditing cluster posture** — start with [Findings checklist](#findings-checklist). The common findings (public control-plane endpoint, missing audit logs, missing KMS envelope encryption, default node-group hardening) are universal.

**If you are deciding between EKS, AKS, and GKE** — the cross-cloud crosswalk section is the structural comparison; this document does not advocate for one over another.

---

## The baseline checklist

The non-negotiable cluster-level baseline. Every production Kubernetes cluster should have these.

| Item | Why | Section |
| --- | --- | --- |
| Workload identity enabled | Eliminates static cloud credentials in pods | [Cluster identity](#cluster-identity) |
| Control-plane endpoint private (or restricted public) | Reduces attack surface | [Control-plane access](#control-plane-access) |
| Audit logs enabled and shipped to central archive | Detection and forensics | [Audit logging](#audit-logging) |
| Etcd encrypted with customer-managed key (KMS envelope) | Encryption beyond defaults | [Etcd encryption](#etcd-encryption) |
| Node OS hardening (managed node groups, automatic patching) | Reduces node attack surface | [Node hardening](#node-hardening) |
| Automatic minor / patch upgrades | Closes vulnerability windows | [Cluster lifecycle](#cluster-lifecycle) |
| Network plugin with NetworkPolicy support (Calico, Cilium, native) | Enables pod-level segmentation | [network-policies.md](./network-policies.md) |
| Pod Security Admission enforced (`restricted` profile baseline) | Prevents privileged-pod misconfigurations | [pod-security.md](./pod-security.md) |
| Admission policy framework (OPA Gatekeeper, Kyverno, or CEL) | Enforces organizational policy | [admission-control.md](./admission-control.md) |
| Image signing enforcement (Cosign / Sigstore) | Supply-chain attestation | [image-supply-chain.md](./image-supply-chain.md) |

The last four are covered in their own documents in this folder; the rest are this document's scope.

---

## Cluster identity

The single most-impactful baseline decision: how pods authenticate to the cloud.

### Why this matters

Without workload identity:

- Pods that need AWS / Azure / GCP API access have IAM credentials mounted as Kubernetes secrets.
- The secrets live in etcd; compromise of etcd compromises every credential.
- Credential rotation is per-secret; coordination is brittle.
- Audit trail is at the secret-fetch layer; per-pod attribution is poor.

With workload identity:

- Pods authenticate via the cluster's identity federation; no static credentials.
- Per-pod IAM identities (via per-pod service accounts).
- Cloud-native audit trail per credential issuance.
- Rotation is implicit (every credential is short-lived).

This is the highest-leverage single configuration change available in a Kubernetes cluster. Every new EKS / AKS / GKE cluster should have workload identity enabled at creation; existing clusters should migrate.

### EKS: IAM Roles for Service Accounts (IRSA)

EKS exposes an OIDC provider for the cluster:

```bash
# Verify OIDC provider URL
aws eks describe-cluster --name CLUSTER --query "cluster.identity.oidc.issuer"
# Create the OIDC provider in IAM (one-time per cluster)
eksctl utils associate-iam-oidc-provider --cluster CLUSTER --approve
```

Then per-service-account:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: care-coordinator-sa
  namespace: care-coordinator
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/care-coordinator-app-role
```

The IAM role's trust policy accepts the OIDC token from the cluster's issuer for the specific service account:

```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/CLUSTER-ID"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "oidc.eks.us-east-1.amazonaws.com/id/CLUSTER-ID:sub": "system:serviceaccount:care-coordinator:care-coordinator-sa"
    }
  }
}
```

The pod-side AWS SDK transparently exchanges the projected service-account token for IAM credentials at runtime.

### AKS: Azure AD Workload Identity

AKS supports Azure AD Workload Identity (replacing the older Azure AD Pod Identity, which is deprecated):

```bash
# Enable workload identity on cluster
az aks update --enable-workload-identity --enable-oidc-issuer
```

Per-service-account mapping to a federated identity on an Azure AD application or User-Assigned Managed Identity:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: care-coordinator-sa
  annotations:
    azure.workload.identity/client-id: CLIENT-ID
```

The federated credential on the Azure AD identity accepts tokens from the cluster's OIDC issuer:

```bash
az identity federated-credential create \
  --name care-coordinator-sa-cred \
  --identity-name care-coordinator-app \
  --resource-group meridian-prod \
  --issuer "$AKS_OIDC_ISSUER" \
  --subject "system:serviceaccount:care-coordinator:care-coordinator-sa"
```

### GKE: Workload Identity

GKE has Workload Identity (recommended) or the older metadata-server-based approach (legacy):

```bash
# Enable Workload Identity on cluster
gcloud container clusters update CLUSTER --workload-pool=PROJECT.svc.id.goog
```

Per-service-account binding to a GCP service account:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: care-coordinator-sa
  annotations:
    iam.gke.io/gcp-service-account: care-coordinator@PROJECT.iam.gserviceaccount.com
```

GCP IAM binding:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:PROJECT.svc.id.goog[care-coordinator/care-coordinator-sa]" \
  care-coordinator@PROJECT.iam.gserviceaccount.com
```

### Per-pod identity discipline

Across all three platforms, the discipline:

- **Per-pod service accounts.** Each pod has its own; the `default` service account is empty / unused.
- **Per-application IAM role.** The IAM role is scoped to the application's specific needs.
- **No shared roles.** Two applications that need different permissions get different roles.
- **No fallback to node-IAM-role.** EKS nodes have an instance role; pods should NOT inherit it. Disable `metadataAccountIam` / equivalent fallback.

References:
- [EKS IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [AKS Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
- [GKE Workload Identity](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)

---

## Control-plane access

Where the cluster's API server is reachable from.

### Public endpoint (the default that needs fixing)

By default, EKS / AKS / GKE expose the Kubernetes API server on a public endpoint. Anyone on the internet can attempt to connect; the only barriers are TLS, IAM authentication, and (often) IP allowlist.

The risk: a misconfigured RBAC binding, a leaked kubeconfig, a compromised CI credential — any of these is an open door if the endpoint is internet-reachable.

### Private endpoint (the right default for production)

The cluster's API endpoint is reachable only from inside the VPC / VNet.

- **EKS:** `endpointPrivateAccess: true`, `endpointPublicAccess: false` (or restricted public CIDR list).
- **AKS:** Private Cluster mode (the API server's IP is a private IP in your VNet).
- **GKE:** Private Cluster mode (the master endpoint is private; node pools also private).

Access from outside the VPC / VNet requires a bastion (Session Manager / Azure Bastion / IAP), a peered network, or VPN connectivity. The cost is operational (engineers need a bastion path); the benefit is structural (the attack surface drops to inside-the-VPC only).

### Restricted public (the compromise)

For environments where pure private is operationally untenable, restrict the public endpoint to specific source CIDR ranges:

- Corporate VPN egress IPs.
- CI runner IPs (if external).
- The bastion's egress IPs.

The pattern is weaker than pure private (any compromise of an allowed IP is a foothold) but stronger than open public.

### The kubectl-from-laptop pattern

Engineers running `kubectl` from laptops:

- **From corporate network:** kubectl reaches the cluster via the VPN to the private endpoint, or via SSO to a cloud-shell-equivalent that has cluster access.
- **From bastion:** engineer SSHs (via Session Manager / Bastion / IAP) to a bastion in the cluster's VPC; runs kubectl there.
- **From CloudShell:** AWS CloudShell, Azure Cloud Shell, GCP Cloud Shell — these are inside the cloud and have network access to the cluster.

The pattern depends on the organization's network architecture; the principle is: kubectl access traverses a managed channel, not the public internet.

---

## Audit logging

The Kubernetes API server's audit log is the most important detection signal for cluster activity.

### What to capture

Kubernetes audit logs include:

- **Authentication events.** Who authenticated to the API server.
- **Authorization decisions.** What requests were allowed or denied.
- **Resource operations.** Create / read / update / delete on Kubernetes resources.
- **Subresource operations.** Pod exec, port-forward, attach (often higher-risk operations).

### Audit policy

Kubernetes audit policy determines what to log:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log pod exec/attach/port-forward at high verbosity
  - level: RequestResponse
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]
  # Log changes to RBAC at high verbosity
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: "rbac.authorization.k8s.io"
  # Log all secret operations at metadata level
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]
  # Log all resource operations at Metadata level
  - level: Metadata
    omitStages: ["RequestReceived"]
```

Higher levels (`Request`, `RequestResponse`) capture more detail at higher cost. The tiered policy (high verbosity for high-risk operations, metadata-only for routine) is the standard.

### EKS audit log shipping

EKS Control Plane Logs:

```bash
aws eks update-cluster-config \
  --name CLUSTER \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
```

Logs land in CloudWatch Logs; ship from there to the central log archive ([../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md)).

### AKS audit log shipping

AKS Diagnostic Settings:

- `kube-audit` and `kube-audit-admin` log categories.
- Ship to Log Analytics workspace.
- From there to Sentinel or external SIEM via Event Hub.

### GKE audit log shipping

GKE Audit Logs (Admin Activity and Data Access):

- Admin Activity is enabled by default; cannot be disabled.
- Data Access requires explicit enablement; high-volume.
- Ship to Cloud Logging; export to BigQuery / Pub/Sub / Cloud Storage.

### SIEM detection rules

With audit logs centralized, build detection rules:

- **`pods/exec` from unusual principals or to unusual pods.** Production execs should be rare and from specific roles.
- **`secrets` reads from unusual principals.** Service accounts should read their own secrets; cross-namespace secret reads are suspicious.
- **RBAC binding changes outside of CI / IaC.** Hand-edited bindings (especially additions of `cluster-admin`) are red flags.
- **Mass deletion patterns** (a principal deleting many resources in quick succession; potential indicator of compromised credential or ransomware).
- **Authentication failures bursts** (potential brute force).

The audit log without detection is just storage. The detection without the audit log has no signal. Both are required.

---

## Etcd encryption

The cluster's etcd database stores everything: secrets, configurations, RBAC bindings. Encryption at rest with a customer-managed key is the structural defense.

### EKS

EKS uses AWS KMS envelope encryption for etcd by default (provider-managed key). For customer-managed:

```bash
aws eks update-cluster-config \
  --name CLUSTER \
  --encryption-config '[{"resources":["secrets"],"provider":{"keyArn":"arn:aws:kms:us-east-1:ACCOUNT:key/CMK-ID"}}]'
```

The CMK should be per-cluster or per-workload-tier (per [../data-security/kms-strategy.md](../data-security/kms-strategy.md)).

### AKS

AKS supports customer-managed keys for etcd via Azure Key Vault:

```bash
az aks update --name CLUSTER --resource-group RG \
  --enable-azure-keyvault-kms \
  --azure-keyvault-kms-key-id "https://VAULT.vault.azure.net/keys/KEY/VERSION"
```

The Key Vault must be in the same region as the cluster; CMK rotation is supported.

### GKE

GKE uses CMEK for etcd application-layer encryption:

```bash
gcloud container clusters update CLUSTER \
  --database-encryption-key projects/PROJECT/locations/REGION/keyRings/RING/cryptoKeys/KEY
```

For maximum assurance, GKE also supports node-disk encryption with CMEK and Confidential GKE Nodes (hardware-encrypted memory).

### What encryption-at-rest doesn't prevent

- A pod that can read a Kubernetes Secret object (RBAC-allowed) gets the decrypted value. Encryption protects against compromise of the underlying etcd storage; it doesn't protect against legitimate-IAM-with-broad-permissions.
- For the secrets that genuinely shouldn't be in etcd at all, use External Secrets Operator with a cloud-native secrets manager ([secrets-in-kubernetes.md](./), coming).

---

## Node hardening

The Kubernetes nodes themselves run the pods. Node hardening reduces the attack surface.

### Managed node groups / managed node pools

- **EKS Managed Node Groups** (or Karpenter, or Fargate) — AWS handles AMI selection, patching, replacement.
- **AKS Managed Node Pools** — Azure handles equivalent.
- **GKE Standard / Autopilot** — Autopilot abstracts nodes entirely; Standard still uses managed pools.

For new clusters: use the managed option. Self-managed nodes (EC2 instances you operate yourself) add operational burden without security benefit in most cases.

### Automatic patching

- **EKS:** Managed Node Groups support automatic AMI updates with rolling node replacement.
- **AKS:** Auto-upgrade channels (`patch`, `stable`, `rapid`) control upgrade cadence.
- **GKE:** Auto-upgrade is enabled by default; the maintenance window controls when.

Enable automatic patching. The alternative is manual patching that the team forgets to do; the alternative is unpatched nodes for months.

### Node OS choice

- **Bottlerocket** (AWS) — minimal Linux OS designed for container hosts; fewer packages, smaller attack surface, immutable filesystem.
- **Ubuntu** (default on EKS / GKE) — familiar but larger surface.
- **Azure Linux** (formerly CBL-Mariner; AKS) — Microsoft-maintained minimal distro.
- **Container-Optimized OS** (GKE default) — Google's minimal node OS.

For security-sensitive workloads: prefer the minimal-OS option (Bottlerocket, Azure Linux, Container-Optimized OS). The cost is some operational unfamiliarity; the benefit is a smaller attack surface and provider-maintained hardening.

### Confidential nodes (where available)

For high-assurance workloads, confidential compute nodes use hardware memory encryption (AMD SEV, Intel TDX):

- **EKS Confidential Containers** — nascent; check availability per region.
- **AKS Confidential Containers** — preview / available.
- **GKE Confidential Nodes** — generally available.

Cost premium is meaningful; reserve for workloads with the regulatory or threat-model requirement.

### IMDSv2 / IMDS hop limit

For EKS specifically, ensure node-IAM-metadata-service is hardened:

- **IMDSv2 required** (session-based; defeats SSRF attacks that target IMDSv1).
- **Hop limit = 1** for pods that use host network; prevents pods from reading the node's IMDS.
- **Pod-IMDS access disabled** for non-IRSA pods (forces them to use IRSA instead).

These settings are part of the EKS node-group launch template.

---

## Cluster lifecycle

The patterns for keeping the cluster current.

### Kubernetes version

Kubernetes follows a ~3-version-per-year release cadence. Each version is supported for ~12 months.

Discipline:

- **Track the supported versions.** EKS, AKS, GKE publish their supported version matrix.
- **Plan upgrades within the support window.** Upgrading an unsupported cluster is more expensive than upgrading on schedule.
- **Test upgrades in non-production first.** Each Kubernetes minor version may deprecate APIs; workloads using deprecated APIs break.
- **Use auto-upgrade for patch versions; controlled upgrade for minor versions.** Auto-upgrade between 1.30.0 → 1.30.5 is safe; 1.30 → 1.31 is the planned event.

### Maintenance windows

All three platforms support maintenance windows. Configure them:

- Off-peak hours for the workload.
- Coordinated with deployment freezes (no Friday-afternoon upgrades).
- Cluster-by-cluster scheduling for staged rollout.

### Cluster deletion protection

Production clusters should be deletion-protected (where the provider supports). Accidental cluster deletion is recoverable via backup but expensive in downtime.

---

## The four detective controls

Beyond the audit log, four specific detective patterns every cluster should have.

### 1. Workload runtime monitoring

Per [runtime-security.md](./) (coming): Falco, Tetragon, or vendor EDR detect runtime anomalies (unexpected process execution, file access patterns, network anomalies).

For cluster baseline: ensure the runtime-monitoring agent is deployed as a DaemonSet on every node; agents report to the central detection backend.

### 2. Policy violations from admission control

Per [admission-control.md](./admission-control.md): Gatekeeper / Kyverno violations indicate attempted policy bypasses. Surface as detection signals, not just admission rejections.

### 3. Resource-quota / LimitRange anomalies

A pod or namespace suddenly hitting quota limits (CPU, memory, pod count) can indicate a runaway workload or a cryptominer. Detection:

- ResourceQuota events.
- Sustained high CPU on specific nodes.
- Unusual pod creation patterns (one principal creating many pods rapidly).

### 4. Cluster-config drift

Configuration drift detection (Argo CD, Flux, Config Sync) catches in-cluster changes that don't match the desired state in Git. Drift signals:

- Hand-edited Deployments.
- Manually-applied RBAC.
- Out-of-band Secret creation.

The IaC-as-source-of-truth discipline catches drift; the detection makes it visible.

---

## Cross-cloud crosswalk

| Capability | EKS | AKS | GKE |
| --- | --- | --- | --- |
| Workload identity | IRSA | Azure AD Workload Identity | Workload Identity |
| Private control-plane | Endpoint Private Access | Private Cluster | Private Cluster |
| Audit logs | EKS Control Plane Logs → CloudWatch | Diagnostic Settings → Log Analytics | Cloud Audit Logs |
| Etcd encryption (CMK) | KMS envelope encryption | Azure Key Vault KMS | CMEK database encryption |
| Managed node groups | EKS Managed Node Groups / Karpenter / Fargate | AKS Managed Node Pools | GKE Standard pools / Autopilot |
| Minimal node OS | Bottlerocket | Azure Linux | Container-Optimized OS |
| Auto-upgrade | Managed Node Groups | Auto-upgrade channels | Auto-upgrade (default on) |
| Confidential compute | Confidential Containers (nascent) | Confidential Containers (preview) | Confidential Nodes (GA) |
| Network plugin | AWS VPC CNI / Calico / Cilium | Azure CNI / Calico / Cilium | Cloud-managed / Calico / Cilium |

The patterns are functionally equivalent across the three; the operational details differ. A team operating across multiple clouds should standardize on the patterns and accept per-cloud configuration differences.

---

## Worked example: Meridian Health's EKS baseline

Meridian operates several EKS clusters across regions. The baseline:

### Per-cluster configuration

- **Private endpoint only.** kubectl access via Session Manager bastions or via the Meridian VPN to the cluster's VPC.
- **IRSA enabled** with OIDC provider configured at cluster creation.
- **EKS Control Plane Logs** (api, audit, authenticator, controllerManager, scheduler) → CloudWatch → central log archive.
- **CMK-encrypted secrets** with the cluster's PHI CMK (per [../data-security/kms-strategy.md](../data-security/kms-strategy.md)).
- **Bottlerocket** as the node OS.
- **Managed Node Groups** with automatic AMI updates.
- **Auto-upgrade** for patch versions; controlled upgrade for minor versions (quarterly review).
- **IMDSv2 required** on all nodes; hop limit = 1 for host-network pods.

### Per-cluster baseline policy

In addition to the cluster config, every Meridian cluster has:

- **Pod Security Admission** enforcing `restricted` profile on workload namespaces.
- **Calico CNI** with default-deny NetworkPolicies at namespace level (per [network-policies.md](./network-policies.md)).
- **Gatekeeper** with the Meridian-standard constraint library (per [admission-control.md](./admission-control.md)).
- **Cosign** signature verification at admission (per [image-supply-chain.md](./image-supply-chain.md)).
- **Falco** as the runtime-detection DaemonSet (per [runtime-security.md](./), coming).
- **Istio** service mesh with mTLS-by-default (per [service-mesh-security.md](./), coming).

### Cluster lifecycle discipline

- Cluster Kubernetes version reviewed monthly.
- Upgrade windows planned 30 days in advance; staged across environments (dev → staging → prod).
- Cluster deletion protection enabled.
- Cluster backup via Velero, daily, to a separate account.

### The Care Coordinator workload deployment

A Care Coordinator workload pod:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: care-coordinator-supervisor-sa
  namespace: care-coordinator
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/care-coordinator-supervisor-app-role
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: care-coordinator-supervisor
  namespace: care-coordinator
spec:
  template:
    spec:
      serviceAccountName: care-coordinator-supervisor-sa
      containers:
      - name: app
        image: meridian-registry.local/care-coordinator-supervisor:v2.4.1@sha256:abc123...
        # ... pod security context per pod-security.md
```

The pod gets cloud credentials via IRSA; no Kubernetes Secret for cloud credentials needed.

### Findings opened during the EKS baseline audit

- **K8S-BASE-001** (some clusters had public control-plane endpoint without CIDR restriction). Closed by private-only with bastion access.
- **K8S-BASE-002** (audit logs were enabled but not shipped to the central archive). Closed by CloudWatch → central log shipper.
- **K8S-BASE-003** (etcd encryption was using AWS-managed key, not Meridian's CMK). Closed by migration to PHI CMK.
- **K8S-BASE-004** (one cluster was on a Kubernetes version 4 months past end-of-support). Closed by emergency upgrade; quarterly review added.
- **K8S-BASE-005** (IMDSv2 was not required on legacy node groups). Closed by node-group launch template update.
- **K8S-BASE-006** (a few pods were using the `default` service account with no IRSA annotation). Closed by per-pod service-account migration.

---

## Anti-patterns

### 1. The public-endpoint production cluster

The Kubernetes API server is reachable from the internet with no CIDR restriction. Compromise of any kubeconfig is direct cluster access.

The fix: private endpoint; bastion access for engineers; restricted public only as a transition or with documented justification.

### 2. The IAM-credentials-mounted-as-secrets pattern

Pods get cloud credentials via Kubernetes Secrets containing access keys. The pattern predates workload identity; modern clusters should not have it.

The fix: migrate to IRSA / Workload Identity / Azure AD Workload Identity. The migration is per-application; the result is no static credentials in etcd.

### 3. The provider-managed-key etcd

Etcd is encrypted with the cloud's provider-managed key. Compliance audit asks "who controls the encryption key" and the answer is "the cloud provider."

The fix: customer-managed key (CMK / CMEK) for etcd encryption.

### 4. The unshipped audit log

Audit logging is enabled. Logs live in CloudWatch / Log Analytics / Cloud Logging. No central archive; no SIEM consumption.

The fix: ship to central log archive; build SIEM detection rules per [Audit logging](#audit-logging).

### 5. The frozen Kubernetes version

The cluster was created at Kubernetes 1.24. The team has not upgraded. The version is unsupported; new features are unavailable; CVEs accumulate.

The fix: upgrade cadence; auto-upgrade for patch; planned upgrade for minor; track supported versions.

### 6. The shared node-IAM-role exposure

Pods can reach the node's IMDS endpoint; pods can use the node's IAM role. The role is broader than any individual pod needs; lateral attacks exploit this.

The fix: IMDSv2 required; hop limit = 1 for host-network pods; non-IRSA pods cannot reach IMDS.

### 7. The hand-managed node OS

Self-managed EC2 / VM nodes with manually-installed kubelet; patching is a manual quarterly project; OS hardening drifts.

The fix: managed node groups / managed node pools / Autopilot. Provider manages the OS lifecycle.

### 8. The cluster-without-disaster-recovery

The cluster's etcd is on a single AZ; etcd corruption or accidental cluster deletion is unrecoverable.

The fix: managed services replicate etcd across AZs by default; deletion protection enabled; Velero or equivalent for application-state backup.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| K8S-BASE-001 | Cluster control-plane endpoint public without CIDR restriction | High | Migrate to private endpoint; bastion access for engineers | Platform Eng + Security Eng |
| K8S-BASE-002 | Audit logs enabled but not shipped to central archive | High | Configure log shipping per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md); SIEM consumption | Platform Eng + Security Eng |
| K8S-BASE-003 | Etcd encryption uses provider-managed key | High | Migrate to customer-managed key (CMK / CMEK); align with [../data-security/kms-strategy.md](../data-security/kms-strategy.md) | Platform Eng + Security Eng |
| K8S-BASE-004 | Cluster running on unsupported Kubernetes version | High | Upgrade to a supported version; establish upgrade cadence | Platform Eng + SRE |
| K8S-BASE-005 | IMDSv2 not required on EKS node groups | High | Update launch templates; require IMDSv2; hop limit = 1 for host-network pods | Platform Eng + Security Eng |
| K8S-BASE-006 | Pods using `default` service account; no per-pod IAM scoping | Medium | Per-pod service accounts; IRSA / Workload Identity mapping | Platform Eng + Workload Owner |
| K8S-BASE-007 | Workload identity not enabled; static cloud credentials in Kubernetes Secrets | High | Migrate to IRSA / Workload Identity / Azure AD Workload Identity | Platform Eng + Workload Owner |
| K8S-BASE-008 | Audit policy too coarse (all-metadata) or too verbose (all-RequestResponse) | Medium | Tiered policy per [Audit logging](#audit-logging); high-verbosity on high-risk operations | Security Eng |
| K8S-BASE-009 | No automatic patching on managed node groups | Medium | Enable automatic AMI updates (EKS) / auto-upgrade channels (AKS) / auto-upgrade (GKE) | Platform Eng + SRE |
| K8S-BASE-010 | Node OS is full Linux (Ubuntu) not minimal (Bottlerocket / Container-Optimized OS / Azure Linux) | Low | Consider minimal OS for new node groups; security-sensitive workloads benefit | Platform Eng |
| K8S-BASE-011 | Cluster deletion protection not enabled | Medium | Enable deletion protection on production clusters | Platform Eng + SRE |
| K8S-BASE-012 | No backup pattern for cluster state (etcd, application state) | Medium | Velero (or equivalent) daily backup to separate account; tested quarterly | SRE + Platform Eng |
| K8S-BASE-013 | Upgrade cadence undocumented; clusters drift to unsupported versions | Medium | Quarterly version review; upgrade windows scheduled in advance | Platform Eng + SRE |
| K8S-BASE-014 | SIEM detection rules absent on Kubernetes audit logs | High | Build rules per [Audit logging](#audit-logging) — pod exec, secret reads, RBAC changes, mass deletions | Security Eng + SOC |
| K8S-BASE-015 | Cluster identity provider (OIDC) not federated correctly; subject scoping missing | High | Trust-policy conditions on `oidc-issuer:sub` per service-account; per-app trust scoping | Security Eng + IAM Eng |
| K8S-BASE-016 | Node IAM role over-privileged; pods inheriting node identity get broad permissions | High | Tighten node role; IRSA for pod identity; no fallback to node role | Platform Eng + Security Eng |
| K8S-BASE-017 | Cluster API server reachable from anywhere via public endpoint with no firewall | High | Restrict to specific CIDRs or migrate to private | Platform Eng + Security Eng |
| K8S-BASE-018 | Cluster lacks runtime detection (Falco / Tetragon / EDR DaemonSet) | High | Deploy runtime-detection DaemonSet; integrate with SOC | Security Eng + Platform Eng |

---

## What this document is not

- **A Kubernetes administration guide.** Cluster operations, autoscaling design, observability beyond security telemetry are covered in vendor / upstream documentation.
- **A complete CNI / network-plugin reference.** Calico / Cilium / native CNI patterns appear in [network-policies.md](./network-policies.md).
- **A complete pod-security reference.** Pod Security Admission and the pod-level security context live in [pod-security.md](./pod-security.md).
- **A complete service-mesh tutorial.** Istio / Linkerd patterns appear in [service-mesh-security.md](./), coming.
