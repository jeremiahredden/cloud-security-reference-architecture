# Pod Security

A practitioner's reference for Pod Security Admission (PSA) and the pod-level security context — the `restricted` / `baseline` / `privileged` profiles, the PodSecurityPolicy-to-PSA migration playbook, namespace labeling strategy, exemption discipline, and the privileged-pod inventory pattern every multi-tenant platform should run quarterly. The patterns here are about preventing the in-cluster equivalent of "everyone is root" — pods that can mount host paths, run as root, use host networking, or escape their security boundary.

This document picks up where [eks-aks-gke-baselines.md](./eks-aks-gke-baselines.md) leaves off. The cluster baseline is settled; the question is the pod-level enforcement. Pod Security Admission is the replacement for the deprecated PodSecurityPolicy; the migration has been done badly in many environments because it was treated as a like-for-like rather than as an opportunity to tighten.

For the broader admission control around pods (signed-image policies, custom organizational constraints), see [admission-control.md](./admission-control.md). For the network-layer pod isolation, see [network-policies.md](./network-policies.md).

---

## When to read this document

**If you are running Kubernetes 1.25 or later** — PSP is removed; you are on Pod Security Admission whether you intended to be or not. Read top to bottom.

**If you migrated from PSP to PSA recently** — start with [The migration anti-patterns](#the-migration-anti-patterns). Many migrations end up at a weaker posture than the original PSP intended.

**If you operate a multi-tenant cluster** — start with [The multi-tenant baseline](#the-multi-tenant-baseline). The non-negotiable: every workload namespace has the `restricted` profile.

**If you are auditing pod-security posture** — start with [Findings checklist](#findings-checklist). The common findings (no PSA enforcement, exemptions without expiration, privileged pods without documented justification) are universal.

---

## The PSP-to-PSA transition

PodSecurityPolicy (PSP) was deprecated in Kubernetes 1.21 and removed in 1.25. **Pod Security Admission (PSA)** is the replacement.

### What changed

- **PSP** was a Kubernetes resource that engineers configured per-cluster; many fine-grained controls; complex authorization model (Pod Security Policy bindings via RBAC).
- **PSA** is a built-in admission controller that enforces three standard profiles (`privileged`, `baseline`, `restricted`) via namespace labels; simpler model.

PSA is less granular than PSP. The community decision: simplicity beats granularity; specific customizations should be done via OPA/Gatekeeper or Kyverno ([admission-control.md](./admission-control.md)), not by extending the built-in mechanism.

### The three PSA profiles

| Profile | Allows | Use case |
| --- | --- | --- |
| **privileged** | Everything. Host network, host paths, privileged containers, root user, all capabilities. | Cluster-system workloads only (CNI, log collectors, admission webhooks themselves). |
| **baseline** | Most pod operations except known-risky (no host network, no host paths, no privileged, no CAP_SYS_ADMIN). Pods can still run as root. | Migration / transition profile; legacy workloads that need accommodation. |
| **restricted** | Tight. Must run as non-root, must drop all capabilities, must use RuntimeDefault seccomp profile, no privilege escalation. | The default for all workload namespaces. |

The recommendation: **`restricted` is the right default for all workload namespaces**. `baseline` is a transitional accommodation for legacy workloads; `privileged` is for specific cluster-system namespaces only.

### The PSP-to-PSA migration's common failure

The pattern: a team had PSP configured with custom policies (e.g., specific allowed host paths, specific capabilities). Migration to PSA defaults to `baseline` "to not break anything." Result: pods that PSP would have blocked now pass; the cluster's posture is weaker than before migration.

The fix: PSA migration is an opportunity to revisit. Workloads that need exceptions get explicit exemptions (in their own namespaces, with documented justification). Other workloads get `restricted`.

References:
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [PSP-to-PSA migration](https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/)

---

## Namespace labeling strategy

PSA enforces profiles via namespace labels. The labels:

- `pod-security.kubernetes.io/enforce: <profile>` — reject non-conforming pods.
- `pod-security.kubernetes.io/audit: <profile>` — log non-conforming pods but allow.
- `pod-security.kubernetes.io/warn: <profile>` — warn the user but allow.

And optional version pinning:

- `pod-security.kubernetes.io/enforce-version: v1.27` (otherwise uses latest).

### The standard labeling pattern

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: care-coordinator
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

All three modes (enforce, audit, warn) set to the same profile. Engineers see warnings; admission rejects violations; audit logs capture detail.

### The dual-mode rollout pattern

For an existing namespace that's not yet PSA-compliant:

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/audit: restricted   # log violations
    pod-security.kubernetes.io/warn: restricted    # warn users
    # no enforce yet
```

The audit log captures which pods would fail under `restricted`. The team fixes those pods. Once clean:

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Enforcement kicks in; the work to get clean was done in advance.

### Cluster-wide default vs per-namespace

PSA has a cluster-wide default profile (via admission controller config). The pattern:

- **Cluster default: `restricted`** — namespaces without explicit labels get the tight default.
- **System namespaces (`kube-system`, `kube-public`, `kube-node-lease`): `privileged`** — these need it; explicit labeling.
- **Workload namespaces: `restricted`** — explicit labels via the namespace creation template.

Some teams set cluster default to `baseline` to avoid breaking unlabeled namespaces. The pattern is a trap; new namespaces created without labels silently inherit the weaker default.

---

## The `restricted` profile in detail

What `restricted` actually requires.

### Pod-level requirements

- **`runAsNonRoot: true`** — pod must specify a non-root user.
- **`runAsUser` not 0** — explicit user ID, non-zero.
- **`seccompProfile.type: RuntimeDefault`** — the runtime's default seccomp profile (or `Localhost`).
- **No `hostNetwork`, `hostIPC`, `hostPID`** — pod cannot share host namespaces.
- **No host-path volumes** — pods can use only emptyDir, configMap, secret, downwardAPI, projected, csi, persistentVolumeClaim, ephemeral.

### Container-level requirements

- **`allowPrivilegeEscalation: false`** — `setuid` and similar capabilities defeated.
- **`capabilities.drop: ["ALL"]`** — start from zero; explicit adds if needed.
- **`capabilities.add`** — only specific allowed capabilities (`NET_BIND_SERVICE` is acceptable; `SYS_ADMIN` is not).
- **`runAsNonRoot: true`** at container level (overrides pod-level).
- **`readOnlyRootFilesystem: true`** (recommended but not strictly required by PSA; commonly added via admission policy).

### A `restricted`-compliant pod manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: care-coordinator-supervisor
  namespace: care-coordinator
spec:
  template:
    spec:
      serviceAccountName: care-coordinator-supervisor-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: meridian-registry.local/care-coordinator-supervisor:v2.4.1@sha256:abc123
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
          runAsNonRoot: true
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: cache
          mountPath: /tmp
      volumes:
      - name: cache
        emptyDir: {}
```

This pod satisfies `restricted`. It runs as non-root, has no privileges, drops all capabilities, uses RuntimeDefault seccomp, has a read-only root filesystem with `/tmp` as a writable emptyDir.

### What `restricted` denies

A pod that:

- Runs as root.
- Mounts a host path.
- Adds privileged capabilities.
- Uses `hostNetwork`.
- Has `allowPrivilegeEscalation: true`.
- Doesn't specify a seccomp profile.

is rejected at admission.

### The fixing-an-existing-workload pattern

Most existing workloads aren't `restricted`-compliant. The fix sequence per workload:

1. **Identify why it isn't compliant.** PSA's audit mode reports the specific violations.
2. **Fix the security context.** Add the required fields to the pod template.
3. **Test in non-prod.** Verify the workload still works (some apps assume root or specific capabilities).
4. **Roll out.** Apply to staging, then prod.
5. **Enable enforce.** After all workloads are compliant.

For workloads that genuinely need exceptions (some legacy software is hard-coded to require root or specific capabilities): see [Exemption discipline](#exemption-discipline).

---

## The multi-tenant baseline

For multi-tenant clusters (multiple application teams sharing a cluster), the discipline is stricter than single-tenant.

### Per-namespace `restricted`

Every workload namespace gets `restricted`. No exceptions without documented review.

### Namespace creation automation

Namespaces are created by automation (a cluster-platform-team API or controller); never hand-created with `kubectl create namespace`. The automation:

- Applies the standard labels (PSA, network-policy isolation, owner annotations).
- Sets resource quotas and LimitRanges per the tenant's tier.
- Creates the tenant's default RBAC bindings.
- Provisions per-tenant secrets and service accounts.

The pattern: a tenant doesn't get a namespace by `kubectl`; they request it through the platform's API; the platform applies the baseline.

### The privileged-pod inventory

Quarterly audit:

- List every pod with `securityContext.privileged: true`.
- List every pod with host-path mounts.
- List every pod with `hostNetwork`, `hostPID`, `hostIPC`.
- List every namespace not at `restricted` profile.
- For each: confirm the exception is still justified; renew or remove.

Tools: `kubectl get pods -A -o json | jq` queries; or use Polaris, Kubescape, or Datree for managed inventory.

### Tenant isolation beyond PSA

PSA is one layer. The full multi-tenant isolation:

- **PSA `restricted`** at the namespace level.
- **NetworkPolicy default-deny** at the namespace level (per [network-policies.md](./network-policies.md)).
- **Resource quotas and LimitRanges** to bound per-tenant resource use.
- **RBAC** scoped per-tenant; tenants cannot list resources outside their namespace.
- **Service mesh authorization** (per [service-mesh-security.md](./), coming) for application-layer isolation.

PSA alone is necessary but insufficient for multi-tenant; it's one of several layers.

---

## Exemption discipline

Some workloads legitimately need privileges that `restricted` denies. The discipline for granting exemptions.

### Common legitimate exemptions

- **CNI plugins** (Calico, Cilium, AWS VPC CNI agents) — need host network access for pod networking.
- **Log collectors** (Fluentd, Vector, Datadog Agent) — need host paths for `/var/log/containers`.
- **Monitoring agents** (Prometheus node exporter, Datadog Agent) — need host paths for `/proc`, `/sys`.
- **Runtime detection** (Falco, Tetragon) — need privileged mode for eBPF and kernel access.
- **Storage CSI drivers** — need privileged mode for volume mounting.
- **Service mesh data planes** (Istio proxy, Linkerd2 proxy) — need NET_ADMIN capability.

These are all cluster-platform workloads. They run in cluster-platform namespaces (`kube-system`, `istio-system`, `falco`, etc.).

### Exemption mechanism

Exemptions are applied at the namespace level:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: falco
  labels:
    pod-security.kubernetes.io/enforce: privileged  # Falco needs privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: baseline       # warn on baseline violations beyond Falco
```

Or via PSA-controller-level exemptions:

```yaml
# admission-controller config
exemptions:
  usernames: []
  runtimeClasses: []
  namespaces: ["falco", "calico-system", "istio-system"]
```

### Exemption discipline checklist

For each exemption:

- **Documented justification:** which capability is needed, why.
- **Reviewed by security:** before the exemption is granted.
- **Expiration date:** quarterly re-review at minimum.
- **Scope:** narrowest applicable (exempt the namespace, not the cluster; exempt the specific pod, not the namespace if PodSecurityPolicy via admission control is available).
- **Audit:** the exemption appears in the privileged-pod inventory.

### The application-team-asking-for-exemption pattern

A common scenario: an application team asks for an exemption because their workload "needs to run as root."

The response:

1. **Investigate why.** Often the answer is "the Docker image was built with root as default; the application doesn't actually need root."
2. **Fix the image.** Add a `USER 1000` directive to the Dockerfile.
3. **Test.** Verify the application works as non-root.
4. **Reject the exemption.** The fix was straightforward; the exemption is unnecessary.

The pattern: exemption requests are an opportunity to fix the underlying issue, not a procedural rubber-stamp.

---

## The migration anti-patterns

The common ways PSP-to-PSA migration goes wrong.

### 1. The "baseline everywhere" migration

The team migrates from PSP (with custom tight policies) to PSA `baseline` to avoid breakage. The new posture is weaker than the old.

The fix: migrate to `restricted` (the equivalent of typical PSP). Workloads that don't fit get explicit exemptions, not a weaker default.

### 2. The cluster-default-too-loose

The cluster's default PSA profile is `privileged`. New namespaces created without labels silently inherit `privileged`. Engineers create namespaces and never think to label them.

The fix: cluster default `restricted`; system namespaces explicitly labeled `privileged`.

### 3. The forever-audit-mode

The team set up audit and warn modes; never moved to enforce. Pods that would fail `restricted` continue to run; the posture is theoretical.

The fix: explicit timeline for moving from audit to enforce; review audit logs; fix violators; flip to enforce.

### 4. The exemption-creep

Exemptions were granted years ago; they're still in place; nobody re-reviews. New workloads keep getting added to exempted namespaces.

The fix: quarterly exemption re-review; expiration dates; scope limited to specific pods where possible.

### 5. The hand-edited namespace

The platform-team's namespace-creation automation applies labels. An engineer creates a namespace by hand without the labels; the namespace gets the cluster default; if the default is wrong, the namespace is unenforced.

The fix: SCP / OPA Gatekeeper policy that rejects namespace creation without the standard labels.

### 6. The privileged-by-default service mesh

Some service mesh installations request `privileged` for the entire `istio-system` namespace. The workload namespaces hosting Istio sidecars may then accept privileged pods inadvertently.

The fix: workload namespaces stay `restricted`; Istio sidecars use NET_ADMIN capability (allowed within `baseline` with specific config) rather than full privileged. Modern Istio supports this.

### 7. The migration without security-context updates

The cluster moved to PSA enforce mode. Workload pod templates were not updated; pods now fail to deploy. The team rolls back the PSA enforcement instead of fixing the pods.

The fix: complete the workload-fix sequence before flipping to enforce; the discomfort of the failed deploys is the forcing function, but pre-emptive fixing is cheaper.

### 8. The audit-log-not-consumed

PSA audit logs go to the audit log; nobody reviews them. Violations accumulate; the team is unaware that pods are bypassing `restricted` (because audit mode allows them).

The fix: SIEM rule on PSA audit events; alerts on consistent violation patterns; the audit signal drives the enforce-mode rollout.

---

## The privileged-pod inventory pattern

Operational discipline: every quarter, run a cluster-wide privileged-pod scan and review.

### What to scan for

```bash
# Pods with privileged: true
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"'

# Pods with hostNetwork
kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork == true) | "\(.metadata.namespace)/\(.metadata.name)"'

# Pods with host path volumes
kubectl get pods -A -o json | jq '.items[] | select(.spec.volumes[]?.hostPath != null) | "\(.metadata.namespace)/\(.metadata.name)"'

# Pods running as root
kubectl get pods -A -o json | jq '.items[] | select(.spec.securityContext.runAsUser == 0 or (.spec.containers[] | .securityContext.runAsUser == 0)) | "\(.metadata.namespace)/\(.metadata.name)"'

# Namespaces not at restricted
kubectl get ns -o json | jq '.items[] | select(.metadata.labels."pod-security.kubernetes.io/enforce" != "restricted") | .metadata.name'
```

### The review

For each pod / namespace in the inventory:

- Identify the owner.
- Verify the exemption is still justified.
- Confirm the documentation matches the actual configuration.
- For unexpected entries: investigate; remediate.

### Tools

Manual `kubectl + jq` works for small clusters. For larger:

- **Polaris** (Fairwinds) — opinionated configuration scanner.
- **Kubescape** — security scanner with Pod Security and benchmark coverage.
- **Datree** — admission-control + scanning.
- **Trivy** (besides image scanning) has Kubernetes-config scanning.

These produce reports; consume in CSPM / dashboards.

---

## Worked example: Meridian Health's Pod Security posture

Meridian's EKS clusters enforce `restricted` profile by default; workload namespaces get the standard labels via automation; exemptions are restricted to cluster-platform namespaces.

### Cluster default

PSA's admission controller config sets cluster default to `restricted`. Any namespace created without explicit labels inherits the tight default.

### System namespaces

- `kube-system`: `privileged` (required for CNI, kube-proxy, etc.).
- `falco`: `privileged` (eBPF-based runtime detection requires it).
- `calico-system`: `privileged` (CNI agent).
- `istio-system`: `baseline` (Istio sidecars use NET_ADMIN; control plane fits within `baseline`).
- `datadog`: `privileged` (Datadog Agent needs host paths and capabilities).

Each is labeled explicitly; the labels include a comment in the IaC documenting why.

### Workload namespaces

Every Meridian workload namespace gets:

```yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/audit: restricted
  pod-security.kubernetes.io/warn: restricted
```

Created via the platform's namespace-vending API. SCP / OPA Gatekeeper rejects hand-created namespaces lacking these labels.

### Care Coordinator pod template

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: care-coordinator-supervisor
  namespace: care-coordinator
spec:
  template:
    spec:
      serviceAccountName: care-coordinator-supervisor-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: meridian-registry.local/care-coordinator-supervisor:v2.4.1@sha256:abc123
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
          runAsNonRoot: true
```

### Exemption process

When an application team requests an exemption, the workflow:

1. Submit a request with: which pod / namespace; which capability needed; business justification; alternative considered.
2. Security team reviews; either approves with conditions or rejects with alternative suggestions.
3. If approved: documented exemption with expiration; namespace label updated.
4. Quarterly re-review.

In practice: ~80% of exemption requests are resolved by suggesting alternatives (image fixes, capability narrowing) without granting the exemption. ~20% result in exemption with documented justification.

### Migration story

Meridian's clusters predated PSA (originally on PSP). The migration in 2024:

- Sprint 1: enable PSA in audit mode at `restricted`; collect audit data.
- Sprint 2: review violations; categorize by team and workload.
- Sprints 3–6: each application team fixes violations in their workloads.
- Sprint 7: flip to enforce mode on dev clusters.
- Sprint 8: flip to enforce mode on staging.
- Sprint 9: flip to enforce mode on production.

Result: ~150 violation patterns at the start; ~10 legitimate exemptions at the end. The rest were fixed at the pod-template level.

### Findings opened during the pod-security audit

- **POD-001** (some namespaces had no PSA labels; inherited cluster default which was `privileged` at the time). Closed by automation enforcing labels at namespace creation.
- **POD-002** (cluster default was `privileged`; new namespaces inherited weak posture). Closed by setting cluster default to `restricted`.
- **POD-003** (workload pods ran as root because base images defaulted to root). Closed by image-team adding `USER 1000` to base images; downstream image rebuilds.
- **POD-004** (Falco namespace was `privileged` but also hosted non-Falco pods that didn't need it). Closed by separating namespaces; Falco-only stays `privileged`.
- **POD-005** (quarterly exemption review hadn't happened in 18 months). Closed by scheduled quarterly reviews; expired exemptions remediated.
- **POD-006** (audit mode was enabled but no SIEM consumption of PSA audit events). Closed by ingest into SIEM with alerting on violation patterns.

---

## Anti-patterns

### 1. The `baseline` default for workload namespaces

The team's rollout sets workload namespaces to `baseline` because "we don't want to break things." Pods can run as root, mount projected volumes, do many things `restricted` would block.

The fix: `restricted` is the right default. Fix the workloads; don't weaken the policy.

### 2. The cluster-wide `privileged` default

PSA's cluster default is `privileged`. New namespaces created without explicit labels accept any pod.

The fix: cluster default `restricted`; explicit `privileged` labels on system namespaces only.

### 3. The audit-only-forever rollout

The team set up audit mode; production enforcement never happens. The audit signal is treated as informational, not actionable.

The fix: planned cutover date; pre-cutover violation cleanup; enforce mode active.

### 4. The exemption-by-precedent

An exemption was granted to namespace A two years ago. Namespace B now needs the same exemption "because A has it." The exemption count grows without per-case review.

The fix: each exemption is per-namespace and per-justification; no cross-namespace precedent.

### 5. The hand-namespace bypass

The platform team has namespace automation. An engineer creates a namespace via `kubectl create namespace` to bypass. The namespace is unlabeled; the cluster default applies.

The fix: SCP / Gatekeeper policy rejects unlabeled namespace creation; admin-only override.

### 6. The capability-creep

A pod needed `NET_BIND_SERVICE` (to bind to port 80). The team added `["NET_BIND_SERVICE", "NET_ADMIN", "SYS_ADMIN"]` "to be safe." The pod has unnecessary capabilities; PSA's tight defaults are defeated by the over-broad add.

The fix: add only the specific capability needed; verify the application doesn't need the others.

### 7. The seccomp-profile-omission

The pod manifest doesn't specify `seccompProfile`. Older Kubernetes versions defaulted to `Unconfined`; `restricted` requires `RuntimeDefault`. Pods fail at admission.

The fix: pod template includes `seccompProfile.type: RuntimeDefault`; cluster runtime defaults aligned.

### 8. The readOnlyRootFilesystem disabled

The application writes to `/tmp` or `/var/cache`. The team disables `readOnlyRootFilesystem` instead of mounting an `emptyDir` for the writable paths.

The fix: keep `readOnlyRootFilesystem: true`; mount `emptyDir` for needed writable paths; the application is no less functional and the security posture is better.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| POD-001 | Namespaces have no PSA labels; inherit cluster default | High | Namespace-vending automation sets standard labels; Gatekeeper rejects hand-created namespaces without labels | Platform Eng + Cluster Owner |
| POD-002 | Cluster default PSA profile is `privileged` or `baseline` instead of `restricted` | High | Set cluster default to `restricted`; system namespaces explicitly labeled `privileged` | Platform Eng + Security Eng |
| POD-003 | Workload pods run as root | High | Fix base images (`USER 1000`); pod template `runAsNonRoot: true`; verify with audit | Workload Owner + Platform Eng |
| POD-004 | Mixed-purpose namespaces have weak PSA labels because one pod needs it | Medium | Separate namespaces; per-namespace PSA profile aligned to its workload | Platform Eng + Workload Owner |
| POD-005 | Quarterly privileged-pod inventory not run | Medium | Establish quarterly inventory; exemption re-review | Security Eng |
| POD-006 | PSA audit-event SIEM consumption absent | Medium | Audit logs ingested into SIEM; alert on violation patterns | Security Eng + SOC |
| POD-007 | Audit mode enabled indefinitely; no enforce-mode timeline | High | Planned cutover; clean violations; flip to enforce | Platform Eng + Security Eng |
| POD-008 | Exemptions lack documented justification, expiration, or scope | Medium | Exemption metadata; quarterly review; expiration dates | Security Eng + Platform Eng |
| POD-009 | Pods use `securityContext.privileged: true` without documented requirement | High | Audit each; legitimate (CNI, Falco) annotated; illegitimate fixed | Security Eng + Platform Eng |
| POD-010 | Pods mount hostPath volumes for non-system purposes | High | Audit each; replace with PVC, emptyDir, or ConfigMap where possible | Workload Owner + Platform Eng |
| POD-011 | Pods over-add capabilities (e.g., SYS_ADMIN for binding to port 80) | High | Add only required capability; usually NET_BIND_SERVICE alone | Workload Owner |
| POD-012 | seccomp profile not specified; pods reject under `restricted` | High | Pod template `seccompProfile.type: RuntimeDefault`; runtime defaults aligned | Platform Eng + Workload Owner |
| POD-013 | `readOnlyRootFilesystem: false`; writable root for convenience | Medium | Enable read-only; mount emptyDir for writable paths | Workload Owner |
| POD-014 | `allowPrivilegeEscalation: true`; PSA `restricted` rejected silently | Medium | Set to false in pod template; investigate apps that genuinely need it | Workload Owner |
| POD-015 | Namespace creation outside the platform's automation; PSA labels missing | Medium | Gatekeeper or OPA policy rejects hand-creation without labels | Platform Eng |
| POD-016 | Service mesh requests `privileged` for sidecars when narrower capabilities suffice | Low | Configure mesh for NET_ADMIN capability only; works within `baseline` | Platform Eng + Mesh Owner |
| POD-017 | Workload exemption requests granted without review of alternatives | Medium | Review process: investigate underlying need; suggest alternatives; reject if alternatives work | Security Eng |
| POD-018 | Image registry doesn't enforce non-root images; root-default images accumulate | Medium | Registry policy: reject images without `USER` directive; CI enforces | Image Owner + DevOps |

---

## What this document is not

- **A Pod Security Standards specification.** The Kubernetes upstream documentation has the authoritative profile definitions.
- **A pod security context tutorial.** General Kubernetes documentation covers the security context fields; this document focuses on the platform-level enforcement.
- **A complete admission-control reference.** PSA is one admission controller; the broader admission patterns (OPA Gatekeeper, Kyverno, CEL) live in [admission-control.md](./admission-control.md).
- **A container-image hardening guide.** Image-level patterns (non-root user, minimal base images) belong in [image-supply-chain.md](./image-supply-chain.md).
