# Network Policies

A practitioner's reference for pod-level network segmentation in Kubernetes — native Kubernetes NetworkPolicy, Calico, Cilium, and Cilium's CiliumNetworkPolicy with FQDN-based egress and L7 enforcement. The patterns here cover the default-deny baseline (non-negotiable for any multi-tenant cluster), egress policies as a hard requirement, the "two NetworkPolicies per namespace minimum" baseline, and the migration sequence from an unpoliced cluster to a default-deny posture.

This document closes the network-layer gap in Kubernetes security. The cluster baseline ([eks-aks-gke-baselines.md](./eks-aks-gke-baselines.md)) and pod security ([pod-security.md](./pod-security.md)) handle the pod's *configuration*; NetworkPolicy handles the pod's *connectivity*. Without NetworkPolicy, a compromised pod can reach any other pod in the cluster on any port — the same lateral movement problem that flat networks have in the physical world.

For the in-VPC security groups that sit underneath, see [../network-security/segmentation-patterns.md](../network-security/segmentation-patterns.md). For the service-mesh-layer authorization that sits on top, see [service-mesh-security.md](./), coming.

---

## When to read this document

**If your Kubernetes cluster has no NetworkPolicies** — read top to bottom. This is the single highest-leverage change you can make to a cluster's security posture.

**If you have some NetworkPolicies but no default-deny** — start with [The default-deny baseline](#the-default-deny-baseline). Without default-deny, individual policies are exception lists in a permissive world; the security model is inverted.

**If you have Cilium and aren't using FQDN egress or L7 policy** — start with [Cilium-specific patterns](#cilium-specific-patterns). The capabilities are substantial; underused in most environments.

**If you are migrating from a permissive cluster to default-deny** — start with [The migration sequence](#the-migration-sequence). The migration is bounded but real; this is the runbook.

---

## Why NetworkPolicy matters

The default Kubernetes network model: every pod can reach every other pod on every port. This is the equivalent of every server in a datacenter being on the same broadcast domain with no firewall between them.

In production this means:

- A compromised pod in namespace A can reach pods in namespace B without restriction.
- A vulnerable application's lateral movement is unbounded.
- Multi-tenant workloads cannot be isolated at the network layer.
- Data exfiltration via pod-to-pod connections is invisible to network security tools watching the cluster perimeter.

NetworkPolicy fixes this. With default-deny + explicit allows:

- Compromised pods can reach only their pre-authorized targets.
- Lateral movement requires the attacker to compromise specifically-allowed paths.
- Multi-tenant isolation is enforced at the network layer.
- Egress filtering provides equivalent defense to VPC egress control but at pod granularity.

The cost: NetworkPolicy is an upfront investment to design and apply. The cost is bounded; the security improvement is structural.

---

## The CNI plugin choice

NetworkPolicy enforcement requires a CNI plugin that supports it. The choice:

| CNI | NetworkPolicy support | Notes |
| --- | --- | --- |
| **Native Kubernetes NetworkPolicy** | Yes (depends on CNI) | Built-in resource type; enforcement requires CNI support. |
| **Calico** | Yes (native + Calico-specific) | Most mature; widely deployed; supports global policies. |
| **Cilium** | Yes (native + Cilium-specific) | eBPF-based; FQDN egress, L7 policy, identity-based; rich feature set. |
| **AWS VPC CNI** | Limited (use NetworkPolicy with VPC-CNI in newer versions; or Calico on top) | Native NetworkPolicy support added in 2024; older deployments need Calico overlay. |
| **Azure CNI** | Yes (Azure NetworkPolicy or Calico) | Two options; Calico is more featureful. |
| **GKE Cloud-managed** | Yes (built-in NetworkPolicy or Dataplane V2 with Cilium) | GKE Dataplane V2 uses Cilium for richer L7/FQDN support. |

The recommendation: **Cilium for new clusters** that want the richer features (FQDN egress, L7 policy, identity-based). **Calico** for mature deployments that already use it. **Native NetworkPolicy** is sufficient for basic L3/L4 segmentation when the CNI supports it.

---

## Native Kubernetes NetworkPolicy

The built-in primitive. Supports L3/L4 (ingress/egress on IP and port).

### Basic structure

A NetworkPolicy resource:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: care-coordinator-app-policy
  namespace: care-coordinator
spec:
  podSelector:
    matchLabels:
      app: care-coordinator-supervisor
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: care-coordinator-ingress
      ports:
        - port: 8443
          protocol: TCP
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: care-coordinator-clinical-knowledge
      ports:
        - port: 8443
          protocol: TCP
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```

The policy:

- Applies to pods labeled `app: care-coordinator-supervisor`.
- Allows ingress from pods labeled `app: care-coordinator-ingress` on TCP 8443.
- Allows egress to pods labeled `app: care-coordinator-clinical-knowledge` on TCP 8443.
- Allows egress to kube-dns for DNS resolution.
- Denies everything else (by default, once `policyTypes` includes Ingress / Egress).

### The default-deny pattern

A namespace-level default-deny policy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: care-coordinator
spec:
  podSelector: {}        # matches all pods
  policyTypes:
    - Ingress
    - Egress
```

Empty `podSelector` matches all pods in the namespace; `policyTypes` listing Ingress and Egress without any `ingress` / `egress` rules means *no* traffic in or out is allowed. Subsequent more-specific NetworkPolicies layer permissions on top.

### Allow DNS specifically

A common addition: every pod needs DNS. After default-deny, you must explicitly allow DNS:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: care-coordinator
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
```

This pattern is common enough that some teams include it in their namespace template.

### Selector limitations

Native NetworkPolicy selectors are label-based. Limitations:

- **No FQDN-based rules.** Egress to `api.openai.com` requires resolving to IP, which can change.
- **No L7 rules.** Cannot restrict to specific HTTP methods or paths.
- **No identity-based rules beyond label-matching.** No "this pod's service account can call that pod's service account."

For these patterns, use Calico or Cilium.

References:
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

---

## The default-deny baseline

Non-negotiable for any production cluster.

### Per-namespace default-deny

Every workload namespace has:

1. **Default-deny ingress** policy.
2. **Default-deny egress** policy (often combined with ingress into one).
3. **Allow-DNS** policy.

These three policies are the baseline; additional NetworkPolicies layer specific allows on top.

The namespace-vending automation (per [pod-security.md](./pod-security.md)) applies these at namespace creation:

```bash
# Pseudo-code
kubectl create namespace care-coordinator \
  --labels="pod-security.kubernetes.io/enforce=restricted"
kubectl apply -f network-policies/default-deny.yaml -n care-coordinator
kubectl apply -f network-policies/allow-dns.yaml -n care-coordinator
```

### What "default-deny everywhere" means in practice

After applying default-deny:

- Pods cannot make new outbound connections without an explicit egress policy.
- Pods cannot accept new inbound connections without an explicit ingress policy.
- Existing connections (e.g., established TCP streams) are not interrupted; only new connection attempts are denied.

For an existing namespace migration: pods will start failing to make their normal connections; the team must add explicit allow policies for the connections that should work.

### The "two NetworkPolicies per namespace minimum" baseline

The minimum policy set per workload namespace:

1. **Default-deny.** All ingress and egress denied by default.
2. **Allow-DNS.** DNS resolution to kube-dns.

That's two policies. Plus per-application policies for the specific connections the application needs.

A namespace with zero NetworkPolicies = the cluster has no segmentation. A namespace with only one (e.g., an application-specific allow without default-deny) = the allow is decorative; everything else is permitted.

### The cluster-wide vs per-namespace decision

NetworkPolicies are namespace-scoped. For cluster-wide controls:

- **Calico GlobalNetworkPolicy** — applies to all pods regardless of namespace.
- **Cilium CiliumClusterwideNetworkPolicy** — same concept.

Use cases:

- **Cluster-wide egress controls** (e.g., deny pod egress to external metadata services).
- **Cluster-wide ingress isolation** (e.g., deny inbound from non-cluster sources to specific labels).

Native Kubernetes NetworkPolicy is namespace-only; per-namespace default-deny is the equivalent at cluster scale.

---

## Calico patterns

Calico's NetworkPolicy extensions add features beyond native.

### Calico GlobalNetworkPolicy

Cluster-wide policy, not bound to a namespace:

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-pod-egress-to-cloud-metadata
spec:
  selector: ""        # all pods
  types:
    - Egress
  egress:
    - action: Deny
      destination:
        nets:
          - 169.254.169.254/32   # AWS / Azure / GCP IMDS
```

This policy denies every pod from reaching the cloud's instance metadata service, regardless of namespace. The metadata service is a common attack vector (SSRF to credentials); blocking it cluster-wide is high-value.

### Calico tiers (Enterprise feature)

Policies are organized in tiers; higher-priority tiers can be evaluated before lower-priority tiers. The platform team owns the highest-priority tier (the baseline); application teams own lower tiers.

The benefit: application teams cannot override platform-baseline policies.

### Calico HostEndpoint

Calico can enforce NetworkPolicies on host endpoints (nodes themselves), not just pods. Useful for:

- Restricting node-to-node communication.
- Enforcing policies on the kubelet endpoint.

This is more specialized; reserved for clusters with specific host-isolation requirements.

References:
- [Calico NetworkPolicy](https://docs.tigera.io/calico/latest/network-policy/)
- [Calico GlobalNetworkPolicy](https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy)

---

## Cilium-specific patterns

Cilium's CiliumNetworkPolicy adds substantial capabilities beyond native.

### FQDN-based egress

The killer feature for many environments:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-egress-to-approved-saas
  namespace: care-coordinator
spec:
  endpointSelector:
    matchLabels:
      app: care-coordinator-supervisor
  egress:
    - toFQDNs:
        - matchName: "api.datadoghq.com"
        - matchPattern: "*.snyk.io"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
```

The pod can reach `api.datadoghq.com` and `*.snyk.io` over TCP 443. Cilium resolves the FQDNs and dynamically updates the policy as IPs change.

Without FQDN support: the team would need to maintain an IP allowlist that changes whenever Datadog or Snyk adds infrastructure.

### L7 HTTP policy

Cilium can enforce HTTP-method and path restrictions:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: care-coordinator-api-l7
  namespace: care-coordinator
spec:
  endpointSelector:
    matchLabels:
      app: care-coordinator-supervisor
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: care-coordinator-ingress
      toPorts:
        - ports:
            - port: "8443"
              protocol: TCP
          rules:
            http:
              - method: "GET"
                path: "/api/v1/coordinator/.*"
              - method: "POST"
                path: "/api/v1/coordinator/sessions"
```

The ingress endpoint can call GET on any `/api/v1/coordinator/*` and POST only on `/api/v1/coordinator/sessions`. Other paths or methods are denied.

This is application-layer policy at the network layer. Useful when service mesh isn't deployed but L7 controls are needed.

### Identity-based policy

Cilium uses identity (workload labels), not just IP. The benefit:

- Policies stable across pod rescheduling.
- Per-service-account policies (with appropriate label conventions).

### Cilium's policy enforcement modes

- **Default mode:** policies as written; no implicit deny.
- **Always-allow mode:** like the Kubernetes default (no policies = no restrictions).
- **Always-default-deny mode:** every endpoint has implicit default-deny; policies are explicit allows.

The always-default-deny mode is the secure-by-default option. Configure at cluster initialization.

References:
- [Cilium NetworkPolicy](https://docs.cilium.io/en/stable/security/policy/)
- [Cilium FQDN Filtering](https://docs.cilium.io/en/stable/security/policy/language/#dns-based)

---

## The egress-policy discipline

Egress is more important than ingress (per the broader thesis in [../network-security/egress-control.md](../network-security/egress-control.md)). NetworkPolicy egress matters.

### Per-pod egress allowlists

Each pod's egress is explicitly allowed:

- **Cluster-internal:** allowed pods (other tiers in the same workload, shared services).
- **Cluster-external (cloud services):** allowed FQDNs or cloud-service IP ranges (Cilium FQDN, or label-based pods that proxy).
- **Cluster-external (internet):** allowed via the egress firewall ([../network-security/egress-control.md](../network-security/egress-control.md)), not directly from pods.

The pattern: pod's egress NetworkPolicy allows specific connections; broader internet egress flows through the cluster's egress proxy / NAT / Network Firewall.

### Egress to managed services

Cloud-managed services (S3, RDS, etc.) are typically reached via VPC endpoints / Private Endpoints / PSC. The NetworkPolicy allows egress to the endpoint's IP (or, with Cilium, FQDN).

For databases on managed services (RDS, Cloud SQL, Azure SQL):

```yaml
egress:
  - to:
      - ipBlock:
          cidr: 10.20.30.40/32   # RDS endpoint IP
    ports:
      - port: 5432
        protocol: TCP
```

The IP is fixed (private endpoint); the policy is stable.

### Egress to other Kubernetes namespaces

Cross-namespace egress requires explicit policy:

```yaml
egress:
  - to:
      - namespaceSelector:
          matchLabels:
            tier: shared-services
        podSelector:
          matchLabels:
            app: vault
    ports:
      - port: 8200
        protocol: TCP
```

The pod can reach Vault in the `shared-services` namespace. Without this, cross-namespace egress is denied.

### Egress to the cluster API

A common pattern: pods that need to call the Kubernetes API server. The API server's endpoint:

- **In EKS:** the cluster's API endpoint (resolves to the EKS-managed IP).
- **In AKS / GKE:** similar; cluster-managed.

The egress policy allows TCP 443 (or 6443) to the cluster API endpoint. Often combined with a service-account-bound RBAC for the API access.

---

## The migration sequence

For an existing cluster without NetworkPolicies, the migration to default-deny.

### Phase 1: observability (1–2 weeks)

Before policy enforcement, understand the actual traffic:

- **Cilium Hubble** observes all flows; produces a flow log.
- **Calico Flow Logs** equivalent.
- **eBPF-based observability** in general.

The output: a directed graph of "which pods talk to which pods on which ports." This is the data to build policies from.

### Phase 2: per-namespace policy authoring (1–4 weeks per namespace)

For each namespace:

- **Identify expected flows** from the observability data.
- **Author NetworkPolicies** for each flow.
- **Apply in audit mode** (where supported) or in a non-prod cluster first.

### Phase 3: default-deny rollout

For each namespace:

1. Apply the per-application allow policies (Phase 2 output).
2. Apply the default-deny policy.
3. Observe — denied flows indicate missed allow policies.
4. Fix; iterate.

### Phase 4: monitoring

- **Denied-flow logs** become a detection signal — what pods tried to reach what but were blocked?
- **Cilium Hubble dashboard** continues to show the flow graph.
- **Quarterly review** of policies and denied flows.

### The cluster-wide rollout discipline

For multi-namespace clusters:

- **Start with the smallest, most-contained workload.** Build confidence in the team's understanding before tackling complex namespaces.
- **Coordinate with application teams.** They need to know NetworkPolicies are arriving; they may have undocumented dependencies that surface during the migration.
- **Roll out in waves.** A namespace per sprint is sustainable; cluster-wide in one shot is high-risk.

For new clusters: default-deny from day one. The migration cost is avoided.

---

## Worked example: Meridian Health's NetworkPolicy posture

Meridian operates Cilium across EKS clusters with cluster-wide default-deny and rich egress / L7 policy.

### Cluster-wide baseline

- **Cilium in always-default-deny mode.** Every endpoint has implicit default-deny.
- **CiliumClusterwideNetworkPolicy** denies pod egress to AWS IMDS (169.254.169.254) cluster-wide.
- **CiliumClusterwideNetworkPolicy** denies pod-to-pod cross-namespace traffic by default (overridden by per-namespace policies).

### Per-namespace baseline

Every workload namespace has these CiliumNetworkPolicies via the namespace-vending automation:

```yaml
# Default-deny
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: default-deny
spec:
  endpointSelector: {}
  ingress: []
  egress: []
---
# Allow DNS
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-dns
spec:
  endpointSelector: {}
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
          rules:
            dns:
              - matchPattern: "*"
```

The DNS policy uses Cilium's DNS proxy to log every DNS query (additional detection signal).

### Care Coordinator workload policies

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: care-coordinator-supervisor
  namespace: care-coordinator
spec:
  endpointSelector:
    matchLabels:
      app: care-coordinator-supervisor
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: care-coordinator-ingress
      toPorts:
        - ports:
            - port: "8443"
              protocol: TCP
          rules:
            http:
              - method: "GET"
                path: "/api/v1/coordinator/.*"
              - method: "POST"
                path: "/api/v1/coordinator/sessions"
  egress:
    - toEndpoints:
        - matchLabels:
            app: care-coordinator-clinical-knowledge
      toPorts:
        - ports:
            - port: "8443"
              protocol: TCP
    - toFQDNs:
        - matchName: "api.datadoghq.com"
        - matchPattern: "*.snyk.io"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
    - toEntities:
        - "cluster"   # Cilium-defined entity for cluster services
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
```

### Observability

- **Hubble flow logs** ship to the central log archive.
- **Denied flows alert** the SOC when patterns indicate active exploitation attempts.
- **Quarterly review** of denied flows surfaces both legitimate-missing-policies and adversary-attempts.

### The migration story

Meridian's EKS clusters originally had no NetworkPolicies. Migration over 6 sprints:

- Sprint 1–2: install Cilium with Hubble; collect flow data.
- Sprint 3: author per-namespace policies for two pilot namespaces.
- Sprint 4: roll out default-deny to pilots.
- Sprints 5–6: roll out to remaining workload namespaces.

Surprises during migration:

- Discovered legacy cron jobs reaching external services that nobody knew about; allowlisted after review.
- Discovered cross-tenant connections (one tenant's pod reaching another tenant's database via shared internal service); flagged as a real issue requiring application change.
- Discovered DNS queries to obscure external services from compromised-but-not-yet-detected pods; the migration accidentally detected an incident.

### Findings opened during the NetworkPolicy audit

- **NETPOL-001** (cluster had no default-deny; pods could reach any other pod on any port). Closed by per-namespace default-deny.
- **NETPOL-002** (no cluster-wide IMDS block; pod-level SSRF could reach instance metadata). Closed by CiliumClusterwideNetworkPolicy denying 169.254.169.254.
- **NETPOL-003** (no egress filtering on pods; egress to internet via pod's NAT was unrestricted). Closed by per-application egress policies; broader egress via egress Network Firewall.
- **NETPOL-004** (cross-tenant pod connections silently allowed). Closed by cross-namespace default-deny; explicit per-tenant allow policies.
- **NETPOL-005** (no FQDN-based egress; team maintained brittle IP allowlists for third-party SaaS). Closed by migration to Cilium FQDN policies.
- **NETPOL-006** (no L7 HTTP policy; pod-to-pod traffic was L4-only). Closed by adding L7 policies on critical paths.
- **NETPOL-007** (Hubble flow logs not consumed by SIEM). Closed by ingest and detection rules.

---

## Anti-patterns

### 1. The cluster without NetworkPolicies

The cluster runs no NetworkPolicies. Pods are unrestricted; lateral movement is unbounded. The most common single Kubernetes-security finding.

The fix: per-namespace default-deny baseline.

### 2. The single allow without default-deny

A NetworkPolicy allows specific traffic. Without default-deny, the policy is decorative — everything else is still allowed by default.

The fix: default-deny first, then layered allows.

### 3. The DNS-forgotten default-deny

The team applies default-deny. Pods cannot resolve DNS; everything breaks; the team rolls back.

The fix: allow-DNS policy alongside default-deny; tested in non-prod first.

### 4. The CNI that doesn't enforce

The cluster has NetworkPolicies; the CNI plugin doesn't support enforcement. Policies are accepted but not enforced; the team has false confidence.

The fix: verify the CNI enforces; AWS VPC CNI (older versions), some basic CNIs don't.

### 5. The IP-allowlist-instead-of-FQDN

The team's NetworkPolicies allow egress to specific IPs of third-party SaaS. The SaaS provider's IPs change; the team's policies are stale; legitimate traffic breaks.

The fix: Cilium FQDN-based policies; or, where stuck on native NetworkPolicy, use the cloud's PrivateLink / Private Endpoint pattern to make the IP stable.

### 6. The pod-to-pod self-reference

A NetworkPolicy says `allow ingress from podSelector matchLabels: app=app-tier` and the pod itself is in `app-tier`. The pod can talk to itself, which it would do anyway. The policy provides no real isolation.

The fix: policies use distinct labels for source and destination; meaningful tier separation.

### 7. The forgotten cluster-API access

Pods need to call the Kubernetes API (e.g., for leader election, configuration loading). The default-deny doesn't include API access; pods fail.

The fix: allow egress to the cluster API endpoint (`kubernetes.default.svc`) in the per-namespace baseline.

### 8. The denied-flow log not consumed

NetworkPolicy denies flows; the deny events go to the CNI's flow log; nobody reads it. Both attacker behavior and missed-allow flows are invisible.

The fix: ingest flow logs into SIEM; alert on patterns; periodic review.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| NETPOL-001 | Cluster has no NetworkPolicies; pods unrestricted | High | Per-namespace default-deny + allow-DNS baseline; namespace-vending automation applies | Platform Eng + Security Eng |
| NETPOL-002 | No cluster-wide block of pod egress to instance metadata (169.254.169.254) | High | CiliumClusterwideNetworkPolicy or Calico GlobalNetworkPolicy denying IMDS | Platform Eng + Security Eng |
| NETPOL-003 | No egress policies on pods; pod-to-internet unrestricted | High | Per-application egress allowlists; broader egress via egress Network Firewall | Platform Eng + Workload Owner |
| NETPOL-004 | Cross-tenant connections allowed; isolation absent | High | Cross-namespace default-deny; explicit per-tenant allow policies | Platform Eng + Security Eng |
| NETPOL-005 | IP-based allowlists for third-party SaaS; brittle as IPs change | Medium | Migrate to Cilium FQDN-based egress, or use cloud-native PrivateLink | Platform Eng + Workload Owner |
| NETPOL-006 | L7 HTTP policy absent on critical paths | Medium | Cilium L7 policies for sensitive endpoints (admin APIs, internal data paths) | Platform Eng + Workload Owner |
| NETPOL-007 | Hubble / Calico flow logs not consumed by SIEM | Medium | Ingest flow logs; alert on denied-flow patterns; periodic review | Security Eng + SOC |
| NETPOL-008 | Default-deny missing allow-DNS; DNS resolution breaks pods | High | Allow-DNS policy in every workload namespace; included in baseline | Platform Eng |
| NETPOL-009 | CNI plugin does not enforce NetworkPolicies; policies decorative | High | Migrate to Calico or Cilium; verify enforcement; or upgrade CNI version | Platform Eng |
| NETPOL-010 | Pod-to-self labels match allow rules; rules are decorative | Low | Use distinct labels for tiers; meaningful separation | Platform Eng + Workload Owner |
| NETPOL-011 | No allow rule for Kubernetes API access; pods that need it fail | Medium | Allow egress to `kubernetes.default.svc` in namespace baseline where needed | Platform Eng |
| NETPOL-012 | NetworkPolicy enforcement not tested in CI; production-only verification | Medium | Test policies in CI with mock traffic; verify enforcement before production | Platform Eng |
| NETPOL-013 | Cilium not in always-default-deny mode; pods without policies are unrestricted | High | Configure always-default-deny in Cilium config | Platform Eng |
| NETPOL-014 | Policy authorship is per-team without platform-team review; quality varies | Medium | Platform team owns templates; application teams customize within constraints | Platform Eng + Security Eng |
| NETPOL-015 | Application teams can author NetworkPolicies that override platform baseline | Medium | Calico tiers (Enterprise) or admission-control policies enforce platform precedence | Platform Eng + Security Eng |
| NETPOL-016 | Migration to default-deny done without observability; missed allow policies broke production | High | Cilium Hubble or Calico Flow Logs first; observe before enforce | Platform Eng + SRE |
| NETPOL-017 | Quarterly policy review absent; policies drift from reality | Low | Quarterly review per workload; remove obsolete policies; verify denied flows are intentional | Security Eng + Workload Owner |
| NETPOL-018 | No alerting on policy denials; attacker probing invisible | Medium | SIEM rules on denied-flow patterns; alert on unusual sources or volumes | Security Eng + SOC |

---

## What this document is not

- **A CNI plugin comparison.** Calico / Cilium / native CNI all enforce NetworkPolicy; the choice depends on operational fit.
- **A complete Hubble or Flow Logs reference.** Observability tools are mentioned; their full operational depth lives in vendor / project documentation.
- **A service-mesh reference.** mTLS, authorization policies, and application-layer authentication live in [service-mesh-security.md](./), coming.
- **A complete kube-proxy / IPVS / iptables reference.** Underlying data-plane mechanics are covered in upstream Kubernetes documentation.
