# Workload Identity for Zero Trust

A practitioner's reference for workload identity as the Zero Trust foundation — SPIFFE / SPIRE for service identity, AuthorizationPolicy keyed off SPIFFE IDs, the cross-cluster and cross-cloud identity federation patterns, and the "every service has an identity, every call is authenticated" baseline that turns the network from a trust boundary into an implementation detail.

This document is the workload-side companion to [identity-aware-access.md](./identity-aware-access.md). That document covers workforce identity at the edge (user-to-application); this document covers workload identity inside the environment (service-to-service). The two together comprise the identity-layer foundation that the rest of Zero Trust builds on.

For the cloud-IAM workload identity patterns (IRSA, AKS WI, GKE WI), see [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md). For the K8s-specific mesh patterns that implement SPIFFE identity, see [../kubernetes-and-container-security/service-mesh-security.md](../kubernetes-and-container-security/service-mesh-security.md). For the static-secret elimination that workload identity enables, see [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md).

---

## When to read this document

**If you have workload identity (IRSA / Workload Identity) but no service-to-service identity layer** — read top to bottom. The cloud-IAM layer authenticates workloads *to the cloud*; the workload-to-workload identity is a separate (but related) problem.

**If you have a service mesh with mTLS but you're not using SPIFFE IDs in authz policy** — start with [SPIFFE identity in authz](#spiffe-identity-in-authz). The mesh provides the identity; using it in policy is the leverage point.

**If you operate across multiple clusters or clouds and want to authenticate workloads cross-environment** — start with [Cross-trust-domain federation](#cross-trust-domain-federation).

**If you are auditing workload identity posture** — start with [Findings checklist](#findings-checklist).

---

## The Zero Trust identity baseline

The Zero Trust premise applied to workloads:

- **Every service has an identity** (not "an IP" or "a hostname" — a cryptographic identity).
- **Every service-to-service call is authenticated** (both client and server prove identity).
- **Authorization is identity-based**, not network-based.
- **The network is not a trust boundary** — a pod on the same subnet as another pod has no implicit trust.

The pattern compounds with [identity-aware-access.md](./identity-aware-access.md): workforce identity gates user-to-service; workload identity gates service-to-service. The combination eliminates network-based trust entirely.

### What the cloud's native workload identity provides

- **Workload-to-cloud-API identity:** the cloud authenticates the workload (IRSA / Workload Identity / Managed Identity).
- **Per-pod scoping:** per-workload IAM roles enable least-privilege at the workload level.
- **Standard IAM grant model:** policies, conditions, audit logs.

What it does *not* provide:

- **Workload-to-workload identity:** the workload's identity at the cloud doesn't directly translate to a service-to-service identity.
- **Cross-cluster / cross-cloud federation:** identity from cluster A isn't recognized in cluster B without explicit federation.
- **Application-layer authentication:** the cloud IAM layer is at the API boundary; service-to-service calls happen at the network layer.

SPIFFE fills these gaps.

---

## SPIFFE: the standard

SPIFFE (Secure Production Identity Framework for Everyone) is a CNCF-graduated specification for workload identity.

### Core concepts

- **SPIFFE ID:** a workload's identity, in URI form: `spiffe://trust-domain/path`.
- **SVID (SPIFFE Verifiable Identity Document):** a signed credential bearing the SPIFFE ID. Two forms: X.509 SVID (certificate) or JWT SVID.
- **Trust Domain:** a security boundary; SPIFFE IDs are unique within a trust domain.
- **Workload API:** the local socket the workload calls to get its SVID.

### Example SPIFFE IDs

```
spiffe://meridian.health/cluster/prod-us-east/ns/care-coordinator/sa/supervisor
spiffe://meridian.health/cluster/prod-us-east/ns/care-coordinator/sa/clinical-knowledge
spiffe://meridian.health/cluster/prod-eu-central/ns/care-coordinator/sa/supervisor
```

The structure reflects the workload's location and purpose. Identities are stable across pod restarts (the SPIFFE ID is per-workload-purpose, not per-pod-instance).

### What SPIFFE solves

- **Portable workload identity:** the same SPIFFE ID can be issued in different environments (Kubernetes, VMs, serverless) by different issuers (SPIRE, Istio, mesh-built-in), but the format is standard.
- **Federation:** workloads in trust domain A can authenticate to workloads in trust domain B via federation primitives.
- **Cryptographic identity:** SVIDs are signed by the trust domain's CA; verification doesn't require contacting the issuer.

References:
- [SPIFFE](https://spiffe.io/)
- [SPIFFE specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)

---

## SPIRE: the reference implementation

SPIRE (SPIFFE Runtime Environment) is the reference implementation. It's the most-deployed SPIFFE issuer in production.

### Architecture

- **SPIRE Server:** the CA. Issues SVIDs based on workload attestation.
- **SPIRE Agent:** runs on each node. Attests workloads (via Kubernetes attestation, AWS attestation, etc.) and provides SVIDs via the Workload API socket.
- **Workload:** calls the Workload API socket; receives SVIDs.

### Attestation mechanisms

How SPIRE knows what workload it's issuing an identity to:

- **Kubernetes attestation:** the SPIRE Agent verifies the pod's service account token, namespace, labels via the Kubernetes API.
- **AWS attestation:** the agent verifies the EC2 instance's identity document (via IMDS), then identifies the workload running on the instance.
- **Process attestation:** the agent verifies the workload's process identity (UID, executable hash) against expectations.

Combination attestation (e.g., "the workload must be running in this Kubernetes namespace AND with this service account AND with this image hash") provides strong identity binding.

### Selectors

SPIRE entries are defined as selectors:

```bash
spire-server entry create \
  -spiffeID spiffe://meridian.health/cluster/prod-us-east/ns/care-coordinator/sa/supervisor \
  -parentID spiffe://meridian.health/spire/agent/k8s_psat/prod-us-east/... \
  -selector k8s:ns:care-coordinator \
  -selector k8s:sa:care-coordinator-supervisor-sa \
  -selector k8s:pod-image:meridian-registry.local/care-coordinator-supervisor@sha256:abc123
```

A workload matches the entry only if all selectors match. The image-hash selector binds identity to specific image content; running a different image (even with the same service account) gets a different identity (or none).

### Deployment shape

- **SPIRE Server cluster:** HA Raft cluster, typically 3 nodes.
- **SPIRE Agent DaemonSet** in each Kubernetes cluster.
- **Workloads call** the Workload API socket (typically `/run/spire/agent-sockets/agent.sock`) for their SVIDs.

References:
- [SPIRE](https://spiffe.io/docs/latest/spire-about/)

---

## SPIFFE identity in authz

The leverage point: using SPIFFE IDs in authorization policies.

### Istio AuthorizationPolicy with SPIFFE

Istio configured with SPIRE as the identity backend:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: care-coordinator-supervisor-access
  namespace: care-coordinator
spec:
  selector:
    matchLabels:
      app: care-coordinator-supervisor
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "spiffe://meridian.health/cluster/prod-us-east/ns/care-coordinator/sa/care-coordinator-ingress-sa"
              - "spiffe://meridian.health/cluster/prod-us-east/ns/care-coordinator/sa/care-coordinator-clinical-knowledge-sa"
      to:
        - operation:
            methods: ["GET", "POST"]
            paths: ["/api/v1/coordinator/*"]
```

The policy:

- Allows specific SPIFFE IDs to reach `care-coordinator-supervisor`.
- The identities are cross-cluster portable (a service in another cluster with the same SPIFFE ID would also be allowed).
- The identity is cryptographic; the mesh validates the SVID at the connection.

### The principal vs serviceaccount distinction

Istio supports both:

- `source.principals: [...]` — uses SPIFFE IDs.
- `source.namespaces: [...]` + `source.serviceAccountName: [...]` — uses Kubernetes-namespace-and-SA identity.

For Zero Trust portability: prefer SPIFFE IDs. The format is standard; identities translate across environments.

### What this enables

- **Cross-cluster authentication:** a service in cluster A can call a service in cluster B; the SPIFFE IDs are in the same trust domain (or federated); the policy works.
- **Workload-identity-bound audit:** every authenticated call carries the SPIFFE ID; logs show which workload made which call.
- **Image-bound identity:** the SPIFFE ID is bound to specific image content (via SPIRE selectors); changes to the image require an explicit identity re-issuance.

---

## Cross-trust-domain federation

The pattern for cross-cluster, cross-cloud, or cross-org workload authentication.

### Trust domain boundaries

A trust domain is a security perimeter:

- All workloads in a trust domain have SPIFFE IDs with the same trust-domain prefix.
- SVIDs in trust domain A are signed by A's CA; not directly trusted in trust domain B.

Common patterns:

- **One trust domain per organization** (`spiffe://meridian.health/...`).
- **One trust domain per environment** (`spiffe://meridian.health.prod/...`, `spiffe://meridian.health.staging/...`).
- **One trust domain per cluster** (`spiffe://meridian.health.prod-us-east/...`).

The granularity matters: per-cluster is fine-grained (more federation work); per-org is simpler (broader trust).

### Federation mechanics

SPIFFE federation lets trust domain A trust trust domain B:

- Trust domain A's SPIRE Server is configured with trust domain B's bundle (B's CA's public keys).
- B's SVIDs verify against B's bundle when presented in A.
- Policies in A can reference SPIFFE IDs from B (`spiffe://b.example/...`).

### Use cases for federation

- **Multi-cluster deployments:** workloads in different clusters need to authenticate to each other.
- **Multi-cloud deployments:** workloads in AWS need to talk to workloads in GCP.
- **Cross-organization integration:** business partners with their own trust domains need to authenticate.

### The bundle distribution

The federation mechanism requires distributing trust bundles between domains:

- **Manual:** the operators of each domain exchange bundles out-of-band; configured in SPIRE.
- **SPIFFE Federation API:** SPIRE Server exposes the bundle; other SPIRE Servers fetch periodically.
- **Custom mechanisms** for specific environments.

The pattern: federation is bounded operational work; the result is cross-domain authentication without sharing IAM or merging Kubernetes clusters.

---

## SPIFFE without SPIRE

Some mesh and identity systems issue SPIFFE-format identities without using SPIRE.

### Istio without SPIRE

Istio's built-in `istiod` is a CA that issues SVIDs based on Kubernetes service-account tokens:

- SPIFFE ID format: `spiffe://cluster.local/ns/<namespace>/sa/<serviceaccount>`.
- No explicit SPIRE deployment; istiod handles it.
- Cluster-level trust domain (`cluster.local`).

Pros: simpler; no separate SPIRE to operate.
Cons: cluster-bound (no cross-cluster federation without additional setup); identity is bound to service-account only (no image-binding).

For organizations that want SPIFFE identities without SPIRE: Istio's built-in is sufficient for the single-cluster case. For multi-cluster or stronger attestation: SPIRE.

### Linkerd

Linkerd uses its own identity system; SPIFFE-compatible in the sense of having strong cryptographic workload identity but not using SPIFFE IDs in its native policy.

### Vault PKI as SPIFFE issuer

Some teams configure Vault's PKI engine to issue SPIFFE-format certificates:

- Vault is the CA.
- Workloads authenticate to Vault (via Kubernetes auth, AWS auth, etc.) and request SVIDs.
- The SPIFFE format is honored by downstream consumers.

Useful for teams already running Vault.

---

## The application-side integration

Workloads need to use SVIDs.

### Service-mesh integration (the common path)

For meshed services:

- The mesh sidecar (or Ambient ztunnel) handles SVID fetch and mTLS negotiation.
- The application speaks plaintext to the sidecar; the sidecar wraps in mTLS.
- The application never directly handles SVIDs.

The simplest pattern; most production deployments use this.

### Direct SDK integration (for non-meshed services)

For services not in a mesh:

```go
import (
    "github.com/spiffe/go-spiffe/v2/workloadapi"
    "github.com/spiffe/go-spiffe/v2/spiffetls"
    "github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
    ctx := context.Background()

    // Connect to the Workload API
    source, err := workloadapi.NewX509Source(ctx)
    defer source.Close()

    // Server side: TLS with SPIFFE verification
    serverID := spiffeid.RequireFromString("spiffe://meridian.health/cluster/prod-us-east/ns/care-coordinator/sa/supervisor")
    expectedClient := spiffeid.RequireFromString("spiffe://meridian.health/cluster/prod-us-east/ns/care-coordinator/sa/ingress")

    listener, err := spiffetls.Listen(ctx, "tcp", ":8443",
        spiffetls.MTLSServerWithSourceAndIDs(source, source, spiffeid.IsMemberOf(serverID.TrustDomain())))

    // Server handles incoming mTLS connections; verifies peer's SPIFFE ID
}
```

The application explicitly handles SVIDs and mTLS. More code; useful when the mesh isn't deployed or the workload runs outside Kubernetes.

References:
- [go-spiffe library](https://github.com/spiffe/go-spiffe)
- [java-spiffe](https://github.com/spiffe/java-spiffe)
- [py-spiffe](https://github.com/HewlettPackard/py-spiffe)

---

## Worked example: Meridian Health's workload identity

Meridian operates a SPIFFE-based identity layer with SPIRE as the issuer, federated across production clusters, with Istio using SPIRE-issued SVIDs.

### Trust domain structure

- Production: `spiffe://meridian.health.prod/...`
- Staging: `spiffe://meridian.health.staging/...`
- Development: `spiffe://meridian.health.dev/...`

The three trust domains do not federate (production and dev / staging are intentionally separated). Within production: federation across regional clusters.

### SPIRE deployment

- **SPIRE Server cluster** in `meridian-secrets-broker` shared services account (the same as Vault per [../secrets-and-keys/vault-patterns.md](../secrets-and-keys/vault-patterns.md)).
- **HA Raft** 3-node cluster.
- **Cross-region replicas** for federation.
- **SPIRE Agent DaemonSet** in every workload cluster.

### Attestation rules

Each Meridian workload has SPIRE entries with combined selectors:

```bash
spire-server entry create \
  -spiffeID spiffe://meridian.health.prod/cluster/us-east-1/ns/care-coordinator/sa/supervisor \
  -parentID spiffe://meridian.health.prod/spire/agent/k8s_psat/us-east-1/... \
  -selector k8s:ns:care-coordinator \
  -selector k8s:sa:care-coordinator-supervisor-sa \
  -selector k8s:pod-image-count:1 \
  -selector k8s:pod-image:meridian-registry.local/care-coordinator-supervisor@sha256:abc123...
```

The image-hash selector binds the SPIFFE ID to specific image content. Image rotation requires updating the selector (handled by the deployment pipeline).

### Istio integration

Istio configured to use SPIRE as identity provider:

- `meshConfig` references SPIRE's bundle.
- Sidecars fetch SVIDs from SPIRE Agent's Workload API.
- AuthorizationPolicies reference SPIFFE IDs (not cluster.local IDs).

### Federation across regions

Production trust domain spans US-East and US-West clusters. The pattern:

- SPIRE Servers in each region federate with each other.
- A workload in US-East can authenticate to a workload in US-West (and vice versa).
- AuthorizationPolicies reference the cross-region SPIFFE IDs explicitly.

For EU-region production (`meridian.health.prod.eu`): the trust domain is separate (data residency). Federation across US and EU is configured for specific cross-region services with explicit justification.

### Non-meshed services

A few legacy services run outside the mesh. They use direct SPIRE SDK integration:

- The service's pod has a sidecar SPIRE Agent (or DaemonSet agent on the node).
- Application code uses go-spiffe to fetch SVIDs and perform mTLS.
- AuthorizationPolicies-equivalent logic is in the application code (less standardized than mesh policy).

### Findings opened during the workload-identity-ZT audit

- **WIDZT-001** (Istio was using `cluster.local` SA-based identity, not SPIFFE-formatted IDs; cross-cluster authentication impossible). Closed by SPIRE integration.
- **WIDZT-002** (no image-binding in SPIRE selectors; identity was per-SA, not per-image). Closed by adding image-hash selectors.
- **WIDZT-003** (trust domain was single across prod/staging/dev; misconfigured policies could allow cross-environment access). Closed by per-environment trust domains.
- **WIDZT-004** (non-meshed services used static credentials for inter-service auth). Closed by SPIRE SDK integration for those services.
- **WIDZT-005** (federation across regions was not documented; cross-region policies were ad-hoc). Closed by formal federation configuration and policy documentation.

---

## Anti-patterns

### 1. The cluster-local-only identity

The mesh uses cluster-local identity (`cluster.local/ns/.../sa/...`). Cross-cluster authentication is impossible without further configuration. Multi-region or multi-cluster ZT is blocked.

The fix: SPIFFE-format identities with a meaningful trust domain; federation as needed.

### 2. The over-broad authz policy

AuthorizationPolicies reference `*` or broad selectors. SPIFFE IDs are issued but the policy doesn't use them meaningfully. The identity is decorative.

The fix: per-source-SPIFFE-ID policies; specific allowed identities, not wildcards.

### 3. The trust-domain-too-wide

One trust domain across production, staging, and development. A misconfigured policy can allow staging workloads to authenticate to production resources.

The fix: per-environment trust domains; no federation between them.

### 4. The forgotten image-binding

SPIRE entries are SA-based only; any pod with the right SA gets the SPIFFE ID. An attacker who compromises the cluster and runs a different image with the right SA gets a legitimate-looking SPIFFE ID.

The fix: image-hash selectors in SPIRE entries; identity binds to specific image content.

### 5. The non-meshed-services-fall-through

The mesh handles identity for in-mesh services. Non-meshed services use static credentials. The Zero Trust posture is partial.

The fix: SPIRE SDK integration for non-meshed services; everyone has a SPIFFE identity.

### 6. The SPIRE-as-SPOF

SPIRE Server is a single node. SPIRE failure means no new SVID issuance. Pods that start during SPIRE outage cannot authenticate.

The fix: HA SPIRE Server cluster; cross-region replication; SVID caching in agents.

### 7. The federation without policy review

Trust domains A and B federate. Policies on each side reference identities from the other. Over time, the policies drift; cross-domain access expands without review.

The fix: cross-domain policies are first-class artifacts; quarterly review of federation; per-policy justification.

### 8. The SVID rotation breakage

SVIDs have short TTLs (typically 1 hour); rotation is automatic. If the rotation mechanism breaks (SPIRE Agent restart loop, clock skew), SVIDs expire and connections fail.

The fix: monitor SVID rotation; alert on rotation failures; SPIRE Agent health checks.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| WIDZT-001 | Mesh uses cluster-local identity; cross-cluster authentication impossible | Medium | Adopt SPIFFE-format identities; configure trust domain | Platform Eng + Security Eng |
| WIDZT-002 | SPIRE selectors are SA-only; image binding absent | High | Add image-hash selectors; identity binds to image content | Platform Eng + Security Eng |
| WIDZT-003 | Trust domain spans environments (prod/staging/dev); cross-env risk | High | Per-environment trust domains; no federation between non-prod and prod | Platform Eng + Security Eng |
| WIDZT-004 | Non-meshed services use static credentials for inter-service auth | High | SPIRE SDK integration; everyone has SPIFFE identity | Workload Owner + Platform Eng |
| WIDZT-005 | Federation across trust domains is undocumented | Medium | Formal federation configuration; policy documentation; quarterly review | Security Eng + Architecture |
| WIDZT-006 | AuthorizationPolicies use SA-based identity instead of SPIFFE IDs | Medium | Migrate to SPIFFE-ID-based policies for portability | Security Eng |
| WIDZT-007 | SPIRE Server is single node; SPOF | High | HA Raft cluster (3+ nodes); cross-region replication | Platform Eng + SRE |
| WIDZT-008 | SVID rotation failures unmonitored | Medium | Monitoring on SVID rotation; alert on failures | Platform Eng + SRE |
| WIDZT-009 | SVID TTL too long; lateral movement window large if credential compromised | Low | Reduce TTL to 1 hour or less; verify rotation works at the cadence | Security Eng |
| WIDZT-010 | Workload identity not integrated with workforce identity for end-to-end auth | Low | Propagate end-user identity through service chain via mesh / JWT | Security Eng + Architecture |
| WIDZT-011 | SPIFFE Federation Bundle distribution manual; updates miss | Medium | Federation API for automated bundle exchange | Platform Eng |
| WIDZT-012 | Vault PKI used as SPIFFE issuer without proper attestation | Medium | Workload attestation discipline; image / SA / namespace binding | Security Eng |
| WIDZT-013 | Audit logs of SVID issuance not consumed by SIEM | Medium | SPIRE audit logs to SIEM; alert on anomalous patterns | Security Eng + SOC |
| WIDZT-014 | Test / development clusters federate with production trust domain | High | No federation between non-prod and prod; explicit separation | Security Eng |
| WIDZT-015 | SPIRE entries created manually; drift from desired state | Low | IaC for SPIRE entries; reconciliation from source-of-truth | Platform Eng |
| WIDZT-016 | Application-level mTLS rolled by hand for non-meshed services | Medium | go-spiffe / py-spiffe / etc. instead of custom mTLS code | Workload Owner |
| WIDZT-017 | Cross-cluster network paths don't carry mesh; identity stops at cluster boundary | Medium | mesh multi-cluster configuration; or non-mesh SPIFFE for cross-cluster paths | Platform Eng + Security Eng |
| WIDZT-018 | SPIRE upgrade procedure untested; concerned to upgrade in production | Medium | Test in staging; rolling upgrade procedure; rollback documented | Platform Eng |

---

## What this document is not

- **A SPIRE administration tutorial.** SPIRE's documentation covers deployment depth.
- **A service-mesh comparison.** Mesh-specific patterns live in [../kubernetes-and-container-security/service-mesh-security.md](../kubernetes-and-container-security/service-mesh-security.md).
- **A workforce identity reference.** Workforce identity lives in [identity-aware-access.md](./identity-aware-access.md) and [../identity-and-access/](../identity-and-access/).
- **A complete mTLS reference.** mTLS-everywhere patterns live in [mtls-everywhere.md](./mtls-everywhere.md).
