# Service Mesh Security

A practitioner's reference for using a service mesh as a security control — Istio, Linkerd, Consul Connect, mTLS-by-default, AuthorizationPolicy for service-to-service authentication, the SPIFFE / SPIRE identity story, and the decision framework for when service mesh is worth the operational cost and when it is not. The patterns here are about application-layer authentication and authorization at the network boundary — what NetworkPolicy can't enforce because it operates at L4 rather than L7.

This document is opinionated about service mesh: **most Kubernetes environments don't need one**. The pattern is high-leverage when it fits and a substantial operational cost when it doesn't. The honest framing: a team running mTLS-by-default + AuthorizationPolicy is a team that has invested in service mesh; a team running NetworkPolicy + admission control is a team that has chosen to invest elsewhere. Both are valid; the choice should be deliberate.

For the L4 segmentation that complements (not substitutes) service mesh, see [network-policies.md](./network-policies.md). For workload identity at the IAM layer, see [eks-aks-gke-baselines.md §Cluster identity](./eks-aks-gke-baselines.md#cluster-identity).

---

## When to read this document

**If you have a service mesh and aren't using its security features (mTLS, AuthorizationPolicy)** — read top to bottom. The mesh is paid for; the security capabilities are the high-leverage payoff.

**If you are considering adopting a service mesh** — start with [When service mesh is the right answer](#when-service-mesh-is-the-right-answer). The decision is consequential; the cost is operational not just licensing.

**If your team has Istio but mTLS is in "permissive" mode forever** — start with [mTLS migration patterns](#mtls-migration-patterns). The migration from permissive to strict is bounded but real.

**If you are auditing service-mesh security posture** — start with [Findings checklist](#findings-checklist). The common findings (permissive-mode mTLS, no AuthorizationPolicy, certificate-rotation gaps) are universal.

---

## What service mesh provides as security

The security-relevant capabilities of a service mesh:

### mTLS by default

Every service-to-service connection within the mesh uses mutual TLS:

- The client authenticates the server (standard TLS).
- The server authenticates the client (mutual TLS).
- Identity is cryptographic (the workload's SPIFFE ID or service-account identity in the certificate).

The benefit: a compromised network (L4 firewall bypass, attacker positioned between pods) cannot impersonate or eavesdrop without compromising a workload identity.

### AuthorizationPolicy

Beyond authentication, the mesh enforces authorization at the application layer:

- **Service-to-service authz:** service A can call service B's `/api/v1/...` endpoint; cannot call B's admin endpoints.
- **Method-level authz:** GET allowed, POST denied.
- **Header-based conditions:** authz depends on JWT claims, custom headers.
- **Source-identity-based:** only specific service-account identities can reach a particular endpoint.

The benefit: application-layer policy enforcement at the network boundary; the application doesn't need to implement service-to-service authz itself.

### Observability

Most service meshes expose rich observability:

- Per-call latency, error rate, throughput.
- Per-service mTLS status (cipher, certificate version).
- Authorization-policy denials.
- Distributed tracing.

The benefit: detection signals at the application boundary; per-service security telemetry that L4-only tools don't see.

### Identity propagation

The mesh propagates identity through request chains:

- Service A receives a request with caller identity X.
- Service A calls service B; the mesh forwards identity X (in addition to A's identity).
- B can authorize based on the original caller's identity, not just the immediate caller's.

The benefit: end-to-end identity-aware access control.

---

## When service mesh is the right answer

The decision framework. Service mesh is *not* universally the right call.

### Choose service mesh when

- **The cluster runs many microservices** that need pairwise authentication.
- **mTLS-by-default is a compliance requirement.**
- **Application-layer authorization (path, method, headers) is needed across many services.**
- **The team already has service-mesh expertise** (Istio or Linkerd operations).
- **The cluster is large enough** that per-application implementation of mTLS / authz isn't tractable.

### Don't choose service mesh when

- **The cluster has fewer than ~10 services.** The operational cost outweighs the benefit; per-app implementation is tractable.
- **The team doesn't have service-mesh expertise** and isn't planning to acquire it.
- **The applications are single-tenant or trust-the-network.**
- **The applications already implement mTLS / authz** sufficiently.

### The honest reading

Most Kubernetes environments in 2026 don't need a service mesh. The pattern that suffices for many:

- **NetworkPolicy default-deny** ([network-policies.md](./network-policies.md)) for L4 segmentation.
- **Admission control** ([admission-control.md](./admission-control.md)) for image and pod policy.
- **Workload identity** ([eks-aks-gke-baselines.md](./eks-aks-gke-baselines.md)) for IAM-layer authentication.
- **Application-layer authz** in each service (or in an API gateway).

A team running this stack has good security posture without the mesh operational burden. A team adding the mesh on top gains incremental defense-in-depth at meaningful operational cost.

For teams that *do* adopt the mesh: the security capabilities are the load-bearing reason. Adopt the mesh for the security features, not for the observability features alone (cheaper alternatives exist).

---

## Istio vs Linkerd vs Consul Connect

The three dominant service meshes in 2026.

### Istio

- **CNCF Graduated**; the dominant service mesh.
- Rich feature set: mTLS, AuthorizationPolicy, traffic management, custom plugins via WASM.
- Sidecar (Envoy) per pod by default; ambient mode (sidecar-less) is newer.
- Complex; substantial operational burden.

Best for: large environments needing the full feature set; teams with mesh expertise.

### Linkerd

- **CNCF Graduated**; simpler than Istio.
- mTLS by default, AuthorizationPolicy, traffic management.
- Sidecar (lightweight Rust proxy) per pod.
- Significantly simpler operational story than Istio.

Best for: teams that want mesh capabilities without Istio's complexity.

### Consul Connect

- HashiCorp's service mesh.
- Multi-platform (works across Kubernetes, VMs, cloud-native services).
- Tighter integration with Consul for service discovery and Vault for PKI.

Best for: HashiCorp-heavy environments; multi-platform service-to-service needs.

### The decision

- **For Kubernetes-only environments needing simplicity:** Linkerd.
- **For Kubernetes-only environments needing the full feature set:** Istio.
- **For multi-platform (Kubernetes + VMs + cloud services) environments:** Consul Connect.
- **For ambient (sidecar-less) modern deployments:** Istio Ambient (newer; reduced sidecar overhead).

References:
- [Istio](https://istio.io/)
- [Linkerd](https://linkerd.io/)
- [Consul Connect](https://www.consul.io/docs/connect)

---

## mTLS by default

The pattern that the mesh implements; this section covers the operational discipline.

### Modes

Most meshes have three modes:

- **Disabled / plaintext:** no encryption.
- **Permissive:** the server accepts both mTLS and plaintext from clients; allows gradual migration.
- **Strict:** server requires mTLS; plaintext is rejected.

The pattern: start in permissive during migration; move to strict per service as confidence builds.

### Istio PeerAuthentication

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: care-coordinator
spec:
  mtls:
    mode: STRICT
```

The namespace-level policy: all pods in `care-coordinator` require mTLS for inbound connections.

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

The mesh-wide policy: applied to `istio-system`, this sets the default for the entire mesh. Per-namespace policies override.

### Linkerd mTLS

Linkerd uses mTLS by default for all meshed traffic; no explicit configuration needed. The trade: simpler than Istio; less granular control.

### What mTLS doesn't authenticate

- **External traffic** entering the mesh from outside (handled by ingress gateways with their own TLS).
- **Egress traffic** leaving the mesh (mesh-controlled but the external endpoint is not authenticated by mesh).
- **Pods not in the mesh** (no sidecar; no mTLS).

The pattern: every pod that should be in the mesh has the sidecar; external connections use separate TLS at the ingress / egress gateway layer.

### mTLS migration patterns

Migrating from no-mTLS to strict-mTLS:

1. **Install the mesh** with mTLS in permissive mode mesh-wide.
2. **Verify all workloads have sidecars** (or are explicitly out-of-mesh via annotation).
3. **Per namespace, switch to strict.** Monitor for failures; fix non-mesh services.
4. **Mesh-wide strict.** After all namespaces clean.

The pattern takes weeks per environment; the result is end-to-end mTLS.

---

## AuthorizationPolicy

The application-layer authz that mesh enables.

### Istio AuthorizationPolicy

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: care-coordinator-supervisor-policy
  namespace: care-coordinator
spec:
  selector:
    matchLabels:
      app: care-coordinator-supervisor
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/care-coordinator/sa/care-coordinator-ingress-sa"]
      to:
        - operation:
            methods: ["GET"]
            paths: ["/api/v1/coordinator/*"]
        - operation:
            methods: ["POST"]
            paths: ["/api/v1/coordinator/sessions"]
    - from:
        - source:
            principals: ["cluster.local/ns/monitoring/sa/datadog-cluster-agent"]
      to:
        - operation:
            methods: ["GET"]
            paths: ["/metrics"]
```

The policy:

- Applies to pods labeled `app: care-coordinator-supervisor`.
- Allows the `care-coordinator-ingress-sa` service account to GET `/api/v1/coordinator/*` and POST `/api/v1/coordinator/sessions`.
- Allows the Datadog agent to GET `/metrics`.
- Denies everything else (default-deny when an AuthorizationPolicy exists).

### The default-deny pattern

For an AuthorizationPolicy to default-deny, define an empty `ALLOW` policy (or no policy at all where the mesh defaults to deny). Then per-application allow policies layer on top.

Istio's default-deny pattern:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-all
  namespace: care-coordinator
spec: {}
```

Empty `spec` = deny everything. Per-application policies above add allows.

### Conditions: JWT, headers, source IP

AuthorizationPolicy supports rich conditions:

```yaml
rules:
  - from:
      - source:
          requestPrincipals: ["okta/admin"]  # JWT subject
    when:
      - key: request.headers[X-Tenant-Id]
        values: ["tenant-acme"]
      - key: source.ip
        values: ["10.20.30.0/24"]
    to:
      - operation:
          paths: ["/api/admin/*"]
```

Allows requests with the `admin` Okta JWT, where the `X-Tenant-Id` header is `tenant-acme` and the source IP is in the admin VPN range, to reach `/api/admin/*`.

### Linkerd's policy

Linkerd has a similar `Server` and `ServerAuthorization` resource pattern:

```yaml
apiVersion: policy.linkerd.io/v1beta1
kind: Server
metadata:
  name: care-coordinator-supervisor
spec:
  podSelector:
    matchLabels:
      app: care-coordinator-supervisor
  port: 8443
---
apiVersion: policy.linkerd.io/v1beta1
kind: ServerAuthorization
metadata:
  name: care-coordinator-supervisor-authz
spec:
  server:
    name: care-coordinator-supervisor
  client:
    meshTLS:
      serviceAccounts:
        - name: care-coordinator-ingress-sa
          namespace: care-coordinator
```

Simpler than Istio; less granular (no per-method, per-path).

---

## SPIFFE / SPIRE identity

The standard identity model that modern service meshes implement.

### What SPIFFE provides

SPIFFE (Secure Production Identity Framework for Everyone):

- **SPIFFE ID:** a unique identity for a workload (e.g., `spiffe://cluster.local/ns/care-coordinator/sa/care-coordinator-supervisor-sa`).
- **SVID (SPIFFE Verifiable Identity Document):** a signed credential containing the SPIFFE ID (typically an X.509 certificate).
- **Workload API:** a local socket that workloads call to get their SVIDs.

### SPIRE

SPIRE is the reference SPIFFE implementation:

- **SPIRE Server** issues SVIDs based on attestation.
- **SPIRE Agent** runs on each node; attests pods via Kubernetes (kubelet, service account) and provides them with SVIDs.
- **Workloads** call the Workload API socket to get their SVID; use it for mTLS and authz.

### Integration with Istio

Istio can use SPIRE as the identity backend:

- SPIRE issues SVIDs to pods.
- Istio sidecars use SVIDs for mTLS.
- AuthorizationPolicy references SPIFFE IDs.

The pattern: SPIFFE is the standard; the mesh provides the operational layer; SPIRE is the reference issuance authority.

### Why SPIFFE matters

- **Standard identity:** portable across meshes, across clouds, across runtime environments.
- **Federation:** SPIFFE supports cross-trust-domain federation (workloads in different clusters / clouds can authenticate to each other).
- **Vendor-neutral:** SPIFFE is a CNCF standard; not tied to a specific mesh vendor.

For most teams: SPIFFE is implicit (the mesh handles it). For teams building cross-cluster or cross-cloud identity: SPIFFE is the explicit foundation.

References:
- [SPIFFE](https://spiffe.io/)
- [SPIRE](https://spiffe.io/docs/latest/spire-about/)

---

## Certificate lifecycle

The mesh's mTLS depends on certificates; lifecycle matters.

### Certificate sources

- **Mesh-built-in CA:** Istio's `istiod` is a CA by default; signs SVIDs for sidecars.
- **External CA via SPIRE:** SPIRE-issued certificates passed to the mesh.
- **AWS Private CA / Cloud KMS-backed CAs:** for enterprise certificate hierarchies.

### Certificate rotation

Mesh certificates are short-lived (typically 24 hours by default in Istio). Rotation:

- Sidecar periodically requests a new certificate.
- The mesh CA issues; sidecar reloads.
- No manual intervention; should be transparent.

The failure mode: a clock skew, a CA outage, or a misconfigured TTL can break rotation; mTLS connections fail silently.

The detection:

- Mesh observability shows certificate expiration per service.
- Alert on certificates approaching expiration without rotation.

### The mTLS-without-rotation-is-not-mTLS baseline

A team that disables rotation "for stability" creates a certificate that lives indefinitely. Compromise of that certificate is unrecoverable without a manual rotation event.

The fix: rotation is the default; verify rotation is working; alert on failures.

---

## The performance vs security trade

Service mesh sidecars add latency. Typical overhead:

- **mTLS handshake:** ~1ms additional per connection.
- **Per-request proxy hop:** ~1ms additional.
- **CPU/memory overhead:** ~50-100m CPU, 50-200MB memory per pod for the sidecar.

For most workloads: acceptable. For latency-critical workloads (real-time trading, real-time gaming): the overhead matters.

The mitigations:

- **Istio Ambient mode** (sidecar-less): reduces overhead.
- **Linkerd** (lighter sidecar than Istio).
- **Connection pooling and keep-alive:** amortize handshake cost.
- **Per-workload opt-out:** specific pods opt out of mesh (no sidecar); use AuthorizationPolicy at the gateway instead.

The performance cost is the most-common reason a team chooses not to adopt mesh. For teams that adopt: measure baseline latency before and after; tune.

---

## Worked example: Meridian Health's Istio deployment

Meridian uses Istio across production EKS clusters with mTLS-strict mode, AuthorizationPolicy default-deny + per-service allows, and Vault-PKI-backed certificates.

### Deployment

- **Istio Ambient mode** in production (sidecar-less; lower overhead).
- **Istio control plane** (istiod) in `istio-system` namespace.
- **Per-namespace PeerAuthentication** in strict mode.
- **Default-deny AuthorizationPolicy** mesh-wide; per-service allows layered on.
- **Vault-PKI** as the root CA; istiod is an intermediate.

### mTLS configuration

Mesh-wide strict mode via:

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

Every namespace inherits; explicit per-namespace policies for the few exceptions (e.g., monitoring scrape endpoints that need to be reachable from outside the mesh — handled via gateway).

### AuthorizationPolicy library

Per-service authz policies for every workload. Example for Care Coordinator:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: care-coordinator-supervisor
  namespace: care-coordinator
spec:
  selector:
    matchLabels:
      app: care-coordinator-supervisor
  action: ALLOW
  rules:
    # Ingress from gateway
    - from:
        - source:
            principals: ["cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"]
      to:
        - operation:
            methods: ["GET", "POST"]
            paths: ["/api/v1/coordinator/*"]
    # Clinical knowledge model can call back for cache invalidation
    - from:
        - source:
            principals: ["cluster.local/ns/care-coordinator/sa/care-coordinator-clinical-knowledge-sa"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/internal/cache/invalidate"]
    # Datadog scraping
    - from:
        - source:
            principals: ["cluster.local/ns/monitoring/sa/datadog-cluster-agent"]
      to:
        - operation:
            methods: ["GET"]
            paths: ["/metrics", "/health"]
```

Every other request to care-coordinator-supervisor is denied.

### Certificate lifecycle

- **Root CA:** Vault PKI engine.
- **Intermediate CA:** istiod, signed by Vault.
- **Workload certificates:** istiod-issued, 24-hour TTL, rotated every 12 hours.
- **Monitoring:** Istio's certificate expiration metrics shipped to Prometheus; alerts on rotation failures.

### Migration story

Meridian's clusters originally had no service mesh. Adoption in 2024 over 8 sprints:

- Sprints 1–2: Istio control plane install; permissive mode mesh-wide.
- Sprints 3–4: progressive sidecar injection (one namespace at a time); verify each namespace works.
- Sprints 5–6: per-namespace switch to STRICT mode.
- Sprint 7: default-deny AuthorizationPolicy mesh-wide; per-service allow policies authored.
- Sprint 8: Vault PKI integration; Ambient mode migration begun.

### Findings opened during the service-mesh audit

- **MESH-001** (mTLS was in permissive mode mesh-wide; many services still on plaintext). Closed by namespace-by-namespace strict migration.
- **MESH-002** (no AuthorizationPolicy; mTLS authenticated but didn't authorize). Closed by default-deny + per-service allows.
- **MESH-003** (Istio built-in CA used without rotation oversight). Closed by Vault PKI integration + rotation monitoring.
- **MESH-004** (sidecar overhead caused latency issues for one critical path). Closed by Ambient mode migration; latency reduced significantly.
- **MESH-005** (no observability on policy denials; legitimate denials and attempted-bypass indistinguishable). Closed by AuthorizationPolicy denial logs to SIEM.

---

## Anti-patterns

### 1. The permanent permissive mode

mTLS is in permissive mode "to allow gradual migration." Years later, still permissive. The mesh provides no security guarantee.

The fix: planned migration to strict; per-namespace cutover; verified before next namespace.

### 2. The mesh-without-policy

mTLS is on; AuthorizationPolicy isn't. Workloads authenticated but anyone-authenticated-can-do-anything. The mesh's authz feature is unused.

The fix: default-deny AuthorizationPolicy; per-service allows.

### 3. The forgotten certificate rotation

The CA rotates certificates with a long TTL; the rotation mechanism breaks; certificates eventually expire; mesh connections fail.

The fix: short TTL (24 hours); rotation monitoring; alerts on rotation failures.

### 4. The mesh-for-observability-only

The team adopts Istio for the observability features but doesn't use mTLS or AuthorizationPolicy. The operational cost is paid for a fraction of the value.

The fix: adopt the security features too; otherwise simpler observability tools provide the same observability at lower cost.

### 5. The over-broad AuthorizationPolicy

A policy allows `*` from `*` "for development." Migration to tight policies never happens; production runs the dev-permissive policy.

The fix: dev-tight policies enforced; production policies are tightenings, not loosenings.

### 6. The sidecar that didn't inject

The mesh requires the sidecar; some pods don't get the injection (missing namespace label, missing annotation). Those pods are out-of-mesh; mTLS doesn't apply.

The fix: admission policy that requires the sidecar (Istio's `sidecar.istio.io/inject: "true"` annotation enforced; pods missing it are rejected or auto-annotated).

### 7. The mesh as the only security layer

The team relies entirely on mesh policy. NetworkPolicy is omitted; admission control is weak; pod security is loose. The mesh is one compromise from being bypassed (e.g., via host network mode if not restricted).

The fix: defense-in-depth. Mesh is one layer; NetworkPolicy, admission, pod security are the others.

### 8. The cross-cluster mesh without federation

Two clusters; each has its own mesh; they need to communicate. Without proper federation, the mesh boundaries are unclear; mTLS doesn't traverse cleanly.

The fix: multi-cluster mesh configuration with SPIFFE federation; explicit trust domain bridging.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| MESH-001 | Mesh in permissive mTLS mode without migration timeline | High | Plan namespace-by-namespace strict migration; verify each before next | Platform Eng + Security Eng |
| MESH-002 | No AuthorizationPolicy; mTLS authenticated but authz absent | High | Default-deny AuthorizationPolicy; per-service allows | Platform Eng + Security Eng |
| MESH-003 | Certificate rotation TTL too long (multi-day or weeks) | Medium | Reduce to 24 hours; verify rotation working | Security Eng + Platform Eng |
| MESH-004 | Certificate rotation failures unmonitored | High | Alert on rotation failures; certificate expiration metrics shipped to SIEM | Security Eng + Platform Eng |
| MESH-005 | Pods missing sidecar injection; out-of-mesh | Medium | Admission policy enforces sidecar annotation; auto-injection where namespaces enabled | Platform Eng |
| MESH-006 | Mesh adopted for observability; security features (mTLS, authz) unused | Medium | Adopt security features; otherwise consider simpler observability tools | Architecture + Security Eng |
| MESH-007 | AuthorizationPolicy uses wildcards (`*` from `*`); decorative | Medium | Tighten policies; per-source-principal scoping | Security Eng |
| MESH-008 | AuthorizationPolicy denials not logged to SIEM | Medium | Logs to SIEM; alert on patterns suggesting attempted bypass | Security Eng + SOC |
| MESH-009 | Mesh as only security layer; NetworkPolicy / admission absent | High | Defense-in-depth: NetworkPolicy + admission control + mesh | Platform Eng + Security Eng |
| MESH-010 | Multi-cluster mesh without SPIFFE federation | Medium | Configure trust-domain federation; explicit cross-cluster policies | Platform Eng + Security Eng |
| MESH-011 | Mesh CA is built-in without enterprise integration; rotation manual | Low | Integrate with Vault PKI / AWS Private CA / cloud KMS-backed CA | Platform Eng + Security Eng |
| MESH-012 | Sidecar overhead causes latency issues; no Ambient mode evaluation | Low | Evaluate Ambient mode for latency-critical workloads | Platform Eng + SRE |
| MESH-013 | mTLS migration moved fast; some workloads broken silently | Medium | Migration includes verification per service; rollback procedure | Platform Eng + Workload Owner |
| MESH-014 | External traffic enters mesh without mTLS at the gateway | Medium | Ingress gateway enforces TLS; external clients use mTLS for high-assurance | Platform Eng + Security Eng |
| MESH-015 | Per-service AuthorizationPolicy not version-controlled | Medium | IaC; policy changes via PR review | Platform Eng + Security Eng |
| MESH-016 | Mesh's CA private key on a shared filesystem; protection insufficient | High | CA key in HSM or KMS-backed storage; restrict access | Security Eng + Platform Eng |
| MESH-017 | No tabletop on mesh-failure scenarios; mTLS failure response unclear | Low | Tabletop on CA outage, certificate expiration, mesh failure | Security Eng + SRE |
| MESH-018 | Service mesh adopted in environment with <10 services; operational cost unjustified | Low | Evaluate; consider deferring mesh adoption until cluster scales | Architecture |

---

## What this document is not

- **A complete Istio / Linkerd reference.** Vendor documentation covers operational depth.
- **A traffic-management reference.** Mesh's traffic-management capabilities (canary, fault injection, retries) are mentioned only where they intersect with security.
- **A SPIFFE deep dive.** SPIFFE / SPIRE deserve their own document; this covers the basics.
- **An Ambient mode tutorial.** Istio Ambient is mentioned as the lower-overhead option; deep adoption guidance is in Istio's documentation.
