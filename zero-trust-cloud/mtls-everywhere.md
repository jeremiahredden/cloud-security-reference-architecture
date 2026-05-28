# mTLS Everywhere

A practitioner's reference for mutual TLS as a Zero Trust posture — service-mesh mTLS-by-default (Istio, Linkerd, Consul), application-layer mTLS for services outside the mesh, the certificate-lifecycle patterns (SPIRE-issued, ACM Private CA, Vault PKI), and the baseline that mTLS-without-rotation-is-not-mTLS. The patterns here cover what it takes to get to genuine end-to-end mutual authentication, beyond the partial deployments that most organizations stop at.

This document is the unifying view across mTLS patterns in this folder. Service-mesh mTLS is in [../kubernetes-and-container-security/service-mesh-security.md](../kubernetes-and-container-security/service-mesh-security.md); SPIFFE identity is in [workload-identity-zt.md](./workload-identity-zt.md); mTLS at the cluster boundary requires both. This document is about the broader pattern: mTLS at every workload-to-workload boundary, including the ones the mesh doesn't cover.

For the workload identity that issues the certificates, see [workload-identity-zt.md](./workload-identity-zt.md). For the mesh-specific patterns, see [../kubernetes-and-container-security/service-mesh-security.md](../kubernetes-and-container-security/service-mesh-security.md). For the broader KMS and PKI patterns, see [../secrets-and-keys/](../secrets-and-keys/).

---

## When to read this document

**If you have service-mesh mTLS but services outside the mesh use plaintext** — read top to bottom. The non-mesh tail is the gap.

**If you've implemented mTLS but rotation is manual or broken** — start with [mTLS without rotation is not mTLS](#mtls-without-rotation-is-not-mtls). Static certificates aren't a real security posture.

**If you are evaluating PKI options (Vault PKI, ACM PCA, SPIRE)** — start with [Certificate authority options](#certificate-authority-options).

**If you are auditing mTLS posture** — start with [Findings checklist](#findings-checklist).

---

## What mTLS provides at each layer

mTLS extends standard TLS with client authentication:

- **TLS:** client authenticates the server (server presents a certificate).
- **mTLS:** client also authenticates itself to the server (client presents a certificate).

The security benefits:

- **Identity binding:** both ends prove their identity cryptographically.
- **Authentication-without-passwords:** no shared secrets, no API tokens at the connection layer.
- **Replay protection:** TLS session keys are unique per connection.
- **MITM defense:** an attacker positioned between client and server can't impersonate either without compromising a key.

For Zero Trust: mTLS is the wire-level enforcement of "every call is authenticated."

---

## What the mesh covers (and doesn't)

Service-mesh mTLS is the dominant pattern; it covers a specific scope.

### What in-mesh covers

- Sidecar-injected pods (Istio, Linkerd default).
- Ambient-mode pods (Istio Ambient).
- Pods that explicitly opt into the mesh via annotation.

For these workloads, mTLS is automatic. The sidecar (or ztunnel in Ambient mode) handles SVID fetch, mTLS negotiation, certificate validation. Application code is unaware.

### What in-mesh doesn't cover

- **Pods not in the mesh** (no sidecar, no annotation).
- **External services** (SaaS, cloud APIs reached over the internet).
- **Workloads outside Kubernetes** (EC2, VM-based, serverless).
- **Cross-cluster paths without mesh federation.**
- **Ingress from outside the mesh** (the ingress gateway terminates external TLS; mTLS to external clients requires explicit configuration).
- **Egress to non-mesh destinations** (the mesh's egress gateway may or may not enforce mTLS to the destination).

For genuine mTLS everywhere: each of these gaps needs an explicit pattern.

---

## Non-mesh patterns

For services not in a mesh, mTLS requires explicit application-layer integration.

### Pattern 1: SPIFFE SDK direct integration

The application calls the SPIFFE Workload API to get its SVID; uses it for mTLS:

```go
import (
    "github.com/spiffe/go-spiffe/v2/workloadapi"
    "github.com/spiffe/go-spiffe/v2/spiffetls"
)

func main() {
    ctx := context.Background()
    source, err := workloadapi.NewX509Source(ctx)
    defer source.Close()

    // Listen with mTLS, verifying client SPIFFE IDs
    listener, err := spiffetls.Listen(ctx, "tcp", ":8443",
        spiffetls.MTLSServerWithSourceAndAuthorizer(source, source, /* authorizer */))
    // Handle connections
}
```

Pros: standard SPIFFE; identity-aware; works with SPIRE.

Cons: application code change; SDK availability depends on language.

### Pattern 2: Sidecar pattern outside Kubernetes

For VMs: deploy a SPIRE Agent on the VM; use a local sidecar proxy (Envoy, ghostunnel) that handles mTLS for the application. Application speaks plaintext to localhost; sidecar wraps in mTLS.

Pros: language-agnostic; minimal application change.

Cons: extra process per VM; requires SPIRE Agent on every VM.

### Pattern 3: Application-managed mTLS with PKI

The application is configured with a CA and client certificate (issued from Vault PKI, ACM PCA, etc.). Standard TLS libraries handle the mTLS.

Pros: standard TLS code; no SPIFFE dependency.

Cons: certificate distribution and rotation become application concerns; less standard than SPIFFE.

### Pattern 4: AWS App Mesh / GCP equivalent

Cloud-vendor managed mesh that extends to VMs and serverless. Includes mTLS configuration as part of the mesh.

Pros: managed service; vendor handles rotation.

Cons: vendor-specific; portability concerns.

---

## mTLS at the ingress

External clients reaching internal services via ingress.

### Standard TLS at ingress (the common pattern)

- External client uses standard TLS to the ingress gateway / load balancer.
- The gateway terminates TLS.
- Inside the cluster, traffic flows via mTLS (mesh).

The pattern is acceptable for most workforce-facing applications.

### mTLS at ingress (for higher-assurance scenarios)

For machine-to-machine ingress (e.g., partner integrations, B2B APIs):

- External client presents a client certificate at the ingress gateway.
- Gateway verifies the certificate (typically from a partner-specific CA).
- Authenticated request flows into the cluster.

The pattern: AWS API Gateway with mTLS, Cloudflare Access with mTLS, Istio ingress gateway with mTLS configuration.

### Per-partner mTLS

For organizations with many B2B partners:

- Each partner has a CA registered with the ingress gateway.
- Per-partner authorization policies.
- Partner certificate rotation coordinated with each partner.

The operational discipline is meaningful; the security improvement is real for sensitive integrations.

---

## mTLS at the egress

Calls from the workload to external services.

### Egress to vendor APIs (the common case)

Most vendor APIs accept standard TLS (server-side authentication only). The application uses standard HTTPS; the vendor's certificate is validated.

The workload presents no certificate to the vendor; the vendor's identity is validated; the request is authenticated by other means (OAuth token, API key).

This is fine for most vendor integrations.

### Egress with mTLS to specific destinations

For high-trust destinations (specific vendors, cross-organization integrations):

- The application presents a client certificate.
- The vendor validates the certificate.
- Authentication is identity-based, not token-based.

Examples:

- **Anthropic's mTLS for high-security customers.**
- **Banking APIs requiring mTLS.**
- **B2B integrations where both parties want mutual authentication.**

The pattern: the workload's client certificate is issued by a known CA; the vendor's allowlist includes the workload's identity.

---

## Certificate authority options

The CA choices for mTLS infrastructure.

### Mesh built-in CAs

- **Istio `istiod`:** built-in CA by default; signs SVIDs for sidecars.
- **Linkerd Identity:** Linkerd's built-in identity component.
- **Consul Connect:** Consul as CA.

Pros: simple; integrated with the mesh.

Cons: cluster-bound; rotation tied to mesh upgrades; not suitable for cross-cluster or non-mesh use cases.

### SPIRE

The reference SPIFFE issuer; covered in [workload-identity-zt.md](./workload-identity-zt.md).

Pros: portable across environments; strong attestation; multi-cluster federation.

Cons: SPIRE is a service to operate; separate from the mesh.

### Vault PKI

HashiCorp Vault's PKI engine as the CA:

```bash
vault write pki/roles/care-coordinator-internal \
  allowed_domains="*.care-coordinator.svc.cluster.local,care-coordinator.meridian.health" \
  allow_subdomains=true \
  max_ttl="24h"
```

Workloads authenticate to Vault and request certificates.

Pros: integrated with broader Vault ecosystem; flexible policy.

Cons: Vault is a service to operate; not SPIFFE-native (though Vault can issue SPIFFE-format certs).

### AWS Private CA (ACM Private CA)

Cloud-managed CA:

- AWS-managed; per-cert pricing.
- Integrates with ACM for cloud-native resources.
- Can issue certificates for any use.

Pros: managed service; cloud-native.

Cons: AWS-specific; cost can compound at scale.

### Public CAs (Let's Encrypt, DigiCert) for some use cases

For external-facing certificates that need public trust (e.g., ingress with public TLS). Not used for internal mTLS.

### The decision

For most teams:

- **In-mesh internal mTLS:** mesh built-in CA is sufficient.
- **Cross-cluster / non-mesh internal mTLS:** SPIRE or Vault PKI.
- **External-facing TLS:** public CA (Let's Encrypt, DigiCert).
- **External-facing mTLS (B2B):** ACM PCA or Vault PKI; per-partner trust.

References:
- [Vault PKI engine](https://developer.hashicorp.com/vault/docs/secrets/pki)
- [AWS Private CA](https://docs.aws.amazon.com/privateca/latest/userguide/)
- [SPIRE](https://spiffe.io/docs/latest/spire-about/)

---

## mTLS without rotation is not mTLS

The pattern that makes mTLS theater.

### What can go wrong without rotation

- A static long-lived certificate is essentially a long-lived shared secret.
- If compromised, no recovery without manual rotation (which the team isn't doing because rotation was never set up).
- Long-lived certificates accumulate; expired certificates break workloads silently.

### What rotation should look like

- **Short TTLs:** 24 hours is typical for mesh-issued certificates; some patterns go shorter (1 hour).
- **Automatic:** the mesh or PKI client handles rotation; no human intervention.
- **Tested:** rotation is exercised in non-prod; failures are visible.

### Monitoring rotation

- **Per-workload certificate expiration metric.**
- **Alert when certificates approach expiration without rotation.**
- **Alert on rotation failures** (e.g., CA outage, network issue).
- **SVID issuance rate metric** (rotation cadence at scale).

For Istio: `istio_request_certs_total`, `istio_cert_expiry_seconds` metrics.

For SPIRE: SPIRE Agent and Server metrics.

### The forgotten-rotation failure mode

A common production failure:

- The mesh CA's intermediate certificate expires.
- All sidecars' SVIDs become invalid.
- mTLS connections fail.
- The cluster degrades.

The fix: CA certificate rotation is itself a lifecycle event; monitor CA expiration; rotate CAs on schedule.

### Per-call cert validation

mTLS validates certificates at connection establishment. For long-lived connections:

- The validation happens once.
- A certificate revoked mid-connection isn't immediately re-validated.

For high-assurance use cases: configure short connection timeouts; per-request re-validation; OCSP / CRL integration.

---

## Mixed mesh and non-mesh environments

Most production environments have a mix: meshed pods, non-meshed pods, VMs, serverless. The integration patterns.

### The hybrid pattern

- **Meshed pods:** standard mesh mTLS.
- **Non-meshed Kubernetes pods:** SPIFFE SDK direct integration; SPIRE issues SVIDs.
- **VMs:** SPIRE Agent on the VM; SPIFFE SDK or sidecar.
- **Serverless:** application-layer mTLS where supported; AWS Lambda or similar with custom certificate fetch.

The identity layer (SPIFFE / SPIRE) is the unifier. The data-plane enforcement varies per workload type but the identity is consistent.

### The trust domain alignment

For mixed environments to authenticate cross-type:

- All workload types share a trust domain.
- SPIRE attests each workload type via its specific attestation mechanism.
- AuthorizationPolicies reference SPIFFE IDs regardless of workload type.

### The legacy fallback

For legacy services that can't be migrated to SPIFFE or modernized:

- Application-layer mTLS with traditional PKI.
- Workload's certificate fetched from Vault or similar at startup.
- Rotation handled by application or by config-management tooling.

Acceptable as a tail; not the target pattern.

---

## Worked example: Meridian Health's mTLS posture

Meridian runs mTLS across meshed Kubernetes pods, non-meshed legacy services, EC2 workloads, and B2B integrations.

### In-mesh mTLS (Istio Ambient)

- Istio Ambient mode mesh-wide.
- mTLS STRICT mode enforced.
- SPIRE-issued SVIDs (per [workload-identity-zt.md](./workload-identity-zt.md)).
- AuthorizationPolicies reference SPIFFE IDs.
- Certificate TTL: 1 hour; rotation automatic.

### Non-meshed Kubernetes pods

A few pods (mostly stateful workloads with sidecar incompatibilities) run outside the mesh. They use SPIRE SDK directly:

- SPIRE Agent DaemonSet provides Workload API socket.
- Application code uses go-spiffe / py-spiffe for SVID fetch + mTLS.
- Server-side validation includes SPIFFE ID authorization.

### EC2 workloads

Legacy services on EC2 (some integrations that pre-date Kubernetes):

- SPIRE Agent installed on each EC2 instance.
- Attestation via AWS instance identity document.
- Application uses SPIFFE SDK; integrates into the same trust domain as Kubernetes workloads.

### B2B partners

For external partner integrations:

- AWS API Gateway with mTLS at the partner's edge.
- Per-partner CA registered.
- Partner certificate rotation coordinated 30 days in advance.

### Internal-to-internal cross-domain

For specific cross-environment integrations (e.g., a partner's workloads needing to reach Meridian's internal services):

- SPIRE federation between trust domains.
- Explicit policies for the specific cross-domain flows.
- Documented and quarterly-reviewed.

### Certificate-rotation monitoring

- Per-workload SVID expiration metric in Prometheus.
- Grafana dashboard showing certificates approaching expiration.
- Alert when a workload's SVID hasn't rotated in 90 minutes (TTL is 60; should rotate well before).
- Quarterly CA certificate rotation drill.

### Findings opened during the mTLS audit

- **MTLS-001** (non-meshed pods used plaintext; mesh covered most but not all). Closed by SPIRE SDK integration for non-mesh services.
- **MTLS-002** (EC2 workloads used static credentials for internal calls; no mTLS). Closed by SPIRE Agent on EC2.
- **MTLS-003** (B2B integrations used IP allowlists + API keys; no mTLS). Closed by API Gateway mTLS with per-partner CA.
- **MTLS-004** (certificate TTL was 7 days; rotation issues less visible). Closed by reducing TTL to 1 hour.
- **MTLS-005** (no monitoring on CA-certificate expiration; intermediate CA had 1 month to expiration when found). Closed by automated CA rotation monitoring.
- **MTLS-006** (cross-cluster paths bypassed mesh; no mTLS). Closed by mesh multi-cluster federation.

---

## Anti-patterns

### 1. The mesh-only mTLS

mTLS is on for in-mesh services; non-mesh services use plaintext. The Zero Trust posture is partial.

The fix: SPIRE-based mTLS for non-mesh services; all workloads have certificates.

### 2. The forever-permissive mode

mTLS is configured in permissive mode (server accepts both mTLS and plaintext) "to allow gradual migration." Migration to strict never happens.

The fix: explicit timeline to strict; per-namespace cutover.

### 3. The long-TTL certificate

Certificate TTL is days or weeks. Rotation is rare; CA compromise has long blast radius.

The fix: TTL of 24 hours or shorter; automatic rotation.

### 4. The manual rotation

Rotation requires manual intervention. The team forgets; certificates expire; services break.

The fix: automatic rotation; rotation monitoring; alerts on failures.

### 5. The CA-without-rotation

The CA certificate itself has a long life and isn't actively monitored. Eventually the CA expires; all workloads' SVIDs become invalid simultaneously.

The fix: CA certificate rotation as a lifecycle event; multi-year scheduled rotation; tested in non-prod.

### 6. The plaintext-egress to vendor APIs

Internal mTLS is in place. Egress to vendor APIs over plaintext HTTPS (server-TLS only). The vendor connections are an audit gap.

The fix: TLS for vendor APIs is standard; mTLS for high-trust vendors where supported.

### 7. The cross-cluster mesh-not-federated

Two clusters; each has its own mesh; cross-cluster paths use plaintext or partial mTLS.

The fix: mesh multi-cluster configuration or SPIFFE federation across clusters.

### 8. The application-mTLS-without-validation

Application uses mTLS but doesn't validate the peer certificate (or validates only chain, not specific identity). An attacker with any valid cert can connect.

The fix: peer-identity validation; SPIFFE ID match; specific allowed-issuer trust.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| MTLS-001 | Non-meshed services use plaintext for inter-service communication | High | SPIRE SDK integration; all workloads have certificates | Platform Eng + Workload Owner |
| MTLS-002 | EC2 / VM workloads use static credentials; no mTLS | High | SPIRE Agent on VMs; SPIFFE SDK in applications | Platform Eng + Workload Owner |
| MTLS-003 | B2B integrations use API keys or IP allowlists without mTLS | Medium | Migrate to mTLS-at-ingress with per-partner CA | Platform Eng + Architecture |
| MTLS-004 | Certificate TTL too long (multi-day or weeks) | Medium | Reduce to 24 hours or shorter; verify rotation working | Security Eng + Platform Eng |
| MTLS-005 | Certificate rotation manual; failures lead to outages | High | Automatic rotation; monitor rotation success / failure | Platform Eng + SRE |
| MTLS-006 | Cross-cluster paths bypass mesh; no mTLS | Medium | Mesh multi-cluster configuration or SPIFFE federation | Platform Eng + Architecture |
| MTLS-007 | mTLS in permissive mode without migration timeline | Medium | Planned migration to strict; namespace-by-namespace | Platform Eng + Security Eng |
| MTLS-008 | CA certificate rotation not monitored; potential mass-expiration | High | CA rotation as lifecycle event; monitor; multi-year schedule | Security Eng + Platform Eng |
| MTLS-009 | Application-mTLS doesn't validate peer identity (any-cert-acceptable) | High | Peer identity validation; SPIFFE ID match or specific issuer | Workload Owner + Security Eng |
| MTLS-010 | Egress to vendor APIs not part of mTLS posture | Low | Document vendor-API trust model; mTLS where supported | Security Eng + Architecture |
| MTLS-011 | Long-lived connections don't re-validate certificates mid-connection | Low | Short connection timeouts where high-assurance; OCSP integration | Security Eng + Workload Owner |
| MTLS-012 | mTLS observability absent; certificate health invisible | Medium | Per-workload certificate metrics; dashboard; alerts | Platform Eng + Observability |
| MTLS-013 | Per-workload SVID isn't bound to workload attestation (any-pod-with-SA gets identity) | Medium | Image-hash binding via SPIRE selectors per [workload-identity-zt.md](./workload-identity-zt.md) | Security Eng |
| MTLS-014 | Multiple CA hierarchies without rationalization; complexity | Low | Document CA hierarchy; consolidate where possible | Architecture + Security Eng |
| MTLS-015 | Public CA used for internal mTLS; unnecessary external dependency | Low | Internal CA (SPIRE, Vault PKI, ACM PCA) for internal mTLS | Security Eng |
| MTLS-016 | mTLS for HTTP/HTTPS only; other protocols (gRPC, custom) not mTLS-protected | Medium | mTLS at all protocols where workload-to-workload | Workload Owner + Security Eng |
| MTLS-017 | Certificate revocation not implemented; compromised certificates remain valid | Medium | OCSP / CRL integration; short TTL is the primary mitigation | Security Eng |
| MTLS-018 | Serverless / FaaS workloads not in mTLS posture | Medium | Application-layer mTLS where supported; identity propagation via JWT | Workload Owner + Architecture |

---

## What this document is not

- **A TLS / cryptography reference.** TLS handshake mechanics, cipher suites, and protocol versions are out of scope.
- **A complete PKI tutorial.** PKI hierarchy design depth lives in dedicated PKI documentation.
- **A vendor mesh comparison.** Mesh-specific patterns live in [../kubernetes-and-container-security/service-mesh-security.md](../kubernetes-and-container-security/service-mesh-security.md).
- **A SPIRE administration guide.** SPIRE operational depth lives with the SPIRE project.
