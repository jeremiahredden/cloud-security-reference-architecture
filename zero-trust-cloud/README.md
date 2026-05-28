# Zero Trust Cloud

## What this folder is

A practitioner's reference for implementing Zero Trust patterns in cloud environments — identity-aware access proxies, microsegmentation, service-to-service identity with SPIFFE / SPIRE, mTLS service mesh, and continuous authorization. The material here is what I put in front of a team when the question is: *the leadership wants a Zero Trust roadmap, the budget will not buy a Zero Trust platform, and the existing network has VPNs that everyone uses — what do we actually adopt, in what order?*

## The organizing principle

Zero Trust in cloud is mostly a wiring exercise on top of capabilities that the platform already provides. Identity-aware proxies are productized (Cloudflare Access, AWS Verified Access, GCP Identity-Aware Proxy). Workload identity is native (IRSA, Workload Identity Federation, Azure Managed Identities). mTLS-by-default is one Istio / Linkerd installation away. The patterns are well-understood. The reason most Zero Trust programs stall is not a missing capability — it is the absence of an adoption sequence that lets a team retire the legacy posture incrementally without an all-or-nothing cutover.

The folder is opinionated about three things. First, that **Zero Trust is a posture, not a product** — any document that recommends purchasing a "Zero Trust platform" without naming the specific control it implements is selling a narrative. The patterns here are component-level (identity-aware access, mTLS, microsegmentation, continuous authorization) and the procurement decisions land at the component layer. Second, that **the order of adoption matters more than the destination** — workforce identity-aware access first (because it retires the corporate VPN, which is the most user-visible win), then workload identity (because it retires long-lived service-account secrets), then mTLS-by-default (because it raises the bar on lateral movement), then microsegmentation (because it requires the previous three to be useful). Third, that **continuous authorization is the under-engineered control in 2026** — most teams adopt the identity-aware access piece and stop there; the policies remain coarse and largely point-in-time, and the BeyondCorp vision of continuous device-and-context-aware authorization gets quietly deferred.

## Planned documents

- **[identity-aware-access.md](./identity-aware-access.md)** — Cloudflare Access, AWS Verified Access, GCP Identity-Aware Proxy, and the homegrown identity-aware-proxy patterns (envoyproxy + JWT, nginx + auth-request). The retire-the-corporate-VPN adoption sequence. The user-experience trade-offs that determine whether the rollout succeeds.
- **workload-identity-zt.md** *(coming)* — Workload-identity-as-Zero-Trust-foundation. SPIFFE / SPIRE for service identity, Istio AuthorizationPolicy keyed off SPIFFE IDs, the cross-cluster / cross-cloud identity federation patterns, and the "every service has an identity, every call is authenticated" baseline.
- **microsegmentation.md** *(coming)* — Microsegmentation in cloud: VPC + security groups vs Kubernetes NetworkPolicy vs service mesh AuthorizationPolicy vs identity-aware-proxy enforcement. The four-tier microsegmentation model. The "north-south is the perimeter, east-west is the lateral-movement budget" framing.
- **mtls-everywhere.md** *(coming)* — Service-mesh mTLS-by-default (Istio, Linkerd, Consul), application-layer mTLS for services outside the mesh, the certificate-lifecycle patterns (SPIRE-issued, ACM Private CA, Vault PKI). The mTLS-without-rotation-is-not-mTLS baseline.
- **continuous-authorization.md** *(coming)* — Continuous authorization patterns: device-trust signals (Okta Verify, Entra Conditional Access, Cloudflare Zero Trust), session re-evaluation, the step-up-authn pattern. The OPA-as-policy-decision-point reference architecture. The under-engineered controls that most ZT programs defer.
- **zt-adoption-sequence.md** *(coming)* — The six-month Zero Trust adoption plan: month one, identity-aware access for the highest-value internal application; month two, retire the corporate VPN for that user population; month three, workload-identity migration off long-lived keys; month four, mTLS-by-default in the production cluster; months five and six, microsegmentation and continuous authorization. With the success criteria at each milestone.
- **beyondcorp-on-existing-stack.md** *(coming)* — How to land the BeyondCorp vision without ripping out the existing network or buying a new platform. The "additive overlay" pattern. The conditions under which a greenfield ZT platform is the right answer and the conditions under which it is not.

## How to use this section

**If you are starting a Zero Trust adoption**, `zt-adoption-sequence.md` is the planning document. The six-month sequence is opinionated about ordering; the order matters because each milestone enables the next.

**If you are evaluating identity-aware-access products**, `identity-aware-access.md` includes the comparison and the decision criteria. The honest answer is "any of the three major options work; pick the one whose user-experience trade-offs match your environment."

**If you are landing service-mesh mTLS**, `mtls-everywhere.md` covers the patterns and the certificate-lifecycle decisions. Most service-mesh mTLS rollouts fail not on the cryptography but on the rotation operations.

## What this section is not

- **A Zero Trust maturity-model walkthrough.** NIST SP 800-207 and the CISA Zero Trust Maturity Model are referenced, not reproduced. The folder is about implementation patterns, not about maturity-model scoring.
- **A complete service-mesh adoption manual.** Istio and Linkerd appear because they implement Zero Trust patterns; the folder is not a service-mesh administration guide.
- **A vendor comparison.** Where products are named, they illustrate patterns. The folder is agnostic on procurement choice within a given pattern.
