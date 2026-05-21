# Kubernetes and Container Security

## What this folder is

A practitioner's reference for securing Kubernetes platforms and the container supply chain on AWS, Azure, and GCP — EKS / AKS / GKE baselines, pod security, network policies, admission control, runtime detection, service mesh, image signing, and supply-chain attestation. The material here is what I put in front of a platform team when the question is: *we are running a multi-tenant Kubernetes cluster for the rest of the engineering organization — what is our responsibility versus theirs, and how do we enforce the boundary?*

## The organizing principle

Kubernetes security is a platform-layer problem with an application-layer interface. The platform team is responsible for the controls the application teams above them cannot retrofit — pod security policies, network policies, admission control, runtime detection, image registry security, image signing enforcement, node hardening. The application teams are responsible for what runs inside the pods. A Kubernetes platform that does not enforce the platform-layer responsibilities cleanly will see those responsibilities silently transfer to the application teams, who are not staffed to do them and will not do them well.

The folder is opinionated about three things. First, that **Pod Security Admission with the `restricted` profile is the correct default** for new workloads — the PodSecurityPolicy era is over, and the migration to Pod Security Admission has been done badly in many environments because the migration was treated as a like-for-like rather than as an opportunity to tighten. Second, that **NetworkPolicy default-deny at the namespace level is non-negotiable** for any multi-tenant cluster — the failure mode of a permissive default is lateral movement during a workload compromise, and the cost of enforcing default-deny is a one-time migration that pays for itself the first time it prevents an incident. Third, that **image signing with Cosign / Sigstore should be enforced at admission, not advised at build** — an admission policy that rejects unsigned images is the difference between a supply chain attack you might catch in a post-incident review and one you prevent.

## Planned documents

- **eks-aks-gke-baselines.md** *(coming)* — EKS / AKS / GKE security baseline side by side: cluster authentication (IRSA, Workload Identity, AKS workload identity), control-plane access (public vs private endpoints), node-group hardening, audit log configuration, automatic upgrades, the four detective controls every cluster should have.
- **pod-security.md** *(coming)* — Pod Security Admission (`restricted` / `baseline` / `privileged` profiles), the PSP-to-PSA migration playbook, namespace labeling strategy, exemptions and how to grant them safely. The privileged-pod inventory pattern that every multi-tenant platform should run quarterly.
- **network-policies.md** *(coming)* — Calico, Cilium, native Kubernetes NetworkPolicy. Default-deny at the namespace level. Egress policies as a hard requirement. The "two NetworkPolicies per namespace minimum" baseline. Cilium-specific patterns (CiliumNetworkPolicy, FQDN-based egress, L7 policy).
- **admission-control.md** *(coming)* — OPA / Gatekeeper, Kyverno, ValidatingAdmissionPolicy (CEL). Policy as code for Kubernetes. The constraint-templates / policies pattern. Common policies (no privileged pods, signed images required, resource limits required, no NodePort services, no default service account use, no `:latest` tag).
- **runtime-security.md** *(coming)* — Falco, Tetragon, eBPF-based runtime detection. Rule selection: high-signal rules vs noisy ones, the rule-tuning workflow, integration with detection-and-response, the runtime-detection-vs-EDR boundary in container environments.
- **service-mesh-security.md** *(coming)* — Istio, Linkerd, mTLS-by-default, AuthorizationPolicy for service-to-service authn, the SPIFFE / SPIRE identity story, when service mesh is worth the operational cost and when it is not.
- **image-supply-chain.md** *(coming)* — Image scanning (Trivy, Grype, vendor scanners), registry security (private registries, immutable tags, retention), Cosign / Sigstore signing, SLSA provenance, the keyless-signing-with-OIDC pattern, in-toto attestation, admission-controlled image policy.
- **secrets-in-kubernetes.md** *(coming)* — Why etcd-stored Secrets are not secret without KMS envelope encryption, External Secrets Operator, SOPS, sealed-secrets, the workload-identity-to-secrets-manager pattern that obviates Kubernetes Secrets entirely.
- **multi-tenant-cluster-design.md** *(coming)* — Namespace-per-tenant vs cluster-per-tenant vs virtual-cluster-per-tenant. The four-level tenancy model. Resource quotas, LimitRanges, PriorityClasses, NetworkPolicy tenant isolation, RBAC tenant isolation.

## How to use this section

**If you are standing up a new cluster**, `eks-aks-gke-baselines.md` and `pod-security.md` together cover the platform-layer responsibilities you need to land before the first workload arrives. `network-policies.md` is the third one — default-deny is much cheaper to land before the workloads do than after.

**If you are operating a multi-tenant cluster**, `multi-tenant-cluster-design.md` is the destination. The tenancy decisions are hard to reverse; making them explicitly is cheaper than making them implicitly.

**If you are tightening an existing cluster's supply chain**, `image-supply-chain.md` is the playbook. The Cosign-signed-images-required-at-admission pattern is the single highest-leverage move; everything else is incremental.

## What this section is not

- **A Kubernetes administration guide.** Cluster operations (upgrades, autoscaling, observability) appear only where they intersect with security. For pure operations, the vendor documentation and the upstream Kubernetes docs are more current.
- **A complete service mesh tutorial.** Istio and Linkerd appear because they implement patterns the folder describes (mTLS-by-default, AuthorizationPolicy). The folder is not a service-mesh adoption manual.
