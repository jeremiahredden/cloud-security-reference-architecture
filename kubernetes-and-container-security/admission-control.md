# Admission Control

A practitioner's reference for Kubernetes admission control as policy enforcement — OPA / Gatekeeper, Kyverno, ValidatingAdmissionPolicy (CEL), and the common policies every multi-tenant cluster should enforce (no privileged pods, signed images required, resource limits required, no NodePort services, no default service account use, no `:latest` tag, etc.). The patterns here are about policy-as-code at the cluster's intake point — the place where every resource creation is evaluated against organizational rules.

This document is the platform-team's enforcement leverage. Pod Security Admission ([pod-security.md](./pod-security.md)) handles a narrow set of pod-level security; admission-control is where the broader organizational policies live. Image signature requirements, naming conventions, label requirements, RBAC restrictions, network-policy presence, resource-limit requirements — all enforced at admission.

For the policies that NetworkPolicy enforces, see [network-policies.md](./network-policies.md). For image-signing specifically, see [image-supply-chain.md](./image-supply-chain.md).

---

## When to read this document

**If your cluster has no admission-control policies beyond PSA** — read top to bottom. The pattern is high-leverage; the install is bounded.

**If you are choosing between OPA Gatekeeper, Kyverno, and ValidatingAdmissionPolicy** — start with [The tool choice](#the-tool-choice). The three solve overlapping problems with different operational characteristics.

**If you have admission policies but they routinely warn rather than block** — start with [The enforce-vs-warn discipline](#the-enforce-vs-warn-discipline). Warning-only policies are decoration.

**If you are auditing admission control posture** — start with [Findings checklist](#findings-checklist).

---

## What admission control is

Kubernetes admission controllers run after a request is authenticated and authorized but before it's persisted to etcd. They can:

- **Validate** — accept or reject based on the resource content.
- **Mutate** — modify the resource before persistence (add defaults, inject sidecars, label).

Admission controllers run for every `kubectl apply`, every CI/CD deployment, every controller-driven resource creation. They are the chokepoint where policy is enforced.

### Built-in admission controllers

Kubernetes ships with several built-in admission controllers (NamespaceLifecycle, LimitRanger, ResourceQuota, Pod Security Admission, etc.). They handle well-defined policies; for custom organizational policies, the team adds an admission-policy framework.

### Why admission control matters

- **Prevention beats detection.** A policy violation rejected at admission never exists in the cluster; a violation that lands and is detected later requires remediation.
- **Consistent enforcement.** Every resource creation goes through admission; no escape hatch (other than admission-controller-bypass, which requires cluster-admin and is auditable).
- **Policy-as-code.** Policies live in source control; reviewed via PR; deployed via the same pipeline as everything else.

---

## The tool choice

Three dominant tools in 2026.

| Tool | Best when | Avoid when |
| --- | --- | --- |
| **OPA / Gatekeeper** | Already-OPA-aware organization; complex policies that benefit from Rego's expressiveness; cross-platform policy reuse. | Simpler policy needs; teams unfamiliar with Rego. |
| **Kyverno** | Kubernetes-native preference; YAML-based policies; mutation use cases (sidecar injection, label adding); simpler learning curve. | Need for Rego across non-Kubernetes systems. |
| **ValidatingAdmissionPolicy (CEL)** | Kubernetes 1.30+; simple validation-only use cases; want to avoid external admission webhooks. | Mutation use cases; complex multi-resource policies. |

The recommendation:

- **For most new deployments:** Kyverno. The YAML-based policy syntax is approachable; mutation works well; the operational pattern is straightforward.
- **For OPA-heavy organizations:** Gatekeeper. Reuse Rego knowledge from other systems.
- **For simple validation in modern clusters:** ValidatingAdmissionPolicy (CEL). Built-in; no external dependency; reasonable for straightforward checks.

The three can coexist; teams sometimes use ValidatingAdmissionPolicy for simple cases and Gatekeeper or Kyverno for complex ones.

References:
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- [Kyverno](https://kyverno.io/)
- [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

---

## The common-policy library

The policies every multi-tenant cluster should enforce. Each is a Gatekeeper constraint or Kyverno policy or CEL ValidatingAdmissionPolicy; the specific syntax varies.

### 1. Required pod-security context

Every pod must have explicit `securityContext` settings:

- `runAsNonRoot: true`.
- `runAsUser` non-zero.
- `seccompProfile.type: RuntimeDefault`.
- Container-level: `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `readOnlyRootFilesystem: true`.

PSA's `restricted` profile covers most of this; admission policies add the explicit-required check (PSA's check happens at namespace-label level; admission policies are per-resource).

### 2. Required resource limits

Every container must specify `resources.requests` and `resources.limits`:

```yaml
resources:
  requests:
    cpu: "100m"
    memory: "128Mi"
  limits:
    cpu: "500m"
    memory: "512Mi"
```

Without limits: a runaway pod can consume an entire node's resources; cluster scheduling breaks; noisy-neighbor.

The policy: reject pod creation without resource requests and limits.

### 3. No `:latest` tag on images

Images referenced by tag `:latest` are mutable; the image's content can change without any version control trail. Pods restarted later may run different code than when deployed.

The policy: reject pods with images using `:latest` (or any tag without a digest). Require digest-pinned references (`image:tag@sha256:...`).

### 4. Required image signature verification

Pods must use images signed by an approved signing key. Implementation:

- Sigstore / Cosign keyed signing or keyless signing.
- Admission policy verifies the signature before allowing pod creation.
- Implementation via Kyverno's verifyImages or Gatekeeper's image-validation patterns or a dedicated tool like Connaisseur or Sigstore Policy Controller.

Detail: see [image-supply-chain.md](./image-supply-chain.md).

### 5. No NodePort services

`NodePort` services expose pods on every node's IP at a specific port; opens an internet-reachable port if the node has a public IP. Bypasses ingress controllers and their security features.

The policy: reject Service resources with `type: NodePort`. Use LoadBalancer or ClusterIP + Ingress instead.

### 6. No default service account in production

Pods that use the `default` service account get whatever permissions that account has; usually broader than needed; per-application IAM scoping is impossible.

The policy: reject pods that don't specify an explicit `serviceAccountName`, or that specify `default`.

### 7. Required namespace labels

Namespaces must have required labels (PSA labels, owner, environment, cost center). Without them, the namespace doesn't fit the platform's automation.

The policy: reject Namespace resources without required labels.

### 8. Required NetworkPolicy presence

Every workload namespace must have at least one NetworkPolicy (the default-deny). Detect on namespace creation; warn until policies exist, then enforce.

The policy: a periodic check (cluster-scanner) or admission-policy-on-namespace creation that requires NetworkPolicy presence within a grace period.

### 9. No host-namespace sharing

Pods using `hostNetwork: true`, `hostPID: true`, `hostIPC: true` (PSA `baseline` denies but admission policy reinforces).

The policy: reject pods with host-namespace sharing unless in an exempted system namespace.

### 10. RBAC restrictions

Application-team service accounts can't grant themselves `cluster-admin`; can't list secrets across namespaces; can't escalate permissions.

The policy: validate RBAC create / update operations; reject patterns that grant excessive permissions.

### 11. No privileged containers (PSA reinforcement)

Pods with `securityContext.privileged: true` are rejected outside system namespaces. PSA's `restricted` denies this; admission policy reinforces.

### 12. Resource-name conventions

Resources must follow naming conventions (e.g., `<workload>-<tier>`). Helps with inventory; the policy reinforces.

---

## Implementation: Kyverno examples

The Kyverno syntax is YAML; approachable.

### Reject `:latest` images

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-image-tag
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "Image tag :latest is not allowed; pin to a specific version or digest."
        pattern:
          spec:
            containers:
              - image: "!*:latest"
            initContainers:
              - image: "!*:latest"
```

### Require resource limits

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-pod-resources
spec:
  validationFailureAction: Enforce
  rules:
    - name: validate-resources
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "CPU and memory limits / requests are required."
        pattern:
          spec:
            containers:
              - resources:
                  requests:
                    memory: "?*"
                    cpu: "?*"
                  limits:
                    memory: "?*"
                    cpu: "?*"
```

### Reject NodePort services

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-nodeport
spec:
  validationFailureAction: Enforce
  rules:
    - name: deny-nodeport
      match:
        any:
          - resources:
              kinds: ["Service"]
      validate:
        message: "NodePort services are not allowed; use LoadBalancer or ClusterIP + Ingress."
        deny:
          conditions:
            all:
              - key: "{{ request.object.spec.type }}"
                operator: Equals
                value: "NodePort"
```

### Verify image signature

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-meridian-images
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences:
            - "meridian-registry.local/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/meridian-health/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
```

The pattern: pods using images from `meridian-registry.local` must have a Cosign signature attested by a GitHub Actions workflow in the `meridian-health` org. Keyless signing via Sigstore.

References:
- [Kyverno Policies](https://kyverno.io/policies/)

---

## Implementation: Gatekeeper / OPA examples

Gatekeeper uses Rego (a declarative policy language).

### Constraint template + constraint

Gatekeeper separates the **template** (the reusable policy logic) from the **constraint** (the policy instance with specific parameters).

```yaml
# Template
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg}] {
          required := input.parameters.labels
          missing := required[_]
          not input.review.object.metadata.labels[missing]
          msg := sprintf("Missing required label: %v", [missing])
        }
```

```yaml
# Constraint
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-workload-labels
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    labels: ["owner", "cost-center", "environment"]
```

The constraint requires namespaces to have `owner`, `cost-center`, and `environment` labels.

### Rego strengths

Rego handles complex policy logic well:

- Querying across multiple resources.
- Aggregating constraints.
- Conditional logic (allow X if Y unless Z).

For simple policies: Kyverno or CEL is simpler. For complex policies: Rego is more expressive.

References:
- [Gatekeeper Constraint Templates](https://open-policy-agent.github.io/gatekeeper/website/docs/howto)
- [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)

---

## Implementation: ValidatingAdmissionPolicy (CEL)

Built-in to Kubernetes 1.30+; no external admission webhook.

### Example: disallow `:latest`

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: disallow-latest-tag
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: "object.spec.containers.all(c, !c.image.endsWith(':latest'))"
      message: "Image tag :latest is not allowed"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: disallow-latest-tag-binding
spec:
  policyName: disallow-latest-tag
  validationActions: [Deny]
```

CEL (Common Expression Language) is simpler than Rego; suitable for straightforward validation. Built-in means no external webhook to operate.

### Strengths and limits

Strengths:

- No external admission webhook (no webhook to maintain, no failure mode of the webhook being unavailable).
- Built into Kubernetes; well-supported.
- Simple expression language.

Limits:

- Validation only (no mutation).
- Single-resource scope (cannot easily check against other resources).
- Newer (less community-tested than Gatekeeper / Kyverno).

For Kubernetes 1.30+: ValidatingAdmissionPolicy for simple validation cases; Gatekeeper / Kyverno for more complex patterns.

References:
- [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [CEL Language](https://github.com/google/cel-spec)

---

## The enforce-vs-warn discipline

Admission policies have two modes:

- **Enforce** (Deny): violations are rejected.
- **Warn** (audit / dryrun): violations are logged but allowed.

### The transition pattern

For a new policy:

1. **Apply in warn mode.** The policy logs violations; doesn't block.
2. **Review the warnings** for a period (1–4 weeks). Discover legitimate cases the policy should accommodate.
3. **Refine the policy.** Add exceptions, narrow the match.
4. **Switch to enforce.** Violations now blocked.

The warn-mode period is the discovery phase; enforce-mode is the production state.

### The forever-warn anti-pattern

A common failure: the team applies a policy in warn mode and never moves to enforce. Warnings accumulate; the team ignores them; new resources continue to violate.

The fix: every warn-mode policy has an enforce-mode target date. Quarterly review.

### Exemptions vs warn-mode

For policies that some workloads legitimately can't satisfy: use exemptions (per-namespace, per-resource) rather than warn-mode for the whole policy. Exemptions are documented; warn-mode is decoration.

---

## Mutation patterns

Some admission policies mutate (modify) resources rather than just validate.

### Sidecar injection

Service-mesh sidecars (Istio proxy, Linkerd2 proxy) are typically injected by admission webhooks:

- Pod is created without the sidecar in the spec.
- Mesh's mutating admission webhook adds the sidecar container.
- Pod is created with the sidecar.

Application teams don't need to know about the sidecar; the platform handles it.

### Default labels and annotations

A mutating policy adds default labels:

- `cost-center: <inherited from namespace>`.
- `owner: <inherited from namespace>`.
- `deployed-at: <timestamp>`.

Helps with inventory; the team doesn't need to remember to add.

### Default security context

For pods missing security context fields, a mutating policy can add defaults:

- `runAsNonRoot: true` if not set.
- `allowPrivilegeEscalation: false` if not set.

Combined with validation policies that reject pods that override the defaults inappropriately.

### When mutation is the wrong choice

- **When mutation hides the policy from the developer.** If the team doesn't see the mutation, they don't know to maintain the contract.
- **When mutation produces unexpected behavior.** A pod's behavior changes based on cluster policy; debugging is harder.

For most security policies: validation is clearer than mutation. Mutation is for platform conveniences (sidecar injection, label defaulting), not security.

---

## Webhook failure modes

Admission webhooks are network calls; they can fail. The failure modes:

### The webhook-down failure

If the webhook is unreachable:

- **`failurePolicy: Fail`** (default for most patterns): admission requests fail; no new resources can be created.
- **`failurePolicy: Ignore`**: admission requests proceed without policy evaluation; policy violations land.

For security-critical policies: Fail. For convenience policies (sidecar injection): may use Ignore to avoid blocking deployments during webhook outages.

### The webhook-slow failure

Webhooks have a timeout (default 10 seconds). A slow webhook blocks admission. Pattern:

- Webhook timeout configured per policy.
- Webhook latency monitored.
- High-latency webhooks investigated; often a sign of resource exhaustion or policy complexity.

### The webhook-misconfigured failure

A webhook is configured but its certificate is expired or its endpoint is wrong. Admission requests fail; the team can't deploy.

The pattern: webhook configurations are tested in non-prod; cert rotation is automated; monitoring alerts on certificate expiry approaches.

### Cluster-system webhook exclusion

A webhook that depends on cluster-system services creates a chicken-and-egg problem. If the webhook is down, kube-system can't deploy fixes for the webhook.

The fix: webhook configurations exclude `kube-system` and other critical namespaces. Platform-team operations bypass the webhook in emergencies.

---

## Worked example: Meridian Health's admission control

Meridian operates Kyverno across EKS clusters with a comprehensive policy library, supplemented by Pod Security Admission for pod-level enforcement.

### The Kyverno policy library

Active policies:

- **disallow-latest-tag** — image references must be tagged with specific version or digest-pinned.
- **require-pod-resources** — CPU and memory requests and limits required.
- **disallow-nodeport** — NodePort services rejected.
- **require-namespace-labels** — namespaces must have `owner`, `cost-center`, `environment` labels.
- **disallow-default-sa** — pods must specify a non-default service account.
- **verify-meridian-images** — Cosign signature verification on images from `meridian-registry.local`.
- **require-network-policy** — periodic check (scheduled, not admission) that namespaces have default-deny NetworkPolicy.
- **disallow-privileged-containers** — pods with `securityContext.privileged: true` rejected outside system namespaces.
- **rbac-restrictions** — RBAC create / update with `cluster-admin` or `secrets` reads rejected (admin role exempted).
- **require-pod-labels** — pods must have `app`, `tier`, `version` labels.

### The exemption discipline

Each policy has documented exemptions:

```yaml
# In the policy
exclude:
  resources:
    namespaces: ["kube-system", "kyverno", "calico-system", "istio-system"]
```

System namespaces are exempted; workload namespaces are not.

For workload-specific exemptions (rare): per-workload exemption with documented justification, owner, and expiration. Quarterly re-review.

### Enforcement mode

All policies are in Enforce mode in production. Warn mode is used only during policy rollout (typically 2-week observation period before enforcement).

### Observability

- **Policy violation events** ship to the central log archive.
- **SIEM rules** alert on:
  - Workload teams attempting to create violating resources (often legitimate-mistake; sometimes attempt at bypass).
  - Patterns suggesting active exploitation (mass attempts at policy bypass).
- **Quarterly review** of policy effectiveness — violations attempted vs blocked; legitimate cases needing accommodation.

### Migration story

Meridian's clusters originally had no admission control beyond PSA. Migration over 8 sprints:

- Sprints 1–2: install Kyverno; deploy the policy library in audit mode.
- Sprints 3–4: collect violations; refine policies; categorize legitimate cases needing exemptions.
- Sprints 5–6: per-workload remediation of violating resources.
- Sprint 7: switch dev clusters to enforce mode; observe.
- Sprint 8: switch staging and prod clusters to enforce mode.

Result: ~95% of policies in enforce mode; ~5 documented exemptions (Falco needing privileged, Datadog needing host paths, etc.).

### Findings opened during the admission-control audit

- **ADM-001** (no policy framework beyond PSA; broader organizational policies not enforced). Closed by Kyverno deployment.
- **ADM-002** (image tags using `:latest` in some workloads; non-reproducible deployments). Closed by disallow-latest-tag enforcement.
- **ADM-003** (resource limits missing on some pods; noisy-neighbor incidents). Closed by require-pod-resources.
- **ADM-004** (NodePort services exposing pods directly on node IPs). Closed by disallow-nodeport.
- **ADM-005** (workload pods using `default` service account). Closed by disallow-default-sa.
- **ADM-006** (Cosign signature verification not enforced). Closed by verify-meridian-images.
- **ADM-007** (admission webhook had no monitoring; latency / failure rate unknown). Closed by webhook health metrics + alerting.

---

## Anti-patterns

### 1. The forever-warn policy

A policy is in warn mode "to gather data." It stays in warn forever. Violations accumulate; the policy is decoration.

The fix: every warn policy has an enforce-mode target date; quarterly review.

### 2. The over-broad exception

A pod needed an exemption for one specific capability. The exemption was written to cover an entire namespace. New pods in the namespace inherit the exemption.

The fix: narrow exemptions; per-pod or per-deployment rather than per-namespace.

### 3. The webhook-down outage

The admission webhook is down. Failed `failurePolicy: Fail` prevents all new pod creation. Cluster-wide outage caused by webhook failure.

The fix: webhook HA; monitoring on webhook health; tested failover; emergency-bypass procedure for critical incidents.

### 4. The unsigned cluster-system pods

The image-signature policy applies to all namespaces including cluster-system. Cluster-system images (CNI, kube-proxy) aren't signed by the team's signing key; cluster breaks.

The fix: exempt cluster-system namespaces; signature policies apply only to workload namespaces and Meridian-owned images.

### 5. The policy-without-tests

A policy was deployed; nobody tested edge cases; the policy rejected legitimate resources at scale.

The fix: policy testing in CI (e.g., Conftest for OPA, Kyverno CLI test); rollout to non-prod first.

### 6. The mutated-without-validation

A mutating policy adds defaults; the team thinks the defaults are "always set." A subsequent change removes the mutating policy; pods that depended on the defaults now break.

The fix: combine mutation with validation; the validation policy fails the resource if the expected default isn't present (regardless of source).

### 7. The bypass-via-admin

The cluster-admin role bypasses admission policies. An engineer with cluster-admin can bypass for "quick fixes"; the bypass becomes habit; the policy is theoretical.

The fix: cluster-admin restricted to break-glass scenarios; admin actions audited; SCP or RBAC narrowing for routine operations.

### 8. The policy-without-violation-monitoring

Policies block violations. The blocked-attempt events go to the audit log; nobody monitors. Detection of attempted-bypass is invisible.

The fix: SIEM consumption of policy-violation events; alert on patterns suggesting active exploitation.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| ADM-001 | No admission-policy framework beyond PSA | High | Deploy Kyverno (or Gatekeeper / OPA / CEL); apply standard policy library | Platform Eng + Security Eng |
| ADM-002 | Pods reference images with `:latest` tag | High | disallow-latest-tag policy; image references must be version or digest | Platform Eng + Workload Owner |
| ADM-003 | Pods lack resource requests / limits | High | require-pod-resources; noisy-neighbor protection | Platform Eng + Workload Owner |
| ADM-004 | NodePort services in use; pods exposed on node IPs | High | disallow-nodeport policy | Platform Eng + Workload Owner |
| ADM-005 | Workload pods use `default` service account | Medium | disallow-default-sa; per-workload service accounts | Platform Eng + Workload Owner |
| ADM-006 | Image signature verification not enforced | High | verify-images policy (Kyverno) or Sigstore Policy Controller; align with [image-supply-chain.md](./image-supply-chain.md) | Platform Eng + Security Eng |
| ADM-007 | Admission webhook lacks health monitoring | High | Webhook health metrics; alert on latency / failure rate | Platform Eng + SRE |
| ADM-008 | Policies in audit mode without enforce-mode timeline | Medium | Quarterly review; enforce-mode target dates | Security Eng |
| ADM-009 | Over-broad exemptions (namespace-wide for one pod's need) | Medium | Per-pod or per-deployment exemptions; documented justification | Security Eng + Workload Owner |
| ADM-010 | Webhook misconfigured; admission requests fail | High | Webhook configuration tested in non-prod; cert rotation automated; failure alerting | Platform Eng + SRE |
| ADM-011 | Cluster-admin bypasses admission policies routinely | Medium | Restrict cluster-admin to break-glass; audit admin actions; rework routine operations through narrower roles | Security Eng + Platform Eng |
| ADM-012 | Policy violations not consumed by SIEM | Medium | Ingest policy-violation events; alert on attempted-bypass patterns | Security Eng + SOC |
| ADM-013 | RBAC creation / modification not policy-controlled; over-privileged grants land | Medium | RBAC restriction policies; alert on excessive permission grants | Security Eng + IAM Eng |
| ADM-014 | Namespace labels not required at creation; auto-vending automation absent | Medium | require-namespace-labels policy; vending automation applies defaults | Platform Eng |
| ADM-015 | Mutating policy without paired validation; defaults can be silently overridden | Low | Validation policy verifies expected defaults; works regardless of source | Security Eng |
| ADM-016 | Policy testing absent; production rollout is the first execution | Medium | Test policies in CI (Conftest, Kyverno CLI test); non-prod rollout first | DevOps + Platform Eng |
| ADM-017 | Cluster-system namespaces over-exempted; broader policies apply | Medium | Per-namespace exemption granularity; system-namespace-only exclusions | Platform Eng + Security Eng |
| ADM-018 | Image signature policy applies to all images including third-party; cluster breaks on cluster-system images | High | Restrict signature policy to Meridian-owned image patterns; third-party images allowed with separate vetting | Security Eng + Platform Eng |

---

## What this document is not

- **A Kyverno / OPA / Gatekeeper tutorial.** The vendor / project documentation covers operational depth.
- **A complete admission-controller reference.** Built-in admission controllers (NamespaceLifecycle, ResourceQuota, etc.) are mentioned; their full configuration is in upstream Kubernetes documentation.
- **An RBAC reference.** RBAC design intersects with admission control but the broader RBAC patterns belong with [../identity-and-access/](../identity-and-access/).
- **A Sigstore / Cosign reference.** Image-signing patterns live in [image-supply-chain.md](./image-supply-chain.md).
