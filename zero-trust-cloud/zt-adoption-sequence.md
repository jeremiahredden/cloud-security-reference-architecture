# Zero Trust Adoption Sequence

A practitioner's reference for the order in which to adopt Zero Trust capabilities — the six-month plan that lets a team retire the legacy posture incrementally without an all-or-nothing cutover. The patterns here are about sequencing: identity-aware access first (because it retires the corporate VPN, the most user-visible win), then workload identity (because it retires long-lived service-account secrets), then mTLS-by-default (because it raises the bar on lateral movement), then microsegmentation (because it requires the previous three to be useful), then continuous authorization (because it's the highest-leverage but requires the foundation to be in place).

This document is the strategic companion to the other zero-trust-cloud documents. Each prior document describes a capability; this document describes how to land them in sequence so the team doesn't get stuck in a year-long platform build before any user-visible benefit appears.

The honest framing: Zero Trust as a strategic initiative typically fails because the team tries to land all the capabilities simultaneously, runs out of political capital, and ends up with partial deployments of everything. The sequence here is opinionated about the order because the order matters more than the destination.

---

## When to read this document

**If you are starting a Zero Trust adoption** — read top to bottom. This is the planning document.

**If your ZT adoption stalled** — start with [The common stall points](#the-common-stall-points). Most stalls happen at predictable points; the sequence is designed to avoid them.

**If you have leadership asking for a ZT roadmap** — start with [Success criteria per milestone](#success-criteria-per-milestone). The roadmap is most useful when each phase has clear, demonstrable outcomes.

**If you are auditing ZT-adoption progress** — start with [Findings checklist](#findings-checklist).

---

## The six-month plan

The opinionated sequence.

| Month | Focus | Visible deliverable |
| --- | --- | --- |
| 1 | Identity-aware access for one high-value internal application | Application accessible without VPN; pilot user population reports improved experience |
| 2 | Retire VPN for the pilot user population | VPN concentrator load drops measurably; users report no functional regression |
| 3 | Workload identity migration off long-lived service-account secrets | The credential count in CI / Kubernetes Secrets drops by 60%+ |
| 4 | Service-mesh mTLS-by-default in production cluster | All meshed services authenticated; mTLS observability dashboards |
| 5 | Microsegmentation across the four tiers | Cross-namespace and cross-workload traffic visible; default-deny baseline |
| 6 | Continuous authorization (initial) | PDP deployed; step-up authentication for sensitive actions |

This is not a strict timeline. Some phases take longer; the sequence matters more than the precise duration.

### Why this order

- **Month 1 / 2 (IAA, VPN retirement):** highest user-visible benefit. Builds political capital for subsequent phases.
- **Month 3 (workload identity):** highest security benefit per unit of effort. Eliminates the largest single class of leak vectors.
- **Month 4 (mTLS):** requires workload identity to be useful. mTLS without per-workload identity is just transport encryption.
- **Month 5 (microsegmentation):** requires identity layers (workforce + workload + mTLS) to be useful. Without the previous, policies can't reference meaningful identities.
- **Month 6 (continuous authz):** the deepest layer; requires the identity foundation and policy infrastructure that earlier phases built.

Each phase enables the next. Reversing the order means trying to build later phases on a missing foundation.

---

## Month 1: identity-aware access for one high-value application

The pilot phase.

### Goals

- Deploy an identity-aware proxy (Cloudflare Access, AWS Verified Access, GCP IAP, Entra App Proxy).
- Make one internal application accessible *without* VPN.
- Demonstrate that the user experience is better than VPN.

### The right pilot application

Criteria:

- **High-value:** users actually use it; the benefit is felt widely.
- **Contained:** the application's dependencies are clear; making it accessible without VPN doesn't require lots of network re-architecture.
- **Non-sensitive:** policy tuning is simpler; lower stakes for getting the policy wrong.

Common choices: internal monitoring dashboards (Grafana, Datadog), internal wikis, engineering tooling.

### Success criteria

- Pilot users can reach the application from any network without VPN.
- Identity-aware proxy enforces SSO + MFA.
- Per-application policy is documented and tested.
- User satisfaction (informal: positive feedback; formal: NPS or similar).

See [identity-aware-access.md](./identity-aware-access.md) for the deployment details.

### Common stall: politics

The political fights this phase tends to surface:

- IT operations doesn't want to operate "another auth system" beyond Active Directory.
- Security wants the deployment to be more comprehensive before rolling out (the perfect being the enemy of the good).
- Network team is concerned about routing.

The fix: small pilot; ship in one sprint; demonstrate value; iterate.

---

## Month 2: retire the VPN for the pilot user population

The political win.

### Goals

- Expand the identity-aware proxy to enough internal applications that the pilot population's daily needs are met.
- Disable VPN access for the pilot population (or make it opt-out rather than default).
- Measure: VPN sessions per day drop; help-desk tickets about VPN drop; user satisfaction increases.

### What to migrate

Add applications behind the proxy:

- All the engineering tools (Jira, Confluence, GitLab, etc.).
- Internal CI / deployment dashboards.
- Internal customer-success tools.

For each: deploy behind the proxy with per-application policy.

### The non-meshed applications

Some applications can't be put behind the proxy easily:

- **Legacy SSH access to specific hosts:** these stay on VPN for the moment.
- **Third-party tools requiring IP allowlists:** specific case-by-case (sometimes the vendor supports SSO; sometimes not).
- **Non-HTTP protocols:** the proxy is HTTP-only; other protocols stay on VPN.

The principle: don't try to migrate everything in month 2. The 80% migrates; the 20% tail stays on VPN with a documented migration plan for later.

### Success criteria

- Pilot user population uses the proxy for daily access; VPN is opt-in for the long-tail applications.
- Measurable reduction in VPN connection count for the population.
- User satisfaction maintained or improved.

### Common stall: long-tail applications

The 20% of applications that can't easily migrate become an excuse to keep VPN.

The fix: accept the tail; document the migration plan for each tail application; commit to retiring VPN for the population once the tail is acceptable; expand the pilot to additional populations in parallel.

---

## Month 3: workload identity migration

The structural win.

### Goals

- Identify the largest pools of static cloud credentials.
- Migrate CI workflows to OIDC federation.
- Migrate Kubernetes pods to workload identity (IRSA, Workload Identity, AKS WI).
- Reduce the static-credential count measurably (target: 60%+ reduction).

### The migration playbook

Per [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md):

1. **Inventory.** Find every stored cloud credential.
2. **Prioritize.** CI pipelines with broad cloud access first; Kubernetes pods second; cross-account access third.
3. **Migrate per pattern.** Each pattern has a documented before/after.
4. **Rotate + delete.** Rotate the legacy credential to confirm nothing still uses it; delete it.

### Success criteria

- Static-credential count down by 60% (or more).
- CI workflows use OIDC federation; no long-lived cloud access keys in CI secrets.
- Kubernetes workloads use workload identity; no IAM-credentials-in-Secrets.
- SCP / policy in place preventing reintroduction of long-lived credentials.

### Common stall: legacy applications

Some applications can't easily migrate to workload identity (older SDK versions, custom integration, etc.).

The fix: tolerable tail; remaining credentials get rotation discipline and Secrets Manager storage. Document each as an exception with planned migration.

---

## Month 4: service-mesh mTLS-by-default

The technical foundation for service-to-service ZT.

### Goals

- Deploy service mesh in the production Kubernetes cluster (Istio or Linkerd).
- Enable mTLS in permissive mode mesh-wide.
- Migrate per-namespace to strict mode.
- Establish observability on mTLS health (certificate rotation, mesh policy denials).

### The migration sequence

Per [mtls-everywhere.md](./mtls-everywhere.md) and [../kubernetes-and-container-security/service-mesh-security.md](../kubernetes-and-container-security/service-mesh-security.md):

- Sprint 1: install mesh; mTLS in permissive mode.
- Sprint 2: per-namespace sidecar injection.
- Sprint 3: per-namespace strict mode.
- Sprint 4: mesh-wide strict mode + default-deny AuthorizationPolicy.

### Success criteria

- All meshed services use mTLS.
- AuthorizationPolicy default-deny enforced mesh-wide; per-service allow policies.
- Certificate rotation healthy; expiration metrics shipped to observability.

### Common stall: non-meshed services

A significant fraction of services may not be in the mesh (legacy workloads, specific compatibility issues).

The fix: SPIRE SDK integration for critical non-meshed services; remaining tail documented and migration planned.

---

## Month 5: microsegmentation

The lateral-movement-budget reduction.

### Goals

- Implement default-deny NetworkPolicy in all production namespaces.
- Tighten per-application authz policies in the mesh.
- Enforce egress allowlists via egress firewall.
- Establish observability on the four-tier model.

### The migration sequence

Per [microsegmentation.md](./microsegmentation.md):

- Sprint 1: NetworkPolicy default-deny per namespace; allow-DNS pattern.
- Sprint 2: per-application allow policies (NetworkPolicy + mesh authz).
- Sprint 3: egress allowlists (FQDN-based via Cilium where applicable).
- Sprint 4: cross-tier observability; lateral-movement-budget measurement.

### Success criteria

- Cross-namespace traffic explicitly authorized; default-deny everywhere.
- Per-application policies in mesh and at network layer.
- Egress allowlisted; broader egress denied.
- Flow logs consumed by SIEM; denied-flow patterns reviewed.

### Common stall: the productivity hit

Migration to default-deny breaks legitimate flows that weren't documented. Engineers complain. The team rolls back.

The fix: observability first (Hubble, Calico Flow Logs); identify legitimate flows; author allow policies before enabling default-deny; per-namespace cutover.

---

## Month 6: continuous authorization (initial)

The capstone (and ongoing investment).

### Goals

- Deploy a Policy Decision Point (OPA or vendor).
- Integrate device-trust signals into the PDP.
- Implement step-up authentication for sensitive actions.
- Initial risk-based session re-evaluation.

### What "initial" means

Continuous authorization is the deepest layer; full implementation is a multi-quarter or multi-year journey. Month 6 establishes the foundation:

- PDP deployed and consulted by key applications.
- One or two step-up patterns implemented.
- Device-trust signals propagate to at least one application's decision.
- Observability on PDP decisions.

Full continuous authorization expands incrementally over subsequent months.

### Success criteria

- PDP in production; observability active.
- Step-up authentication on at least one sensitive flow.
- Device-state-driven session evaluation on at least one application.
- Documentation for expanding to additional applications.

See [continuous-authorization.md](./continuous-authorization.md) for the depth.

---

## Success criteria per milestone

A summary for leadership reporting.

### Month 1: pilot identity-aware access

- ✅ Identity-aware proxy deployed.
- ✅ One application accessible without VPN.
- ✅ Pilot users report improved experience.

### Month 2: VPN retirement for pilot

- ✅ 80%+ of pilot users no longer use VPN for daily work.
- ✅ VPN sessions per day for pilot population drops measurably.
- ✅ Help-desk tickets about VPN issues drops.

### Month 3: workload identity migration

- ✅ Static-credential count down 60% or more.
- ✅ CI workflows use OIDC federation.
- ✅ Kubernetes pods use workload identity.
- ✅ Policy prevents regression.

### Month 4: mTLS-by-default

- ✅ Production cluster mesh deployed.
- ✅ mTLS strict mesh-wide.
- ✅ AuthorizationPolicy default-deny.

### Month 5: microsegmentation

- ✅ NetworkPolicy default-deny per namespace.
- ✅ Per-application mesh authz.
- ✅ Egress allowlists active.

### Month 6: continuous authorization (initial)

- ✅ PDP deployed and operational.
- ✅ Step-up authentication for at least one sensitive flow.
- ✅ Device-trust signals integrated into at least one decision.

Cumulative posture: a year that started with VPN + long-lived secrets + permissive network ends with identity-aware access + workload identity + mTLS-by-default + microsegmentation + initial continuous authorization. Each phase is a measurable win.

---

## The common stall points

The places where ZT adoptions get stuck.

### Stall 1: month 1 takes 6 months

The team tries to deploy identity-aware access perfectly the first time. Policy design takes months; vendor evaluation drags; the pilot never ships.

The fix: deploy in one sprint; ship to a small pilot; iterate. Don't optimize before observation.

### Stall 2: VPN keeps coming back

VPN retirement is announced. Some specific use case can't be migrated. The team keeps VPN "as a fallback"; users keep VPN client installed; the retirement is incomplete.

The fix: timebox the VPN tail; commit to a retirement date; coordinate the long-tail migrations.

### Stall 3: workload identity migration is "too risky"

The team is concerned about breaking CI workflows or production pods. The migration is deferred.

The fix: per-pattern migration with rollback. The OIDC migration is reversible; the IRSA migration is reversible. Start with low-stakes (dev workflows); build confidence.

### Stall 4: mesh adoption stalls in permissive mode

mTLS is in permissive mode; "we'll move to strict soon." Soon never arrives.

The fix: per-namespace timeline; commit to strict-mode dates; observable progress.

### Stall 5: microsegmentation breaks legitimate flows

Default-deny is enabled; legitimate flows break; engineers complain; the deny is reverted.

The fix: observability first (4-week observation period); per-namespace cutover with verification.

### Stall 6: continuous authorization is "too ambitious"

The team realizes the depth of work in month 6 and defers indefinitely.

The fix: initial scope is one application + one step-up pattern. Expand iteratively. Don't try to do everything in month 6.

### Stall 7: leadership loses interest after month 2

The user-visible wins of month 1-2 produce excitement. The structural wins of month 3+ are less visible to leadership. Funding and attention shift elsewhere.

The fix: leadership reporting on structural metrics (credential count, mTLS coverage, microsegmentation policy density). Make the invisible visible.

---

## What ZT is not

Worth being precise about, since the term is overloaded.

### Zero Trust is not a product

Vendors sell "Zero Trust platforms." These typically implement one or two capabilities (often identity-aware access). They're not the whole posture.

### Zero Trust is not "no trust"

The phrase is misleading. The actual model is: trust is established through cryptographic identity, context, and policy — not through network position. There's plenty of trust; it's just not implicit.

### Zero Trust is not a project that ends

The adoption sequence has a six-month horizon. The posture is ongoing. Continuous authorization, microsegmentation policy maintenance, identity-system evolution — all are operational disciplines, not project artifacts.

### Zero Trust is not perimeter-elimination

The perimeter still exists (the public internet boundary). Zero Trust changes what happens inside the perimeter (no implicit trust based on network position).

---

## Worked example: Meridian Health's ZT adoption

Meridian completed the six-month adoption in 2024. The timeline:

### Months 1-2: identity-aware access + VPN retirement (pilot)

- **Month 1:** Cloudflare Access deployed in front of internal Grafana. Engineering team adopted; VPN sessions for engineering dropped by 30% within two weeks.
- **Month 2:** Expanded to 12 internal tools (Confluence, Jira, internal Argo CD, etc.). Engineering, customer-success, and finance populations migrated. 70% reduction in VPN sessions for those populations.

### Month 3: workload identity migration

- **CI workflows:** all migrated to OIDC federation by end of month. AWS access keys in GitHub Actions secrets: from 47 to 0.
- **Kubernetes pods:** core production workloads migrated to IRSA. Kubernetes Secrets containing AWS keys: from 31 to 5 (the 5 remaining are legacy workloads with migration planned).
- **Cross-account access:** IAM users replaced with role assumption. Long-lived IAM users in production accounts: from 23 to 1 (1 break-glass user with MFA-required policy).

### Month 4: mTLS-by-default

- **Istio installed** in production cluster; permissive mode mesh-wide.
- **Per-namespace strict migration** completed over 4 sprints.
- **AuthorizationPolicy default-deny** mesh-wide; per-service allows landed.

### Month 5: microsegmentation

- **NetworkPolicy default-deny** in all production namespaces.
- **Egress allowlisting** via AWS Network Firewall + Cilium FQDN policies.
- **Cross-tenant isolation** enforced.

### Month 6: continuous authorization (initial)

- **OPA deployed** as a sidecar to internal API gateways.
- **Step-up authentication** for financial system admin actions.
- **Device-trust integration** via Jamf + Cloudflare WARP for admin tools.

### Post-month-6: ongoing

- Expansion of continuous authorization to additional applications.
- Microsegmentation policy refinement.
- mesh upgrade to Ambient mode for latency improvements.
- VPN long-tail migration (the 20% deferred in month 2).

### What worked

- Sequencing: each phase enabled the next; no phase blocked others.
- User-visible wins early: the IAA / VPN retirement built political capital.
- Per-pattern migration in workload identity: rolled back where issues found; resumed.
- Time-boxed phases: forcing function for completion.

### What didn't (and was course-corrected)

- Month 1 initially scoped too large; reduced to one application after first two weeks.
- Workload identity migration initially manual; automated mid-month to scale.
- mTLS migration to strict initially aggressive; per-namespace timeline more sustainable.

### Findings opened during the ZT adoption tracking

- **ZTSEQ-001** (no ZT adoption plan; capabilities pursued ad-hoc). Closed by the six-month plan.
- **ZTSEQ-002** (workload identity attempted before identity-aware access; political capital absent). Closed by sequence reordering.
- **ZTSEQ-003** (microsegmentation attempted before workload identity; policies couldn't reference meaningful identities). Closed by sequence enforcement.
- **ZTSEQ-004** (continuous authorization attempted as month 1; scope too large; stalled). Closed by deferring to month 6.

---

## Anti-patterns

### 1. The all-at-once adoption

The team tries to land all ZT capabilities simultaneously. None completes; partial implementations of everything; no demonstrable value.

The fix: sequence; complete each phase before moving on.

### 2. The vendor-as-strategy

The team buys a "Zero Trust platform" and considers ZT solved. The platform implements one or two capabilities; the rest is still missing.

The fix: ZT is a posture; vendors provide components. Map vendor capabilities to the four/five layers; identify the gaps.

### 3. The infinite-pilot

The pilot phase extends indefinitely. Expansion never happens. The investment doesn't pay off.

The fix: timeboxed phases; explicit success criteria; commitment to expansion.

### 4. The reversed sequence

The team starts with the deepest layer (continuous authorization) because it's the most strategic. The earlier layers aren't in place; the deep layer can't function.

The fix: build the foundation first.

### 5. The Month 1 user-experience disaster

The IAA rollout is rushed; UX issues are common; users hate it; the political capital is lost.

The fix: small pilot; gather feedback; iterate before expanding.

### 6. The workload-identity-without-rollback

Migration to workload identity breaks production; no rollback plan; outage extends.

The fix: per-pattern migration with rollback; rotate-then-delete discipline; tested in dev.

### 7. The forever-permissive-mTLS

mTLS in permissive mode; the team moves on to other phases; mTLS never goes strict.

The fix: per-namespace timeline for strict mode; review at month 5.

### 8. The microsegmentation-without-observability

Default-deny is enabled; legitimate flows break; engineers blame ZT; the team retreats.

The fix: observability first; identify flows; author allow policies; then enforce.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| ZTSEQ-001 | No documented ZT adoption plan; capabilities pursued ad-hoc | High | Adopt the six-month sequence; documented milestones | Architecture + Security Eng |
| ZTSEQ-002 | Capability sequencing skipped foundations; deeper layers attempted without prerequisites | High | Sequence enforcement; foundation phases before depth | Architecture + Security Eng |
| ZTSEQ-003 | Pilot phase extending beyond two months; expansion stalled | Medium | Timebox; success criteria for advancing to next phase | Security Eng + IT |
| ZTSEQ-004 | VPN retirement deferred indefinitely; legacy VPN remains primary access | Medium | Time-box VPN tail; commit to retirement date | IT + Security Eng |
| ZTSEQ-005 | Workload identity migration not started; static-credential count still high | High | Begin month 3 work; per-pattern migration | DevOps + Security Eng |
| ZTSEQ-006 | mTLS in permissive mode indefinitely | Medium | Per-namespace timeline for strict mode | Platform Eng + Security Eng |
| ZTSEQ-007 | Microsegmentation attempted without observability; broken legitimate flows | High | Observability first; per-namespace cutover with verification | Platform Eng + SRE |
| ZTSEQ-008 | Continuous authorization scoped too broadly for initial phase | Low | Initial scope: one application + one step-up pattern; expand iteratively | Security Eng |
| ZTSEQ-009 | Leadership-reportable metrics absent; ZT progress invisible | Medium | Per-phase metric dashboard: VPN sessions, credential count, mTLS coverage, policy density, PDP integration count | Security Eng + Leadership |
| ZTSEQ-010 | Vendor adopted as "ZT platform" without mapping to layers | Medium | Map vendor capabilities to four/five layers; document gaps | Architecture + Security Eng |
| ZTSEQ-011 | ZT treated as a project that ends; ongoing operational discipline absent | Medium | ZT as operational discipline post-adoption; continuous improvement | Security Eng + Architecture |
| ZTSEQ-012 | Per-phase rollback plans absent; migrations are one-way | Medium | Documented rollback per phase; tested in non-prod | Platform Eng + DevOps |
| ZTSEQ-013 | Long-tail applications (legacy / non-HTTP) blocking phase progression | Medium | Accept tail; migration plan for each; don't block phase | Architecture + IT |
| ZTSEQ-014 | Workload identity tail (legacy services) blocking workload-identity phase completion | Low | Tail accepted with documented exceptions; migration as legacy services modernize | Security Eng + Workload Owner |
| ZTSEQ-015 | mTLS coverage metric undefined; can't measure phase completion | Low | Mesh coverage % + non-mesh service identity coverage % | Observability + Security Eng |
| ZTSEQ-016 | Microsegmentation observability gap; lateral-movement budget unmeasured | Medium | Flow-log analysis; cross-tier traffic pattern metrics | Security Eng + Observability |
| ZTSEQ-017 | Continuous authorization PDP isn't HA; outage blocks all auth decisions | High | PDP HA; tested failover; fail-open / fail-closed documented | Platform Eng + Security Eng |
| ZTSEQ-018 | Post-phase-6 plan absent; team uncertain whether to expand or maintain | Low | Document ongoing operational practice; quarterly review of posture | Security Eng + Architecture |

---

## What this document is not

- **A six-month timeline that fits every organization.** Smaller organizations may complete faster; larger may take 12+ months. The sequence matters more than the calendar.
- **A vendor selection guide.** Specific vendor choices belong with broader security tooling decisions.
- **A maturity-model walkthrough.** NIST ZT Maturity Model is referenced; the document focuses on adoption patterns rather than maturity scoring.
- **A complete adoption guide.** Each phase has its own document with operational depth; this document is the strategic frame.
