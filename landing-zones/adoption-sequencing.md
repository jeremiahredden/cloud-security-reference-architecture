# Landing-Zone Adoption Sequencing

A practitioner's reference for the six-week adoption arc that takes a team from "one AWS account" or "one Azure subscription" or "one GCP project" to a real landing zone with baseline guardrails, account / subscription / project vending, and the discipline to keep it that way. Sequencing is the under-documented part of every landing-zone reference architecture; this document fills the gap.

This document complements the per-cloud designs in [aws-organizations-design.md](./aws-organizations-design.md), [azure-management-groups.md](./azure-management-groups.md), and [gcp-organization-design.md](./gcp-organization-design.md). Those documents describe the target state; this one describes how to get there. They are independent — the destination shape is the same regardless of which cloud you start with; the sequencing patterns are the same; only the per-step mechanics differ.

The honest framing: most landing-zone reference architectures are pictures of the destination. Teams stare at the picture and don't know where to start. The natural temptation is to start with the most architecturally satisfying piece (the multi-account / multi-subscription topology) and discover six months in that they haven't shipped controls because they're still rearranging accounts. The sequencing pattern that works is "ship controls early, shape the topology incrementally."

---

## When to read this document

**If you have one cloud account / subscription / project and a directive to "implement a landing zone"** — read top to bottom.

**If you've started a landing-zone project and aren't sure if you're on track** — start with [Common stall points](#common-stall-points).

**If you're sponsoring a landing-zone initiative and want a credible plan** — start with [The six-week arc](#the-six-week-arc).

**If you're trying to retrofit an existing estate** — start with [Retrofitting an existing estate](#retrofitting-an-existing-estate).

---

## The six-week arc

The opinionated sequence. Six weeks is aspirational; many teams stretch to 12. The shape is the same.

### Week 1 — Foundational identity and audit

**Goals:**
- Sign-in to the cloud lands through the corporate IdP (or stand up Cloud Identity / Entra ID equivalent).
- Org-level audit logs (CloudTrail / Activity Log / Audit Log) enabled and shipping to a dedicated log destination.
- Break-glass account documented and tested.

**Why first:** identity and audit are prerequisites for every subsequent control. You cannot tighten IAM if you can't see who's doing what. You cannot remove standing access if there's no JIT path.

**Tangible outputs:**
- IdP-to-cloud federation working (1 hour test of SSO).
- A central log destination (LogArchive account / Log Analytics workspace / centralized logging project).
- A SCP / Org Policy preventing org-level audit log disable.
- A documented break-glass procedure (sealed credentials, quarterly test).

### Week 2 — Org-level baseline controls

**Goals:**
- The 5-10 universal-deny policies that protect against the worst configurations.
- Org-level identity hygiene (MFA-required, IAM-user-blocked, etc.).

**Why second:** the controls have org-level scope; deploying them now prevents new misconfigurations even before the multi-account topology exists.

**Tangible outputs:**
- AWS: SCP at org root with the Tier 1 deny set per [baseline-guardrails.md](./baseline-guardrails.md).
- Azure: tenant-root Azure Policy initiative with deny set.
- GCP: organization-level Org Policy constraints with deny set.
- Conditional access policies enforced (not audit-only).

### Week 3 — First multi-account / multi-subscription / multi-project structure

**Goals:**
- Two or three additional accounts / subscriptions / projects beyond the original.
- The MG / OU / folder structure for organizing them.

**Why third:** the structure is the substrate for everything else, but it doesn't matter until you have controls (Weeks 1-2) and workloads to put in it.

**Tangible outputs:**
- Bootstrap account / subscription / project for IaC state.
- Log archive / security tooling account.
- One or two workload accounts (the existing original workload moved or copied).
- OU / MG / folder hierarchy with the deny set inherited.

### Week 4 — Vending automation (minimal)

**Goals:**
- A pipeline that creates a new account / subscription / project with the baseline applied.
- Manual creation is the exception, not the norm.

**Why fourth:** without automation, the topology doesn't scale; manual creation drifts from the baseline.

**Tangible outputs:**
- Terraform / CFT / ALZ-bicep / equivalent vending module.
- CI / CD pipeline triggered by a ticket / form.
- First vended account / subscription / project as proof.

### Week 5 — Networking baseline

**Goals:**
- Hub-and-spoke or Shared VPC pattern initiated.
- Egress filtering through central inspection (AWS Network Firewall / Azure Firewall / Cloud NGFW).
- VPC SC perimeter for regulated workloads (GCP) or service-tag-based isolation (AWS / Azure).

**Why fifth:** networking is the next-largest blast radius; controls deserve attention but only after the topology + vending make it sustainable.

**Tangible outputs:**
- Hub VNet / Shared VPC / equivalent.
- Egress through central firewall.
- First spoke / service-project / workload account integrated.

### Week 6 — Detection and IR foundations

**Goals:**
- SIEM ingestion of the centralized logs.
- The first IR runbook (typically leaked-IAM-key per [../cloud-detection-response/runbook-leaked-iam-key.md](../cloud-detection-response/runbook-leaked-iam-key.md)).
- One detection-as-code rule (e.g., disable-audit-log alerting).

**Why sixth:** detection is the validating layer over the preventive controls. By Week 6 you have controls; now you can detect violations.

**Tangible outputs:**
- SIEM ingestion pipeline (CloudWatch Logs / Event Hub / Pub/Sub → SIEM).
- One IR runbook tested via tabletop.
- One detection rule live and tested.

### What's not in the six weeks

These are intentionally deferred:

- **Threat-modeling exercises** — wait until you have a real workload to model.
- **Per-workload tightening** — happens as workloads onboard.
- **Comprehensive compliance mapping** — wait until controls are stable.
- **Sophisticated detection coverage** — Week 6 is the floor; ongoing buildout.
- **Cost-optimization** — wait until the topology is stable.

The six-week arc gets you to a defensible posture and a sustainable platform. The rest is incremental.

---

## Retrofitting an existing estate

Most teams aren't starting greenfield. The retrofit pattern.

### The starting reality

- 10-100 cloud accounts / subscriptions / projects, organic growth.
- Identity model varied (some IdP-federated, some local, some IAM users).
- Org-level controls absent or partial.
- Networking patterns inconsistent.
- Logging exists but not centralized.

### The retrofit arc (12-24 weeks)

**Phase A — Observe and inventory (2 weeks)**

- Enumerate everything: accounts, subscriptions, projects, identities, workloads.
- Categorize: per-workload, per-environment, per-risk class.
- Map current controls; identify gaps vs target.
- Build the registry; build the per-workload owner map.

**Phase B — Restructure (2-4 weeks)**

- Create target OU / MG / folder hierarchy.
- Move accounts / subscriptions / projects into their target scope.
- Movement is non-destructive (no workload disruption).

**Phase C — Policy rollout (4-8 weeks, staged)**

- Per policy: deploy in audit / dry-run mode; observe for 2 weeks; promote to enforce.
- Phased: universal denies first, workload-specific later.
- Per-policy violations identified → workload owners remediate or document exception.

**Phase D — Networking migration (8-16 weeks)**

- Stand up hub / Shared VPC.
- Migrate workloads one at a time; per-workload coordination.
- Long phase by design; per-workload risk reviewed.

**Phase E — Logging centralization (2-4 weeks)**

- Aggregated sink / forwarder to central destination.
- SIEM ingestion.
- Per-workload log lineage documented.

**Phase F — Vending and ongoing (1 sprint, then ongoing)**

- Vending automation built.
- New accounts / subscriptions / projects follow vending.
- Existing accounts brought to baseline as ongoing work (5-10% / quarter).

**Phase G — Detection coverage (ongoing)**

- Per-quarter: add 5-10 detection rules.
- Per-quarter: run an IR tabletop on a different scenario.
- Per-quarter: measure detection coverage against [../threat-modeling-cloud/mitre-attack-cloud-coverage.md](../threat-modeling-cloud/mitre-attack-cloud-coverage.md).

### The retrofit takes longer than the greenfield

Greenfield: 6-12 weeks to first-defensible-posture.
Retrofit: 6-12 months to first-defensible-posture.

The difference is the existing workloads. Every Org Policy you want to enforce may break a workload running today. Coordination is the work.

---

## Common stall points

The places where landing-zone projects get stuck. Listed in approximate order of frequency.

### Stall 1 — "We need to redesign the topology before we can do anything"

The team gets stuck in topology debates. Months pass. No controls ship.

The fix: start shipping controls at the org level (Weeks 1-2). Topology decisions don't block universal-deny SCPs / Azure Policy / Org Policy. Topology emerges incrementally; the team can refine it after controls are in place.

### Stall 2 — "We can't enforce this Org Policy because workload X will break"

The team identifies a workload that violates a target policy. The team postpones the policy rather than negotiating with the workload owner.

The fix:
- Deploy the policy in audit mode.
- Identify all affected workloads (typically a small set; the loudest voice represents one of them).
- Owners get 90 days to remediate or document exception.
- Exception requires justification; reviewed quarterly.
- Enforce by deadline.

The first time a team holds this line, it sets a precedent that allows the next 10 policies to ship smoothly.

### Stall 3 — "The vendor / ALZ / CFT reference doesn't fit our existing estate"

The team can't apply the reference cleanly because their estate has history. The reference assumes greenfield.

The fix: the reference is a target, not a constraint. Adapt; document the deviations; track tech debt for each deviation; close debt over quarters.

### Stall 4 — "The network team is the bottleneck"

The networking migration (hub-and-spoke / Shared VPC) is a multi-quarter effort. Other phases stall waiting for networking.

The fix: parallelize. Identity, audit, org-level controls, and vending can all proceed without the networking migration completing. The networking migration is its own track.

### Stall 5 — "We don't have engineering capacity"

The landing-zone project competes with feature work for engineering time. Loses to feature work each sprint.

The fix:
- Dedicated landing-zone team or rotation.
- Executive sponsor commits a percentage of engineering capacity per quarter.
- Visible weekly progress (commits to the IaC repo, # accounts vended, # policies deployed); makes the project hard to silently de-prioritize.

### Stall 6 — "The audit / compliance team wants different things"

Audit / compliance wants framework-mapping deliverables; engineering wants controls. The two tracks drift.

The fix: shared roadmap. Per-control: which compliance frameworks does it satisfy? Compliance team gets evidence; engineering team gets technical controls. Per [../compliance-and-control-mapping/](../compliance-and-control-mapping/).

### Stall 7 — "We don't know what the destination looks like"

The team has read the reference docs but can't translate them to their specific environment. Analysis paralysis.

The fix: pick the canonical reference for your cloud (AWS Landing Zone Accelerator / Azure Landing Zones / Cloud Foundation Fabric). Deploy it (or a subset) into a sandbox. See it working. Adapt from there.

### Stall 8 — "We tried before and it didn't work"

Previous landing-zone effort stalled; team is skeptical. Project is over-architected on the second attempt to compensate.

The fix: post-mortem the previous attempt. Identify the specific stall. Plan the new attempt to avoid the specific stall. Smaller scope at first; "ship something in 6 weeks" is the rule.

---

## Per-cloud sequencing differences

The arc is the same; the per-week mechanics differ.

### AWS — sequencing notes

- **Week 1:** AWS IAM Identity Center federated to IdP; organization CloudTrail to LogArchive; SCP at root preventing CloudTrail disable. Account Factory for Terraform (AFT) or Landing Zone Accelerator (LZA) as the eventual vending tooling.
- **Week 3:** typical structure is the eight-OU pattern from [aws-organizations-design.md](./aws-organizations-design.md). Move-account is one-click.
- **Week 4:** AFT or LZA provides the vending pipeline.
- **Week 5:** Transit Gateway or Cloud WAN; AWS Network Firewall as the central inspection.

AWS-specific note: the organization root SCP that prevents CloudTrail disable is one of the highest-leverage single SCPs. Ship it Week 1.

### Azure — sequencing notes

- **Week 1:** Entra ID identity should already exist (Azure tenants come with it). Federate to corporate IdP if not already. Activity Log to central Log Analytics workspace. Conditional access policies enforced.
- **Week 3:** Management Group hierarchy per [azure-management-groups.md](./azure-management-groups.md). Subscription move is non-destructive.
- **Week 4:** ALZ-bicep or Terraform AVM modules for subscription vending.
- **Week 5:** hub VNet; Azure Firewall; Private Endpoints / DNS resolver.

Azure-specific note: Defender for Cloud configuration is best done early — it provides immediate value with zero engineering effort. Enable Standard tier or specific Defender plans for production subscriptions.

### GCP — sequencing notes

- **Week 1:** Workforce Identity Federation or Cloud Identity sync. Cloud Audit Logs already enabled by default; configure aggregation to org-level sink.
- **Week 3:** Folder hierarchy per [gcp-organization-design.md](./gcp-organization-design.md). Project move is allowed.
- **Week 4:** cft-projects / project-factory for vending.
- **Week 5:** Shared VPC host project; per-region subnets; VPC SC for regulated workloads.

GCP-specific note: `iam.disableServiceAccountKeyCreation` is one of the highest-leverage Org Policies. Ship it Week 2; coordinate with workload owners on Workload Identity Federation migration.

---

## Worked example — Meridian Health landing-zone roll-up (2025-2026)

Meridian's history with landing-zone work spans 18 months across three clouds. The summary tells the sequencing pattern across all three.

### AWS (started 2025-Q1, took 12 weeks for first-defensible-posture)

- Started with 3 AWS accounts, ad-hoc.
- Greenfield-ish (the existing accounts were small enough to absorb the discipline).
- Week 1-2 went as designed: federated to Okta, Identity Center, baseline SCPs.
- Week 3-4 stalled on OU design debate; broke the stall by picking the AWS-recommended eight-OU pattern and moving on.
- Week 5-6 networking took longer; deferred to Q2 and completed in Q2.
- By end of Q1: 8 accounts, baseline SCPs enforced, Identity Center in place, organization CloudTrail to LogArchive.

### Azure (started 2025-Q3, took 16 weeks for first-defensible-posture)

- Started with 25 subscriptions, organic growth.
- Retrofit scenario.
- Phase A inventory was 4 weeks (existing estate complexity).
- Phase B MG restructure 1 sprint.
- Phase C policy rollout took 8 weeks (more than greenfield because workloads to coordinate with).
- Phase D networking deferred to 2026-Q1 (large project).
- By end of 2025-Q3: 25 subscriptions in target MG hierarchy, baseline initiatives enforced, central Log Analytics, hub VNet design in progress.

### GCP (started 2026-Q1, took 16 weeks)

- Started with 45 projects, organic growth.
- Retrofit scenario.
- Similar shape to Azure.
- VPC SC was the late-arriving capability; rolled out in 2026-Q2.

### The cross-cloud sequencing observation

In all three retrofits, the same patterns appeared:
- Identity + audit + universal-deny controls shipped early.
- Topology restructure was relatively quick (move accounts / subscriptions / projects).
- Networking migration was the longest single phase.
- Vending automation was a 1-sprint task once decided.
- Detection coverage was an ongoing buildout.

The cross-cloud consistency makes a multi-cloud platform team feasible; the same playbook applies in each cloud with per-cloud mechanics.

---

## Anti-patterns

### 1. Topology-first, controls-later

The team designs the OU hierarchy for 8 weeks; ships no controls; the existing accounts continue to be the attack surface.

The fix: controls Week 1; topology Week 3.

### 2. Big-bang migration

The team plans a one-weekend migration from "old structure" to "new structure." Coordination across many teams; rollback impossible.

The fix: incremental migration; per-account / per-subscription / per-project; rollback per-step.

### 3. "We'll automate vending after we have the topology"

Manual account / subscription / project creation persists "until we automate." Six months later: still manual. Drift between accounts.

The fix: minimal vending automation by Week 4; refine over time.

### 4. Networking blocks everything

The team treats networking as a prerequisite for landing zone. Eight months of network design later, no controls have shipped.

The fix: networking is its own track. Org-level controls don't depend on the network topology.

### 5. No executive sponsor

The platform / security team owns the landing-zone project. Workload teams push back on every policy. No escalation path. The project loses sprint-by-sprint to feature work.

The fix: executive sponsor (CTO / CISO) commits engineering capacity; arbitrates policy disputes; reviews progress quarterly.

### 6. "We adopted the reference; we're done"

The team deploys the AWS Landing Zone Accelerator / Azure Landing Zones / Cloud Foundation Fabric and treats it as finished. The reference is the starting state; ongoing operational discipline is the work.

The fix: post-deploy, per-quarter review; per-account remediation queue; ongoing buildout.

### 7. Controls without owners

Policies deployed; no team owns them. Per-policy violations go unresponded.

The fix: per-policy owner (typically Security Eng); per-violation workflow; quarterly review of false-positive rate.

### 8. "We can't move account X because it's load-bearing"

A specific account / subscription / project becomes too important to disturb. It accumulates exceptions; eventually it's the only one not on baseline.

The fix: explicit exception process; per-exception ticket; expiration date; quarterly review.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| LZ-SEQ-001 | No org-level audit logging from Day 1 | Critical | CloudTrail / Activity Log / Audit Log to centralized destination | Security Eng |
| LZ-SEQ-002 | IdP federation not in place; cloud-local users | High | Federation per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md) | Identity + Security Eng |
| LZ-SEQ-003 | No org-level baseline policy set | High | Tier 1 universal denies; SCP / Azure Policy / Org Policy | Cloud Foundation + Security Eng |
| LZ-SEQ-004 | Single-account / single-subscription / single-project | High | Multi-account / -subscription / -project topology | Cloud Foundation |
| LZ-SEQ-005 | Account / subscription / project creation manual | Medium | Vending automation | Cloud Foundation |
| LZ-SEQ-006 | No central logging destination | High | Centralized log destination; SIEM ingestion | Security Eng + SOC |
| LZ-SEQ-007 | No break-glass procedure documented / tested | High | Per-cloud break-glass; sealed credentials; quarterly test | Security Eng + Identity |
| LZ-SEQ-008 | Networking flat; no segmentation | Medium | Hub-and-spoke / Shared VPC; central inspection | Network Eng |
| LZ-SEQ-009 | No vending owner; per-account / -subscription / -project drift | Medium | Per-cloud vending owner; quarterly drift review | Cloud Foundation |
| LZ-SEQ-010 | Per-policy violations not assigned to owners | Medium | Per-policy owner; per-violation workflow | Security Eng |
| LZ-SEQ-011 | "We adopted the reference; we're done" posture | Medium | Per-quarter remediation queue; ongoing buildout | Cloud Foundation + Security Eng |
| LZ-SEQ-012 | No detection-as-code; controls without detection | Medium | One detection rule per major control; SIEM-deployed | Detection Eng |
| LZ-SEQ-013 | No tested IR runbook | High | At least one runbook (leaked-IAM-key); tabletop quarterly | IR |
| LZ-SEQ-014 | Topology debate stalls control deployment | Medium | Controls Week 1; topology Week 3; parallel tracks | Cloud Foundation + Sponsor |
| LZ-SEQ-015 | Networking blocks other tracks | Medium | Parallel tracks; networking is one track among several | Network Eng + Platform Eng |
| LZ-SEQ-016 | Executive sponsorship absent; project loses to feature work | High | Sponsor with capacity commitment; quarterly review | Sponsor + Platform Eng |
| LZ-SEQ-017 | Per-quarter remediation progress not measured | Low | Quarterly metric: % accounts on baseline | Cloud Foundation |
| LZ-SEQ-018 | Documented exceptions not reviewed quarterly | Low | Per-exception expiration; quarterly review | Security Eng |

---

## Adoption checklist

- [ ] Week 1: IdP federation; org-level audit logs; break-glass.
- [ ] Week 2: Tier 1 baseline policy set.
- [ ] Week 3: Multi-account / -subscription / -project topology; OU / MG / folder hierarchy.
- [ ] Week 4: Vending automation; first vended unit as proof.
- [ ] Week 5: Networking baseline (hub / Shared VPC); egress filtering.
- [ ] Week 6: SIEM ingestion; first IR runbook; first detection rule.
- [ ] Per-policy owner; per-violation workflow.
- [ ] Quarterly metric: % accounts / subscriptions / projects on baseline.
- [ ] Per-exception tracking; quarterly review.
- [ ] Per-quarter detection coverage buildout.
- [ ] Per-quarter IR tabletop on a different scenario.
- [ ] Per-quarter executive review of progress and obstacles.

---

## What this document is not

- **A per-cloud reference architecture.** [aws-organizations-design.md](./aws-organizations-design.md), [azure-management-groups.md](./azure-management-groups.md), [gcp-organization-design.md](./gcp-organization-design.md) cover the target shapes.
- **A vendor adoption guide.** Landing Zone Accelerator, ALZ, Cloud Foundation Fabric each have their own documentation; this is the sequencing pattern that applies regardless.
- **A complete IR / detection reference.** [../cloud-detection-response/](../cloud-detection-response/) covers detection in depth.
- **A compliance-mapping reference.** [../compliance-and-control-mapping/](../compliance-and-control-mapping/) covers framework crosswalks.
- **A change-management playbook.** The technical sequencing is half the work; communications and stakeholder management are out of scope here.
- **A budget / capacity-planning reference.** Engineering capacity is the gating factor for most teams; the actual capacity numbers depend on the team.
