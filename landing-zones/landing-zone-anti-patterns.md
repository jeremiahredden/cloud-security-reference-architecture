# Landing-Zone Anti-Patterns

A catalogue of the landing-zone designs I have seen fail — each described with the appeal that made it seem reasonable, the failure mode, and the corrective move. The patterns are drawn from real environments where the "landing zone" eventually had to be rebuilt; the goal is to recognize the patterns early and avoid the rebuild.

This document complements [aws-organizations-design.md](./aws-organizations-design.md), [azure-management-groups.md](./azure-management-groups.md), [gcp-organization-design.md](./gcp-organization-design.md), and [adoption-sequencing.md](./adoption-sequencing.md). The reference architectures describe what good looks like; this document describes what bad-disguised-as-good looks like. Both halves are useful.

The honest framing: every landing-zone failure I've seen wasn't because someone made an obviously dumb decision. It was because someone made a defensible decision under specific constraints that hardened into a structure that no longer fit. Anti-patterns aren't failures of design; they're failures of revision.

---

## When to read this document

**If you're designing a landing zone and want to avoid known pitfalls** — read top to bottom.

**If you've inherited a landing zone that "works fine but smells off"** — scan the patterns; match against what you see.

**If you're sponsoring a landing-zone initiative and want to recognize trouble early** — start with [The cross-cutting failure modes](#the-cross-cutting-failure-modes).

---

## The five anti-patterns

### 1. The everything-in-one-account pattern

**What it looks like:** one cloud account / subscription / project for the entire organization. Production workloads, dev experimentation, billing, identity, networking — all in one place.

**Why it appears:** the original team optimized for simplicity. Setting up cross-account access is friction; one account is friction-free. The decision was correct *at the time* when the org was small.

**Why it fails:**
- **No isolation.** A compromised principal in the dev workload can reach the production database.
- **No tier-of-control discrimination.** The policies that should apply to production (strict) apply also to dev (where they create friction).
- **Quotas hit.** Per-service quotas are per-account; one account at scale hits IAM-policy-document-size, S3-bucket-count, etc.
- **Billing opacity.** Cost attribution is per-resource-tag, which the team is bad at maintaining.
- **Audit complexity.** A 10-year-old account has 10 years of legacy resources; tracking what's safe to delete is archaeology.

**The corrective move:**
- Split by environment (prod / nonprod / sandbox) first.
- Split by workload risk class within prod (regulated / online / internal).
- Per-workload account / subscription / project beyond a certain scale.
- Migration is per-workload; not big-bang.

### 2. The one-account-per-team sprawl pattern

**What it looks like:** every team has its own AWS account / Azure subscription / GCP project. 200 engineers → 80 accounts. Sometimes more — per-team-per-environment, etc.

**Why it appears:** the team treats account / subscription / project as a unit of team autonomy. "Give the team an account; they own their destiny."

**Why it fails:**
- **Per-account overhead.** Each account / subscription / project needs its own networking config, IAM role layout, logging setup, monitoring. Even with automation, ongoing maintenance per unit.
- **Inconsistency.** Per-team accounts diverge over time. Account-A enables some feature that Account-B doesn't; cross-account work hits the divergence.
- **Quota fragmentation.** Per-account quotas total to more than needed; per-account quotas individually are too small.
- **Audit cost.** N times more accounts to audit.

**The corrective move:**
- Workload-based, not team-based, separation.
- A team can own multiple workloads (multiple accounts).
- A workload can be owned by one team (one account).
- Per-workload-environment accounts: prod, staging, dev.
- Sandbox / experimental accounts are exceptions; the team gets a sandbox, not a full landing-zone replica.

### 3. The Control-Tower-with-no-deviations-allowed rigidity pattern

**What it looks like:** the team deployed AWS Control Tower (or Azure Landing Zones, or Cloud Foundation Toolkit) as-is and treats every deviation as a policy violation. New workload needs a configuration that doesn't fit the reference? "We don't allow that." Six months later: shadow accounts created by frustrated teams.

**Why it appears:** the reference architecture solves the design problem. Adopting it whole feels efficient. Defending it from deviations feels like maintaining the design's integrity.

**Why it fails:**
- **Workloads don't fit the reference.** Every reference is opinionated; real workloads have constraints.
- **The reference doesn't evolve.** AWS / Azure / GCP ships new services; the reference may not incorporate them quickly.
- **Frustration drives shadow infrastructure.** Teams that can't get what they need through official channels build outside the reference.
- **Tech debt accumulates.** The "we'll address that next quarter" exceptions accumulate; the reference becomes brittle.

**The corrective move:**
- The reference is the starting state, not the constraint.
- Per-deviation process: justify; document; expiration date; review.
- Per-quarter review of deviations; promote common deviations to first-class patterns.
- The reference is treated as the team's design, not the vendor's mandate.

### 4. The shared-services-everywhere coupling pattern

**What it looks like:** central accounts / subscriptions / projects for "shared services" proliferate. The networking is shared. The DNS is shared. The logging is shared. The secrets are shared. The CI/CD is shared. The container registry is shared. Eventually: 15 shared accounts that every workload depends on; an outage in one cascades.

**Why it appears:** centralization is operationally efficient. One shared resource is cheaper than N per-workload ones. Each individual centralization decision was correct.

**Why it fails:**
- **Cascading outages.** A bug in the shared logging service brings down logs for every workload simultaneously.
- **Cross-account complexity.** Every workload account has IAM grants to every shared-services account. The IAM graph is unreadable.
- **Change-management friction.** Updating a shared service requires coordinating with N workload teams.
- **Single points of failure.** The shared services become the cloud's load-bearing structure; their failure is catastrophic.

**The corrective move:**
- Centralize what *must* be centralized (network egress, audit logging, identity).
- Per-workload for what *can* be per-workload (CI/CD, container registry, application secrets).
- The discrimination: "is this shared because it's load-bearing for governance" vs "is this shared because we want one to manage."
- Per-shared-service: HA design; per-shared-service: explicit failure-mode planning.

### 5. The "no break-glass" availability pattern

**What it looks like:** identity is tightened to the IdP. JIT is enforced. SCPs prevent IAM-user creation. Conditional access policies are strict. Then: the IdP is down. The team can't get into the cloud at all.

**Why it appears:** "everything through the IdP" is the goal; break-glass feels like an exception that weakens the model.

**Why it fails:**
- **The IdP is a single point of failure.** Okta outage = no AWS access.
- **JIT can fail.** The JIT system can be down for its own reasons.
- **SCPs can be misconfigured.** A poorly-tested SCP can lock out everyone, including the team that would normally fix the SCP.
- **No recovery path.** When the failure happens, the team scrambles; the recovery is improvised.

**The corrective move:**
- Per-cloud break-glass account.
- Credentials sealed (offline, hardware token, sealed envelope).
- Excluded from conditional access policies (with documented exception).
- Quarterly test: sign in; verify access works; rotate credentials; re-seal.
- Use of break-glass triggers the highest-severity alert; investigated.

---

## The cross-cutting failure modes

The patterns underneath the patterns.

### A. Designed for the org as it was, not as it is

The landing zone designed for the 50-engineer startup doesn't fit the 500-engineer scale-up. The team grew; the landing zone didn't.

The fix: per-quarter review of "does this still fit." Resize the topology before it becomes painful.

### B. The "single source of truth" mantra applied where it doesn't fit

The team insists on one Terraform repo for everything. Per-workload teams can't iterate independently; the repo becomes the bottleneck.

The fix: per-workload IaC repos; central modules; central policy gates; per-team autonomy on their own workload's IaC.

### C. The platform team gates everything

The platform team owns the landing zone; every change goes through them. They become the bottleneck. Workload teams work around them.

The fix: platform team owns the *substrate* (vending, baseline controls); workload teams own their *workloads*. Self-service is the platform team's main product.

### D. The "we'll document it later" deferral

The landing-zone design is implemented; documentation is "next sprint." Six months later: no documentation. Tribal knowledge in 3 senior engineers.

The fix: documentation is part of the deliverable, not a separate phase. Per-design-decision: one paragraph in the wiki.

### E. The "we'll add detection later" deferral

The landing zone has controls. Detection of when those controls are violated is "next quarter." A year later: minimal detection coverage. The controls are still effective when followed; nobody knows when they're not.

The fix: detection-as-code coverage as part of the landing-zone deliverable. Per-control: at least one detection rule that fires when the control is violated.

### F. The "the reference takes care of it" abdication

The team relies on the vendor reference to handle security. The vendor reference handles 80% of cases; the other 20% are organization-specific. The 20% goes unaddressed.

The fix: per-organization-specific risk: explicit design decision; explicit control; explicit documentation.

### G. The "compliance is a separate project" disconnect

The landing zone is built without reference to compliance frameworks. Compliance team later maps controls; finds gaps; remediation is post-hoc.

The fix: per-control: which compliance frameworks does it satisfy? Build the crosswalk as you build the controls per [../compliance-and-control-mapping/](../compliance-and-control-mapping/).

### H. The "I'll handle it" hero pattern

One engineer holds the landing-zone knowledge. They're the bus factor. They burn out or leave; the landing zone becomes unmaintainable.

The fix: per-control review by at least one other engineer; documented runbooks; on-call rotation; deliberate knowledge sharing.

---

## Detection patterns for anti-patterns

How to spot these anti-patterns in an existing environment.

### Detection 1 — Single-account dominance

Query: per-cloud, what % of total resources / spend is in the largest single account / subscription / project?

If > 50%: the everything-in-one-account pattern. Investigate.

### Detection 2 — Per-team sprawl

Query: per-cloud, what's the ratio of accounts / subscriptions / projects to engineers?

If > 0.5 (one account per two engineers): the per-team sprawl pattern. Investigate.

### Detection 3 — Reference rigidity

Query: per-quarter, how many deviation tickets are filed against the reference architecture? Are they being denied without justification?

If denied without engagement: rigidity. Investigate.

### Detection 4 — Shared-services coupling

Query: per-shared-service, how many workloads depend on it? What's the historical outage frequency? What's the impact of an outage?

If the shared service has > 50 workload dependents and outages cascade: coupling. Investigate.

### Detection 5 — No break-glass tested

Query: when was the break-glass last tested? Documented?

If > 90 days since test, or no documentation: missing break-glass discipline.

---

## Worked example — Meridian Health landing-zone retrospective (Q2 2026)

After the cloud-security-architecture build-out, Meridian's security team reviewed the landing-zone work against this anti-pattern catalogue. Snapshot:

### What was avoided

- **Everything-in-one-account:** Meridian split early; per-workload-environment accounts since 2024.
- **Per-team sprawl:** the platform team explicitly chose workload-based, not team-based, splits. Engineer-to-account ratio ~10:1 (healthy).
- **No break-glass:** per-cloud break-glass set up during the original landing-zone work; quarterly tested.

### What was caught and corrected

- **Control-Tower-rigidity:** the team initially over-rotated on the Landing Zone Accelerator reference; documented deviations as policy violations. Corrected mid-2025 by introducing a deviation-tracking process; 12 deviations addressed in Q3 2025, of which 5 became first-class patterns.
- **Shared-services-everywhere:** the team had centralized container registry, CI/CD, secrets, networking, logging, DNS, monitoring. Mid-2025 inventory: 11 shared-services accounts. Reduced to 6 by Q1 2026 (CI/CD moved to per-workload; container registry kept central but with per-workload replica caches; secrets moved per-workload).

### What's still being worked

- **Documentation deferral:** the original landing-zone work has good wiki documentation; the per-quarter incremental work is under-documented. Ongoing improvement.
- **Detection coverage:** detection-as-code coverage of landing-zone control violations is at ~60% as of Q2 2026; target 90% by Q4.

### Findings opened during the retrospective

- **LZ-AP-001** (Control-Tower-rigidity pattern, caught mid-2025). Documented in retrospective.
- **LZ-AP-002** (Shared-services-everywhere, caught and corrected). Documented in retrospective.
- **LZ-AP-003** (Detection coverage of landing-zone controls < 90%). In progress; tracked per-quarter.
- **LZ-AP-004** (Per-quarter incremental work under-documented). In progress; per-PR documentation requirement added.

Retrospective took 1 week of engineering time. Worth doing.

---

## The escape hatches

When you've ended up in an anti-pattern and the corrective move is non-trivial, the practical escape hatches.

### Escape 1 — From everything-in-one-account

- Identify the highest-risk workload in the monolithic account.
- Stand up a new account / subscription / project for it.
- Migrate it (the migration itself is the hard part; budget months).
- Repeat for the next-highest-risk workload.
- Multi-quarter project; per-workload value.

### Escape 2 — From per-team sprawl

- Identify accounts / subscriptions / projects with low utilization.
- Consolidate per-team into per-workload.
- Per-team coordination required.
- Multi-quarter project.

### Escape 3 — From reference rigidity

- Per-deviation review: justify or revoke.
- Promote common patterns from deviation to first-class.
- Reference evolves with the team's needs.

### Escape 4 — From shared-services coupling

- Per-shared-service: is it shared by need or by choice?
- Move "by choice" services to per-workload.
- Per "by need" service: HA design; explicit failure-mode planning.

### Escape 5 — From no-break-glass

- Stand up break-glass.
- Document.
- Test.

The escape is the easiest of the five; the discipline of maintaining it is the work.

---

## Anti-patterns to anti-patterns

The meta-pattern: how teams overcorrect.

### Meta-1 — From per-account-sprawl to single-account

A team in the per-account sprawl pattern decides to consolidate. They consolidate too aggressively; end up in the everything-in-one-account pattern.

The fix: workload-based separation, not team-based. The target isn't N or 1; it's "right-sized."

### Meta-2 — From rigidity to anarchy

A team frustrated by reference rigidity opens the floodgates. Per-team-per-deviation; the reference is unused.

The fix: structured deviation process; per-deviation justification; per-quarter consolidation.

### Meta-3 — From shared-services coupling to per-workload duplication

A team frustrated by shared-services coupling moves everything per-workload. Per-workload secrets management; per-workload monitoring; per-workload everything. Operational overhead skyrockets.

The fix: discriminate. Some things should be shared (audit logging, IdP). Some should be per-workload (application secrets). The choice is per-component, not blanket.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| LZAP-001 | Everything-in-one-account pattern | High | Split by environment, then by workload risk; per-workload accounts at scale | Cloud Foundation |
| LZAP-002 | Per-team account sprawl | Medium | Workload-based separation; consolidate per-team into per-workload | Cloud Foundation |
| LZAP-003 | Reference architecture treated as inviolable; deviations denied without engagement | Medium | Per-deviation review process; promote common patterns to first-class | Cloud Foundation |
| LZAP-004 | Shared-services proliferating; cascading-outage risk | High | Discriminate must-share from can-share; per-shared-service HA design | Platform Eng + Security Eng |
| LZAP-005 | No break-glass account or untested break-glass | High | Per-cloud break-glass; sealed credentials; quarterly test | Identity + Security Eng |
| LZAP-006 | Landing zone designed for prior scale; doesn't fit current | Medium | Per-quarter review of fit; resize topology before pain | Cloud Foundation |
| LZAP-007 | "Single source of truth" Terraform repo becoming the bottleneck | Medium | Per-workload IaC repos; central modules; central policy gates | DevOps + Cloud Foundation |
| LZAP-008 | Platform team is bottleneck; workload teams work around | Medium | Self-service; platform team owns substrate, workload teams own workloads | Cloud Foundation + Sponsor |
| LZAP-009 | Documentation deferred indefinitely | Low | Per-design-decision documentation; per-PR requirement | Cloud Foundation |
| LZAP-010 | Detection-as-code coverage of landing-zone controls < 80% | Medium | Per-control: at least one detection rule; ongoing buildout | Detection Eng + Security Eng |
| LZAP-011 | Compliance crosswalk not built alongside controls | Low | Per-control: which frameworks does it satisfy per [../compliance-and-control-mapping/](../compliance-and-control-mapping/) | Compliance + Security Eng |
| LZAP-012 | Bus-factor of 1; landing-zone knowledge in one engineer | Medium | Per-control review by ≥2 engineers; runbooks; deliberate knowledge sharing | Cloud Foundation |
| LZAP-013 | Over-correction from sprawl to monolith | Medium | Right-sized: workload-based separation; not blanket consolidation | Cloud Foundation |
| LZAP-014 | Over-correction from rigidity to anarchy | Medium | Structured deviation process; per-quarter consolidation | Cloud Foundation |
| LZAP-015 | Over-correction from coupling to total duplication | Medium | Discriminate per-component; not blanket per-workload | Platform Eng |

---

## Adoption checklist

- [ ] Per-quarter retrospective against this anti-pattern catalogue.
- [ ] Per-account / -subscription / -project utilization review (catch sprawl or monolith).
- [ ] Per-deviation review process for the reference architecture.
- [ ] Per-shared-service HA design and failure-mode planning.
- [ ] Per-cloud break-glass tested quarterly.
- [ ] Per-control detection coverage; gap-closure plan.
- [ ] Per-control compliance crosswalk.
- [ ] Per-PR documentation requirement.
- [ ] Per-team rotation on landing-zone work; reduce bus factor.
- [ ] Sponsor review per quarter: scale-fit, sprawl vs monolith, reference health.

---

## What this document is not

- **A complete reference architecture.** [aws-organizations-design.md](./aws-organizations-design.md), [azure-management-groups.md](./azure-management-groups.md), [gcp-organization-design.md](./gcp-organization-design.md) cover the target shapes.
- **A sequencing playbook.** [adoption-sequencing.md](./adoption-sequencing.md) covers the build order.
- **An IAM anti-pattern catalogue.** [../identity-and-access/iam-anti-patterns.md](../identity-and-access/iam-anti-patterns.md) covers IAM-specific patterns.
- **A detection-engineering reference.** [../cloud-detection-response/](../cloud-detection-response/) covers detection in depth.
- **An exhaustive failure-mode list.** Real environments fail in more ways than five; this document covers the most-recurring patterns.
- **A blame-attribution guide.** The intent is "recognize and correct," not "identify whose fault."
