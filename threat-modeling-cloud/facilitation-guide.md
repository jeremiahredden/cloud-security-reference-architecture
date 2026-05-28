# Facilitation Guide

A practitioner's reference for running a cloud threat-modeling session with an engineering team — pre-meeting preparation, the data-flow-diagram-on-a-whiteboard process, the STRIDE walkthrough with cloud-specific prompts, the finding-prioritization rubric, and the post-meeting deliverable structure. The guide here is what I follow when I run a 60-90 minute cloud threat-modeling session with a team that hasn't done one before, or for a quarterly review with a team that has.

This document is the how-to companion to the methodology documents in this folder. [cloud-stride-template.md](./cloud-stride-template.md) is the template; [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md) is the coverage check; [attack-path-analysis.md](./attack-path-analysis.md) is the path method; this document is how to run the session that synthesizes them.

The honest framing: threat-modeling sessions stall on logistics more often than on methodology. A team that doesn't know what to bring, how to start, or what to deliver after will produce a session that's confusing for everyone. The patterns here are the logistics.

---

## When to read this document

**If you are about to facilitate your first cloud threat-modeling session** — read top to bottom.

**If you have run sessions before but they tend to run long or produce unclear outputs** — start with [The 60-90 minute structure](#the-60-90-minute-structure) and [The post-session deliverable](#the-post-session-deliverable).

**If you are training new facilitators** — pair this document with [cloud-stride-template.md](./cloud-stride-template.md) and have them shadow two sessions before facilitating.

**If you are auditing facilitation quality** — start with [Findings checklist](#findings-checklist).

---

## What a cloud threat-modeling session is

A 60-90 minute meeting with the engineering team responsible for a workload, facilitated by a security engineer / architect, producing a list of cloud-security findings tied to the architecture.

### Goals

- **Surface architectural and design-level cloud-security threats** that aren't visible from code review or CSPM scanning alone.
- **Build shared understanding** between security and engineering about the cloud-security posture.
- **Produce a concrete finding list** that engineering can act on in subsequent sprints.

### Who attends

- **Facilitator:** the security engineer / architect running the session.
- **Workload owner:** the engineering lead for the workload being modeled.
- **2-3 engineers:** members of the team who know the architecture well.
- **Optional: SRE / platform-team representative** if the workload touches shared platform.

Not invited unless directly relevant: leadership, full team, ad-hoc observers. Small focused group; ~5 people in the room.

### When to run a session

- **New feature touching new cloud resources:** before the feature ships.
- **Quarterly platform review:** ~90 days cadence on the overall architecture.
- **Post-incident:** focused on the incident's vector and adjacent threats.
- **Pre-launch / pre-GA:** as part of the readiness review.

### What it isn't

- **A code review.** Code-level security review happens separately.
- **A compliance audit.** Compliance frameworks have their own format.
- **A red team exercise.** Adversary emulation is separate.
- **A general "let's talk about security" meeting.** The session is structured; the output is concrete.

---

## Pre-meeting preparation

The facilitator's work before the meeting starts.

### 1-2 weeks before

**Schedule the meeting.** 60 or 90 minutes; book the room (or video meeting).

**Identify the workload scope.** What's being modeled? One workload, not the whole portfolio. Document the scope (e.g., "Care Coordinator clinical-knowledge service, including its EKS deployment, S3 buckets, RDS database, and CI pipeline").

**Identify the asset list.** What's the workload protecting? Customer data, regulatory data, credentials, infrastructure.

**Identify the threat actors.** Who is the threat model against? External attacker (commodity / targeted), malicious insider, compromised supply chain, all of the above?

### 1 week before

**Request the architecture documentation.** Get the latest DFD or architecture diagram from the team. If they don't have one, schedule a 30-minute pre-meeting to draw one together.

**Review the architecture.** Walk the diagram; note any IAM / KMS / cross-account elements that should be in the DFD but might be missing.

**Draft initial threat-prompts list.** From [cloud-stride-template.md](./cloud-stride-template.md), select the prompts most relevant to the workload's architecture. Customize based on cloud (AWS / Azure / GCP) and stack (Kubernetes / serverless / VMs).

### 1-2 days before

**Send the agenda + DFD to attendees.** Include:

- Session purpose and scope.
- The DFD (current version).
- The asset list.
- The threat-actor scope.
- What attendees should bring (their understanding of the architecture).
- The expected output (formal finding list within a week).

**Reserve a whiteboard / shared screen.** The DFD needs to be visible and editable during the session.

### Just before the session

**Have the materials ready:**

- DFD on screen (Excalidraw, Miro, or whiteboard).
- STRIDE prompts on a slide.
- Findings doc (shared, editable; the facilitator captures threats live).
- Facilitator's notes on workload-specific context.

---

## The 60-90 minute structure

The actual session.

### Minute 0-5: opening

- **Welcome and goal-setting.** "We're here to identify cloud-security threats in the Care Coordinator workload. We'll spend about 60 minutes walking the architecture and producing a list of findings. The output is a written threat model that engineering can act on this quarter."
- **Confirm scope and constraints.** "We're modeling Care Coordinator. Out of scope: the platform layer (separate session) and customer-facing features (their own threat model)."
- **Set expectations.** "We're not trying to find every threat. We're trying to find the 20-30 most important ones."

### Minute 5-10: confirm the DFD

- **Walk the DFD.** "Let me walk through this. Tell me where I have it wrong."
- **Correct the DFD live.** Most diagrams need adjustment. The team's understanding may differ from the documented architecture.
- **Add IAM / KMS / cross-account elements if missing.** "I notice the trust policy isn't on this diagram. Can someone tell me which principals can assume this role?"

### Minute 10-15: confirm assets and threat model

- **Asset list.** "What's this workload protecting? Customer PII, payment data, internal admin credentials..."
- **Threat model.** "We're modeling against external attacker (targeted) and compromised supply chain. We're not modeling nation-state actors in this scope."

### Minute 15-65: STRIDE walk

The bulk of the session.

For each component on the DFD:

1. **Name the component.** "Let's walk through the Care Coordinator supervisor pod."
2. **Walk S, T, R, I, D, E in order.** For each letter:
   - Read the cloud-specific prompts from [cloud-stride-template.md](./cloud-stride-template.md).
   - Ask "could this happen here?"
   - Capture answers in the findings doc.
3. **Move to next component.** "OK, now let's walk the IAM role this pod uses."

### The pace

For a 60-minute session, plan ~5 minutes per major component. Most workloads have 8-12 components on the DFD. The walk is the work; budget accordingly.

If you're going to run over: prioritize the components with the most threats (typically IAM roles, KMS keys, cross-account boundaries) over the components with fewer (e.g., a generic load balancer).

### Minute 65-75: severity and prioritization

- **Walk the findings list.** "Let's assign severity to each."
- **Use the severity rubric** from [cloud-stride-template.md](./cloud-stride-template.md).
- **Identify top priorities.** "Which are the 5-10 we should address this quarter?"

### Minute 75-90: ATT&CK coverage check + close

If time permits:

- **Quick ATT&CK pass.** "Looking at the matrix techniques we should have surfaced, are there any we missed?"
- **Document gaps as findings.**
- **Close.** "I'll write up the formal findings this week. We'll meet again next quarter for an updated review."

If short on time: skip ATT&CK in the session; do it in the post-session write-up.

---

## Facilitating the STRIDE walk

The walk is the bulk of the session; quality depends on the facilitator.

### The facilitator's job

- **Drive the walk.** Move through components in sequence; don't let conversation wander.
- **Ask the prompts.** Read the prompts from the template; ask "could this happen here?"
- **Capture honestly.** When a threat is identified, write it down even if it's uncomfortable.
- **Defer remediation discussion.** "Good — we've identified the threat. Let's keep moving; remediation will be in the written findings."

### Common facilitation issues

**The "we already have a mitigation" derail.** Engineering responds to a threat with "well, we have X mitigation in place." The facilitator's response: "Great — note that as part of the finding. The finding is the threat exists at all; the mitigation is what limits it. We're capturing both."

**The "that's not realistic" pushback.** Engineering dismisses a threat as unrealistic. Facilitator: "Let's note it as a Low severity finding. We may decide it doesn't warrant action, but we want to document we considered it."

**The "deep technical tangent."** Engineering goes deep on implementation details. Facilitator: "Got it. Let's note the technical detail and keep moving. We can discuss implementation in the follow-up."

**The silent engineer.** One engineer dominates; another doesn't speak. Facilitator: "X, what's your perspective on this component?"

### Maintaining momentum

- **Time-box per component.** Don't spend 20 minutes on one component when the budget is 5.
- **Acknowledge the threat; defer the fix.** Findings, not solutions, are the session output.
- **Take notes everywhere.** Even threats that won't make the formal output benefit from being captured.

---

## The post-session deliverable

Within 3-5 business days after the session.

### Structure

A document with:

1. **Executive summary** (1-2 paragraphs): the workload modeled, the scope, the headline findings.
2. **Architecture** (1-2 pages): the DFD (as walked, with corrections); the asset list; the threat-actor scope.
3. **Findings** (the bulk): the structured findings list per [cloud-stride-template.md](./cloud-stride-template.md)'s format.
4. **MITRE ATT&CK coverage analysis** (1-2 pages): which techniques in the matrix the findings cover; which they don't; the gaps.
5. **Attack-path supplement** (optional): for paths surfaced via [attack-path-analysis.md](./attack-path-analysis.md).
6. **Recommendations summary**: the top 5-10 to address this quarter.
7. **Appendix**: the session notes; the raw STRIDE walk output.

### Finding format

Per [cloud-stride-template.md §Finding structure](./cloud-stride-template.md#finding-structure):

```
ID: CLOUD-001
Title: Production cross-account role accepts trust from CI account's account root
STRIDE: S (Spoofing)
Component: arn:aws:iam::PROD:role/care-coordinator-deploy
Description: ...
Attack path: ...
Severity: High
Recommendation: ...
Owner: Platform Eng + Security Eng
MITRE: T1078.004
```

### Delivery and follow-up

- **Send to attendees + relevant stakeholders** (engineering lead, product owner, security manager).
- **Create tickets** for the prioritized findings (sprint-tracked).
- **Schedule the next session** (quarterly).
- **Track remediation** of findings over the quarter; review at next session.

### What not to deliver

- **A 50-page document** that nobody reads. Keep it to 10-15 pages for a typical workload.
- **A list of every possible threat** including theoretical / academic ones. Focus on actionable.
- **Recommendations without owners.** Every finding has a recommended owner; without it, nothing happens.

---

## Per-session-type adjustments

The structure varies slightly by context.

### New-feature pre-ship session

- Scope: the feature only, not the broader workload.
- 60 minutes typical; the feature is smaller.
- Findings tied to GA / launch checklist; some are blockers.
- Output: launch-readiness assessment.

### Quarterly platform review

- Scope: the overall architecture; what's changed since last quarter.
- 90 minutes typical; broader scope.
- Findings often architectural; multi-sprint remediations expected.
- Output: quarterly threat-model update.

### Post-incident session

- Scope: the incident vector + adjacent threats.
- 60 minutes typical; focused.
- Findings include the actual incident's RCA threats + adjacent.
- Output: lessons learned, broader-than-RCA findings.

### Pre-launch / pre-GA session

- Scope: the entire workload before its first production release.
- 90 minutes; thorough.
- Findings tied to GA blockers; risk-acceptance documented for non-blockers.
- Output: GA readiness assessment.

---

## Worked example: Meridian Health's facilitation pattern

Meridian runs threat-modeling sessions in three contexts: per-new-feature, per-quarter, post-incident.

### The facilitator pool

- 3-4 security engineers trained as facilitators.
- New facilitators shadow 2 sessions before facilitating.
- Quarterly facilitator-only sync to share patterns and surface tooling improvements.

### The pre-session checklist

Before each session, the facilitator:

- Books the meeting with the right attendees (workload owner, 2-3 engineers).
- Reviews the architecture documentation.
- Drafts the customized DFD if needed.
- Sends agenda + DFD + asset list to attendees.
- Books a shared whiteboard / Miro board.

### The session structure

Standard 60-90 minute template per [The 60-90 minute structure](#the-60-90-minute-structure). The Care Coordinator workload's recent threat-modeling session followed this exactly:

- Opening + DFD confirmation (10 min).
- Asset + threat-actor confirmation (5 min).
- STRIDE walk on 12 components (50 min).
- Severity + prioritization (15 min).
- Close + next steps (10 min).

### The post-session deliverable

Within 3 business days:

- Formal finding list (~25 findings).
- MITRE ATT&CK coverage analysis.
- Recommendations summary (top 8).
- Tickets created for findings; sprint-tracked.

### The training cadence

- New security engineers facilitate within 6 months of joining; shadow 2 sessions first.
- Quarterly facilitator sync.
- Annual review of the template and prompts based on observed effectiveness.

### Findings opened during the facilitation discipline rollout

- **FACIL-001** (sessions varied in quality; no facilitation guide). Closed by this document and facilitator training.
- **FACIL-002** (no pre-session preparation discipline; sessions started with confusion). Closed by checklist.
- **FACIL-003** (sessions ran long because tangents weren't managed). Closed by facilitator training on momentum.
- **FACIL-004** (post-session deliverables late or absent). Closed by 3-5 business day SLA + tracking.
- **FACIL-005** (findings without owners). Closed by ownership-assignment discipline.
- **FACIL-006** (sessions stopped at STRIDE; ATT&CK coverage not paired). Closed by pairing discipline.

---

## Anti-patterns

### 1. The unstructured-conversation session

The facilitator hasn't prepared. The session is a 60-minute brainstorm. Output is unclear.

The fix: structured walk per [The 60-90 minute structure](#the-60-90-minute-structure).

### 2. The DFD-from-scratch session

The team draws the DFD in the meeting from scratch. 40 minutes go to drawing; 20 to STRIDE; output is shallow.

The fix: DFD prepared before; session validates and corrects.

### 3. The everyone-invited session

The session has 12 attendees. Conversation is unfocused; engineers who know the architecture can't get a word in.

The fix: small focused group (~5).

### 4. The findings-without-owners output

The post-session document lists threats but doesn't say who owns the remediation. Nothing happens.

The fix: every finding has an owner.

### 5. The remediation-discussion-in-session

The session bogs down on "how do we fix this." Output is partial.

The fix: defer remediation discussion to post-session; capture findings first.

### 6. The technical-tangent

The session goes deep on one component's implementation. Other components are skipped due to time.

The fix: time-box per component; facilitator manages tangents.

### 7. The no-followup

The session produces findings. Nothing tracks them. Quarterly recurrence reveals the same findings.

The fix: ticket per finding; sprint-tracked; reviewed at next session.

### 8. The training-bottleneck

Only one person can facilitate. They're a bottleneck; sessions scheduled around their availability.

The fix: train multiple facilitators; shadow → co-facilitate → solo.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| FACIL-001 | Threat-modeling sessions vary in quality; no facilitation guide | Medium | This document; facilitator training | Security Eng + Architecture |
| FACIL-002 | No pre-session preparation discipline; sessions start confused | Medium | Pre-session checklist; DFD prepared in advance | Security Eng |
| FACIL-003 | Sessions run long; tangents unmanaged | Low | Facilitator training on momentum; time-boxing per component | Security Eng |
| FACIL-004 | Post-session deliverables late or absent | Medium | 3-5 business day SLA; tracking | Security Eng + Engineering Lead |
| FACIL-005 | Findings without owners; remediation doesn't happen | Medium | Ownership-assignment discipline at session | Security Eng + Engineering Lead |
| FACIL-006 | Sessions stop at STRIDE; ATT&CK coverage not paired | Medium | Pair STRIDE with ATT&CK pass per [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md) | Security Eng |
| FACIL-007 | Single-facilitator bottleneck; sessions scheduled around availability | Low | Train multiple facilitators; shadow → co-facilitate → solo | Security Eng + Hiring |
| FACIL-008 | DFD drawn in the session from scratch; 40 min lost | Medium | DFD prepared before; session validates | Security Eng |
| FACIL-009 | Too many attendees; conversation unfocused | Medium | Small focused group (~5); right invitees | Security Eng |
| FACIL-010 | Remediation discussed in session; findings capture incomplete | Low | Defer remediation; capture findings first | Security Eng |
| FACIL-011 | No follow-up tracking; findings lost between sessions | Medium | Tickets per finding; review at next session | Security Eng + Engineering Lead |
| FACIL-012 | Quarterly cadence absent; threat models become stale | Medium | Per-quarter platform review schedule | Security Eng + Architecture |
| FACIL-013 | Pre-launch / pre-GA threat modeling absent; new launches reach production unmodeled | High | GA checklist includes threat-model session | Security Eng + Product |
| FACIL-014 | Post-incident threat-modeling absent; lessons stay narrow | Medium | Post-significant-incident session within 2 weeks | Security Eng + SOC |
| FACIL-015 | Facilitator training program absent; new facilitators learn ad-hoc | Low | Formal training: shadow → co-facilitate → solo within 6 months | Security Eng + Hiring |
| FACIL-016 | Session output format inconsistent; reading deliverables takes longer | Low | Standard deliverable template; consistent across sessions | Security Eng |
| FACIL-017 | Asset and threat-actor scope undefined; sessions wander | Medium | Pre-session asset list; documented threat-actor scope | Security Eng + Architecture |
| FACIL-018 | Threat-modeling outputs not shared with SOC; detection gaps unaddressed | Low | SOC reviews threat-model findings; detection rules updated | Security Eng + SOC |

---

## What this document is not

- **A meeting-facilitation tutorial.** General meeting-facilitation skills apply; this document focuses on threat-modeling-specific patterns.
- **A facilitator-certification program.** This document is a guide, not a certification.
- **A vendor tool-specific guide.** Miro / Excalidraw / Lucidchart are mentioned; the choice belongs with team preference.
- **A complete threat-modeling methodology reference.** Methodology lives in [cloud-stride-template.md](./cloud-stride-template.md), [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md), and [attack-path-analysis.md](./attack-path-analysis.md).
