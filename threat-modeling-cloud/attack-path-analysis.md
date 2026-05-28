# Attack Path Analysis

A practitioner's reference for attack-path analysis as the third threat-modeling method — how to build an attack graph from CloudTrail / Activity Log / Audit Log data, how to extract the high-value paths (those reaching an asset of value in three hops or fewer), how to convert paths into remediations, and the CSPM-attack-paths integration patterns. The patterns here catch what STRIDE misses: the multi-step lateral-movement chains that emerge from edges between resources rather than from properties of individual components.

This document is the third leg of the threat-modeling triad. STRIDE ([cloud-stride-template.md](./cloud-stride-template.md)) walks components; ATT&CK ([mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md)) walks adversary techniques; attack-path analysis walks the graph. Multi-step attacks that exploit edges between resources — `S3-public-bucket → AssumeRole → cross-account data access` — are easier to find by tracing the graph than by walking STRIDE on each step in isolation.

For the STRIDE methodology, see [cloud-stride-template.md](./cloud-stride-template.md). For ATT&CK coverage, see [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md). For how to integrate attack-path analysis into a threat-modeling session, see [facilitation-guide.md](./facilitation-guide.md).

---

## When to read this document

**If your STRIDE threat models miss multi-step attacks** — read top to bottom. Single-component walks don't compose; attack-path analysis does.

**If you have a CSPM that surfaces attack paths and you want to operationalize them** — start with [CSPM attack-path integration](#cspm-attack-path-integration).

**If you want to build attack-path analysis without a CSPM** — start with [Building an attack graph from scratch](#building-an-attack-graph-from-scratch).

**If you are auditing attack-path coverage** — start with [Findings checklist](#findings-checklist).

---

## What attack-path analysis is

A method for finding multi-step attacks that connect an attacker's likely starting position to an asset of value.

### The graph

- **Nodes:** cloud resources (IAM roles, S3 buckets, EC2 instances, KMS keys, etc.).
- **Edges:** the relationships between resources (`can-assume`, `can-read`, `is-trusted-by`, etc.).
- **Initial-position nodes:** where an attacker might start (compromised CI workflow, leaked credential, exposed public bucket, etc.).
- **Asset-of-value nodes:** what's worth protecting (customer data, PII / PHI buckets, production databases).

### The analysis

For each initial-position node, find the paths to asset-of-value nodes. The paths are the attack paths.

### Why this is different from STRIDE

STRIDE walks individual components and asks "what threats apply?" Attack-path walks the graph and asks "given a starting position, what's the path to compromise?" The methods are complementary:

- STRIDE catches architectural threats at each component.
- Attack-path catches multi-step compositions of architectural threats.

A path might be: `compromised-CI-credential → AssumeRole on production deploy role → modify Lambda function → read DynamoDB → exfil`. Each step is a known component property; the composition is the actual attack.

---

## Building an attack graph from scratch

The methodology when you don't have a CSPM with built-in path analysis.

### Step 1: enumerate the resources

For each cloud account, list the resources relevant to your threat model:

- IAM roles and users.
- S3 buckets, RDS databases, DynamoDB tables.
- Lambda functions, EC2 instances, EKS clusters.
- KMS keys, Secrets Manager secrets.
- API Gateway endpoints.
- Cross-account trust policies.

For most cloud accounts: hundreds to thousands of resources. The enumeration is mostly automatable (`aws resourcegroupstaggingapi`, similar in Azure / GCP).

### Step 2: enumerate the edges

For each resource, identify the relationships:

- **IAM role → AssumeRole'able-from:** which other principals can assume this role.
- **IAM role → can-access:** which resources can this role read/write.
- **S3 bucket → readable-by:** which IAM identities, via what mechanism (bucket policy + IAM policy).
- **KMS key → usable-by:** which IAM identities can use this key.
- **Trust-policy relationships:** which identities (including cross-account, OIDC federation) can assume this role.

The edges come from IAM policies, resource policies, KMS key policies, and trust relationships. Most are queryable from the cloud's IAM APIs.

### Step 3: identify initial positions

Common starting positions for an attacker:

- **Compromised CI workflow** — has whatever the CI's role grants.
- **Compromised IAM user** — has whatever the user's policies grant.
- **Leaked access key** — same as IAM user, but possibly the team doesn't realize.
- **Compromised pod via web vulnerability** — has the pod's IRSA role.
- **Public S3 bucket** — anonymous read; some buckets allow anonymous write.
- **Compromised vendor account** — has whatever the vendor's role grants (cross-account).
- **Compromised dependency / supply chain** — code-level compromise.

### Step 4: identify assets of value

The things you're protecting:

- **Customer data buckets / databases.**
- **Credential stores (Secrets Manager, Vault).**
- **CI / production deployment roles** (compromise of these = environment-wide compromise).
- **Cloud-admin roles.**
- **Audit log destinations** (compromise of these = anti-forensics).

### Step 5: trace paths

For each initial position, traverse edges toward each asset of value. A path is the sequence of resources and edges from start to asset.

The interesting paths are:

- **Short** (3-4 hops): direct paths an attacker can exploit quickly.
- **Containing high-privilege intermediaries** (e.g., `iam:PassRole` allows escalating to any role).
- **Crossing trust boundaries** (account, region, environment).
- **Not blocked by detection** (no detection rule catches the technique used).

### Step 6: prioritize and remediate

Short paths to high-value assets are remediated first. The remediation is breaking the path at the weakest link.

### Practical tools

- **AWS IAM Access Analyzer:** detects some cross-account paths.
- **AWS Service Catalog AppRegistry:** resource inventory.
- **Custom scripts:** parse IAM policies, build graphs in Neo4j or NetworkX.
- **CSPMs:** Wiz, Lacework, Prisma Cloud do this natively (next section).

References:
- [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Princeton SkyArk (open-source)](https://github.com/cyberark/SkyArk)
- [PMapper (open-source)](https://github.com/nccgroup/PMapper) — AWS IAM graph analysis tool.

---

## CSPM attack-path integration

Modern CSPMs (Wiz, Lacework, Prisma Cloud, Defender for Cloud) compute attack paths natively.

### What CSPMs provide

- **Continuous graph computation** from cloud APIs.
- **Pre-built attack-path queries** (e.g., "internet-exposed VM with high-permission role"; "public S3 bucket with sensitive content").
- **Prioritization** by reachability of assets of value.
- **Visualization** of the path.

### The integration with threat modeling

- CSPM paths are inputs to the threat-modeling session.
- The session validates: is this path actually exploitable? Is the detection in place?
- Outputs: the paths to remediate; the detection gaps.

### Common high-value paths CSPMs surface

- **Internet-exposed compute with cross-account IAM permission** — public EC2 with role that grants cross-account access.
- **Public bucket with sensitive content** — Macie / data-classification flags content; bucket-policy review.
- **Lateral movement via shared IAM roles** — a role used by multiple workloads; compromise of one = access for all.
- **Pivot via cloud control-plane services** — Lambda function with broad IAM; SSM Session Manager from EC2; etc.

### Limitations of CSPM paths

- **Configuration-only:** CSPMs see the configuration; they don't see runtime behavior.
- **False-positive rate:** some paths look exploitable but have other mitigations.
- **Coverage gaps:** specific techniques may not be in the CSPM's path-detection ruleset.

The pattern: CSPM is one input; STRIDE and ATT&CK are complementary; the threat-modeling session synthesizes.

---

## Common cloud attack paths

The paths that recur across environments.

### Path 1: CI compromise → production

```
Compromised CI workflow
  → AssumeRole on production-deploy role (via CI's IAM)
  → modify CloudFormation / Terraform / Helm deployment
  → deploy attacker-controlled resources to production
  → read customer data
```

The mitigations:

- OIDC federation with `sub` condition scoping (per [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md)).
- Production-deploy role with admission gating (review before apply).
- Detection on cross-account role assumption from CI.

### Path 2: compromised pod → cross-account data exfil

```
Compromised pod (via web vulnerability)
  → IRSA credentials (the pod's role)
  → S3 access (if role has S3 permissions)
  → cross-account S3 write (if SCP doesn't block)
  → attacker-controlled bucket in attacker account
```

The mitigations:

- Per-pod IAM scoping (no over-broad roles).
- SCP blocking cross-account S3 writes outside the organization.
- Network firewall blocking egress to unexpected destinations.
- DNS firewall blocking unauthorized FQDNs.

### Path 3: public bucket → cross-account assumption

```
Anonymous internet user
  → Public S3 bucket (misconfiguration)
  → Read sensitive config including IAM credentials
  → AssumeRole using the credentials
  → Production access
```

The mitigations:

- Block Public Access at account level (per [../data-security/object-storage-hardening.md](../data-security/object-storage-hardening.md)).
- No credentials in S3 (secret-scanning per [../secrets-and-keys/secret-detection.md](../secrets-and-keys/secret-detection.md)).
- Detection on access-key creation events.

### Path 4: IMDS SSRF → cloud admin

```
Attacker exploits SSRF in web app
  → Reads instance metadata service (IMDS)
  → Gets EC2 instance role's credentials
  → If instance role is over-privileged: cloud admin via API calls
  → Persistence via IAM role creation
```

The mitigations:

- IMDSv2 required.
- Per-instance IAM role with narrow permissions.
- Detection on access-key / role creation outside CI.

### Path 5: leaked CI credential → environment

```
Engineer pushes credential to public GitHub
  → Bot scrapes credential within minutes
  → AssumeRole or direct API calls
  → Resource creation in attacker-controlled region
  → Cryptomining or data exfil
```

The mitigations:

- Secret scanning (per [../secrets-and-keys/secret-detection.md](../secrets-and-keys/secret-detection.md)).
- OIDC federation eliminating long-lived credentials.
- Detection on resource creation in unused regions (T1535).
- Cost-anomaly detection.

---

## The hops-and-budget framing

A useful metric: how many hops to compromise?

### The metric

For each attack path: count the steps (resources traversed) from initial position to asset of value.

- **1 hop:** direct compromise. Initial position has direct access to the asset. Critical.
- **2 hops:** one intermediary. Common; usually fixable by removing the intermediary's privilege.
- **3 hops:** two intermediaries. Realistic attack paths; often missed by STRIDE.
- **4+ hops:** longer chains; usually requires sophisticated adversary; lower priority but still real.

### The budget

The "lateral movement budget" (per [../zero-trust-cloud/microsegmentation.md](../zero-trust-cloud/microsegmentation.md)) is the inverse: from a given starting position, how many resources can be reached?

- **Small budget:** ZT posture is working; lateral movement bounded.
- **Large budget:** posture is permissive; one compromise yields broad access.

### Tracking the budget

- Per-workload: what's the lateral-movement budget?
- Per-tenant: what's the cross-tenant reachability?
- Per-credential: if this credential is compromised, what's reachable?

The budget is observable; track it over time. Increases indicate posture degradation; decreases indicate ZT progress.

---

## Worked example: Meridian Health's attack-path analysis

Meridian uses Wiz CSPM for continuous attack-path computation, supplemented by quarterly manual analysis for STRIDE-paired threat models.

### Wiz integration

- **Wiz continuously scans** all Meridian cloud accounts.
- **Attack-path queries** include the common cloud paths (per [Common cloud attack paths](#common-cloud-attack-paths)).
- **Findings** integrated into the security team's workflow:
  - Critical paths page on-call.
  - High paths get tickets with sprint priority.
  - Medium / Low paths queued for review.

### Manual analysis cadence

Quarterly:

- Security team reviews Wiz's attack-path output.
- Pairs with STRIDE threat-model output from new features.
- Identifies paths not in Wiz's standard queries.
- Builds custom queries for Meridian-specific patterns.

### Care Coordinator path analysis

For the Care Coordinator workload, Wiz surfaces and the team validates these paths:

1. **CI compromise → production-deploy role.** Mitigated by GitHub OIDC with `sub: repo:meridian-health/care-coordinator:ref:refs/heads/main`.
2. **EKS pod compromise → cross-account S3 read.** Mitigated by per-pod IRSA with bucket-scoped grants; SCP denying cross-account S3 writes.
3. **Workforce-credential compromise → SSO → admin tools.** Mitigated by Cloudflare Access + MFA + device-trust; step-up for sensitive actions.
4. **Vault compromise → all secrets.** Mitigated by Vault HA cluster; per-namespace policies; recovery-key custodianship.

Each path is documented; remediations sprint-tracked.

### Findings opened during the attack-path analysis adoption

- **PATH-001** (no continuous attack-path analysis; one-shot threat modeling only). Closed by Wiz deployment.
- **PATH-002** (CSPM findings volume overwhelmed; no prioritization). Closed by hops-and-asset-value prioritization.
- **PATH-003** (CI-to-production paths not specifically modeled). Closed by OIDC federation scoping.
- **PATH-004** (cross-account paths not all surfaced; some Wiz queries didn't fire). Closed by custom Wiz queries.
- **PATH-005** (lateral-movement budget unmeasured; ZT progress unmeasurable). Closed by per-credential budget computation.
- **PATH-006** (CSPM attack-paths and threat-model findings tracked separately). Closed by integrated workflow.

---

## Anti-patterns

### 1. The STRIDE-only threat model

The team walks STRIDE; never analyzes paths. Multi-step attacks invisible.

The fix: pair STRIDE with attack-path analysis; the methods are complementary.

### 2. The CSPM-overload

CSPM produces 1000 attack-paths; team can't process; alerts ignored.

The fix: prioritize by hops + asset value; address top 20 per quarter.

### 3. The path-without-detection

A path is identified; remediation deferred. Detection on the path's technique doesn't exist; if exploited, no signal.

The fix: paths drive detection rules; ATT&CK coverage pairs with path remediation.

### 4. The static-snapshot analysis

Attack paths computed once; not updated as architecture changes.

The fix: continuous CSPM-driven computation; or quarterly manual analysis cadence.

### 5. The CSPM-as-only-source

The team relies entirely on CSPM paths. Architectural paths the CSPM doesn't see (application-layer, supply chain) are missed.

The fix: CSPM is one input; STRIDE-paired analysis is another; both contribute.

### 6. The high-hop-ignored

Team focuses on 1-2 hop paths. 3-4 hop paths are real but harder to exploit; deferred indefinitely.

The fix: 3-hop paths are within sophisticated-adversary capability; prioritize after 1-2 but don't defer indefinitely.

### 7. The path-without-validation

A CSPM-reported path is assumed exploitable; remediation effort goes there; the path turns out to be infeasible.

The fix: validate paths before remediation; small validation exercises (does the IAM grant really resolve the way the path assumes?).

### 8. The over-mitigation-of-symptom

The team breaks one resource's edge; the path is mitigated for that path but the underlying issue (e.g., over-broad IAM) remains.

The fix: address the structural issue, not just the specific path. The structural fix addresses many paths.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| PATH-001 | No attack-path analysis; STRIDE-only threat modeling | High | Deploy CSPM with path analysis; pair with STRIDE | Security Eng + Architecture |
| PATH-002 | CSPM findings unprioritized; alert fatigue | High | Prioritize by hops + asset value; address top 20 per quarter | Security Eng + SOC |
| PATH-003 | CI-to-production paths not specifically modeled | High | OIDC federation with `sub` condition scoping; trust policy review | DevOps + Security Eng |
| PATH-004 | CSPM standard queries miss org-specific path patterns | Medium | Custom queries for environment-specific patterns | Security Eng |
| PATH-005 | Lateral-movement budget unmeasured; ZT progress invisible | Medium | Per-credential budget computation; trend over time | Security Eng + Observability |
| PATH-006 | CSPM paths and threat-model findings tracked separately | Low | Integrated workflow; unified prioritization | Security Eng |
| PATH-007 | Attack paths static-snapshot; not updated as architecture changes | Medium | Continuous CSPM or quarterly manual analysis | Security Eng + Architecture |
| PATH-008 | High-hop paths ignored; sophisticated-adversary risk persists | Medium | 3-4 hop paths included in analysis with appropriate prioritization | Security Eng |
| PATH-009 | Path remediation addresses symptom (one edge) not structure (over-broad IAM) | Medium | Structural fix; many paths addressed simultaneously | Security Eng + Architecture |
| PATH-010 | Paths surfaced without validation; some are infeasible; effort wasted | Low | Validate before remediation; small exercise to confirm feasibility | Security Eng |
| PATH-011 | Detection not paired with path remediation; if exploited, no signal | High | Each path's technique covered by detection rule | Security Eng + SOC |
| PATH-012 | Initial-position scenarios not enumerated; coverage gaps | Medium | Enumerate likely starting positions (CI compromise, pod compromise, etc.); analyze each | Security Eng |
| PATH-013 | Asset-of-value list informal; assets shifted but path analysis didn't update | Low | Maintain asset-of-value list; update quarterly; re-analyze | Security Eng + Architecture |
| PATH-014 | Public-internet exposure paths under-analyzed | High | Enumerate internet-exposed resources; each is an initial-position | Security Eng |
| PATH-015 | Cross-cloud paths absent from analysis (CSPM scope is single-cloud) | Medium | Cross-cloud-aware tooling; or manual cross-cloud analysis | Security Eng + Architecture |
| PATH-016 | Path analysis not integrated with incident response; IR doesn't reference precomputed paths | Low | IR runbooks reference common paths; SOC has path-context for triage | Security Eng + SOC |
| PATH-017 | Workforce-identity-to-cloud-admin paths under-analyzed | Medium | Per-workforce-credential analysis; SSO + step-up requirements | IAM Eng + Security Eng |
| PATH-018 | Path metrics not in security KPIs / OKRs | Low | Quarterly path-count + remediation-rate metrics; leadership reporting | Security Eng + Leadership |

---

## What this document is not

- **A graph-theory primer.** Graph traversal and Dijkstra-style algorithms are mentioned at conceptual level.
- **A CSPM vendor comparison.** Wiz / Lacework / Prisma Cloud / Defender for Cloud all do path analysis; the choice belongs with broader tool decisions.
- **A complete PMapper / SkyArk tutorial.** The open-source tools are mentioned; their operational depth lives in project docs.
- **A red-team exercise reference.** Adversary emulation tools (Stratus Red Team, Pacu) are mentioned in passing; depth lives with the tooling.
