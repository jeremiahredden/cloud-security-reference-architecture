# MITRE ATT&CK for Cloud Coverage

A practitioner's reference for using the MITRE ATT&CK for Cloud Matrix as a coverage check against cloud threat models — a tactic-by-tactic walkthrough with the preventive and detective controls per technique, the techniques most commonly missed in real environments, and the "did we model this" checklist that pairs with [cloud-stride-template.md](./cloud-stride-template.md). The patterns here are about turning the matrix into operational coverage, not just framework alignment.

This document is the coverage-check companion to STRIDE. STRIDE walks the architecture and asks "what threats apply at each component?"; ATT&CK walks the adversary playbook and asks "what techniques would an attacker actually use?" Pairing the two catches what each misses individually — STRIDE catches architectural threats; ATT&CK catches adversary techniques the team might not have anticipated.

For the STRIDE methodology this pairs with, see [cloud-stride-template.md](./cloud-stride-template.md). For attack-path analysis as a third method, see [attack-path-analysis.md](./attack-path-analysis.md). For how to integrate ATT&CK coverage into a threat-modeling session, see [facilitation-guide.md](./facilitation-guide.md).

---

## When to read this document

**If you have a STRIDE threat model and want to check it for adversary-technique coverage** — read top to bottom.

**If you are building detection rules and want to know which techniques to cover** — start with [The detective-control mapping](#the-detective-control-mapping). The matrix is the canonical source for "what adversaries actually do."

**If you have a CSPM that produces findings and you want to map them to ATT&CK** — start with [CSPM and ATT&CK integration](#cspm-and-attck-integration).

**If you are auditing ATT&CK coverage** — start with [Findings checklist](#findings-checklist).

---

## What MITRE ATT&CK for Cloud is

MITRE ATT&CK is a framework of adversary tactics and techniques observed in real-world attacks. The Cloud Matrix is the subset relevant to cloud environments (AWS, Azure, GCP, IaaS, SaaS).

### Tactics and techniques

- **Tactics:** the adversary's goal at a given stage (e.g., Initial Access, Persistence, Privilege Escalation).
- **Techniques:** the specific methods used to achieve a tactic (e.g., T1078.004 "Valid Accounts: Cloud Accounts").
- **Sub-techniques:** more specific variants (e.g., T1078.004 has further nuance per cloud).

The matrix is empirically grounded: every technique is observed in real incidents.

### The cloud tactics in 2026

The 2026 ATT&CK for Cloud Matrix covers these tactics:

- **Initial Access** — getting into the cloud environment.
- **Execution** — running attacker-controlled code.
- **Persistence** — maintaining access.
- **Privilege Escalation** — gaining higher permissions.
- **Defense Evasion** — avoiding detection.
- **Credential Access** — obtaining credentials.
- **Discovery** — finding what's in the environment.
- **Lateral Movement** — moving between resources.
- **Collection** — gathering target data.
- **Exfiltration** — extracting data.
- **Impact** — destructive or disruptive actions.

Some tactics have many techniques; others few. The patterns are well-documented at the MITRE site.

References:
- [MITRE ATT&CK for Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [MITRE ATT&CK techniques](https://attack.mitre.org/techniques/)

---

## How to use the matrix for coverage check

The practical pattern.

### After a STRIDE session

1. **List the STRIDE findings.** Each has a STRIDE category and a brief description.
2. **For each finding, identify the ATT&CK technique(s) it represents.** Most STRIDE findings map to one or two techniques.
3. **List the techniques covered.** Aggregate across findings.
4. **Compare to the matrix.** What techniques in the cloud matrix did the STRIDE walk *not* surface?
5. **For each uncovered technique:** ask "is this applicable to our environment?" If yes: that's a coverage gap; convert to a finding.

The output: the STRIDE findings + the additional findings from coverage gaps.

### Common coverage gaps

Techniques STRIDE walks often miss:

- **T1578 Modify Cloud Compute Infrastructure** — adversary modifies cloud compute (EC2 instances, AMIs, snapshots) to gain access or persistence. Often not surfaced by STRIDE because it's an attacker action, not an architectural property.
- **T1098.001 Additional Cloud Roles** — adversary creates additional cloud roles for persistence. STRIDE catches the result (over-broad roles); often doesn't catch the technique (creating new roles as a persistence mechanism).
- **T1530 Data from Cloud Storage** — adversary reads sensitive data from cloud storage. STRIDE catches "could storage be exposed"; often doesn't catch "what is the detection if exfil happens via approved channel."
- **T1538 Cloud Service Dashboard** — adversary uses cloud-provider console to gather information. STRIDE rarely surfaces console-based discovery.
- **T1213.003 Code Repositories** — adversary looks for credentials in source code. STRIDE catches "are there credentials in code" if the team thinks of it; the systematic technique is named in ATT&CK.

These gaps illustrate why coverage check matters.

### When a technique doesn't apply

Not every technique applies to every environment. Document why:

- "T1564.008 Hidden Window — not applicable; no Windows workloads in scope."
- "T1218 System Binary Proxy Execution — not applicable; serverless-only environment."

Documented inapplicability is valid coverage; undocumented gaps are real gaps.

---

## Tactic-by-tactic walkthrough

For each tactic, the techniques to specifically check; preventive and detective controls; common gaps.

### Initial Access

Techniques in cloud:

- **T1078.004 Valid Accounts: Cloud Accounts.** Adversary uses legitimate cloud credentials (compromised IAM user, leaked access key, stolen SAML assertion).
  - Preventive: SSO + MFA; phishing-resistant MFA (hardware key); kill long-lived static credentials (per [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md)).
  - Detective: anomalous IP / geo for known users; impossible travel; access-key usage from unexpected source.

- **T1190 Exploit Public-Facing Application.** Compromise of a public-facing application yields cloud foothold.
  - Preventive: WAF; application security; pod security.
  - Detective: WAF blocks; application error spikes; post-compromise indicators.

- **T1199 Trusted Relationship.** Adversary uses a partner / vendor relationship as the access vector.
  - Preventive: vendor security review; least-privilege for partner access; SCPs limiting partner reach.
  - Detective: monitoring partner-account activity; anomalous cross-account access.

### Execution

Techniques in cloud:

- **T1059 Command and Scripting Interpreter.** Adversary runs commands in compromised environment.
  - Preventive: runtime restriction (sandboxed runtimes, AppArmor / SELinux); minimal images.
  - Detective: process-execution monitoring (Falco); EDR alerts.

- **T1610 Deploy Container.** Adversary runs a malicious container.
  - Preventive: image signing per [../kubernetes-and-container-security/image-supply-chain.md](../kubernetes-and-container-security/image-supply-chain.md); admission control.
  - Detective: unexpected container starts; suspicious image registry pulls.

- **T1648 Serverless Execution.** Adversary uses serverless platforms (Lambda, Functions, Cloud Functions) for execution.
  - Preventive: function-creation IAM restrictions; admission gates.
  - Detective: anomalous function invocation patterns; unexpected function creation.

### Persistence

Techniques in cloud:

- **T1098.001 Additional Cloud Roles.** Adversary creates new IAM roles for persistence.
  - Preventive: SCP limiting role creation; IAM Access Analyzer; just-in-time role creation only.
  - Detective: CloudTrail / Activity Log on role creation; alerts on `CreateRole` outside expected contexts.

- **T1098.003 Additional Cloud Credentials.** Adversary adds credentials (access keys, certificates) to existing identities.
  - Preventive: SCP limiting key creation; phase out long-lived keys.
  - Detective: `CreateAccessKey` events; alerts on credentials added to high-privilege identities.

- **T1136.003 Create Account: Cloud Account.** Adversary creates a new cloud user account.
  - Preventive: IAM user creation prohibited by SCP; only SSO-managed accounts.
  - Detective: `CreateUser` events; alerts.

### Privilege Escalation

Techniques in cloud:

- **T1078.004 Valid Accounts: Cloud Accounts.** Reused; using a higher-privilege legitimate account.

- **T1548 Abuse Elevation Control Mechanism.** Exploiting privilege-escalation flaws (e.g., `iam:PassRole` + `lambda:CreateFunction` combination).
  - Preventive: SCPs preventing dangerous combinations; IAM Access Analyzer findings.
  - Detective: detection rules on suspicious permission combinations.

### Defense Evasion

Techniques in cloud:

- **T1562.008 Impair Defenses: Disable Cloud Logs.** Adversary disables CloudTrail, Activity Log, Audit Log.
  - Preventive: SCP preventing CloudTrail disable; org-level logs that can't be disabled by accounts.
  - Detective: CloudTrail-config-change events; alerts on `StopLogging`, `DeleteTrail`.

- **T1578 Modify Cloud Compute Infrastructure.** Adversary modifies compute resources to bypass controls.
  - Preventive: IaC discipline; admission controls; SCPs restricting compute modifications.
  - Detective: Config-change events on critical resources.

- **T1535 Unused/Unsupported Cloud Regions.** Adversary uses regions the team isn't watching.
  - Preventive: SCP restricting region use; per-region detective coverage.
  - Detective: any resource creation in unused regions = alert.

### Credential Access

Techniques in cloud:

- **T1552.005 Unsecured Credentials: Cloud Instance Metadata API.** SSRF to instance metadata yields credentials.
  - Preventive: IMDSv2 required; pod-level IMDS access blocked; per [../kubernetes-and-container-security/eks-aks-gke-baselines.md](../kubernetes-and-container-security/eks-aks-gke-baselines.md).
  - Detective: anomalous IMDS access patterns; specific Falco rules.

- **T1552.007 Unsecured Credentials: Container API.** Adversary reads kubelet API or container runtime for credentials.
  - Preventive: kubelet authentication; per-pod IAM scoping; restricted runtime access.
  - Detective: anomalous kubelet API access.

- **T1528 Steal Application Access Token.** Adversary captures OAuth / SAML tokens.
  - Preventive: token binding; short token lifetime; refresh-token rotation.
  - Detective: token-replay patterns; token use from unexpected source.

### Discovery

Techniques in cloud:

- **T1538 Cloud Service Dashboard.** Adversary uses the cloud console to gather information.
  - Preventive: console access restrictions; session monitoring.
  - Detective: CloudTrail `Console` events; anomalous console usage.

- **T1526 Cloud Service Discovery.** Adversary enumerates cloud services in use.
  - Preventive: limited by tactic (discovery is hard to fully prevent).
  - Detective: enumeration-pattern detection (List* and Describe* in rapid succession).

- **T1083 File and Directory Discovery.** Cloud storage enumeration.
  - Preventive: S3 / Storage / GCS access policies.
  - Detective: anomalous List* operations.

### Lateral Movement

Techniques in cloud:

- **T1550.001 Use Alternate Authentication Material: Application Access Token.** Adversary uses stolen tokens for lateral movement.
  - Preventive: token scope restriction; per-resource grants.
  - Detective: token use from unexpected sources.

- **T1021.007 Remote Services: Cloud Services.** Adversary uses cloud-native remote-access services (Session Manager, Bastion, IAP) with stolen credentials.
  - Preventive: per-resource access control; MFA required for sensitive remote access.
  - Detective: session-establishment monitoring.

### Collection

Techniques in cloud:

- **T1530 Data from Cloud Storage.** Adversary reads sensitive data from cloud storage.
  - Preventive: bucket policies; encryption; access controls.
  - Detective: anomalous read patterns (volume, source).

- **T1213.003 Data from Information Repositories: Code Repositories.** Adversary reads source code (often containing credentials).
  - Preventive: SSO on repos; least-privilege; per-repo access.
  - Detective: anomalous code-repo access; clone-volume monitoring.

### Exfiltration

Techniques in cloud:

- **T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage.** Adversary exfiltrates to an attacker-controlled S3 / Storage / GCS.
  - Preventive: egress allowlist (per [../network-security/egress-control.md](../network-security/egress-control.md)); per-S3 egress restriction (endpoint policies).
  - Detective: egress to unexpected destinations; anomalous data volumes.

- **T1537 Transfer Data to Cloud Account.** Adversary moves data to attacker-controlled cloud account.
  - Preventive: cross-account access restrictions; SCP on S3 cross-account writes.
  - Detective: cross-account data movement events.

### Impact

Techniques in cloud:

- **T1486 Data Encrypted for Impact.** Ransomware: adversary encrypts cloud storage.
  - Preventive: backups in separate account with Object Lock (per [../data-security/backup-and-data-residency.md](../data-security/backup-and-data-residency.md)).
  - Detective: anomalous encryption operations; mass file modifications.

- **T1496 Resource Hijacking.** Cryptomining or other resource abuse.
  - Preventive: resource quotas; per-tenant limits.
  - Detective: cost anomaly alerts; CPU usage patterns; egress to mining pools (per [../cloud-detection-response/runbook-cryptomining.md](../cloud-detection-response/runbook-cryptomining.md)).

- **T1485 Data Destruction.** Adversary deletes data.
  - Preventive: immutable backups; soft-delete; deletion-protection on critical resources.
  - Detective: mass-deletion patterns.

---

## The commonly missed techniques

Techniques that real-world threat models tend to miss.

### T1098.001 Additional Cloud Roles (persistence via role creation)

The pattern: adversary creates a new IAM role with broad permissions; sets a long-lived trust policy; persists access even if the initial-compromise credential is revoked.

Why missed: STRIDE walks ask "is this role over-permissioned?" but rarely ask "could an attacker create a new role for persistence?"

### T1578 Modify Cloud Compute Infrastructure (compute as persistence)

The pattern: adversary modifies an AMI, modifies a Launch Template, or modifies a snapshot to install a backdoor. Future instances boot with the backdoor.

Why missed: requires thinking about compute-as-persistence, which is uncommon in application-focused threat models.

### T1535 Unused/Unsupported Cloud Regions

The pattern: adversary runs workloads in regions the team isn't monitoring. Detection coverage is per-region; unused regions have no detection.

Why missed: the team thinks they're "only in us-east-1," so doesn't model regions they don't use. But CloudTrail and detection coverage must be in every region.

### T1538 Cloud Service Dashboard

The pattern: adversary uses the cloud console (not the API) to gather information. CloudTrail records the events; detection rules often focus on API patterns.

Why missed: detection rules are API-pattern-focused; console access patterns are different.

### T1213.003 Data from Information Repositories: Code Repositories

The pattern: adversary reads source code looking for credentials or business logic.

Why missed: GitHub / GitLab / Bitbucket access is often outside the scope of cloud threat modeling, even though it's part of the supply chain.

---

## The detective-control mapping

For SOC building detection rules, the matrix tells you what to detect.

### The pattern

- For each technique in scope: build a detection rule.
- The rule output is a SIEM alert.
- The alert routes to the SOC per severity.

### Common detection-rule examples

- **T1098.003:** Alert on `CreateAccessKey` for high-privilege identities; alert on access-key creation outside CI workflows.
- **T1562.008:** Alert on `StopLogging`, `DeleteTrail`, `UpdateTrail` for CloudTrail; alert on log destination changes.
- **T1530:** Alert on anomalous S3 `GetObject` volumes; alert on cross-account S3 access from unexpected accounts.
- **T1486:** Alert on rapid encryption-operation patterns; alert on `Put` operations with new KMS key context.

### Coverage tracking

Detection-rule coverage tracked per technique:

| Technique | Coverage | Detection rule | Tested |
| --- | --- | --- | --- |
| T1098.001 | Yes | SIEM rule: CreateRole outside CI | Yes (Q1) |
| T1098.003 | Yes | SIEM rule: CreateAccessKey | Yes (Q1) |
| T1562.008 | Yes | SIEM rule: CloudTrail StopLogging | Yes (Q1) |
| T1530 | Partial | Volume-based detection only | Q2 |
| T1535 | No | — | TBD |

The "Coverage" column reads: which techniques in scope have a corresponding detection rule? The "Tested" column: when was the rule last tested with a simulated attack?

The simple metric: percentage of in-scope techniques with both Coverage and Tested. A typical mature program achieves 70-85%; high-maturity programs > 90%.

---

## CSPM and ATT&CK integration

Modern CSPMs (Wiz, Lacework, Prisma Cloud, Defender for Cloud) map findings to ATT&CK techniques.

### What CSPM provides

- **Misconfigurations** mapped to MITRE techniques (e.g., "public S3 bucket" → T1530).
- **Attack-path graphs** showing how techniques chain to reach assets of value.
- **Severity** based on the path's reachability of high-value assets.

### Using CSPM output in threat modeling

- CSPM findings supplement STRIDE walks.
- CSPM attack-paths align with [attack-path-analysis.md](./attack-path-analysis.md).
- ATT&CK technique-coverage in CSPM aligns with this document's coverage matrix.

### Limitations

- CSPM coverage is configuration-focused; doesn't catch architectural or design-level threats.
- Detection rules from CSPM are vendor-specific; portability concerns.
- CSPM findings can produce alert fatigue without prioritization.

Use CSPM as one input; STRIDE and ATT&CK coverage as complementary methods.

---

## Worked example: Meridian Health's ATT&CK coverage tracking

Meridian maintains an ATT&CK Cloud Matrix coverage tracker as part of the security-engineering OKRs.

### Coverage status (current)

Out of ~80 techniques in scope:

- 65 covered with active detection rules and tested.
- 8 covered with rules but not recently tested.
- 7 documented as not applicable (e.g., on-prem-only techniques).

Coverage rate: 81% (covered + tested) / 91% (covered).

### The process

Quarterly:

- Review new techniques added to ATT&CK Cloud.
- Verify scoping (in-scope / not-applicable per environment).
- Review detection rule coverage; identify gaps.
- Schedule purple-team exercises to test rules.

After each significant cloud-security incident:

- Map the incident to ATT&CK techniques.
- Verify each technique used was in coverage.
- Add coverage where missing.

### Findings opened during the ATT&CK coverage adoption

- **ATTCK-001** (no ATT&CK coverage tracking; detection-rule effectiveness unknown). Closed by quarterly tracking.
- **ATTCK-002** (techniques relevant to environment not enumerated; coverage gaps invisible). Closed by tactic-by-tactic walkthrough; in-scope marking.
- **ATTCK-003** (detection rules existed but were not tested with simulated attacks). Closed by quarterly purple-team exercises.
- **ATTCK-004** (CSPM findings not mapped to ATT&CK; redundant prioritization signals). Closed by mapping in SIEM ingest.
- **ATTCK-005** (commonly-missed techniques — T1535 Unused Regions, T1538 Console Discovery — not covered). Closed by detection-rule expansion.

---

## Anti-patterns

### 1. The framework-alignment-without-operationalization

The team claims ATT&CK alignment. Detection rules are vendor-default; no testing; no coverage tracking.

The fix: per-technique coverage matrix; tested via simulation.

### 2. The 100%-coverage-claim

The team claims 100% coverage. Investigation reveals the "coverage" is loose (any tangentially-related rule counts).

The fix: strict coverage definition; per-technique tested detection rule.

### 3. The forever-untested-rules

Detection rules exist; never tested. Real attacks may not match the rule's expected pattern.

The fix: quarterly purple-team exercises; alert on rule deviation from expected detection.

### 4. The CSPM-as-only-coverage

The team relies entirely on CSPM. Architectural threats outside CSPM's scope are missed.

The fix: CSPM is one input; STRIDE + ATT&CK + attack-path are complementary methods.

### 5. The technique-applicability-handwave

The team declares a technique "not applicable" without analysis. Real applicability is missed.

The fix: explicit reasoning per non-applicability; reviewed.

### 6. The single-cloud-coverage

The matrix coverage is for AWS. Azure and GCP workloads don't have equivalent coverage.

The fix: per-cloud coverage; technique-applicability per cloud.

### 7. The stale-coverage-matrix

The coverage matrix was built once; never updated as ATT&CK adds techniques.

The fix: quarterly review of new ATT&CK techniques; scoping decision.

### 8. The detection-without-response

Detection rules fire; SOC has no runbook for the technique. Detection is theoretical.

The fix: every detection rule has a corresponding response runbook (per [../cloud-detection-response/](../cloud-detection-response/)).

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| ATTCK-001 | No ATT&CK coverage tracking; detection-rule effectiveness unknown | High | Quarterly coverage tracking; per-technique coverage status | Security Eng + SOC |
| ATTCK-002 | Techniques relevant to environment not enumerated; in-scope unclear | Medium | Tactic-by-tactic walkthrough; explicit in-scope / not-applicable per technique | Security Eng |
| ATTCK-003 | Detection rules not tested with simulated attacks | High | Quarterly purple-team exercises; rule testing | Security Eng + SOC |
| ATTCK-004 | CSPM findings not mapped to ATT&CK; redundant signals | Medium | Mapping in SIEM ingest; unified prioritization | Security Eng |
| ATTCK-005 | Commonly-missed techniques (T1535, T1538, T1098.001) not covered | High | Coverage expansion for the commonly-missed | Security Eng + SOC |
| ATTCK-006 | Per-technique applicability assessed via handwave; gaps possible | Medium | Explicit reasoning per non-applicability; reviewed quarterly | Security Eng |
| ATTCK-007 | Single-cloud coverage only; multi-cloud workloads have gaps | Medium | Per-cloud coverage; technique mapping per cloud | Security Eng |
| ATTCK-008 | ATT&CK coverage matrix stale; new techniques not scoped | Medium | Quarterly review of new techniques; in-scope decision | Security Eng |
| ATTCK-009 | Detection rules fire; no response runbook | High | Every detection rule has corresponding runbook per [../cloud-detection-response/](../cloud-detection-response/) | SOC + Security Eng |
| ATTCK-010 | Coverage metric loose; "covered" includes tangential rules | Medium | Strict definition; per-technique rule + tested | Security Eng |
| ATTCK-011 | Persistent-access techniques (T1098 family) under-covered; long-term persistence invisible | High | Detection on role / credential creation events | Security Eng + SOC |
| ATTCK-012 | Console-based discovery (T1538) not detected | Medium | CloudTrail console events; pattern-based detection | Security Eng + SOC |
| ATTCK-013 | Exfiltration-to-cloud-storage (T1567.002) not specifically detected | Medium | Cross-account S3 writes; unexpected destination patterns | Security Eng + SOC |
| ATTCK-014 | T1486 (data encryption ransomware) detection volume-based only; encryption-pattern detection absent | High | Detection on rapid encryption operations + KMS context change | Security Eng + SOC |
| ATTCK-015 | Per-technique coverage not visible to engineering leadership | Low | Quarterly report; coverage dashboard | Security Eng + Leadership |
| ATTCK-016 | ATT&CK coverage decoupled from threat-modeling output; STRIDE and ATT&CK aren't paired | Medium | Pair STRIDE walks with ATT&CK coverage check per [cloud-stride-template.md](./cloud-stride-template.md) | Security Eng |
| ATTCK-017 | New attack techniques observed in industry not assessed for applicability | Medium | Quarterly review of MITRE updates and threat-intel feeds | Security Eng |
| ATTCK-018 | Detection rule generation not integrated with threat model; ad-hoc rules | Medium | Threat model output drives detection-rule backlog | Security Eng + SOC |

---

## What this document is not

- **A complete MITRE ATT&CK reference.** The MITRE site is authoritative.
- **A SIEM rule-writing guide.** Rule syntax is vendor-specific.
- **A CSPM vendor comparison.** Vendors are mentioned; the choice belongs with broader security-tool decisions.
- **A purple-team-exercise guide.** Adversary emulation is mentioned; deep methodology lives elsewhere.
