# Compliance and Control Mapping

## What this folder is

A practitioner's reference for mapping cloud security controls to compliance frameworks — HIPAA Security Rule, SOC 2 Trust Services Criteria, PCI-DSS v4, FedRAMP Moderate / High, and NIST 800-53 Rev 5. Each framework is mapped row-by-row to concrete cloud controls, implementation examples, and evidence artifacts. The material here is what I put in front of a team when the question is: *we have a SOC 2 audit in six weeks and a control matrix that says "Encryption at rest" but does not name the KMS key, the key policy, the bucket configuration, or the log that proves it — what do we actually hand the auditor?*

## The organizing principle

Compliance mapping in cloud environments fails along a recurring axis: control matrices are written at the requirement layer ("the organization shall encrypt data at rest"), and audits are conducted at the evidence layer ("show me the encryption configuration on this specific resource and the log entry that proves it has not changed"). The gap between those two layers is where most audit findings live. The patterns in this folder close that gap by treating every control as a three-part artifact: the framework requirement, the cloud-native enforcement, and the evidence query that produces the auditor-ready proof. A control that has only a requirement and no enforcement is policy theater; a control with enforcement but no evidence query is a configuration that cannot be defended in an audit.

The folder is opinionated about three things. First, that **continuous-controls-monitoring is the right destination for every framework** — quarterly evidence collection is more expensive than continuous evidence collection, and CSPM tools have made continuous evidence cheap enough that there is no longer a reason to defer it. Second, that **mappings should be tight rather than aspirational** — a row that maps a SOC 2 CC6.1 control to "uses cloud-native IAM" is technically true and operationally useless; the right mapping names the specific IAM patterns (Permission Boundary, IAM Access Analyzer findings closed, no IAM users for human access) that satisfy the criterion. Third, that **frameworks share more than they differ** — the same KMS strategy that satisfies HIPAA satisfies SOC 2 satisfies PCI satisfies FedRAMP, and the value of a multi-framework mapping is that the team builds one set of controls and produces evidence for all frameworks rather than building one set of controls per framework.

## Planned documents

- **hipaa-security-rule.md** *(coming)* — HIPAA Security Rule (Administrative, Physical, Technical Safeguards, Breach Notification) mapped to cloud controls. Per-safeguard implementation examples on AWS, Azure, and GCP. Evidence artifacts: which CloudTrail / Activity Log / Audit Log queries prove the control, which CSPM finding-type indicates a violation. The PHI-in-logs problem and the redaction patterns that close it.
- **soc2-trust-services.md** *(coming)* — SOC 2 Trust Services Criteria (CC1-CC9, plus the additional categories — Availability, Confidentiality, Processing Integrity, Privacy) mapped row-by-row. Per-criterion control descriptions, implementation examples, and the auditor-ready evidence queries. The "what your SOC 2 auditor actually wants" notes by criterion.
- **pci-dss-v4.md** *(coming)* — PCI-DSS v4 (12 requirements, customized approach option) mapped to cloud controls. The CDE-scope-reduction patterns (tokenization, segmentation, encryption with provider-not-key-holder posture). The defined approach vs customized approach decision tree. Worked examples for the most-frequently-failed v4 requirements (encryption keys, network segmentation evidence, multifactor authentication for all access into the CDE).
- **fedramp-moderate-high.md** *(coming)* — FedRAMP Moderate and High control baselines, the GovCloud / Azure Government / GCP Assured Workloads region requirements, the boundary-and-inheritance modeling for cloud-native services, the FIPS 140-2 / 140-3 validated cryptographic module requirement and how to satisfy it with cloud KMS.
- **nist-800-53-rev5.md** *(coming)* — NIST 800-53 Rev 5 control families (AC, AU, IA, SC, SI, etc.) mapped to cloud controls. The crosswalk to the other frameworks. The NIST CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover) with cloud-specific maturity-model bands.
- **continuous-controls-monitoring.md** *(coming)* — Continuous-controls-monitoring architecture: which controls can be continuously monitored from CSPM findings, which can be from CloudTrail / Activity Log / Audit Log queries, which require runtime evidence (Falco / Tetragon / EDR). The "evidence pipeline" pattern that produces audit-ready artifacts on demand.
- **csp-shared-responsibility.md** *(coming)* — The cloud-provider shared-responsibility model translated into concrete control inheritance. AWS Artifact, Azure Service Trust Portal, GCP Compliance Reports Manager. Which controls are inherited from the cloud provider's SOC 2 / FedRAMP / ISO and which the customer owns. The "customer responsibility matrix" that auditors expect for FedRAMP and the equivalent artifact for other frameworks.
- **evidence-collection-runbook.md** *(coming)* — A runbook for collecting evidence on demand: which artifact for which framework, where to query, the standard evidence formats auditors accept, the chain-of-custody discipline that holds up under scrutiny, the screenshot-as-evidence anti-pattern.

## How to use this section

**If you are six weeks from a SOC 2 audit**, `soc2-trust-services.md` and `evidence-collection-runbook.md` together are the kit. The criterion-by-criterion document includes the queries; the runbook describes the collection discipline.

**If you are landing a HIPAA-regulated workload on cloud**, `hipaa-security-rule.md` is the destination. The PHI-in-logs section addresses the most common audit finding in cloud-hosted PHI environments.

**If you are responding to a customer questionnaire that maps to NIST 800-53**, `nist-800-53-rev5.md` provides the crosswalk, and the framework-specific documents provide the per-control depth.

## What this section is not

- **A complete audit-preparation guide.** Audit preparation involves scoping, control selection, gap analysis, evidence collection, and remediation — this folder covers the mapping and the evidence-query patterns. Audit firms maintain their own guidance on scoping and analyst-relationship management; this folder does not duplicate it.
- **Legal or regulatory advice.** The mappings are technical control mappings. Where a framework requires policy or contractual or notification language (e.g., HIPAA business associate agreements, GDPR data processing addenda), the folder names the requirement but does not provide the template — competent counsel for those.
- **Comprehensive across all frameworks.** ISO 27001, CSA CCM, HITRUST, and the various sectoral frameworks (NERC CIP, IRS Pub 1075, CJIS) are out of scope for the initial release. The five frameworks here cover the majority of cloud-customer compliance obligations in 2026; the others can be added as engagement work surfaces them.
