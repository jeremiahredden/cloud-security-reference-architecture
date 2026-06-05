# Threat Modeling Cloud

## What this folder is

A practitioner's reference for threat modeling cloud architectures — STRIDE templates tuned for cloud, MITRE ATT&CK for Cloud Matrix coverage maps, attack-path analysis, and worked threat models against representative multi-account regulated workloads. The material here is what I put in front of an engineering team when the question is: *we have an architecture diagram, a compliance deadline, and a 60-minute meeting to figure out what we should be worried about — how do we run that meeting?*

## The organizing principle

Threat modeling for cloud is a different exercise from threat modeling for a monolithic application. The trust boundaries are different (the boundary is usually the account / subscription / project, not the network), the attack paths are different (lateral movement happens through IAM and KMS more often than through layer-3 networking), and the controls are different (preventive controls live in SCPs and Azure Policy and Organization Policy, not in WAFs). A threat model that treats a cloud architecture as "an application on some servers" will miss the actual attack surface — the role-trust-policy that lets a compromised CI pipeline assume a production role, the cross-account KMS grant that widens the blast radius of a leaked key, the public S3 bucket policy that survives the security-group review because it is not network. The patterns here treat the cloud architecture as the primary object of the threat model, and the application as one of several actors in it.

The folder is opinionated about three things. First, that **STRIDE works fine for cloud threat modeling if the data flow diagram is drawn at the right level of abstraction** — diagrams that hide the IAM and KMS interactions miss most of the high-value threats, and diagrams that include them surface those threats naturally. Second, that **the MITRE ATT&CK for Cloud Matrix is the best coverage map available in 2026** for "did the threat model find the things adversaries actually do" — pairing the STRIDE walkthrough output against the matrix's techniques produces a coverage gap analysis that the team can act on. Third, that **attack-path analysis catches what STRIDE misses** — the multi-step lateral movement chains that CSPM tools surface (e.g., S3-public-bucket → AssumeRole → cross-account data access) are easier to find by tracing edges in an attack graph than by walking STRIDE on each component in isolation, and the worked examples here include both methods.

## Planned documents

- **[cloud-stride-template.md](./cloud-stride-template.md)** — A STRIDE template tuned for cloud: the data-flow-diagram conventions that surface IAM and KMS interactions, the cloud-specific threat prompts at each STRIDE letter (e.g., S → role assumption from unintended principal; I → CloudTrail tampering; D → KMS key disable), and a finding-writing standard with IDs and sprint assignments.
- **[mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md)** — MITRE ATT&CK for Cloud Matrix coverage worksheet: tactic-by-tactic walkthrough with the preventive and detective controls per technique, the techniques most commonly missed in real environments (modify cloud compute infrastructure, additional cloud roles), and the "did we model this" checklist.
- **[attack-path-analysis.md](./attack-path-analysis.md)** — Attack-path analysis methodology: how to build an attack graph from CloudTrail / Activity Log / Audit Log data, how to extract the high-value paths (the ones that reach an asset of value in three hops or fewer), and how to convert the paths into remediations. The CSPM-attack-paths integration patterns.
- **[threat-model-multi-account-saas.md](./threat-model-multi-account-saas.md)** — Worked threat model for a multi-account SaaS application: STRIDE walkthrough, 30+ findings with IDs (e.g., `CLOUD-001` through `CLOUD-030`), severity, sprint assignments, MITRE ATT&CK Cloud Matrix coverage analysis, the four GA blockers identified. Written to the same depth as the worked threat models in the sibling repos (`threat-model-healthcare-api.md` and `agent-threat-model.md`).
- **[threat-model-data-platform.md](./threat-model-data-platform.md)** — Worked threat model for a multi-cloud analytics platform with cross-cloud data movement (S3 → Snowflake → BigQuery + Vertex AI LLM augment): the data-residency threats, the cross-cloud identity-federation threats, the data-egress threats, and the analytics-platform-specific threats (data leakage via shared compute, LLM PHI exposure, external-partner shares). 32 findings with IDs `DATAP-001` through `DATAP-032`; four GA blockers; MITRE ATT&CK for Cloud coverage analysis at 74%.
- **[facilitation-guide.md](./facilitation-guide.md)** — How to run a 60- to 90-minute cloud threat-modeling session with an engineering team: pre-meeting preparation, the dataflow-diagram-on-a-whiteboard process, the STRIDE walkthrough with cloud-specific prompts, the finding-prioritization rubric, and the post-meeting deliverable structure. Mirrors the AppSec facilitation guide but tuned for cloud.

## How to use this section

**If you are about to run a cloud threat-modeling session**, `facilitation-guide.md` and `cloud-stride-template.md` together are the kit. The facilitation guide is designed to be forked into your engagement workspace and customized.

**If you are checking the coverage of an existing threat model**, `mitre-attack-cloud-coverage.md` is the diagnostic. The matrix walkthrough often surfaces 3-5 techniques the original threat model did not consider.

**If you are looking for a depth reference**, the two worked threat models (`threat-model-multi-account-saas.md` and `threat-model-data-platform.md`) are the artifacts to read. They are closer to the deliverables I produce in real engagements than this folder's READMEs are.

## What this section is not

- **A STRIDE methodology primer.** STRIDE is referenced operationally, not introduced from first principles. The sibling AppSec repo's `threat-modeling/` folder includes a STRIDE primer for teams that want it.
- **A complete CSPM walkthrough.** Where CSPM-driven attack-path analysis appears, it illustrates a pattern. The folder is not a vendor manual.
- **A formal-methods threat modeling reference.** Trike, PASTA, OCTAVE, and other methodologies are valuable in some contexts; this folder is biased toward STRIDE + ATT&CK + attack-path because that combination is the highest-leverage one in the engagements I run.
