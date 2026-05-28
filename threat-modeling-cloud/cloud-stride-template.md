# Cloud STRIDE Template

A practitioner's reference for STRIDE threat modeling tuned for cloud — the data-flow-diagram (DFD) conventions that surface IAM and KMS interactions, the cloud-specific threat prompts at each STRIDE letter (S→Spoofing, T→Tampering, R→Repudiation, I→Information Disclosure, D→Denial of Service, E→Elevation of Privilege), and the finding-writing standard with IDs and sprint assignments. The template here is what I put on a whiteboard at the start of a cloud threat-modeling session; the prompts are what I walk through with the team.

This document opens the threat-modeling-cloud folder. It's the template; the methodology around how to use it is in [facilitation-guide.md](./facilitation-guide.md); the coverage check against adversary techniques is in [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md); the alternative path-based approach is in [attack-path-analysis.md](./attack-path-analysis.md).

The honest framing: STRIDE works fine for cloud threat modeling if the DFD is drawn at the right level of abstraction. DFDs that hide IAM and KMS miss most of the high-value cloud threats; DFDs that include them surface those threats naturally. This template is opinionated about the right level.

---

## When to read this document

**If you are running a cloud threat-modeling session** — read top to bottom. This is the template.

**If your existing threat models miss cloud-specific threats (IAM, KMS, cross-account)** — start with [Cloud-specific DFD conventions](#cloud-specific-dfd-conventions). The DFD is where most omissions trace from.

**If you have STRIDE experience from application threat modeling and want to extend to cloud** — start with [The STRIDE prompts for cloud](#the-stride-prompts-for-cloud). The classical prompts apply but specific cloud variants need adding.

**If you are starting from scratch** — pair this document with [facilitation-guide.md](./facilitation-guide.md) and walk through one workload to learn the rhythm.

---

## What STRIDE is (briefly)

STRIDE is a threat-modeling methodology: walk a DFD; for each component, enumerate threats in six categories. The categories:

| Letter | Threat | Property violated |
| --- | --- | --- |
| S | Spoofing | Authentication |
| T | Tampering | Integrity |
| R | Repudiation | Non-repudiation |
| I | Information Disclosure | Confidentiality |
| D | Denial of Service | Availability |
| E | Elevation of Privilege | Authorization |

For each STRIDE letter at each DFD component: ask "could an attacker do this here?" If yes: that's a threat; write it down; assign severity; design a mitigation.

The methodology is widely-documented; see the AppSec sibling repo's STRIDE primer if needed. This document is about applying STRIDE specifically to cloud architectures.

---

## Cloud-specific DFD conventions

The DFD is the diagram the team walks. Most missed cloud threats trace to DFDs that didn't surface the cloud-specific elements.

### What a cloud DFD should include

Beyond the usual application components (services, databases, queues, external APIs):

- **IAM principals.** IAM users, IAM roles, service accounts, managed identities — each is an actor.
- **IAM grants (trust policies, role assumptions, federation).** The lines between principals and resources are policy-defined; show them.
- **KMS keys.** The encryption keys are first-class entities; their access patterns are threat-relevant.
- **CloudTrail / Activity Log / Audit Log destinations.** The audit pipe is itself a target.
- **Cross-account boundaries.** Account boundaries are major trust boundaries.
- **Cross-region boundaries (for residency-relevant workloads).** Region boundaries can be trust-relevant.
- **Public-internet exposure points.** Public IPs, load balancers, public buckets — explicit.

### What a cloud DFD should NOT hide

Common omissions that mask threats:

- **"Application calls the database"** — but doesn't show how. Through what IAM identity? Via what credential path?
- **"Encryption at rest"** as a label without the KMS key shown. What key? Who can use it?
- **"Cross-account access"** as a generic line without the role-assumption shown. Whose role? With what trust policy?
- **"CI/CD pipeline deploys"** without showing the pipeline's identity. How does CI authenticate to production?

If these are hidden, the STRIDE walkthrough at "application" produces only application-layer threats. The IAM, KMS, and cross-account threats remain invisible.

### A worked DFD example: SaaS workload reading from S3

A simple SaaS workload reads from a private S3 bucket. The cloud-aware DFD:

```
[Customer Browser]
       │
       │ HTTPS (via CloudFront)
       ▼
[Application Load Balancer]
       │
       │ TLS
       ▼
[EKS Pod: web-app]
   │   identity: IRSA: web-app-sa
   │   role: arn:aws:iam::PROD:role/web-app-role
   │
   │ STS assume-role (via IRSA)
   ▼
[STS]
   │ returns short-lived creds
   ▼
[EKS Pod: web-app] (now with creds)
   │
   │ S3 GetObject (signed)
   ▼
[S3 Bucket: customer-data]
   │ bucket policy allows: web-app-role
   │ encryption: SSE-KMS with cmk-customer-data
   │
   │ Decrypt
   ▼
[KMS Key: cmk-customer-data]
   │ key policy allows: web-app-role
   │
   ▼
[CloudTrail destination: log-archive bucket]
   │ records every API call
   ▼
[Log Archive Bucket: meridian-cloudtrail-archive]
   │ in central log-archive account
```

The DFD shows: the application's IAM identity (web-app-sa, IRSA-bound to web-app-role), the STS exchange for credentials, the S3 bucket's policy reference, the KMS key's policy, the CloudTrail audit pipe.

Now STRIDE walks naturally surface IAM and KMS threats: Could `web-app-role` be assumed by an unintended principal (S)? Could the S3 bucket policy be modified (T)? Could the KMS key be disabled (D)? Could the CloudTrail recorded to the log-archive bucket be tampered (T, R)?

---

## The STRIDE prompts for cloud

For each STRIDE letter, the cloud-specific prompts that surface threats most often.

### S — Spoofing

The threat: an attacker impersonates a legitimate identity.

Cloud-specific prompts:

- **Role assumption from unintended principal.** Could a role be assumed by a principal whose trust policy doesn't explicitly identify them? (E.g., a too-broad `Principal: "*"` in a trust policy; a confused-deputy via missing ExternalId; cross-account roles without conditions.)
- **CI federation spoof.** Could a CI workflow assume a role intended for a different workflow? (E.g., GitHub Actions OIDC trust policy with `:sub: "repo:org/*"` instead of specific repo.)
- **Service-account token replay.** Could a captured Kubernetes service-account token be used outside the cluster?
- **Leaked credentials reuse.** Could a leaked IAM access key be used by an attacker without being detected?
- **MFA bypass.** Could a sensitive action be performed without MFA?
- **API key reuse across boundaries.** Could an API key intended for one tenant be used by another?

### T — Tampering

The threat: an attacker modifies data or configuration.

Cloud-specific prompts:

- **IAM policy modification.** Could an attacker modify an IAM policy to elevate access?
- **Bucket policy modification.** Could a bucket policy be relaxed to allow public access?
- **KMS key policy modification.** Could a KMS key's policy be modified to grant unintended decryption?
- **CloudTrail tampering.** Could CloudTrail be disabled, redirected, or its log files modified before reaching the central archive?
- **Configuration drift via console.** Could a manual console change bypass IaC and create undocumented configuration?
- **S3 bucket data modification.** Could an attacker overwrite data in S3 with attacker-controlled content?
- **Container image swap.** Could the deployed image be replaced with a malicious one (image registry compromise, mutable tag, missing signature verification)?
- **Build-time tampering.** Could the CI pipeline produce malicious artifacts (compromised CI, dependency confusion, supply-chain injection)?

### R — Repudiation

The threat: an actor denies having performed an action; insufficient audit trail to prove otherwise.

Cloud-specific prompts:

- **Missing CloudTrail.** Are there regions or services without CloudTrail enabled?
- **CloudTrail logs not shipped centrally.** Could CloudTrail logs be lost or tampered before reaching audit storage?
- **Service-account-level audit gap.** When a service account performs an action, do logs identify which workload made the call (not just "service account X")?
- **Cross-account audit gap.** When account A assumes a role in account B, is the audit trail complete on both sides?
- **Console actions without identifiable user.** Are there shared admin accounts (root, ec2-user) used by multiple humans?
- **Backup / restore without audit.** Are backup operations and restore events logged?
- **Vault / secrets-manager-level audit.** Are secret reads attributable to specific principals?

### I — Information Disclosure

The threat: data is exposed to unauthorized parties.

Cloud-specific prompts:

- **Public S3 / GCS / Azure Storage bucket.** Could a bucket be (or become) public?
- **Public RDS / database endpoint.** Could a database have a public endpoint?
- **Public load balancer in front of internal-only services.** Could the LB be misconfigured to serve internal services publicly?
- **Cross-tenant data leakage.** In a multi-tenant workload, could tenant A's data be accessible to tenant B?
- **Egress to non-approved destinations.** Could data be exfiltrated to unauthorized external endpoints?
- **Logs containing sensitive data.** Could PII / PHI end up in CloudWatch / Log Analytics / Cloud Logging where access control is broader than the source data?
- **Snapshot / backup leak.** Could a snapshot or backup be shared to an unauthorized account?
- **EBS / EFS / FSx volume leak.** Could a volume be attached to an unauthorized instance?
- **AMI / image leak.** Could a private AMI be shared publicly or with unauthorized accounts?

### D — Denial of Service

The threat: legitimate users cannot access the service.

Cloud-specific prompts:

- **Cost-based DoS.** Could an attacker cause a financial exhaustion attack (e.g., trigger expensive Lambda invocations, expensive S3 list-bucket calls)?
- **API rate-limit exhaustion.** Could an attacker exhaust the workload's quotas (AWS API throttling, GCP quota limits)?
- **KMS DoS.** Could an attacker disable a KMS key, rendering encrypted data inaccessible?
- **IAM DoS.** Could an attacker cause IAM-related lockouts (e.g., delete a critical role)?
- **Resource quota exhaustion.** Could one tenant exhaust shared resource quotas?
- **Logging-pipeline DoS.** Could the audit log destination be filled / disabled?
- **DNS-based DoS.** Could DNS for the workload be disrupted?

### E — Elevation of Privilege

The threat: an attacker gains higher privileges than they should have.

Cloud-specific prompts:

- **Privilege-escalation via IAM combinations.** Could a set of seemingly-narrow permissions combine to allow privilege escalation? (E.g., `iam:PassRole` + `lambda:CreateFunction` = full account access.)
- **Container escape.** Could a compromised pod escape to the node?
- **Node-to-cluster admin.** Could node-level access lead to cluster-admin via kubelet credentials?
- **Service-to-service privilege escalation.** Could a service authenticate as a higher-privileged service?
- **Vault / secrets-manager misuse for escalation.** Could read access to a secret yield credentials for a higher-privileged identity?
- **Cross-account escalation.** Could compromise of a lower-trust account allow escalation to higher-trust account?
- **CI/CD privilege escalation.** Could a CI compromise allow modification of production?

---

## Finding-writing standard

STRIDE produces threats. Convert to findings with a standard format.

### Finding structure

Every finding has:

- **ID:** sequential, prefix-coded (e.g., `CLOUD-001`).
- **Title:** short, declarative.
- **STRIDE category:** S / T / R / I / D / E.
- **Component / asset affected:** what is at risk.
- **Description:** what the threat is, in 2-3 sentences.
- **Attack path:** how an attacker would actually exploit (the key step or sequence).
- **Severity:** Critical / High / Medium / Low based on a documented rubric.
- **Recommendation:** specific mitigation, sprint-sized.
- **Owner:** team / role responsible.
- **MITRE ATT&CK reference:** the technique ID where applicable.

### Severity rubric

| Severity | Criteria |
| --- | --- |
| Critical | Direct path to customer-data exposure or full account / cluster compromise; little or no other control prevents |
| High | Exploitable path with available exploit; significant impact (e.g., subset of customer data, specific service compromise); requires multiple steps but each is plausible |
| Medium | Plausible exploit but requires significant prerequisites or impact limited; defense-in-depth gap rather than a direct path |
| Low | Theoretical or requires highly specific conditions; mostly informational |

### Sprint sizing

Recommendations should be sprint-implementable. If a recommendation is "rearchitect for Zero Trust," that's not a finding — it's a multi-quarter initiative. Break it down:

- The architectural target can be the multi-sprint goal.
- Each finding's recommendation is one specific step toward it.

### Example finding

```
ID: CLOUD-001
Title: Production cross-account role accepts trust from CI account's account root, not specific role
STRIDE: S (Spoofing)
Component: arn:aws:iam::PROD:role/care-coordinator-deploy
Description: The role's trust policy uses `Principal: AWS: arn:aws:iam::CI-ACCOUNT:root`,
  allowing any principal in the CI account to assume the role. A compromised IAM user in
  the CI account could assume the production-deploy role and modify production resources.
Attack path: Compromise any IAM user in CI account → AssumeRole into production via the
  over-broad trust policy → modify production resources or exfiltrate data.
Severity: High
Recommendation: Tighten trust policy to specific role ARN
  (arn:aws:iam::CI-ACCOUNT:role/github-actions-deploy); add ExternalId condition; verify
  via test of unauthorized AssumeRole attempt (should fail).
Owner: Platform Eng + Security Eng
MITRE: T1078.004 (Valid Accounts: Cloud Accounts)
```

The finding is concrete, actionable, sprint-sized.

---

## Walking the DFD

The session pattern.

### Pre-session

- **DFD prepared** — either by the facilitator from architecture docs, or by the engineering team via a 30-minute pre-meeting.
- **Asset list** — the things of value the workload protects (customer data, credentials, infrastructure).
- **Threat-actor sketch** — who you're modeling against (external attacker, insider, supply chain, etc.).

### During session (60-90 minutes)

1. **Confirm the DFD** (5 min): walk the team through the diagram; correct misunderstandings.
2. **Identify assets** (5 min): which DFD elements are valuable to protect.
3. **STRIDE walk** (40-60 min): for each component on the DFD, walk through the six prompts. Capture threats.
4. **Severity assignment** (10 min): walk the list; assign severities.
5. **Prioritization** (5-10 min): identify the top 5-10 to fix this quarter.
6. **Output capture** (5 min): facilitator commits to delivering the formal findings list.

### Post-session

- **Formal finding list** delivered within 3-5 business days.
- **MITRE ATT&CK coverage map** delivered (see [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md)).
- **Attack-path supplement** if applicable (see [attack-path-analysis.md](./attack-path-analysis.md)).

---

## Worked example: walking STRIDE on the SaaS reading from S3

Using the DFD example above, the threats surfaced by a STRIDE walk on the `[EKS Pod: web-app]` component.

### Spoofing (S)

- **Could another EKS pod assume web-app-sa?** If RBAC is too broad or namespace boundaries leak, yes.
- **Could a non-EKS process forge IRSA credentials?** Only if the OIDC provider trust is misconfigured.
- **Could the IRSA trust policy be too broad?** Check trust policy: `system:serviceaccount:care-coordinator:web-app-sa` should be specific.

Finding (example): the IRSA trust policy uses `:sub: "system:serviceaccount:*:*"` instead of specific SA. Severity High.

### Tampering (T)

- **Could the pod's container image be replaced?** If image registry is unprotected, yes.
- **Could the pod's environment be modified by another pod?** Cross-pod shared volume; check.
- **Could the deployment spec be modified by a non-platform principal?** Check RBAC.

Finding (example): image references use mutable tag (`:latest`); no signature verification at admission. Severity High.

### Repudiation (R)

- **Are API calls from the pod attributable?** CloudTrail records the role; pod-level attribution requires source IP / session name discipline.

Finding (example): IAM session name doesn't include pod identity; pod-level audit attribution is weak. Severity Medium.

### Information Disclosure (I)

- **Could the pod read S3 buckets beyond `customer-data`?** Check IAM policy scope.
- **Could the pod be reached from the internet?** Check security groups, NetworkPolicy, ingress.
- **Could the pod log sensitive data?** Application-layer concern.

Finding (example): web-app-role's S3 read permission is `s3:GetObject` on `*`; allows reading any bucket. Severity High.

### Denial of Service (D)

- **Could the pod's quota / resource limits be exhausted by an external attacker?** Check rate limits at ingress; resource quotas.
- **Could the KMS key the pod depends on be disabled?** Check key policy admins.

Finding (example): KMS key `cmk-customer-data` has broad admin permissions in production account; key-disable DoS is possible. Severity Medium.

### Elevation of Privilege (E)

- **Could web-app-role assume other roles?** Check sts:AssumeRole permissions.
- **Could the pod break out to node?** Pod-security and runtime patterns; check.
- **Could the pod compromise the cluster?** Check service-account permissions on Kubernetes API.

Finding (example): web-app-role has `iam:PassRole` to any role; combined with Lambda creation could yield privilege escalation. Severity Critical.

The single walk produced 6 findings across STRIDE categories. A 60-minute session typically surfaces 30-50 across the workload.

---

## Worked example: Meridian Health's threat-modeling cadence

Meridian runs cloud threat-modeling sessions in three contexts:

### Per-major-feature

For new features that touch new cloud resources (new IAM roles, new data flows, new external integrations): one threat-modeling session before the feature ships.

### Per-quarterly-platform-review

The platform team runs a session per quarter on the overall architecture; surfaces drift and new threats from accumulated changes.

### Per-incident

After a significant incident, a threat-modeling session focused on the incident's vector and adjacent threats.

### The toolkit

- DFD drawn in Excalidraw / Miro (shared via screen).
- This document's prompts on a slide.
- A shared findings doc updated live.
- Post-session formal write-up.

### Outcomes

- Critical / High findings get sprint commitments.
- Medium / Low findings go to the security backlog.
- MITRE coverage analysis is delivered as a supplement (per [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md)).

### Findings opened during the threat-modeling discipline rollout

- **STRIDE-001** (no formal threat modeling for cloud-resource-changing features). Closed by per-major-feature session discipline.
- **STRIDE-002** (DFDs didn't include IAM / KMS; cloud-specific threats invisible). Closed by template adoption (this doc).
- **STRIDE-003** (findings were unformatted; no IDs; no sprint assignment). Closed by finding-writing standard.
- **STRIDE-004** (no MITRE coverage check; bias toward known threats). Closed by ATT&CK pairing (per [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md)).
- **STRIDE-005** (no facilitator playbook; sessions varied in quality). Closed by [facilitation-guide.md](./facilitation-guide.md).

---

## Anti-patterns

### 1. The DFD that hides IAM and KMS

The DFD shows "application → database" without showing how. Most cloud-specific threats are invisible.

The fix: include IAM principals, role assumptions, KMS keys, audit pipes in the DFD.

### 2. The STRIDE-only-on-application-component walk

The team walks STRIDE on `[application]` and stops. Doesn't walk STRIDE on `[KMS key]`, `[IAM role]`, `[CloudTrail destination]`.

The fix: each cloud-specific element is a DFD component; STRIDE walks each.

### 3. The findings-as-paragraphs output

The session produces narrative descriptions of threats. No IDs, no severities, no sprint assignments. Engineering can't act on them.

The fix: finding-writing standard. Every threat becomes a structured finding.

### 4. The everyone-is-critical inflation

Every finding is marked Critical. Engineering tunes out. The signal is lost.

The fix: severity rubric; calibrate based on actual likelihood × impact; reserve Critical for genuine direct paths to compromise.

### 5. The aspirational-recommendation

Recommendations are "implement Zero Trust" or "redesign for least privilege." Engineering can't act in a sprint.

The fix: sprint-sized recommendations. Multi-sprint goals are documented separately.

### 6. The single-session-and-done

The team threat-models once. Six months later, the architecture has drifted; threats are different; no re-model.

The fix: cadence — per-feature, per-quarter, per-incident.

### 7. The threat-model-without-coverage-check

The team's STRIDE walk produces 30 threats. The team is confident they're done. They haven't checked against MITRE ATT&CK; specific adversary techniques are missing.

The fix: pair STRIDE with [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md). Coverage gaps are themselves findings.

### 8. The single-component-walks-don't-compose

STRIDE walks each component independently. Multi-step lateral-movement chains are invisible.

The fix: pair with [attack-path-analysis.md](./attack-path-analysis.md). Attack paths catch what STRIDE misses.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| STRIDE-001 | No formal threat modeling for cloud-resource-changing features | High | Per-major-feature session before ship | Architecture + Security Eng |
| STRIDE-002 | DFDs don't include IAM / KMS / CloudTrail; cloud-specific threats invisible | High | Template-driven DFD per [Cloud-specific DFD conventions](#cloud-specific-dfd-conventions) | Security Eng + Architecture |
| STRIDE-003 | Findings unformatted; no IDs / severities / sprint assignments | High | Adopt finding-writing standard | Security Eng |
| STRIDE-004 | No MITRE coverage check on threat-modeling output | Medium | Pair with [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md) | Security Eng |
| STRIDE-005 | Facilitator playbook absent; session quality varies | Medium | Adopt [facilitation-guide.md](./facilitation-guide.md); train facilitators | Security Eng |
| STRIDE-006 | Severity inflation (everyone is Critical); engineering tunes out | Medium | Severity rubric; calibration training; review of severity assignments | Security Eng + Architecture |
| STRIDE-007 | Recommendations aspirational (not sprint-sized); engineering can't act | Medium | Sprint-sized recommendations; multi-sprint goals separate | Security Eng |
| STRIDE-008 | Per-component STRIDE walks miss multi-step attack chains | Medium | Pair with [attack-path-analysis.md](./attack-path-analysis.md) | Security Eng |
| STRIDE-009 | Single threat model per architecture; no cadence | Medium | Per-feature + per-quarter + per-incident cadence | Security Eng + Architecture |
| STRIDE-010 | STRIDE prompts are application-only; cloud-specific prompts absent | High | Adopt cloud-specific prompts per [The STRIDE prompts for cloud](#the-stride-prompts-for-cloud) | Security Eng |
| STRIDE-011 | Trust policies and role-assumption edges not in DFD; spoofing threats missed | High | Add to DFD; STRIDE walk surfaces | Security Eng |
| STRIDE-012 | KMS keys not in DFD; key-policy threats missed | Medium | Add KMS keys to DFD; walk STRIDE on them | Security Eng |
| STRIDE-013 | Cross-account boundaries not surfaced; cross-account threats missed | High | Account boundaries are major DFD elements; show explicitly | Security Eng + Architecture |
| STRIDE-014 | Audit pipe not in DFD; repudiation and tampering of logs missed | Medium | Add CloudTrail / audit-log destination to DFD | Security Eng |
| STRIDE-015 | Threat-model output not tracked to remediation; findings linger | Medium | Findings get tickets; SLA per severity; tracking | Security Eng + Engineering Lead |
| STRIDE-016 | Cost-based DoS prompts not used; financial-exhaustion threats missed | Low | Add cost-DoS prompts to D walk | Security Eng |
| STRIDE-017 | CI/CD privilege-escalation threats not surfaced; supply chain blind spot | Medium | E prompts include CI compromise paths | Security Eng + DevOps |
| STRIDE-018 | Threat-modeling outputs not consumed by SOC; detection-coverage gap unmeasured | Low | SOC reviews threat-model findings; aligns detection rules | Security Eng + SOC |

---

## What this document is not

- **A STRIDE primer.** STRIDE methodology basics are covered in the AppSec sibling repo's `threat-modeling/` folder.
- **A complete cloud-attack reference.** The MITRE ATT&CK for Cloud Matrix is the canonical reference; pair via [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md).
- **A vendor threat-modeling tool reference.** Threat Dragon, IriusRisk, OWASP-pytm, ThreatModeler — all useful; this document is methodology, not tooling.
- **A formal-methods reference.** Trike, PASTA, OCTAVE are out of scope; the folder is biased toward STRIDE + ATT&CK + attack-path.
