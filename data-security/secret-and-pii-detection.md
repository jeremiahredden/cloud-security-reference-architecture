# Secret and PII Detection

A practitioner's reference for sensitive-data discovery in cloud environments — Amazon Macie, Microsoft Purview, GCP Sensitive Data Protection (formerly DLP). The patterns here cover the discover-before-protecting workflow, the false-positive calibration that determines whether teams actually use the tool, integration with detection rather than as a standalone scanning report, and the secret-scanning workflow that prevents credentials from reaching repos in the first place.

This document distinguishes two related but different problems: **PII / PHI discovery** (where is the sensitive data?) and **secret detection** (where are the credentials?). The first is a data-classification problem solved by sampling-based scanners on object storage and databases. The second is a credential-leak-prevention problem solved by pre-commit and CI scanning. The patterns and tools differ.

For data classification's relationship to encryption, see [kms-strategy.md](./kms-strategy.md). For the storage-hardening that PII discovery informs, see [object-storage-hardening.md](./object-storage-hardening.md). For the secret-management patterns that secret detection complements, see [../secrets-and-keys/](../secrets-and-keys/).

---

## When to read this document

**If your organization has compliance requirements for data classification (HIPAA, GDPR, PCI)** — read top to bottom. The discovery workflow is mandatory in many frameworks; this document is the operational pattern.

**If you have deployed Macie / Purview / Sensitive Data Protection and abandoned it due to false positives** — start with [Calibrating the false-positive rate](#calibrating-the-false-positive-rate). Most abandonment is from default-configuration overuse; calibration is the fix.

**If you have a secret-in-repo incident** — start with [Secret detection in source control](#secret-detection-in-source-control). The pattern prevents the next one.

**If you are scoping a sensitive-data discovery project** — start with [The discover-before-protecting workflow](#the-discover-before-protecting-workflow). The instinct is to scan everything; the practice is to scope to known-relevant scopes.

---

## The two distinct problems

### PII / PHI / sensitive-content discovery

The question: *what data of regulatory or business sensitivity is where?*

- **Data:** unstructured (documents, images, PDFs) and structured (database rows, log entries).
- **Storage:** object storage, databases, file shares, snapshot archives.
- **Use case:** compliance attestation ("we know where PHI is"); incident response ("the exposed bucket — does it contain PHI?"); access control ("only authorized roles should reach this data").
- **Tools:** Amazon Macie, Microsoft Purview, GCP Sensitive Data Protection.

### Secret / credential detection

The question: *are there credentials in places they should not be?*

- **Data:** code, configuration files, container images, environment variables, CI configurations.
- **Storage:** source control (GitHub, GitLab, Bitbucket), container registries, package repositories, S3 buckets containing config.
- **Use case:** prevent credential leaks at the source; remediate when credentials do leak.
- **Tools:** Gitleaks, TruffleHog, GitGuardian, GitHub Secret Scanning, AWS Secrets Manager scanning.

The tooling, workflow, and remediation differ. Treat them separately even though both fall under "sensitive data detection" in marketing material.

---

## The discover-before-protecting workflow

A common failure mode: a team deploys data-protection controls (encryption, access control, audit logging) on storage they assume contains sensitive data — and they're wrong about which storage actually has the data. Protection misses; effort is wasted; the auditor catches it.

The discipline: **discovery first, protection second**.

### The four-step workflow

1. **Scope.** Identify the storage scopes most likely to contain sensitive data (workload data buckets, database backups, log archives that capture user data). Don't try to scan everything; scan the high-likelihood scopes first.
2. **Discover.** Run the discovery tool against the scoped storage. Produce an inventory of where sensitive data was found.
3. **Validate.** Sample the findings. Calibrate the false-positive rate. Distinguish "this bucket has 47 SSNs detected" from "this bucket has 47 instances of strings that look like SSNs but are foreign-postal-code-formatted record IDs."
4. **Protect.** Apply controls (encryption with restrictive CMK, access logging, tightened bucket policies) to the *verified* sensitive-data scopes.

The workflow takes weeks per scope; the result is targeted, calibrated, defensible.

### What to scope first

For most workloads:

- **Workload's primary data bucket** — likely contains the canonical sensitive data.
- **Database backup destination buckets** — likely contains everything the database had.
- **Log archives** — application logs often contain sensitive data the application logged inadvertently.
- **Analytics / data warehouse staging areas** — sensitive data often gets denormalized into these.
- **File share buckets used by humans** — uploaded customer documents.

Lower priority:

- Build artifact buckets (rarely contain sensitive data).
- CDN origin buckets (typically marketing content).
- Terraform state buckets (configuration, not customer data).

The scoping exercise prevents wasting discovery cost on storage that doesn't contain sensitive data.

---

## Amazon Macie

The AWS-native PII / sensitive-data discovery tool.

### What Macie does

- **Scheduled scans** against S3 buckets. Sampling-based; Macie does not read every byte.
- **Pattern matching** for built-in and custom data identifiers (SSN, credit card numbers, HIPAA identifiers, custom regex / keywords).
- **Findings** when sensitive data is detected. Findings include the bucket, the object, the identifier type, the sample count.
- **Continuous monitoring** of new objects (when configured); Macie scans new objects as they land.

### Configuration

- **Coverage:** by default, all buckets in an enabled account. Restrict via configuration to specific buckets / prefixes to control cost.
- **Sampling rate:** 1% to 100%. Lower rates reduce cost; higher rates increase confidence.
- **Custom data identifiers:** for organization-specific patterns (e.g., Meridian's internal patient ID format, internal employee number patterns).
- **Allowlists:** for false-positive suppression (specific values to ignore).

### Cost

- **Per-bucket per-month** plus **per-GB classified**.
- For a typical workload bucket (~100 GB), Macie scanning costs a few dollars per month per bucket.
- For very-large buckets (TB+), cost can become meaningful; scope tightly.

### Integration with detection

- Macie findings ship to **Security Hub** (and from there to SIEM via EventBridge).
- High-severity findings (large volume of SSNs found in a bucket previously believed not to contain PII) page the security team.
- Low-severity findings (small counts of PII in expected locations) feed the compliance dashboard.

### Common Macie patterns

- **Workload onboarding scan.** When a new workload's bucket goes to production, scan it once to verify what data is in it.
- **Quarterly comprehensive scan.** Refresh the inventory; discover new sensitive data classes that appeared.
- **Incident-response scan.** When a bucket exposure is detected, Macie quickly tells you whether sensitive data was in the exposed window.

References:
- [Amazon Macie](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
- [Macie data identifiers](https://docs.aws.amazon.com/macie/latest/user/managed-data-identifiers.html)

---

## Microsoft Purview

The Azure / Microsoft 365 ecosystem's sensitive-data tool. Broader than Macie — Purview covers Microsoft 365 (SharePoint, OneDrive, Exchange), Azure Storage, on-prem file shares, and other connectors.

### What Purview does

- **Sensitive Information Types (SITs).** Built-in and custom patterns for PII.
- **Data classification policies.** Apply labels (e.g., "Confidential — PHI") based on SIT matches.
- **DLP policies.** Block or alert when classified data is moved (uploaded to external services, emailed externally, copied to USB).
- **Records management.** Retention and disposition based on classification.

### Configuration

- **Connect data sources.** Azure Storage, Azure SQL, AWS S3 (cross-cloud connector), on-prem.
- **Scan scope.** Define which sources to scan and how often.
- **Sensitivity labels.** Map detected SITs to labels.
- **DLP policies.** Define what actions to block / alert on for each label.

### Cost

- Per-connected-data-source plus per-asset scanned.
- For broad Microsoft 365 + Azure deployment, cost can be substantial; scope to in-scope data.

### Integration

- Findings to Microsoft Sentinel, Defender for Cloud.
- Labels propagate to Microsoft 365 (a file labeled "Confidential" in SharePoint shows the label in OneDrive, Teams, Outlook).
- API access for custom integrations.

References:
- [Microsoft Purview overview](https://learn.microsoft.com/en-us/azure/purview/overview)

---

## GCP Sensitive Data Protection (formerly DLP)

The GCP-native equivalent. Renamed in 2024 from "Cloud DLP" to "Sensitive Data Protection."

### What it does

- **InfoType-based detection.** Built-in patterns for PII, PHI, PCI; custom regex / dictionaries.
- **Inspection** of Cloud Storage, BigQuery, Cloud SQL, Datastore.
- **De-identification.** Redact, tokenize, or transform detected sensitive content.
- **Risk analysis.** k-anonymity, l-diversity calculations for de-identification effectiveness.

### Configuration

- **Per-bucket / per-table** inspection jobs.
- **Inspection templates** for reusable configurations.
- **Sampling rates** to control cost.
- **Findings** to Cloud Logging, Security Command Center.

### Cost

- Per-byte inspected; per-record transformed.
- Free tier covers initial discovery; production scans incur cost.

### De-identification specific to GCP

GCP's de-identification capabilities are richer than Macie's:

- **Crypto-deterministic tokenization** — same input produces same token, allowing JOIN operations on tokenized data.
- **Format-preserving encryption** — tokens have the same format as original (useful when downstream systems expect specific shapes).
- **Date shifting** — preserve relative time relationships without exposing actual dates.

References:
- [GCP Sensitive Data Protection](https://cloud.google.com/sensitive-data-protection/docs)

---

## Calibrating the false-positive rate

The single most-common reason teams abandon discovery tools: too many false positives. The default configuration produces noise; the team learns to ignore findings; the tool becomes decoration.

### Why default configurations false-positive

- **SSN-pattern matching** flags any 9-digit number with hyphens — including some product IDs, tracking numbers, internal record IDs.
- **Credit-card pattern matching** flags strings that pass Luhn validation but are test data, internal references, or coincidental.
- **Address matching** flags addresses in non-customer contexts (employee directory, vendor records).
- **Email matching** flags every email address — most of which is non-sensitive operational metadata.

### The calibration workflow

1. **Run discovery with default settings** on a representative sample.
2. **Sample the findings.** Pick 50–100 findings at random; review each.
3. **Categorize:**
   - True positive: actual sensitive data in unexpected location.
   - False positive: pattern matched but not actual sensitive data.
   - Expected positive: actual sensitive data in expected location (the workload's data bucket).
4. **Compute the false-positive rate.** > 30% means the configuration needs tuning.
5. **Tune:**
   - Add **allowlists** for known-false-positive values.
   - Restrict scope to higher-likelihood storage.
   - Add **custom data identifiers** with tighter patterns for the organization's actual sensitive data.
   - Adjust **severity thresholds** — only treat high-confidence findings as alerts.
6. **Re-run.** Iterate until false-positive rate < 10%.

### The "expected positive" filter

A workload's data bucket *should* have PHI. A finding of PHI in that bucket is not noise; it's expected. The signal:

- **Findings in unexpected locations** (a CI artifact bucket has PHI; a public marketing bucket has PHI) — investigate.
- **Findings exceeding expected volume** (the workload bucket suddenly has 10x more SSNs than baseline) — investigate.
- **New finding types in any location** (a previously-PHI-only bucket now has credit-card data) — investigate.

The detection rule: pattern + location + volume. Single-axis detection (any PII finding anywhere) produces noise; multi-axis detection produces signal.

---

## Secret detection in source control

The credential-leak prevention problem. Tools and patterns differ from PII discovery.

### The pre-commit + CI + scheduled scan layering

The pattern that catches secrets at three points:

1. **Pre-commit hook.** Local developer hook runs before commit; refuses to commit detected secrets. The earliest detection point.
2. **CI gate.** Every PR runs a secret scan; PR fails if a secret is detected. Catches what pre-commit missed (engineers skipping the hook, new contributors without it).
3. **Scheduled full-history scan.** Periodically (daily / weekly) scans the entire repo history. Catches secrets that landed before scanning was in place, secrets that bypassed the gate, or secrets in branches that weren't gated.

Each layer catches what the others miss.

### Common secret-detection tools

- **Gitleaks** — fast, open-source; widely adopted in CI.
- **TruffleHog** — deeper detection; entropy-based for high-quality matching.
- **GitGuardian** — commercial; managed service with cross-organization coverage.
- **GitHub Secret Scanning** — native to GitHub; works on public repos for free, private repos with Advanced Security.
- **GitLab Secret Detection** — built-in.

The selection: GitHub Secret Scanning if on GitHub Enterprise; Gitleaks for self-hosted CI; TruffleHog for the periodic full-history scan; GitGuardian for the managed-service option.

### What gets detected

- **Cloud-provider credentials** (AWS access keys, Azure service principal credentials, GCP service account keys).
- **API keys** (Stripe, Slack, Twilio, GitHub PAT, etc. — providers maintain published patterns).
- **Private keys** (SSH, GPG, TLS certs).
- **Database connection strings** with embedded passwords.
- **High-entropy strings** that look like secrets even without a known pattern.

### What to do when a secret is detected

The runbook:

1. **Identify the secret.** Which secret leaked? What does it grant access to?
2. **Revoke immediately.** Treat the secret as compromised. Rotate the credential at the source (cloud IAM rotate, GitHub PAT revoke, etc.).
3. **Investigate the exposure window.** When did the secret commit? Has it been pushed to public repos? Was the credential used by an unexpected party in that window?
4. **Remove from repo history.** `git rebase` to remove the commit, or use `git filter-repo`. Force-push (with team coordination). For high-visibility leaks, consider repo deletion + restoration without the commit.
5. **Add to detection.** Update the secret-scanning rules to catch this specific pattern in the future.
6. **Postmortem.** Why did the secret exist? How can the team eliminate the class? (Often the answer: use OIDC federation; see [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md).)

### Container image scanning for secrets

Beyond source control, secrets sometimes get baked into container images:

- **`COPY` of `.env` file** at build time.
- **`ARG` build arguments** containing secrets.
- **Hardcoded secrets in scripts** that the image runs.

Tools (Trivy, Grype, container-specific scanning) catch these. Run in the image-build pipeline; fail the build on detection.

---

## Integration with detection rather than standalone reporting

The maturity model:

### Stage 1: standalone reports

The tool runs; produces a PDF report; the security team reviews monthly; findings are tracked in a spreadsheet. Most findings are stale by the time anyone acts.

### Stage 2: dashboard

Findings appear in a dashboard. Security team has visibility. Action is still manual; remediation is slow.

### Stage 3: workflow integration

Findings auto-create tickets (Jira, ServiceNow). Owners are notified. SLAs apply. Findings close when remediated.

### Stage 4: detection integration

High-severity findings page on-call. SIEM correlations combine findings with other signals (a Macie finding + a bucket access from an unusual location = active incident, not a future-attention item).

Most cloud organizations land at Stage 3; the high-maturity ones reach Stage 4.

---

## Worked example: Meridian Health's discovery posture

Meridian deploys Amazon Macie across all production AWS accounts with workload-specific scoping; runs Gitleaks + GitHub Secret Scanning across all repositories; deploys Trivy scanning in container CI.

### Macie deployment

- **Enabled in every production account.** Per-account configuration restricts scanning to specific buckets (the workload data buckets, the database backup buckets, the log archive buckets).
- **Custom data identifiers:**
  - Meridian patient ID format (`MERID-XXXXXXX` where X is a digit).
  - Internal employee number format.
  - Meridian-specific medical record number patterns.
- **Allowlists:**
  - Known false-positive values (test data, fixture data).
  - Specific patterns common in operational logs that aren't actually sensitive.
- **Sampling rate:** 100% on PHI-likely buckets; 10% on operational buckets.

### Findings workflow

- Macie findings ship to Security Hub.
- Security Hub findings go to:
  - **High severity** (PHI in unexpected location): EventBridge rule → PagerDuty → Security Eng on-call.
  - **Medium severity** (expected location, anomalous volume): Jira ticket auto-created; SLA 5 business days.
  - **Low severity** (expected location, expected volume): logged to a dashboard; reviewed quarterly.

### Calibration history

Meridian's initial Macie deployment in 2024 produced ~50K findings per month, of which ~80% were false positives or expected positives. The team almost abandoned the tool.

The calibration sprint:

- Built custom data identifiers for Meridian's specific patterns.
- Allowlisted known test fixtures.
- Scoped scanning to PHI-likely buckets.
- Tuned severity thresholds to surface only high-confidence, unexpected-location findings.

Post-calibration: ~200 findings per month; ~15 are actionable; the rest go to the dashboard.

### Secret detection

- **Pre-commit hook:** Gitleaks installed via Meridian's developer-environment bootstrap.
- **CI gate:** Every PR runs Gitleaks; PR fails on detection.
- **Scheduled scan:** TruffleHog runs nightly on all repos against full history; surfaces any pre-existing secrets that weren't caught.
- **GitHub Secret Scanning:** enabled across the organization; cross-checked against provider-maintained patterns.
- **Container scanning:** Trivy runs in image-build pipeline; fails the build on secret detection.

### The secret-detection runbook

When a secret is detected:

1. Security team is auto-paged.
2. The first 30 minutes: revoke the credential. AWS access keys deactivated, GitHub PATs revoked, API keys rotated at the provider.
3. The next hour: investigate the exposure window. Was the credential used? By whom?
4. The next day: remove from repo history; force-push; coordinate with team.
5. Postmortem within the week: why did the secret exist? Update the secret-prevention pattern (often "migrate this CI to OIDC federation").

### Findings opened during the discovery audit

- **PII-001** (Macie was deployed but findings volume was overwhelming; team ignored). Closed by the calibration sprint.
- **PII-002** (Macie scope included all buckets; analytics buckets with synthetic data were producing huge false-positive volumes). Closed by tighter scoping.
- **PII-003** (no secret scanning in CI; secrets had been committed historically). Closed by Gitleaks deployment; historical-scan revealed 12 secrets to remediate.
- **PII-004** (container images had not been scanned for secrets). Closed by Trivy in the pipeline.
- **PII-005** (Macie findings went to a dashboard but no ticket workflow). Closed by EventBridge → Jira / PagerDuty integration.

---

## Anti-patterns

### 1. The unscoped Macie deployment

Macie scans every bucket in the account. Cost is high; findings volume is overwhelming; the team learns to ignore.

The fix: scope to high-likelihood buckets. The full-coverage scan can wait for after the calibration is done.

### 2. The findings-go-to-PDF deployment

The discovery tool produces monthly PDF reports. Nobody reads them. Findings stale before they're seen.

The fix: integrate with the existing detection / workflow tooling. Findings auto-create tickets; high-severity findings page; SLAs apply.

### 3. The default-configuration-only deployment

The discovery tool is enabled with default identifiers. False positive rate is 30%+. Team ignores findings.

The fix: calibration sprint. Custom identifiers; allowlists; tuned thresholds. Reduce false-positive rate to under 10%.

### 4. The secret-detected-no-revoke

A secret is detected in a repo. The team removes the commit and force-pushes. The credential itself is not revoked. The attacker, having seen the public commit, uses the credential.

The fix: revoke first, remove from history second. The credential is presumed compromised the moment it's in the wrong place.

### 5. The pre-commit-hook-skipped engineer

Pre-commit hooks exist; engineers run `git commit --no-verify` to skip them. Secrets land in repo because the local check didn't run.

The fix: CI gate catches what pre-commit missed. No `--no-verify` equivalent in the CI gate.

### 6. The container image secret

Application code doesn't have the secret. The CI baked the secret into the image via build args. The image is in a registry; anyone with registry access has the secret.

The fix: secrets at runtime via Secrets Manager / Vault / Kubernetes secrets; never in the image.

### 7. The historical-secret backlog

The team starts secret scanning. A historical scan reveals 50 secrets in repo history. The team decides to "address them over time." Some are years-old and still active.

The fix: treat the backlog as a sprint priority. Rotate all the active credentials; remove from history.

### 8. The discovery-without-remediation

Macie finds PII in an unexpected bucket. The team is notified. Nothing happens because there's no clear owner. The finding closes (stale) without action.

The fix: every storage location has an owner (per tagging discipline in [object-storage-hardening.md](./object-storage-hardening.md)). Findings route to the owner. SLA applies.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| PII-001 | No sensitive-data discovery deployed (Macie / Purview / Sensitive Data Protection) | High | Deploy in production accounts; scope to high-likelihood storage | Security Eng + Compliance |
| PII-002 | Discovery tool deployed with default scope; cost or noise issue | Medium | Calibration sprint: scope to high-likelihood, tune thresholds, custom identifiers | Security Eng |
| PII-003 | False-positive rate > 20% from discovery tool | Medium | Custom data identifiers; allowlists; severity threshold tuning | Security Eng |
| PII-004 | Discovery findings go to PDF / dashboard only; no workflow integration | Medium | Integrate with ticketing / paging; SLA per severity | Security Eng + SOC |
| PII-005 | No secret scanning in source control | High | Gitleaks / GitHub Secret Scanning / GitLab Secret Detection deployed; CI gate enforces | DevOps + Security Eng |
| PII-006 | Pre-commit hooks exist but bypassed; only CI gate is reliable | Low | Document the layering; accept some pre-commit bypass | DevOps |
| PII-007 | Container image build does not scan for secrets | High | Trivy / Grype scanning in image build; fail build on detection | DevOps + Security Eng |
| PII-008 | Historical full-repo scan never run; pre-existing secrets in repos | High | Run TruffleHog deep scan; rotate detected credentials; remove from history | Security Eng + DevOps |
| PII-009 | Secret detected in repo; credential not revoked, only commit removed | High | Revoke at source first; remove from history second; investigate exposure window | Security Eng + SOC |
| PII-010 | Discovery findings have no owner; remediation does not happen | Medium | Findings route to storage owner per tagging; SLA enforced | Security Eng + Workload Owner |
| PII-011 | Custom data identifiers absent; org-specific patterns missed | Medium | Build custom identifiers for org's sensitive-data formats | Security Eng |
| PII-012 | Container registry not scanned for secrets in stored images | Medium | Registry-side scanning (ECR scan-on-push, Azure Container Registry scanning, Artifact Registry scanning) | DevOps + Security Eng |
| PII-013 | CI/CD environment variables contain secrets that should be in Secrets Manager | High | Migrate to OIDC federation + Secrets Manager; rotate exposed credentials | DevOps + Security Eng |
| PII-014 | DLP policy alerts on data movement but does not block | Medium | Move policies from alert to block where the data class warrants | Security Eng + Compliance |
| PII-015 | Backup and snapshot storage not scanned for sensitive content | Medium | Include backup destinations in discovery scope | Security Eng |
| PII-016 | Log archives contain PII / PHI inadvertently logged by applications | Medium | Scan log archives; remediate applications that log sensitive data | Workload Owner + Security Eng |
| PII-017 | No SIEM correlation between discovery findings and access logs | Low | SIEM rule: PII finding + unusual access pattern = high-priority alert | Security Eng + SOC |
| PII-018 | Quarterly discovery review not performed; findings backlog | Low | Quarterly review process; backlog cleanup | Security Eng |

---

## What this document is not

- **A complete DLP product reference.** Macie / Purview / Sensitive Data Protection are named as the cloud-native options; third-party DLP (Symantec, Forcepoint, Trellix) has similar patterns.
- **A complete secret-scanning tool comparison.** Gitleaks / TruffleHog / GitGuardian / GitHub Secret Scanning are the most-used; the patterns transfer.
- **A privacy-regulation reference.** GDPR / CCPA / HIPAA / PCI specifics belong in [../compliance-and-control-mapping/](../compliance-and-control-mapping/); this document is the operational discipline.
- **A data-classification taxonomy.** Public / Internal / Confidential / Restricted classification belongs in the organization's policy; this document covers the tooling that enforces it.
