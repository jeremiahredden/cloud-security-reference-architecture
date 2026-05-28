# Secret Detection

A practitioner's reference for preventing secrets from reaching places they shouldn't — Gitleaks, TruffleHog, the cloud-native secret scanners, the "no secret survives a pull request" workflow, pre-commit hooks vs CI gates vs full-history scanning vs runtime scanning, and the response runbook when a secret is detected. The patterns here are about *preventing* the leak first, *detecting* it when prevention fails, and *responding* to the detected leak quickly enough that it doesn't matter.

This document is the credential-leak-prevention deep dive that complements the discovery patterns in [../data-security/secret-and-pii-detection.md](../data-security/secret-and-pii-detection.md). That document covers the broader sensitive-data discovery problem; this document covers secrets specifically, with the secrets-management-folder lens: prevention is upstream of every other secrets pattern in this folder.

For the patterns that reduce the secret count to begin with (the highest-leverage move), see [kill-the-static-secret.md](./kill-the-static-secret.md). For the secrets manager that should hold every remaining secret, see [secrets-manager-patterns.md](./secrets-manager-patterns.md). For the rotation that bounds the leak window when a detected secret is rotated, see [rotation-patterns.md](./rotation-patterns.md).

---

## When to read this document

**If your team has not deployed secret scanning** — read top to bottom. This is mandatory infrastructure for any organization with source control.

**If you have secret scanning but secrets still reach production** — start with [The four scanning layers](#the-four-scanning-layers). Most environments scan one layer (CI gate); the other three are necessary.

**If a secret has been detected and the team is responding** — start with [The secret-leak response runbook](#the-secret-leak-response-runbook). Time matters.

**If you are auditing secret-detection posture** — start with [Findings checklist](#findings-checklist). Common findings: scanning at only one layer, no historical scan, no container-image scanning, no response runbook.

---

## The premise: prevention is cheaper than response

A leaked secret incident has costs:

- **The credential itself** — anything it could do, an attacker might do.
- **The blast radius** — production environments, customer data, dependent services.
- **The remediation work** — rotate, investigate, audit, postmortem.
- **The trust cost** — customers, regulators, internal stakeholders.

The remediation cost alone is typically tens to hundreds of engineer-hours per incident. The prevention cost is a one-time integration of scanning tools plus ongoing maintenance.

The case for scanning: any organization that uses source control has secret-leak risk. The risk is meaningful at any organization size; the prevention is bounded; the math is obvious.

---

## The four scanning layers

Secrets can be caught at four distinct points. Each catches what the others miss.

### Layer 1: Pre-commit hook (developer machine)

The earliest detection point. Runs on the engineer's laptop before the commit hits the repo.

How it works:

- Pre-commit framework (e.g., `pre-commit` Python library) installs a hook.
- Hook runs Gitleaks, TruffleHog, or similar on the staged changes.
- If a secret is detected, the commit is refused.

Pros: catches before the secret enters source control history.

Cons: engineers can bypass with `git commit --no-verify`; new contributors may not have the hook installed.

### Layer 2: CI gate (pull request / merge check)

Runs on every PR. Catches what pre-commit missed.

How it works:

- CI workflow (GitHub Actions, GitLab CI, etc.) runs a scanning tool on the diff.
- If a secret is detected, the PR check fails.
- Branch protection rules prevent merge until the check passes.

Pros: cannot be bypassed (unless an admin overrides branch protection); runs even for contributors without local hooks.

Cons: secret is now in the repo (in the branch); requires force-push to remove from history; window between commit and detection.

### Layer 3: Scheduled full-history scan

Periodically (daily / weekly), scans the entire repo history. Catches:

- Pre-existing secrets that landed before scanning was in place.
- Secrets in branches that weren't gated.
- Secrets that bypassed the gate (admin override, scanning rule miss).
- Secrets that scanning rules didn't detect at the time but a newer rule would.

Pros: catches the long-tail.

Cons: secret is in history for the period between commit and scheduled scan; rewriting history is disruptive.

### Layer 4: Runtime / artifact scanning

Scans built artifacts (container images, deployed bundles, configuration files) for secrets.

How it works:

- Image-build pipeline runs Trivy / Grype / similar.
- Detection of a baked-in secret fails the build.
- Production deployments are gated.

Pros: catches secrets that didn't appear in source but were baked at build time (`docker build --build-arg API_KEY=...`).

Cons: only as good as the image-scanning rules; doesn't catch secrets that the application fetches at runtime (correctly).

### The layered defense

| Layer | Catches | Doesn't catch |
| --- | --- | --- |
| 1. Pre-commit | Most pre-source-control leaks (when used) | Bypassed commits, new contributors |
| 2. CI gate | Most committed leaks | Pre-existing history, branch-bypassed commits |
| 3. Full-history scan | Long-tail of pre-existing or missed | Real-time response (delay between commit and scan) |
| 4. Runtime artifact | Image-baked secrets | Runtime-fetched secrets (which is correct behavior) |

The combined defense catches almost all leak vectors. Single-layer scanning misses material amounts.

---

## The tools

The dominant secret-scanning tools in 2026.

### Gitleaks

- **Open source**, widely adopted.
- Fast; suitable for pre-commit and CI gates.
- Configurable rule set (built-in plus custom regex).
- Output in many formats (JSON, SARIF, CSV).

Best for: pre-commit hooks; CI gates; the default starting point.

### TruffleHog

- **Open source** (with commercial cloud offering).
- Entropy-based detection (catches high-entropy strings even without specific patterns).
- Verification: TruffleHog can validate detected secrets (e.g., try the AWS key against AWS STS to confirm it works) — produces actionable findings with much lower false-positive rates than pattern-only matching.
- Deeper full-history scans.

Best for: scheduled full-history scans; verification-required workflows.

### GitGuardian

- **Commercial** managed service.
- Cross-repository coverage (organization-wide).
- Validated secrets (similar to TruffleHog).
- Workflow integration (Jira, Slack, security platforms).

Best for: organizations that want a managed service with workflow integration.

### GitHub Secret Scanning

- **Native to GitHub Enterprise** (free for public repos; included with Advanced Security for private).
- Cross-references against provider-maintained patterns (AWS, Stripe, Slack, GitHub, hundreds of providers).
- Pushed-secret alerts before merge (Push Protection).
- Validation against the provider's API.

Best for: GitHub-hosted organizations; provides cross-organization visibility and provider-coordinated revocation.

### GitLab Secret Detection

- **Built-in to GitLab** (with appropriate tier).
- Similar pattern to Gitleaks (uses Gitleaks as the underlying scanner).

Best for: GitLab-hosted organizations.

### Trivy / Grype (for container images)

- **Open source** vulnerability scanners that also detect embedded secrets.
- Trivy is the more comprehensive; Grype is faster.
- Used in image-build pipelines.

Best for: layer 4 (runtime artifact scanning).

### The tool stack for most organizations

- **Gitleaks** for pre-commit and CI gate (layers 1 and 2).
- **TruffleHog** for scheduled full-history scan (layer 3).
- **GitHub Secret Scanning** or **GitLab Secret Detection** for native cross-cutting (layer 2 reinforced).
- **Trivy** for container-image scanning (layer 4).

For organizations on GitHub Enterprise with Advanced Security: GitHub Secret Scanning is often sufficient for layers 2–3.

References:
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [Trivy](https://trivy.dev/)

---

## The "no secret survives a pull request" workflow

The end-to-end pattern for prevention.

### Stage 1: developer machine

- `pre-commit` framework installed via team-shared config.
- Gitleaks runs on staged changes.
- Detection refuses the commit; engineer fixes (typically: move the secret to Secrets Manager, replace with placeholder).

### Stage 2: CI on the feature branch

- Every push to a feature branch triggers a CI workflow.
- The workflow runs Gitleaks on the diff (faster) and on the full branch (catches the case where pre-commit was bypassed).
- Detection fails the build; engineer must rebase to remove the secret from history before the PR can be merged.

### Stage 3: PR merge check

- Branch protection requires the secret-scan check to pass.
- GitHub Secret Scanning or equivalent native integration runs in parallel.
- Push Protection (GitHub Advanced Security) blocks pushes containing known patterns before they reach the remote.

### Stage 4: post-merge

- Scheduled (daily / weekly) TruffleHog full-history scan against all repos.
- Detected secrets trigger immediate ticket / page.

### Stage 5: artifact build

- Container-image build runs Trivy scan for secrets.
- Detection fails the build; the artifact is not published.

### Stage 6: deployment verification

- Final pre-deployment scan of the artifact bundle.
- Detection blocks deployment.

The combined workflow catches secrets at any point in the SDLC. The cost: integration work per layer; ongoing maintenance of the scanning rules and tool versions.

---

## Custom detection rules

Built-in rules cover well-known patterns (AWS, GitHub, Stripe, etc.). Custom rules cover the organization's specific patterns.

### Patterns that benefit from custom rules

- **Internal API keys** with organization-specific prefixes (`mer_live_...`).
- **Internal token formats** (custom JWT signing keys, internal session tokens).
- **Provider-specific patterns the built-in rules miss** (newer or rarer services).
- **High-confidence patterns** to reduce false positives (organization-specific identifiers that look like secrets but aren't).

### Rule design

A good custom rule:

- **Specific prefix or distinguishing marker** for high confidence.
- **Length match** (most secret formats have known lengths).
- **Character set** (often `[A-Za-z0-9+/=]` for base64, `[a-f0-9]` for hex, specific length).

Example Gitleaks rule:

```toml
[[rules]]
id = "meridian-internal-api-key"
description = "Meridian internal API key"
regex = '''mer_(live|test)_[A-Za-z0-9]{32}'''
keywords = ["mer_live_", "mer_test_"]
```

The keywords narrow the search space (Gitleaks skips files without the keyword); the regex confirms the match.

### Maintaining custom rules

- Custom rules in source control alongside the scanning tool's configuration.
- Reviewed when new internal credential types are introduced.
- Tested with positive and negative cases.

The discipline: every internal credential type the team uses has a custom rule that catches it in scanning.

---

## The secret-leak response runbook

What happens when a secret is detected. Speed matters.

### Step 0: triage

The detection alert arrives. Triage:

- **Is the secret active?** TruffleHog and GitHub Secret Scanning often verify; if not, manual verification (try the credential).
- **What does it grant?** AWS credentials? Database password? API key with limited scope?
- **Where is it?** Public repo? Private repo? Pre-merge? Post-merge?

Triage produces severity:

- **Critical:** active credential with broad access in a public repo.
- **High:** active credential with narrow access; or any credential in public.
- **Medium:** inactive credential or any credential in private repo.
- **Low:** false positive or unverifiable.

### Step 1: revoke

**The first action is always to revoke the credential.** Speed beats investigation; the credential is presumed compromised the moment it's exposed.

- AWS access key: `aws iam delete-access-key` immediately.
- GitHub PAT: revoke via GitHub UI / API.
- Database password: rotate immediately (use the rotation runbook from [rotation-patterns.md](./rotation-patterns.md)).
- Third-party API key: rotate at the provider.

Revoke first. Investigate later.

### Step 2: investigate exposure

After revocation:

- **Was the credential used by an unexpected party?** Check audit logs (CloudTrail, API access logs, application logs) for the exposure window.
- **What was accessed?** If the credential was used by an attacker, what data could they have reached?
- **Is the impact reportable?** Some jurisdictions require disclosure for specific data classes; legal needs to know if PHI / PII / financial data was potentially accessed.

### Step 3: remove from history

For the source repo:

- **`git rebase` to remove the commit** containing the secret.
- **`git filter-repo` for older history** (preferred over the deprecated `git filter-branch`).
- **Force-push** (with team coordination — communicate the change).
- For very high-visibility leaks (public repo), consider repo deletion and recreation without the commit.

The goal is to remove the secret from accessible history. For public repos that have been forked or cached by services (npmjs, pypi, etc.), the secret cannot be reliably removed from those caches; this is why revocation comes first.

### Step 4: update detection

The detected pattern should be added to the scanning rules:

- Confirm the existing rules would have caught it (sometimes they did; sometimes there's a gap).
- If gap exists, add the specific pattern as a custom rule.
- Verify rules with tests.

### Step 5: postmortem

Within the next week:

- **Root cause:** why did the secret exist? Why was it committed?
- **Process gaps:** what prevention should have worked? Why didn't it?
- **Systemic fix:** is this a class of issue (e.g., all CI workflows use long-lived credentials) that calls for a structural change (OIDC federation)?
- **Documentation:** what training or tooling changes prevent future occurrences?

The postmortem is the learning step. Without it, the next incident is the same incident.

---

## Special cases

### The historical-secret backlog

When a team first deploys scanning, the full-history scan often finds many pre-existing secrets. The triage:

- **Active secrets:** treat each as a fresh leak; revoke + investigate + remove from history.
- **Inactive but identified:** rotate to confirm; remove from history.
- **False positives:** add to the allowlist to prevent future re-flagging.

The backlog is a sprint priority, not a "we'll address it eventually" item. Active credentials in history are active credentials.

### The container-image-baked secret

A secret was committed via `Dockerfile` `ARG`. The image is in a registry. The secret is in the image layer cache.

Response:

- Revoke the secret.
- Rebuild the image without the secret.
- Push the new image; pin all consumers.
- Identify and delete the old image (and any layers that contained the secret).
- For public registries, the secret may have been pulled by third parties; presume permanent exposure.

### The cross-repo secret

The same secret was committed to multiple repos. The team finds it in one; the others are still exposed.

Response:

- Search the organization's repos for the same secret (Gitleaks / TruffleHog organization-wide scan).
- Treat each as a separate leak; revoke once (the credential is unitary), remove from each repo's history.

### The third-party-disclosed-secret

A vendor publishes a breach; one of the vendor's tokens was in customer environments. The team is notified.

Response:

- Rotate the affected credential immediately.
- Verify the rotation propagated.
- Audit logs for any unauthorized use during the exposure window.

---

## Worked example: Meridian Health's secret-detection posture

Meridian operates Gitleaks (pre-commit and CI gate), GitHub Secret Scanning with Push Protection, TruffleHog for scheduled history scans, and Trivy for container-image scanning. The combination catches secrets at four points; the response runbook executes within 30 minutes for verified leaks.

### Layer 1: pre-commit

- Every Meridian developer's onboarding includes pre-commit hook installation.
- The team-shared `.pre-commit-config.yaml` includes Gitleaks.
- Custom rules added for Meridian's internal API key formats (`mer_live_*`, `mer_test_*`) and patient-token formats.

### Layer 2: CI gate

- GitHub Actions workflow runs Gitleaks on every PR.
- GitHub Secret Scanning with Push Protection is enabled at the organization level.
- Push Protection blocks pushes containing GitHub-recognized patterns before they hit the remote.
- Branch protection requires the secret-scan check to pass.

### Layer 3: scheduled full-history scan

- Nightly TruffleHog scan of all Meridian repositories.
- TruffleHog's verification feature confirms which detected secrets are active.
- Results pipe into PagerDuty for active secrets; into Jira for inactive findings.

### Layer 4: container-image scanning

- Trivy in the image-build pipeline.
- Builds fail on detected secrets in image layers.
- Pre-deployment scan as a second check (catches images that bypassed the build pipeline).

### The response runbook

When a verified active secret is detected:

1. **0–5 min:** PagerDuty alert; on-call engineer acknowledges.
2. **5–15 min:** Engineer identifies the credential; revokes at the source (AWS access key deactivated, API key rotated, etc.).
3. **15–30 min:** Engineer investigates audit logs for any unauthorized use during the exposure window.
4. **30–60 min:** Engineer or contributor removes the commit from history; force-push.
5. **Next business day:** Postmortem ticket created; reviewed in next security standup.

### The historical-secret cleanup story

When Meridian first deployed TruffleHog in 2024, the initial scan found 47 active secrets across the organization's repositories. The remediation:

- All 47 were rotated within 48 hours.
- 32 were CI credentials that triggered a parallel migration to OIDC federation.
- 8 were database passwords that became part of the IAM-database-auth migration.
- 7 were third-party API keys that moved to Secrets Manager + rotation.
- All commits were removed from history; force-pushes coordinated with affected teams.

Post-cleanup: ~3 secret findings per month (down from the initial 47); all are remediated within 24 hours of detection.

### Findings opened during the secret-detection audit

- **SDET-001** (no pre-commit hook standardization; new contributors didn't have scanning locally). Closed by team-shared `.pre-commit-config.yaml` and onboarding documentation.
- **SDET-002** (CI gate ran but didn't block merge; advisory only). Closed by branch protection requiring the check.
- **SDET-003** (no scheduled history scan; pre-existing secrets undetected). Closed by nightly TruffleHog with verification.
- **SDET-004** (container images not scanned for secrets). Closed by Trivy in build pipeline.
- **SDET-005** (response runbook absent; leaks took hours to revoke). Closed by documented runbook and PagerDuty integration.
- **SDET-006** (custom rules for Meridian-specific patterns absent; internal API keys not caught). Closed by custom Gitleaks rules.
- **SDET-007** (allowlists for known false positives missing; engineers learned to ignore findings). Closed by curated allowlist and quarterly review.

---

## Anti-patterns

### 1. The single-layer scanning deployment

The team has Gitleaks in CI. No pre-commit, no historical scan, no container-image scan. Coverage is partial; the layers that aren't covered are silent failure modes.

The fix: all four layers. Each catches what the others miss.

### 2. The advisory-only CI gate

CI runs scanning; results appear as a comment on the PR; merging is not blocked. Engineers learn to ignore the comments.

The fix: branch protection requires the check to pass; merge is blocked on detected secrets.

### 3. The pre-existing-secret denial

Full-history scan reveals secrets; the team plans to "address them over time." The active credentials remain in history, still functional, possibly already exposed.

The fix: treat pre-existing secrets as fresh leaks; rotate immediately; remediate history.

### 4. The bypassed pre-commit hook

Engineers run `git commit --no-verify` to skip the hook for "quick fixes." The bypass becomes habit.

The fix: CI gate catches what pre-commit missed; no equivalent of `--no-verify` for the CI gate.

### 5. The slow response

A secret is detected. The team logs a ticket; nobody works it for a week; the credential is unused or used.

The fix: paging integration for verified secrets; SLA for response.

### 6. The history-not-rewritten

A secret was detected and revoked. The commit remains in history. A future engineer reads the commit, sees the secret format, thinks "this is the pattern" and reintroduces a similar secret.

The fix: remove from history, even after revocation.

### 7. The custom-rule absence

The organization has internal credential formats. The scanner doesn't know them. Internal credentials reach repos undetected.

The fix: custom rules for every internal credential format; reviewed when new types are added.

### 8. The container-image-secret backlog

A secret was baked into an image months ago. The image is still in production. The secret is rotated, but the image still contains the (now-stale) secret material — if pulled and inspected, it reveals what the credential format looks like, which informs future attacks on the team.

The fix: rebuild and redeploy after credential rotation; remove old images from registries.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| SDET-001 | No pre-commit hook for secret scanning; relies on CI only | Medium | Team-shared `.pre-commit-config.yaml` with Gitleaks; onboarding documentation | DevOps + Security Eng |
| SDET-002 | CI scanning is advisory; PRs can merge with detected secrets | High | Branch protection requires check to pass; cannot merge with detected secrets | DevOps + Security Eng |
| SDET-003 | No scheduled full-history scan; pre-existing secrets undetected | High | Nightly TruffleHog with verification; pipe to PagerDuty | Security Eng + DevOps |
| SDET-004 | Container images not scanned for secrets | High | Trivy / Grype in image-build pipeline; fail build on detection | DevOps + Security Eng |
| SDET-005 | No documented response runbook for detected secrets | High | Runbook covering triage, revoke, investigate, remove-from-history, postmortem | Security Eng + SOC |
| SDET-006 | Custom rules for internal credential formats absent | Medium | Custom rules per internal credential type; reviewed when new types added | Security Eng |
| SDET-007 | Allowlists for known false positives missing or stale | Low | Curated allowlist; quarterly review | Security Eng |
| SDET-008 | Detected secrets receive Jira tickets but no paging; response is slow | High | PagerDuty integration for verified active secrets; SLA on response | Security Eng + SOC |
| SDET-009 | Commit history not rewritten after secret detection | Medium | `git filter-repo` or `git rebase` to remove; force-push with team coordination | DevOps + Workload Owner |
| SDET-010 | Container images remain in registry after credential rotation; stale secret material accessible | Medium | Rebuild and redeploy; remove old images from registries | DevOps + Security Eng |
| SDET-011 | Push Protection (GitHub Advanced Security) not enabled | Medium | Enable Push Protection at organization level; review bypasses | Security Eng + GitHub Admin |
| SDET-012 | Organization-wide cross-repo scanning absent; secret in one repo doesn't trigger search elsewhere | Medium | Organization-wide scan for the same secret; remediate all instances | Security Eng |
| SDET-013 | Verified-secret rate of true positives unknown; tool tuning not data-driven | Low | Quarterly review of detection rate; refine rules; refine allowlist | Security Eng |
| SDET-014 | Postmortems on secret leaks not run; same root cause recurs | Medium | Mandatory postmortem; root-cause-driven systemic fixes | Security Eng + Engineering Lead |
| SDET-015 | Pre-commit hooks installed but engineers bypass routinely (`--no-verify`) | Low | Monitor bypass rate; engineering culture / training; CI gate remains the enforcement | DevOps + Engineering Lead |
| SDET-016 | Detection happens but no audit log shows what the leaked credential was used for | High | Audit logs queryable for the credential during the exposure window | SOC + Workload Owner |
| SDET-017 | Forked / public repository inheritance: secret in private fork remains after revocation | Medium | Coordinate with the parent organization on rotation; presume permanent if public | Security Eng |
| SDET-018 | New secret-detection rule not deployed to all repos; coverage gap | Low | Centrally-managed scanning configuration; same rules across all repos | DevOps + Security Eng |

---

## What this document is not

- **A complete secret-scanning tool comparison.** Gitleaks / TruffleHog / GitGuardian / GitHub Secret Scanning are the most common; the patterns transfer.
- **A guide to specific secret formats.** Provider-specific patterns are maintained by the scanning tools themselves.
- **A repo-history rewriting tutorial.** `git filter-repo` and `git rebase` patterns are well-documented elsewhere.
- **A complete container-supply-chain reference.** Container scanning depth lives in [../kubernetes-and-container-security/](../kubernetes-and-container-security/) (coming) and the AppSec sibling repo.
