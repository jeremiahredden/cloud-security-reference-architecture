# Identity and Access

## What this folder is

A practitioner's reference for cloud identity — workforce identity, workload identity, federation, and least-privilege workflows on AWS, Azure, and GCP. The material here is what I put in front of a team when the question is: *we have a hundred IAM users with long-lived access keys and an SSO solution that nobody uses — how do we close that gap without breaking everything?*

## The organizing principle

Identity is the new perimeter, and in 2026 it is also the most common entry point in cloud incident reports. Every credible cloud incident review in the last two years lists one or more of: long-lived access keys committed to a public repository, an over-privileged role assumed by a compromised workload, a federated identity provider with a permissive SAML claim mapping, or a missing MFA enforcement on a privileged account. The patterns in this folder are biased toward closing those four classes by construction rather than by detection — and toward doing it without forcing application teams to rewrite their CI/CD pipelines.

Two opinions drive the document selection. First, that **workload identity is more important than workforce identity** in 2026 — the workforce identity story is largely solved (SSO, MFA, conditional access, PIM), but workload identity is where the long-lived keys still live, and where the leverage from killing them is highest. The OIDC-federation-from-CI-to-cloud pattern is the single highest-leverage move in identity work this decade, and it deserves a dedicated document. Second, that **least privilege is a workflow, not a destination** — every team I have worked with starts from an over-privileged role and tightens it iteratively; the patterns here describe the workflow (CloudTrail → Access Analyzer → policy tightening → Permission Boundary cap) rather than asking the team to land at the destination on day one.

## Planned documents

- **[workforce-identity.md](./workforce-identity.md)** — Workforce identity architecture: Entra ID / Okta / Google Workspace as the identity provider, AWS Identity Center / Azure AD-as-identity-provider / GCP Workforce Identity Federation as the cloud trust anchor, conditional access policies that actually get enforced, PIM / just-in-time elevation, the kill-the-IAM-user playbook, device trust, BYOD tiering, and the break-glass account pattern. Worked Meridian six-month rollout with 18 findings (`WFI-001` through `WFI-018`).
- **[workload-identity.md](./workload-identity.md)** — The static-secret reduction taxonomy and the kill-the-static-secret playbook. IRSA and EKS Pod Identity for EKS workloads with full trust-policy walkthroughs. GitHub Actions OIDC federation with the `sub`-claim scoping patterns (`environment:` binding, pull-request trap, wildcard repo trap). GitLab / CircleCI / Bitbucket equivalents. Lambda execution roles, ECS task roles, EC2 instance profiles. The six-month migration playbook with a worked Meridian Health example, 18 sprint-assignable findings (`WID-001` through `WID-018`), seven anti-patterns, and Azure Managed Identity / GCP Workload Identity Federation crosswalks.
- **[least-privilege-workflow.md](./least-privilege-workflow.md)** — The CloudTrail → IAM Access Analyzer → policy generation → review → tighten runbook in nine numbered steps with the actual commands and queries. The four-layer authorization mental model (SCP → Permission Boundary → identity policy → resource policy). Permission Boundary patterns for developer self-service with the recursive-boundary trap. The IAM Access Analyzer toolkit (external access, unused access, custom policy checks, policy generation). Quarterly review cadence, worked Meridian Q2 2026 review example, 15 sprint-assignable findings (`LPV-001` through `LPV-015`), and eight anti-patterns.
- **[federation-patterns.md](./federation-patterns.md)** — SAML 2.0 vs OpenID Connect vs SCIM 2.0; claim mapping that does not silently widen access; group-to-role binding patterns; "SAML attribute is data, not identity" failure mode; cross-cloud federation (AWS ↔ Azure, GCP ↔ AWS) via Workload Identity Federation; Entra B2B guest pattern. Worked Meridian Snowflake SAML+SCIM migration with 18 findings (`FED-001` through `FED-018`).
- **[just-in-time-access.md](./just-in-time-access.md)** — JIT / PIM patterns: Entra ID PIM, GCP JIT, AWS Identity Center + Aponia / Sym / Indent / Teleport, custom Snowflake JIT. Per-role duration / approval / MFA policy. Break-glass interaction. Audit-and-detection patterns. Vendor landscape. Worked Meridian quarterly rollout with 18 findings (`JIT-001` through `JIT-018`).
- **[service-account-hygiene.md](./service-account-hygiene.md)** — Service-account lifecycle: ownership tags, central registry, renewal workflow, decommissioning, audit. Per-platform specifics (AWS / Azure / GCP / Snowflake / SaaS). The inventory problem and the way out. Worked Meridian audit with 18 findings (`SAH-001` through `SAH-018`).
- **[iam-anti-patterns.md](./iam-anti-patterns.md)** — Catalogue of patterns to remove: `Principal: "*"`, broad-Action policies, missing SourceArn on service trusts, `iam:PassRole` with wildcards, AssumeRole chains, wildcard resource ARNs, IAM users for humans, long-lived service credentials, standing-admin "for emergencies." Per-anti-pattern: why it exists, why it's wrong, the replacement. Tiered remediation order. 22 findings (`IAM-AP-001` through `IAM-AP-022`).

## How to use this section

**If you are killing long-lived access keys**, start with `workload-identity.md`. The OIDC-federation-from-CI pattern is the single biggest lever; everything else in the folder is incremental on top of it.

**If you are tightening over-privileged roles**, `least-privilege-workflow.md` is the procedure. The document is structured as a runbook because every team I have given this work to runs it once a quarter, and the value comes from the workflow being repeatable rather than from a one-time tightening pass.

**If you are designing identity for a new environment**, `workforce-identity.md` and `federation-patterns.md` together cover the design space. Read them before standing up an identity provider; the trust-anchor decisions are hard to reverse.

## What this section is not

- **A complete Entra ID / Okta administration guide.** Vendor administration deserves vendor documentation. This folder covers the security-architecture decisions that determine how cloud trust is wired into whatever identity provider you run.
- **A privileged access management (PAM) buyer's guide.** Where specific PAM tools appear, they illustrate patterns. The folder is agnostic on vendor selection.
