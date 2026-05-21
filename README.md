# Cloud Security Reference Architecture

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Maintained](https://img.shields.io/badge/Maintained-yes-green.svg)
![Sibling repo: appsec-reference-architecture](https://img.shields.io/badge/sibling-appsec--reference--architecture-orange.svg)
![Sibling repo: ai-security-reference-architecture](https://img.shields.io/badge/sibling-ai--security--reference--architecture-orange.svg)

### A practitioner's toolkit for cloud security engineering and architecture — landing zones, identity, network, data, Kubernetes, IaC, detection, and zero trust on AWS, Azure, and GCP

**Jeremiah Redden** | Senior AI/AppSec Security Architect | CISSP | [github.com/jeremiahredden](https://github.com/jeremiahredden)

---

This repository is the cloud-security third of a three-repo reference set. Its siblings, [**appsec-reference-architecture**](https://github.com/jeremiahredden/appsec-reference-architecture) and [**ai-security-reference-architecture**](https://github.com/jeremiahredden/ai-security-reference-architecture), cover application security and AI security respectively. This repository covers the controls that live *below* the application — the cloud accounts, identities, networks, data plane, container platforms, and detection infrastructure on which everything else runs.

The split is deliberate. Cloud security is its own engineering discipline, not a back-office function of AppSec. The controls have to be designed before the workloads land, enforced at the platform layer rather than the application layer, and operated by a team whose primary lever is platform engineering, not code review. Mixing cloud architecture content into an AppSec repo produces a folder that is too shallow to be useful and too broad to be focused. So this repo gets its own.

A second motivation: cloud security in 2026 is a multi-account, multi-cloud, multi-runtime problem. A reference architecture that says "use AWS Organizations and call it done" cannot help a team running EKS clusters across two AWS accounts, a SaaS workload on Azure App Service, and an analytics pipeline in BigQuery. The patterns here assume multi-account is the baseline, multi-cloud is common, and Kubernetes is on the path even when it has not arrived yet.

The sibling AppSec repo includes a [`cloud-security/`](https://github.com/jeremiahredden/appsec-reference-architecture/tree/main/cloud-security) folder that gives the lightweight AWS + Azure + multi-cloud overview most application security architects need. That folder stays in place. This repo goes deeper across more dimensions for engineers and architects whose primary job is the cloud platform itself.

---

## Table of Contents

- **[landing-zones/](./landing-zones/)** — Multi-account AWS Organizations, Azure Management Group hierarchies, and GCP Organization design. Account vending, baseline SCPs / Azure Policy / GCP Organization Policy, Control Tower vs Azure Landing Zones vs Cloud Foundation Toolkit, and the adoption sequencing that lets a team land the first 80% of guardrails in a sprint rather than a quarter. The AWS deep dive ([aws-organizations-design.md](./landing-zones/aws-organizations-design.md)) is landed with 18 sprint-assigned findings, eight anti-patterns, and a worked example; the Azure and GCP counterparts are next.
- **[identity-and-access/](./identity-and-access/)** — Workforce identity (Entra ID, Okta, AWS Identity Center) and workload identity (IAM Roles for Service Accounts, GCP Workload Identity Federation, OIDC federation from GitHub / GitLab / CI providers). Least-privilege workflows that start from CloudTrail / Activity Logs, Permission Boundaries and IAM Access Analyzer, just-in-time access, and the kill-the-long-lived-key adoption checklist. Two AWS deep dives landed: [workload-identity.md](./identity-and-access/workload-identity.md) with the IRSA / GitHub Actions OIDC / CI-federation patterns and six-month migration playbook, and [least-privilege-workflow.md](./identity-and-access/least-privilege-workflow.md) with the nine-step quarterly tightening runbook.
- **[network-security/](./network-security/)** *(coming)* — VPC / VNet design, hub-and-spoke vs Transit Gateway vs Cloud WAN, segmentation patterns, egress filtering (Network Firewall, Azure Firewall, GCP Cloud NGFW), PrivateLink / Private Endpoints / Private Service Connect, DNS firewall, and the inspection-architecture decision tree.
- **[data-security/](./data-security/)** *(coming)* — KMS strategy and key hierarchy, encryption at rest and in transit, BYOK / HYOK / CMK trade-offs, S3 / Azure Storage / Cloud Storage hardening, RDS / Azure SQL / Cloud SQL security, tokenization, and a DLP pattern that integrates with detection rather than living next to it.
- **[kubernetes-and-container-security/](./kubernetes-and-container-security/)** *(coming)* — EKS / AKS / GKE security baselines, Pod Security Standards, network policies, OPA / Gatekeeper / Kyverno, runtime security (Falco, Tetragon), service mesh (Istio, Linkerd), image signing and attestation (Cosign, Sigstore, SLSA), and supply-chain controls from registry to admission.
- **[iac-security/](./iac-security/)** — Terraform / OpenTofu / Bicep / CloudFormation / Pulumi patterns, module design for security, policy-as-code (OPA / Conftest, Checkov, tfsec, Trivy config, Sentinel), IaC pipeline gates, and an intentionally-misconfigured reference IaC bundle so the pipeline has real findings to surface. [policy-as-code.md](./iac-security/policy-as-code.md) landed with the Trivy+Conftest portfolio, severity-to-action mapping, six policy-writing patterns, signal-to-noise discipline, and a worked Meridian Health library example.
- **[secrets-and-keys/](./secrets-and-keys/)** *(coming)* — Secrets Manager, Key Vault, GCP Secret Manager, dynamic credentials with Vault, rotation patterns, KMS key policies, envelope encryption, and the OIDC-federation-replaces-long-lived-keys playbook.
- **[cloud-detection-response/](./cloud-detection-response/)** — CloudTrail / Activity Logs / Audit Logs architecture, GuardDuty / Defender for Cloud / Security Command Center, log pipelines into SIEM, anomaly detection that pays for itself, threat hunting patterns, and a set of IR runbooks for cloud-native incidents. The AWS log pipeline ([log-architecture.md](./cloud-detection-response/log-architecture.md)) is landed, and the five core IR runbooks are landed — [leaked-iam-key](./cloud-detection-response/runbook-leaked-iam-key.md), [exposed-storage](./cloud-detection-response/runbook-exposed-storage.md), [eks-pod-compromise](./cloud-detection-response/runbook-eks-pod-compromise.md), [account-takeover](./cloud-detection-response/runbook-account-takeover.md), and [cryptomining](./cloud-detection-response/runbook-cryptomining.md).
- **[zero-trust-cloud/](./zero-trust-cloud/)** *(coming)* — Identity-aware proxies (Cloudflare Access, AWS Verified Access, GCP IAP), microsegmentation, service-to-service authn with SPIFFE / SPIRE, mTLS service mesh, continuous authorization, and the BeyondCorp-on-existing-stack adoption path that does not require ripping out the network.
- **[serverless-and-paas-security/](./serverless-and-paas-security/)** *(coming)* — Lambda / Azure Functions / Cloud Functions and Cloud Run security, API Gateway / API Management / Apigee, App Service, Container Apps, edge functions (CloudFront Functions, Cloudflare Workers), and the least-privilege patterns that serverless makes both easier and harder than IaaS.
- **[threat-modeling-cloud/](./threat-modeling-cloud/)** *(coming)* — Cloud-specific STRIDE templates, MITRE ATT&CK for Cloud Matrix coverage, attack-path analysis (the lateral movement chains that CSPM tools surface), and worked threat models against a multi-account regulated workload — at the same depth as the worked threat models in the sibling repos.
- **[compliance-and-control-mapping/](./compliance-and-control-mapping/)** *(coming)* — HIPAA Security Rule, SOC 2 Trust Services Criteria, PCI-DSS v4, FedRAMP Moderate / High, and NIST 800-53 Rev 5 mapped row-by-row to concrete cloud controls, implementation examples, and evidence artifacts. CSPM and continuous-controls-monitoring guidance with criteria for native vs third-party tooling.
- **incident-response-cloud/** *(coming, lives under cloud-detection-response/)* — Folded into [cloud-detection-response/](./cloud-detection-response/) rather than split out, because the same logging architecture has to serve both detection and IR.

---

## How to Use This Repo

**If you are a cloud security architect** designing controls for a new workload or a new business unit, start with [landing-zones/](./landing-zones/) and [identity-and-access/](./identity-and-access/). The account boundaries and identity model are the two decisions that are most expensive to reverse later; everything else is renegotiable. Once those are landed, [network-security/](./network-security/) and [data-security/](./data-security/) are the next-most-leveraged decisions, in that order.

**If you are a platform engineer** standing up a Kubernetes platform that other teams build on, [kubernetes-and-container-security/](./kubernetes-and-container-security/) is the destination. The patterns there assume the platform layer is responsible for controls the application teams above cannot retrofit — pod security policies, network policies, admission control, runtime detection, and image supply chain. Pair it with [zero-trust-cloud/](./zero-trust-cloud/) for the service-to-service identity story.

**If you are a security engineer** running detection and response on a cloud environment, [cloud-detection-response/](./cloud-detection-response/) is where the runbooks and the log-pipeline patterns live. Read it alongside [threat-modeling-cloud/](./threat-modeling-cloud/) so your detection coverage is built backward from the attack paths that actually appear in cloud environments, not forward from whatever signatures your tooling ships with.

**If you are an SRE or DevOps engineer** owning the IaC pipeline, [iac-security/](./iac-security/) is the section to start from. Policy-as-code gates that fail fast in CI are the single biggest lever for preventing misconfigured cloud resources from ever landing.

**If you are an auditor or a compliance lead**, [compliance-and-control-mapping/](./compliance-and-control-mapping/) is the artifact set. It is designed to produce the row-by-row evidence package most cloud audits actually require, rather than the policy-document pile they usually receive.

**If you are a hiring manager** evaluating my work, the worked threat models in [threat-modeling-cloud/](./threat-modeling-cloud/), the deep AWS landing zone in [landing-zones/](./landing-zones/), and the policy-as-code reference in [iac-security/](./iac-security/) are closer to my deliverables than a resume will ever be. Read those first.

---

## Philosophy

Four principles drive every piece of content in this repository. They are the same four that govern the sibling AppSec and AI security repos, restated for the cloud context.

**1. Cloud security should make platform and product teams faster, not slower.** A guardrail that blocks every Terraform apply with a 40-minute policy review is not a security control — it is a productivity tax that teams will route around, usually by acquiring shadow accounts. The right cloud security automation runs in the same pipeline as the deployment, fails fast in CI on policy violations, and gives the engineer a concrete remediation in the same PR. I optimize for controls that shorten total cycle time, even when that means accepting residual risk that a maximalist posture would not. A preventive guardrail that ships next week is worth more than a perfect one that ships next quarter, and a CSPM finding that closes within a sprint is worth more than one that accumulates in a queue.

**2. The right cloud control is the one that ships this sprint.** The single biggest failure mode in cloud security is the vendor-hosted reference architecture that shows 47 services wired together, costs six figures per year in licensing, requires two dedicated FTEs to operate, and has no path to incremental adoption. A team inheriting a workload and a tight SOC 2 deadline cannot use it. They need a sequence of concrete moves that each ship within a sprint and each improve posture measurably. Every recommendation here is sized to that reality: when I document a pattern, I name the 80% degraded-mode version that ships fast alongside the gold-standard version that ships eventually.

**3. Every cloud finding needs a fix an engineer can land in the current sprint.** A CSPM report that ends with "tighten IAM posture" has failed. A CSPM report that ends with "remove the `*` action from the `DataPlatformOps` role's KMS statement, replace with the four specific `kms:Decrypt` resource ARNs identified by IAM Access Analyzer, assigned to platform-eng, tracked as CLOUD-204, by sprint 47" has succeeded. Findings without owners, deadlines, and concrete technical guidance become Jira-backlog landfill. Every template and worked example in this repo is written to that standard.

**4. A cloud control that only exists in a policy document doesn't exist. Show your work.** Architecture decks, control matrices, and CSPM dashboards are evidence of intent, not of protection. Where the patterns here can be turned into enforcement code — an SCP applied at the OU, an Azure Policy assigned at the Management Group, a Conftest rule failing the Terraform plan, a Kyverno policy rejecting the admission request — they are. A "Zero Trust cloud architecture" with no enforcement point, a "least-privilege IAM model" with no deny statements, an "encrypted-by-default" data plane with no detective control catching the unencrypted bucket — these are theater. I write to the standard that every architectural claim should be backed by an artifact a reviewer can execute.

---

## What this repo is not

- **A vendor walkthrough.** Where specific tools are named (Wiz, Lacework, Prisma Cloud, Teleport, Vault, Okta, Entra ID, Cloudflare Access), it is because the pattern is easier to explain concretely. Substitute the vendor of your choice; the pattern is what matters.
- **A CIS benchmark walkthrough.** The CIS benchmarks are valuable, and they are also comprehensive enough to be their own project. Use a CSPM tool to measure compliance against them. The patterns here are about which controls matter most and how to implement them without drowning.
- **A complete cloud platform engineering reference.** Cost optimization, observability beyond security telemetry, and pure SRE concerns (capacity planning, autoscaling design, disaster recovery RTO/RPO engineering) are out of scope. Where those topics intersect with security — cost abuse as security incident, observability that doubles as detection, DR patterns that affect data residency — they appear, but the primary lens here is security.
- **AppSec or AI security.** Application-layer controls (input validation, secure API design, OWASP remediation) live in [appsec-reference-architecture](https://github.com/jeremiahredden/appsec-reference-architecture). AI-specific controls (prompt-injection defense, agent permission models, MCP server hardening, ML supply chain) live in [ai-security-reference-architecture](https://github.com/jeremiahredden/ai-security-reference-architecture). Use all three together; the boundaries are deliberate.

---

## License & Attribution

All content in this repository is released under the MIT License unless otherwise noted. Templates, playbooks, and reference implementations may be used, modified, and adapted freely — including in commercial engagements and client deliverables. Attribution is appreciated but not required.

If you find something useful, I would like to hear about it. Open an issue, reach out on LinkedIn, or send a pull request with your improvements.
