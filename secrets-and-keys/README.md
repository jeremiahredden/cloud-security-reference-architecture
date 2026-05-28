# Secrets and Keys

## What this folder is

A practitioner's reference for secrets management and key management in cloud environments — Secrets Manager / Key Vault / Secret Manager, Vault, dynamic credentials, rotation, KMS key policies, and the OIDC-federation patterns that obviate most static secrets. The material here is what I put in front of a team when the question is: *we have AWS access keys in our `.env` files, database passwords in our CI variables, and a Vault deployment that no one understands — how do we get to a coherent story?*

## The organizing principle

Most secrets-management problems in cloud environments are solved by *not having the secret*. An OIDC-federated CI pipeline does not need an AWS access key. A workload running with IRSA / Workload Identity does not need a service-account JSON file. A database connection from a workload with IAM database authentication does not need a stored password. The single highest-leverage move in secrets engineering is removing as many static secrets as possible from the architecture, not protecting the ones that remain. The patterns in this folder are biased accordingly — the static-secret reduction playbook comes first, the protect-what-remains patterns come second.

The folder is opinionated about three things. First, that **the cloud-native secrets manager is the right default** for almost all teams — Vault is the right answer for organizations that already operate it well, and the wrong answer for organizations that adopt it because a slide deck said to. Second, that **dynamic credentials are worth the engineering cost** for databases and cloud APIs specifically, and not worth it for everything else — the Vault database secrets engine, AWS IAM database authentication, and the per-session credential patterns in cloud SDKs are where the engineering cost is justified. Third, that **rotation as a process is more important than rotation as automation** — the failure mode of automated rotation without runbooks is silent rotation failures; the failure mode of manual rotation runbooks without automation is rotation that never happens.

## Planned documents

- **[kill-the-static-secret.md](./kill-the-static-secret.md)** — The static-secret reduction playbook: replace CI access keys with OIDC federation, replace service-account files with workload identity, replace database passwords with IAM database authentication, replace cross-account access keys with role assumption. With paired before/after Terraform / GitHub Actions / Kubernetes manifests.
- **secrets-manager-patterns.md** *(coming)* — AWS Secrets Manager, Azure Key Vault, GCP Secret Manager. Resource-policy patterns, access-from-Kubernetes patterns (External Secrets Operator, CSI Secret Driver), versioning, replication, deletion-protection, and the cost-comparison context that matters for high-volume access.
- **vault-patterns.md** *(coming)* — HashiCorp Vault when it is the right answer: dynamic database credentials, dynamic cloud-provider credentials, the PKI engine for internal mTLS, the transit engine for application-layer encryption. The Vault-on-Kubernetes deployment patterns and the auth-method choice tree.
- **rotation-patterns.md** *(coming)* — Rotation cadence, the rotate-without-downtime pattern (dual-credential rotation), AWS Secrets Manager rotation Lambdas, Azure Key Vault rotation, the "verify the new credential works *before* invalidating the old one" baseline, and the rotation-runbook structure that catches silent rotation failures.
- **kms-key-policies.md** *(coming)* — KMS key policy design: principal scoping (specific roles only), action scoping (least privilege per consumer), condition scoping (`kms:ViaService`, source IP, encryption context). Cross-account key sharing patterns. The "key policy is the access decision, IAM is permissive" mental model.
- **envelope-encryption.md** *(coming)* — Envelope encryption patterns: data key generation, data key caching, multi-region key materials, the AWS Encryption SDK / Tink / age-as-CLI patterns. When to use the cloud KMS directly versus through an SDK abstraction.
- **secret-detection.md** *(coming)* — Gitleaks, TruffleHog, AWS Secrets Manager / Azure Key Vault scanning patterns for unintended secrets. The "no secret survives a pull request" workflow. Pre-commit hooks versus CI gates versus full-history scanning.

## How to use this section

**If you are reducing secret sprawl**, start with `kill-the-static-secret.md`. The OIDC-federation pattern is the single biggest lever; most teams discover that 60-80% of their stored secrets simply do not need to exist.

**If you are choosing between Secrets Manager and Vault**, `secrets-manager-patterns.md` and `vault-patterns.md` together cover the decision. The honest answer is "cloud-native unless you already operate Vault well."

**If you are tightening KMS posture**, `kms-key-policies.md` is the destination. The cross-account key-sharing patterns and the `kms:ViaService` condition are where the most common KMS over-grants live.

## What this section is not

- **A complete Vault administration guide.** HashiCorp's documentation covers Vault operations better than this folder could.
- **A cryptography primer.** Where envelope encryption is described, it is described operationally, not from primitives.
