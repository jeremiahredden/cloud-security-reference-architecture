# Workload Identity

A practitioner's reference for replacing long-lived AWS credentials with short-lived, federated identity — IAM Roles for Service Accounts (IRSA), GitHub Actions OIDC federation, GitLab / CircleCI / Bitbucket OIDC federation, Lambda execution roles, ECS task roles, EC2 instance profiles, and the migration playbook that takes an environment from "access keys everywhere" to "no static secrets for compute." The document is AWS-first; Azure Managed Identities and GCP Workload Identity Federation are named at the end for cross-reference.

This is, in my opinion, the single highest-leverage document in this repository for engineers. The number of cloud incidents driven by leaked long-lived access keys is staggering, and almost every one of them was preventable with the patterns below.

---

## Why this is the highest-leverage work

Every credible cloud incident review in the last two years lists "leaked long-lived credential" as either the root cause or an early step in the attack chain. The credentials come from the same handful of places: a `.env` file committed to a repository, an access key in a CI pipeline's environment variables, a service-account JSON file checked into a private repository that became public, a long-lived access key on an IAM user whose owner left the company three years ago.

The leverage from killing static secrets is structural, not tactical. A short-lived credential cannot be exfiltrated meaningfully because by the time the attacker uses it, the credential has expired. A federated credential cannot be exfiltrated at all because there is no credential to exfiltrate — the trust is established at runtime through a chain of OIDC claims that the attacker cannot reproduce without compromising the upstream identity provider.

The migration is also operationally cheap. The OIDC-federation patterns below typically take 1-3 engineering days per CI pipeline; the IRSA patterns take 1-2 days per Kubernetes cluster. The one-time engineering cost is far less than the cost of operating credential rotation for the same workload, and the security improvement is significant.

The patterns here are organized into two halves: the workload side (a service that needs AWS access, running in EKS / Lambda / ECS / EC2) and the build side (a CI pipeline that needs AWS access during builds and deployments). The workload side has been solved at AWS for years (IRSA, task roles, execution roles, instance profiles); the build side was solved more recently with OIDC federation. Both halves are now ready for production use, and there is no longer a defensible operational reason to keep long-lived access keys for either.

---

## When to read this document

**If you have IAM users with access keys in your Organization** — start with [The migration playbook](#the-migration-playbook). Run the discovery first to know what you are migrating; commit to a cut-over date; then work through the patterns by source.

**If you are setting up a new CI pipeline with AWS access** — start with [GitHub Actions OIDC federation](#github-actions-oidc-federation) (or the equivalent for your CI provider). There is no defensible reason to use a long-lived access key for new CI pipelines in 2026.

**If you are designing the workload-identity story for a Kubernetes platform** — start with [IRSA for EKS](#irsa-for-eks). Pair with EKS Pod Identity for the more recent simplification.

**If you are auditing the workload-identity posture of an existing environment** — start with [Findings checklist](#findings-checklist) and [Anti-patterns](#anti-patterns).

---

## The static-secret reduction taxonomy

Static secrets in cloud environments come from a small number of patterns. The patterns and their federation replacements:

| Static-secret pattern | Federation replacement | Maturity |
| --- | --- | --- |
| Access key on an IAM user, used by an engineer for CLI access | IAM Identity Center (SSO) | Production-ready since 2018 |
| Access key on an IAM user, used by a workload running on EC2 | EC2 instance profile + IAM role | Production-ready since 2012 |
| Access key on an IAM user, used by a workload running in EKS | IRSA or EKS Pod Identity | Production-ready since 2019 (IRSA) / 2023 (EKS Pod Identity) |
| Access key on an IAM user, used by a Lambda function | Lambda execution role | Production-ready since 2014 |
| Access key on an IAM user, used by an ECS task | ECS task role | Production-ready since 2017 |
| Access key in a GitHub Actions secret | GitHub Actions OIDC federation | Production-ready since 2021 |
| Access key in GitLab CI/CD variables | GitLab OIDC ID tokens to AWS | Production-ready since 2022 |
| Access key in CircleCI / Bitbucket / Jenkins / Buildkite | OIDC federation (provider-specific patterns) | Production-ready since 2022-2023 |
| Access key for cross-account access in another AWS account | Cross-account `sts:AssumeRole` (no key needed) | Production-ready since 2011 |
| Access key for third-party service (Datadog, PagerDuty, etc.) | Third-party-specific OIDC patterns or cross-account roles | Production-ready since 2022 (varies by vendor) |

The bottom row — third-party SaaS access to AWS — is the last remaining pattern where access keys are still common. The major SaaS providers (Datadog, New Relic, Wiz, Lacework) all support cross-account-role-based access in 2026; the few that do not should be replaced or pressured into supporting it.

Every other row has had a working federation pattern for at least 3 years. There is no defensible operational reason for the patterns above to still use static secrets in 2026.

---

## IRSA for EKS

IAM Roles for Service Accounts (IRSA) is the EKS pattern for granting AWS permissions to individual Kubernetes pods without baking long-lived credentials into the pod or the node.

### The mental model

```
Kubernetes ServiceAccount  ←─[annotation]─→  IAM Role
        │                                       │
        │                                       │ trust policy
        ▼                                       ▼
   Pod uses SA                            EKS OIDC provider
        │                                       │
        ▼                                       │
   AWS SDK requests                             │
   credentials from                             │
   the SDK token file                           │
   (projected by kubelet)                       │
        │                                       │
        └──────────────►  STS  ←────────────────┘
                          │
                          ▼
                   Short-lived credentials
                   returned to the pod
```

The chain: a Kubernetes ServiceAccount is annotated with an IAM role ARN. Pods that use the ServiceAccount have a projected token volume mount with a JWT signed by the EKS cluster's OIDC provider. The AWS SDK, when running in the pod, detects the projected token and calls `sts:AssumeRoleWithWebIdentity` with the token. STS validates the token against the cluster's OIDC provider, validates the IAM role's trust policy, and returns short-lived AWS credentials. The pod uses the credentials. When the credentials expire (default 1 hour), the SDK refreshes them automatically.

The pod never holds an access key. The pod's ServiceAccount JWT cannot be used outside the cluster (the OIDC provider validates the issuer, audience, and signing key). The pod's permissions are bounded by the IAM role's policy and trust policy.

### Setting up IRSA

1. **Associate the OIDC provider with IAM.** When the EKS cluster is created, the cluster has an OIDC issuer URL. Register that issuer as an IAM Identity Provider.

```bash
# Get the cluster's OIDC issuer.
OIDC_ISSUER=$(aws eks describe-cluster --name <cluster-name> \
  --query "cluster.identity.oidc.issuer" --output text)

# Create the IAM identity provider.
eksctl utils associate-iam-oidc-provider \
  --cluster <cluster-name> --approve
```

2. **Create the IAM role with a trust policy that references the OIDC provider.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:aud": "sts.amazonaws.com",
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:sub": "system:serviceaccount:meridian-app:patient-api"
        }
      }
    }
  ]
}
```

The `sub` claim is the critical condition: it binds the IAM role to the specific Kubernetes namespace and ServiceAccount (`system:serviceaccount:<namespace>:<serviceaccount>`). Without this condition, *any* ServiceAccount in the cluster could assume the role, which is a privilege-escalation pattern.

3. **Annotate the Kubernetes ServiceAccount.**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: patient-api
  namespace: meridian-app
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/PatientApiRole"
```

4. **The pod uses the ServiceAccount.**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: patient-api
  namespace: meridian-app
spec:
  template:
    spec:
      serviceAccountName: patient-api
      containers:
        - name: patient-api
          image: meridian-ecr.dkr.ecr.us-east-1.amazonaws.com/patient-api:1.2.3
          # No AWS credentials in env vars. The SDK picks up the projected token.
```

5. **Verify.** Inside the pod, `aws sts get-caller-identity` should return the IAM role's ARN, not an IAM user.

### The IRSA trust-policy mistakes

The most-common IRSA misconfigurations all live in the trust policy:

**Missing the `sub` condition.** The trust policy allows any ServiceAccount in the cluster to assume the role. An attacker who compromises any pod in any namespace can assume the role. Fix: always include the `sub` condition with the exact namespace and ServiceAccount.

**Wildcard `sub` condition.** A trust policy that uses `StringLike` with `system:serviceaccount:meridian-app:*` allows any ServiceAccount in the `meridian-app` namespace to assume the role. This is sometimes intentional (a namespace-scoped role) but is usually a slip. Fix: use `StringEquals` with the exact ServiceAccount name unless the wildcard is deliberate.

**Missing the `aud` condition.** The `aud` (audience) claim must be `sts.amazonaws.com`. Without this condition, an OIDC token issued for a different audience (a different AWS service or a third-party service) could potentially be used to assume the role. Fix: always include the `aud` condition.

**Trust policy refers to a different cluster's OIDC provider.** Copy-paste errors when creating roles for multiple clusters. The role works in the source cluster but not the target. Fix: every cluster has its own OIDC provider; per-cluster trust policies are required.

### EKS Pod Identity (the simpler alternative)

EKS Pod Identity, released in late 2023, simplifies IRSA by removing the OIDC trust-policy complexity. The new pattern:

```bash
# Create the IAM role with a trust policy for the EKS Pod Identity service.
# Trust policy is much simpler:
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "pods.eks.amazonaws.com"},
      "Action": ["sts:AssumeRole", "sts:TagSession"]
    }
  ]
}
```

```bash
# Associate the role with the cluster's ServiceAccount via the Pod Identity API.
aws eks create-pod-identity-association \
  --cluster-name <cluster-name> \
  --namespace meridian-app \
  --service-account patient-api \
  --role-arn arn:aws:iam::123456789012:role/PatientApiRole
```

**Trade-offs:** EKS Pod Identity has a simpler trust policy and a faster credential-issuance path. It is the right choice for new EKS clusters in 2026. IRSA still works for clusters where it was already adopted; there is no urgent reason to migrate existing IRSA workloads to Pod Identity, but new workloads should use Pod Identity.

The IRSA trust-policy complexity matters when the cluster's OIDC provider must be referenced by external systems (e.g., a Vault Kubernetes auth method); IRSA is the better choice when external integrations need the OIDC provider's existence.

References:
- [IAM roles for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)

---

## GitHub Actions OIDC federation

GitHub Actions OIDC federation to AWS is the highest-leverage single migration for most engineering organizations. It eliminates the long-lived access keys that live in `secrets.AWS_ACCESS_KEY_ID` / `secrets.AWS_SECRET_ACCESS_KEY` across hundreds of GitHub repositories.

### The mental model

GitHub Actions, on every workflow run, can request an OIDC token from GitHub's OIDC provider. The token contains claims that identify the repository, the branch / tag, the workflow, and the environment. AWS IAM can be configured to trust GitHub's OIDC provider and accept its tokens for `sts:AssumeRoleWithWebIdentity`. The result: the workflow gets short-lived AWS credentials at runtime, scoped to a specific IAM role, with no long-lived secrets stored anywhere.

```
   GitHub Actions Workflow             AWS Account
   ┌─────────────────────────┐        ┌──────────────────────────┐
   │                         │        │                          │
   │  1. Request OIDC token  │        │  IAM Identity Provider:  │
   │     from GitHub         │        │  token.actions.gh.com    │
   │                         │        │                          │
   │  2. Token contains:     │        │  IAM Role:               │
   │     - iss: github.com   │        │   - Trust policy refers  │
   │     - aud: sts.aws.com  │ ─────→ │     to GitHub OIDC IdP   │
   │     - sub: repo:org/    │        │   - Condition on sub:    │
   │       repo:ref:branch   │        │     repo, ref, env       │
   │                         │        │                          │
   │  3. Call AssumeRoleWith │        │  4. STS validates:       │
   │     WebIdentity         │        │     - issuer, signature  │
   │                         │        │     - audience           │
   │                         │        │     - sub vs trust pol.  │
   │  5. Get short-lived     │ ←───── │  Returns short-lived     │
   │     AWS credentials     │        │  credentials (1 hour     │
   │                         │        │  default)                │
   │                         │        │                          │
   │  6. Use credentials in  │        │                          │
   │     subsequent steps    │        │                          │
   └─────────────────────────┘        └──────────────────────────┘
```

### Setting up GitHub OIDC

1. **Create the IAM Identity Provider for GitHub.**

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

The thumbprint is the SHA-1 of the OIDC provider's root certificate. AWS validates that the thumbprint matches the certificate chain. The thumbprint can change when GitHub rotates certificates; the current value is well-documented and stable.

(In 2024, AWS started supporting thumbprint-less OIDC providers for known IdPs including GitHub, so the thumbprint may become optional in newer deployments. Include it for compatibility.)

2. **Create the IAM role with a precise trust policy.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:meridian-health/patient-api:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

The `sub` claim binds the role to a specific repository, branch, or environment. The pattern `repo:<org>/<repo>:ref:refs/heads/<branch>` binds to a branch; the pattern `repo:<org>/<repo>:environment:<env-name>` binds to a GitHub environment (a more rigorous boundary, see below). The pattern `repo:<org>/<repo>:pull_request` binds to pull request workflows.

3. **The workflow.**

```yaml
name: Deploy patient-api
on:
  push:
    branches: [main]

permissions:
  id-token: write  # Required to request the OIDC token.
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsPatientApiDeployRole
          aws-region: us-east-1
      - run: aws sts get-caller-identity  # Should return the role's ARN.
      - run: ./deploy.sh
```

The `permissions: id-token: write` is required for the workflow to request the OIDC token. The `aws-actions/configure-aws-credentials` action calls `sts:AssumeRoleWithWebIdentity` and exports the credentials as environment variables for subsequent steps.

### Trust-policy scoping for GitHub OIDC

The `sub` claim is where most of the security work happens. Common patterns:

| Pattern | Matches | Use when |
| --- | --- | --- |
| `repo:<org>/<repo>:ref:refs/heads/main` | Workflows on the `main` branch | Production-deployment roles |
| `repo:<org>/<repo>:ref:refs/heads/*` | Workflows on any branch | Limited; usually too broad |
| `repo:<org>/<repo>:pull_request` | Workflows on pull requests | Limited-permission test roles |
| `repo:<org>/<repo>:environment:prod` | Workflows targeting the `prod` GitHub environment | Strongest production binding |
| `repo:<org>/*:ref:refs/heads/main` | Workflows on `main` in any repo in the org | Org-wide deploy roles |
| `repo:*/*:ref:refs/heads/main` | Any repo in any org | Almost certainly wrong |

The `environment` binding is the strongest because GitHub environments support manual approval gates, required reviewers, and deployment-protection rules. A role bound to `environment:prod` can only be assumed when the workflow targets a workflow step within the `prod` environment, which carries the approval-gate enforcement.

**The wildcard repo trap.** A trust policy with `repo:meridian-health/*` allows *any* repo in the `meridian-health` org to assume the role. If the org has 200 repos, 199 of them can assume a role that maybe one needs. The leak vector: an attacker who can land a workflow in any repo (e.g., a malicious dependency that triggers a workflow on a pull request) can assume the role. Fix: scope to the specific repo, or use the `environment` binding.

**The pull-request trap.** A trust policy that allows `pull_request` events to assume a deployment role is the same vector: an attacker opens a pull request that runs the deployment workflow. The pull-request workflow runs *the attacker's code* with the role's permissions. Fix: do not bind deployment roles to pull-request events; bind them to push events on protected branches or to the `environment` form.

### What permissions to grant the role

The role's IAM policy (separate from the trust policy) defines what the workflow can do once it has assumed the role. Common patterns:

- **A read-only role for pull-request CI.** Reads from S3 for cached artifacts, reads ECR for base image inspection, can call `aws sts get-caller-identity` for diagnostic purposes. No write permissions anywhere.
- **A deployment role for the `main` branch.** Writes to a specific ECR repository, deploys to a specific EKS cluster (via the cluster's update-kubeconfig + kubectl), writes to specific S3 paths for assets. Scoped tightly to the application's resources.
- **A Terraform-apply role.** Reads from the state-file S3 bucket, writes to the state-file S3 bucket, reads from the state-lock DynamoDB table, writes to the state-lock DynamoDB table. The application-resource permissions are separate (and broader) — Terraform applies need wide IAM. The Terraform-apply role is usually the broadest workload role in the system; protect it with the strongest trust policy (specific repo + `environment:prod` + required reviewers).

References:
- [Configuring OpenID Connect in Amazon Web Services](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials)
- [GitHub OIDC token claims](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)

---

## Other CI providers

The pattern generalizes to every modern CI provider; the trust-policy conditions change.

### GitLab CI/CD

GitLab supports OIDC ID tokens since GitLab 15.7. The pattern:

```yaml
# .gitlab-ci.yml
deploy:
  id_tokens:
    AWS_TOKEN:
      aud: https://gitlab.com
  script:
    - aws sts assume-role-with-web-identity \
        --role-arn arn:aws:iam::123456789012:role/GitLabDeployRole \
        --role-session-name gitlab-ci \
        --web-identity-token "$AWS_TOKEN" \
        --duration-seconds 3600
```

The IAM trust policy references the GitLab OIDC provider (`gitlab.com` for SaaS, the self-hosted URL otherwise) and conditions on `sub` for the project and ref.

### CircleCI

CircleCI supports OIDC tokens via the `CIRCLE_OIDC_TOKEN` environment variable since 2022. The pattern is similar to GitLab; the trust policy references `oidc.circleci.com/org/<org-id>` and conditions on the project.

### Bitbucket Pipelines

Bitbucket supports OIDC since 2022. The trust policy references `api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc`. The `sub` claim identifies the repository and branch.

### Jenkins

Jenkins does not have first-party OIDC support; the `aws-jenkins-oidc` plugin provides it. Newer environments may prefer to migrate Jenkins workloads to GitHub Actions / GitLab CI for native OIDC rather than maintain a plugin.

The pattern across CI providers is identical: the CI provider issues an OIDC token at runtime, the AWS IAM trust policy validates the token's claims, STS returns short-lived credentials. Every CI provider that supports OIDC in 2026 supports this; there is no defensible reason to keep long-lived access keys in any modern CI system.

---

## Workload-side patterns (Lambda, ECS, EC2)

The workload-side patterns are mature and well-documented. The summary:

**Lambda execution roles.** Every Lambda function has an execution role; the role is the function's identity. The pod-equivalent IRSA pattern is built into the Lambda runtime. Best practices:
- One execution role per Lambda function. The "shared execution role across functions" pattern produces broader roles than necessary.
- Per-function role policies. Scope the role to the exact resources the function reads and writes.
- No environment variables for secrets. Use Secrets Manager or Parameter Store, accessed via the execution role's permissions.

**ECS task roles.** Every ECS task definition can reference a task role. The task role is the identity used by code running inside the container. Best practices:
- One task role per task definition. The "shared task role across services" pattern is the same anti-pattern as Lambda.
- Separate execution role from task role. The execution role pulls the image from ECR and writes logs to CloudWatch; the task role is what the application code uses. Conflating them produces unnecessary breadth.

**EC2 instance profiles.** Every EC2 instance can be launched with an instance profile that exposes an IAM role. The application running on the instance picks up the role via IMDSv2 (the metadata service). Best practices:
- IMDSv2 required (see [baseline-guardrails.md](../landing-zones/baseline-guardrails.md) Guardrail 4.2). IMDSv1 is vulnerable to SSRF; IMDSv2 is not.
- Per-Auto-Scaling-Group instance profiles. One ASG, one instance profile. Cross-ASG sharing produces broader profiles than necessary.

References:
- [Lambda execution role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)
- [ECS task role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
- [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)

---

## The migration playbook

The migration from "access keys everywhere" to "no static secrets for compute" is a multi-month project for most organizations. The playbook:

### Phase 1: Discovery (week 1-2)

Inventory every long-lived AWS credential in the environment. Sources:

```bash
# IAM users with access keys.
aws iam list-users --output json | jq -r '.Users[] | .UserName' | \
  while read user; do
    aws iam list-access-keys --user-name "$user" --output json | \
      jq -r --arg user "$user" '.AccessKeyMetadata[] | "\($user) \(.AccessKeyId) \(.Status) \(.CreateDate)"'
  done
```

Then, for each access key, identify the consumer. The IAM Access Analyzer's last-accessed data (`aws iam get-access-key-last-used`) reveals which services and regions the key has called. The IP-source of recent CloudTrail events for the key reveals where the key is being used.

For CI pipelines, the inventory is repository-by-repository. Search every GitHub Actions workflow for `AWS_ACCESS_KEY_ID` references; search every GitLab repository for similar; search every Jenkins configuration. Build a per-repository / per-pipeline list of the AWS credentials in use.

For workloads, the inventory is service-by-service. EKS deployments that mount AWS credentials as secrets. ECS task definitions with credentials in environment variables. EC2 user-data scripts that pull credentials from S3. Lambda functions with `AWS_ACCESS_KEY_ID` in their environment variables.

The discovery output is a spreadsheet: every credential, its owner, its current consumer, and its target federation pattern.

### Phase 2: New work uses federation (week 3 onward)

A policy decision: from week 3 onward, no new IAM user with access keys is created. New CI pipelines use OIDC. New EKS workloads use IRSA / Pod Identity. New ECS tasks use task roles. New EC2 instances use instance profiles. The IAM-user-deny SCP (see [baseline-guardrails.md](../landing-zones/baseline-guardrails.md) Guardrail 4.1) enforces the policy by construction in OUs where it is applied.

This stops the bleeding. The existing access keys are not yet migrated, but the pool is no longer growing.

### Phase 3: Per-pattern migration (months 1-6)

Migrate the existing access keys in priority order:

1. **GitHub Actions OIDC** (highest leverage, lowest effort). Most CI pipelines can be migrated with a single workflow edit and a one-time IAM role creation. The migration is fast and the leverage from killing the access keys is the highest in the environment.
2. **IRSA / EKS Pod Identity** for production EKS workloads. The migration requires application-side cooperation (the deployment must use the annotated ServiceAccount) but no code changes.
3. **Lambda execution roles** for any Lambda functions still using IAM-user keys. The migration removes the environment variables; the application's AWS SDK calls pick up the execution role automatically.
4. **ECS task roles** for any ECS tasks using IAM-user keys. Same as Lambda; the migration removes the environment variables.
5. **EC2 instance profiles** for any EC2 instances using IAM-user keys. The migration requires re-launching the instances (instance profile cannot be added post-launch without a stop-start cycle, although in 2024 AWS added an Associate-IamInstanceProfile-Without-Reboot path).
6. **Cross-account access keys** for any IAM users used to cross-account-access. The migration replaces the user with a cross-account role and `sts:AssumeRole` calls.
7. **Third-party SaaS access keys** for the few vendors that still require them. The migration depends on the vendor's federation support; in 2026, most major vendors support cross-account roles.

Each migration is a small project. The total cost of the program varies by environment; a 100-engineer organization with moderate cloud sprawl typically completes the migration in 3-6 months.

### Phase 4: Removal (after each migration)

For every migration, the final step is deleting the IAM user (or the access keys, if the user has another legitimate purpose). Set a strict cut-over date: 30 days after the federation pattern is verified working, the access key is deactivated; another 30 days later, the IAM user is deleted.

Keep CloudTrail events for the deactivated keys for at least 90 days to catch any forgotten consumer that fails when the key disappears. After 90 days of zero usage, the key (and probably the user) can be safely removed.

### Phase 5: Enforcement (ongoing)

Apply the deny-IAM-user-creation SCP across the Organization. Configure detection rules that page when a new IAM user is created (which should now be only the break-glass rotation user). Monitor the IAM Access Analyzer's findings for any new IAM user access keys; investigate every such finding.

The endgame: an environment where the only IAM users are the break-glass users in each account, where every CI pipeline and every workload uses federation, and where the access-key inventory is zero.

---

## Worked example: Meridian Health's federation migration

Meridian Health (the fictional 350-engineer regulated SaaS from [aws-organizations-design.md](../landing-zones/aws-organizations-design.md)) ran the migration in six months. The starting state:

- 47 IAM users with access keys.
- 12 GitHub Actions workflows using `AWS_ACCESS_KEY_ID` from `secrets`.
- 6 GitLab CI pipelines (legacy) using long-lived keys.
- 28 EKS deployments mounting credentials via Kubernetes Secrets.
- 3 Lambda functions with credentials in environment variables (legacy from an acquisition).
- 8 EC2 instances using IAM users (legacy, scheduled for retirement).
- 4 third-party SaaS integrations (Datadog, PagerDuty, Wiz, a custom backup vendor) using IAM user keys.

The migration sequence:

**Month 1.** Discovery completed. Spreadsheet built. The IAM-user-deny SCP applied to the Sandbox OU first (to verify it does not break the sandbox auto-nuke), then to Dev, then announced as the target state for Prod.

**Month 2.** GitHub Actions OIDC adoption. Eleven of the twelve workflows migrated; one workflow on a deprecated repository was retired instead. The 11 IAM users associated with the workflows had their access keys deactivated.

**Month 3.** GitLab CI migration (lower priority, only 6 pipelines, but the legacy code paths needed verification). All six migrated to GitLab OIDC ID tokens. The IAM users deleted.

**Month 4.** IRSA / Pod Identity rollout in EKS. All 28 deployments migrated; the platform team standardized on EKS Pod Identity for the new cluster and kept IRSA for the older cluster. The Kubernetes Secrets containing AWS keys were deleted.

**Month 5.** Lambda and EC2 migration. The 3 Lambda functions had their environment-variable credentials removed and their execution roles tightened. The 8 EC2 instances were re-launched with instance profiles.

**Month 6.** Third-party SaaS migration. Datadog, PagerDuty, and Wiz were migrated to cross-account roles (all three support it). The custom backup vendor refused to support cross-account roles; Meridian replaced the vendor with one that did, on the grounds that vendor support for federation is a 2026 security requirement.

**End state.** Zero IAM users with access keys (except 6 break-glass users, one per regulated account). The IAM-user-deny SCP applied at the Organization root. Every CI pipeline uses OIDC. Every workload uses workload identity. The annual rotation overhead (previously: 47 keys rotated annually, ~5 engineer-days) dropped to zero.

The migration's total engineering cost was approximately 30 engineer-days spread across the platform and security teams. The recurring annual cost (key rotation, credential incident response, compliance evidence collection) dropped by approximately 15 engineer-days per year. The break-even on the engineering investment was 18 months — but the actual return was on incident risk, which is hard to quantify but felt to the team as "the most-common cloud incident class no longer exists in our environment."

---

## Findings checklist

Findings IDs use the `WID-` prefix (workload identity).

| ID | Finding | Severity | Remediation |
| --- | --- | --- | --- |
| WID-001 | IAM user with access keys exists for human access | Critical | Migrate to IAM Identity Center; delete the user. |
| WID-002 | IAM user with access keys for CI pipeline | Critical | Migrate to OIDC federation; delete the user. |
| WID-003 | IAM user with access keys for EKS workload | Critical | Migrate to IRSA or EKS Pod Identity. |
| WID-004 | IAM user with access keys for Lambda function | Critical | Move to execution role; remove env vars. |
| WID-005 | IAM user with access keys for ECS task | Critical | Move to task role; remove env vars. |
| WID-006 | IAM user with access keys for EC2 instance | High | Move to instance profile. |
| WID-007 | IAM user with access keys for cross-account access | High | Move to cross-account role; delete the user. |
| WID-008 | Access keys not rotated in > 90 days | Medium | Investigate consumer; migrate to federation; delete. |
| WID-009 | IRSA trust policy missing `sub` condition | High | Add `StringEquals` on `sub` with exact namespace and ServiceAccount. |
| WID-010 | IRSA trust policy missing `aud` condition | Medium | Add `StringEquals` on `aud` with `sts.amazonaws.com`. |
| WID-011 | GitHub OIDC trust policy uses `repo:org/*` wildcard | High | Scope `sub` to specific repo, or use `environment:` binding. |
| WID-012 | GitHub OIDC trust policy allows `pull_request` for deployment role | Critical | Scope to push events on protected branches or `environment:` only. |
| WID-013 | Lambda function has env-var AWS credentials | Critical | Remove env vars; rely on execution role. |
| WID-014 | EC2 instance using IMDSv1 (not IMDSv2-required) | High | Modify instance metadata options to require IMDSv2. |
| WID-015 | No deny-IAM-user-creation SCP applied | High | Apply the SCP at the Organization or OU level. |
| WID-016 | Third-party SaaS integration uses IAM-user keys despite cross-account-role support | Medium | Migrate to cross-account role per the vendor's documentation. |
| WID-017 | Lambda execution role is shared across functions | Medium | Per-function execution roles. |
| WID-018 | Trust policy validation skipped (Access Analyzer findings ignored) | High | Tighten trust policies per Access Analyzer's recommendations. |

---

## Anti-patterns

**Anti-pattern 1: The "we federate sometimes" partial migration.** Some workflows use OIDC; some still use access keys. The IAM-user-deny SCP is not applied because "we are still migrating." Failure mode: the migration drags on indefinitely; new workflows use access keys "because it's faster than setting up OIDC the first time"; the credential inventory grows again. Corrective: set a hard cut-over date; apply the SCP after the date.

**Anti-pattern 2: The over-broad trust policy.** IRSA trust policies that match any ServiceAccount in the cluster; GitHub OIDC trust policies that match any repo in the org. Failure mode: privilege escalation from any compromised pod or any compromised repo. Corrective: tight trust policies; the IAM Access Analyzer's external-access findings surface the over-broad cases.

**Anti-pattern 3: The forgotten old key.** A federation migration completes; the federation pattern works; the team moves on. The old IAM user with the old access key is forgotten. Failure mode: the credential lives in someone's `.env` file or someone's `.bashrc` for years, until it leaks. Corrective: every migration's final step is the deletion of the old credential.

**Anti-pattern 4: The "secrets manager as credential cache."** Engineers move their long-lived access keys from `.env` files into Secrets Manager and consider the problem solved. Failure mode: the credentials are still long-lived; they still leak when Secrets Manager is misconfigured; the rotation problem still exists. Corrective: Secrets Manager is for application-layer secrets (database passwords, third-party API keys); it is not for AWS credentials. AWS credentials should be federated, not stored.

**Anti-pattern 5: The execution-role-as-CI-role conflation.** A Lambda function's execution role is also used by the team's CI pipeline to update the Lambda. Failure mode: the role's permissions include both runtime permissions (read from DynamoDB) and deployment permissions (update Lambda code, modify Lambda configuration), so a runtime compromise can deploy malicious code. Corrective: separate roles for separate purposes; the CI deployment role is distinct from the function's execution role.

**Anti-pattern 6: The IRSA-and-IAM-user hybrid.** An EKS pod uses IRSA for some AWS calls and still has an IAM-user access key in a Kubernetes Secret for others, because the IRSA migration is partial. Failure mode: the leakable credential negates the benefit of IRSA. Corrective: complete the migration; no pod should hold credentials.

**Anti-pattern 7: The pull-request-deployment trap.** A GitHub Actions workflow runs deployment steps on pull-request events with a deployment role assumed via OIDC. Failure mode: an attacker opens a pull request with a malicious workflow change; the malicious workflow runs with the deployment role's permissions. Corrective: bind deployment roles to push-on-protected-branch events or to environment-protected workflows; pull-request workflows should have read-only roles only.

---

## Azure Managed Identities equivalent

For Azure environments, the equivalent of IRSA / OIDC federation is **Managed Identity** and **Workload Identity Federation**:

| AWS pattern | Azure equivalent |
| --- | --- |
| IAM role | Managed Identity (system-assigned or user-assigned) |
| IRSA | Azure Workload Identity in AKS |
| GitHub Actions OIDC | Azure Workload Identity Federation for GitHub Actions |
| Lambda execution role | Function App Managed Identity |
| EC2 instance profile | VM Managed Identity |

Workload Identity Federation in Azure is conceptually identical to AWS OIDC federation; the trust policy is on the Managed Identity rather than on an IAM role. The full Azure treatment lives in the eventual `azure-management-groups.md`.

---

## GCP Workload Identity Federation equivalent

For GCP environments, **Workload Identity Federation** is the OIDC federation pattern. **Workload Identity** (different name, related concept) is the GKE pattern:

| AWS pattern | GCP equivalent |
| --- | --- |
| IAM role | Service Account |
| IRSA | GKE Workload Identity |
| GitHub Actions OIDC | Workload Identity Federation for GitHub Actions |
| Lambda execution role | Cloud Function Service Account |
| EC2 instance profile | Compute Engine Service Account |

GCP Workload Identity Federation is more mature than AWS's in some dimensions (it has been the default GCP pattern since 2020 and the documentation is the most complete). The pattern is structurally identical to AWS.

---

## Further reading

- [IAM roles for service accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)
- [GitHub Actions OIDC with AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials)
- [GitLab CI OIDC with AWS](https://docs.gitlab.com/ee/ci/cloud_services/aws/)
- [CircleCI OIDC with AWS](https://circleci.com/docs/openid-connect-tokens/)
- [Bitbucket OIDC with AWS](https://support.atlassian.com/bitbucket-cloud/docs/deploy-on-aws-using-bitbucket-pipelines-openid-connect/)
- This repo:
  - [least-privilege-workflow.md](./least-privilege-workflow.md) — the IAM Access Analyzer workflow that complements this document's role-creation patterns.
  - [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) — Guardrails 4.1 (deny IAM user creation) and 4.2 (require IMDSv2) that this document references.
  - [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md) — companion document that covers the broader static-secret reduction including application-layer secrets.
