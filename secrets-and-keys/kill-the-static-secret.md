# Kill the Static Secret

A practitioner's reference for the static-secret reduction playbook in cloud environments — replace CI access keys with OIDC federation, replace service-account JSON files with workload identity, replace database passwords with IAM database authentication, replace cross-account access keys with role assumption. With before/after patterns for Terraform, GitHub Actions, Kubernetes, and the cloud SDKs.

This is the opening document of the secrets-and-keys folder, and it is intentionally the first one. The single highest-leverage move in secrets engineering is removing as many static secrets as possible from the architecture before designing the protection patterns for the ones that remain. A team that has eliminated 70% of its static secrets is operating at a fundamentally lower risk than a team that has the same secrets but stored them in Vault.

This document is the playbook for the elimination. Subsequent documents in this folder cover what to do with the secrets that remain ([secrets-manager-patterns.md](./), [vault-patterns.md](./), [rotation-patterns.md](./)) and the cryptographic primitives that the elimination enables ([envelope-encryption.md](./), [secret-detection.md](./)).

---

## When to read this document

**If your engineers have AWS access keys in their `.aws/credentials` files** — read top to bottom. The IAM Identity Center + AWS SSO pattern is the workforce-side replacement; the federation patterns below are the workload-side replacements.

**If your CI pipelines use long-lived cloud credentials** — start with [The OIDC-federation CI pattern](#the-oidc-federation-ci-pattern). This is the single biggest static-secret reduction available in 2026; most teams discover that 60–80% of their stored secrets are CI credentials that don't need to exist.

**If your Kubernetes workloads mount service-account JSON files** — start with [Workload identity for Kubernetes](#workload-identity-for-kubernetes). The pattern eliminates the file entirely; pods authenticate via the cluster's identity-projection.

**If your databases have passwords in connection strings** — start with [IAM database authentication](#iam-database-authentication). Where supported, the password disappears.

---

## The static-secret reduction premise

A static secret is a long-lived credential stored somewhere: an AWS access key in a `.env` file, a Google service account JSON file mounted into a container, a database password in a CI variable, a personal access token in source control.

Every static secret is a leak risk. The leak vectors are well-cataloged:

- Engineers commit secrets to repos.
- CI logs capture secrets in tracebacks.
- Container images bake secrets at build time.
- Backups of `.env` files leak.
- Engineers share credentials in Slack to debug.
- Compromised laptops yield credentials.
- Compromised CI yields the secret store.

Every static-secret-leak incident traces to one of these. The protection patterns (Vault, Secrets Manager, encryption, scanning) reduce the leak rate; they don't eliminate it.

The structural fix is to **not have the secret in the first place**. Cloud-native federation patterns make this possible for a large fraction of historical static-secret use cases:

- **CI to cloud:** OIDC federation. CI workflow exchanges a short-lived OIDC token for short-lived cloud credentials. No long-lived secret.
- **Workload to cloud:** workload identity. The cloud SDK authenticates via the workload's environment (IRSA, Workload Identity, Managed Identity) — no credentials in the workload.
- **Workload to database:** IAM database authentication. Database trusts the cloud IAM identity; no password.
- **Cross-account access:** role assumption with conditions. The originating account's role assumes the destination role; no cross-account static credentials.

This document is each pattern in turn, with before/after examples.

---

## The OIDC-federation CI pattern

The single highest-leverage pattern. Most teams' largest static-secret pool is CI credentials.

### The pattern

OIDC federation lets the CI provider (GitHub Actions, GitLab CI, CircleCI, Buildkite, others) generate a signed token attesting to the workflow's identity. The cloud provider validates the token against the CI provider's OIDC discovery document and issues short-lived cloud credentials in exchange.

The cloud-side configuration:

- **AWS:** an OIDC identity provider for the CI provider; an IAM role with a trust policy accepting OIDC tokens with specific claims; the role grants the permissions the CI workflow needs.
- **Azure:** federated credential on an Entra ID app or managed identity; specific issuer + subject claims.
- **GCP:** Workload Identity Federation pool; provider with attribute conditions; impersonation-target service account.

The CI-side configuration:

- The workflow runs a setup action that requests the OIDC token from the CI provider.
- The action calls AWS STS / Azure AD / GCP STS to exchange the OIDC token for cloud credentials.
- Subsequent steps use the credentials (which last 1 hour by default).

### Before: GitHub Actions with stored AWS access key

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure AWS credentials
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: aws sts get-caller-identity
      - run: ./deploy.sh
```

The secrets `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are long-lived. Compromise of the GitHub Actions environment, compromise of the repo's secrets, or any logging leak exposes them.

### After: GitHub Actions with OIDC federation

```yaml
# .github/workflows/deploy.yml
permissions:
  id-token: write   # required for OIDC token request
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::ACCOUNT:role/github-actions-deploy
          aws-region: us-east-1
      - run: aws sts get-caller-identity
      - run: ./deploy.sh
```

No `AWS_ACCESS_KEY_ID` anywhere. The action requests an OIDC token from GitHub, exchanges it for AWS credentials via STS, configures the AWS CLI / SDK for subsequent steps. The credentials last 1 hour and are scoped to the role's permissions.

### AWS IAM role trust policy

The IAM role `github-actions-deploy` has a trust policy like:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:meridian-health/care-coordinator:ref:refs/heads/main"
      }
    }
  }]
}
```

The `sub` condition is critical: it scopes the role to a specific repo, specific branch, specific environment. A workflow from a different repo cannot assume this role. A workflow from a feature branch cannot assume the production-deploy role.

The condition tightening is the security control. Without it, any workflow from any repo in the organization could assume the role.

### Azure federated credential

For Azure:

```bash
az ad app federated-credential create \
  --id <app-id> \
  --parameters '{
    "name": "github-actions-meridian-care-coordinator-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:meridian-health/care-coordinator:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

The workflow uses `azure/login@v2` with `federated-token: true`; the Azure SDK exchanges the OIDC token for an Azure AD access token.

### GCP Workload Identity Federation

For GCP, slightly more complex setup:

- Create a Workload Identity Pool.
- Create a provider in the pool for GitHub Actions OIDC.
- Configure attribute mapping (`google.subject = assertion.sub`).
- Grant the WIP principal the right to impersonate a target service account.
- Workflow uses `google-github-actions/auth@v2` with `workload_identity_provider` and `service_account` inputs.

### What to migrate

Inventory the CI provider's secrets:

- AWS access keys (the single biggest target).
- Azure service principal credentials.
- GCP service account JSON files.
- Cloud-provider credentials of any kind.

For each, identify the workflows using it and migrate them to OIDC federation. The remaining CI secrets (third-party API tokens, deployment-target credentials that aren't OIDC-capable) are the ones that need Secrets Manager protection.

### The scope-tightening discipline

Migrating to OIDC is necessary but not sufficient. The condition syntax allows scoping by:

- **Repository** (`repo:org/repo`).
- **Branch** (`ref:refs/heads/main`).
- **Environment** (`environment:production`).
- **Pull request vs push** (`event_name:pull_request`).

The discipline: production-deploy roles are scoped to the protected branch + production environment + push events. Feature-branch workflows assume different (less-privileged) roles. Pull requests from forks assume even more restricted roles (or are blocked entirely).

References:
- [GitHub Actions OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [AWS configure-aws-credentials action](https://github.com/aws-actions/configure-aws-credentials)
- [Azure federated credentials](https://learn.microsoft.com/en-us/azure/active-directory/workload-identities/workload-identity-federation)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)

---

## Workload identity for Kubernetes

The Kubernetes-specific federation pattern.

### The pattern

Each Kubernetes service account is associated with a cloud-IAM identity. Pods that mount the service account assume the cloud-IAM identity at runtime via the cloud SDK; no credentials are stored anywhere.

- **AWS:** IAM Roles for Service Accounts (IRSA) — the EKS cluster has an OIDC provider; pods get a projected service-account token; the AWS SDK exchanges it for IAM credentials.
- **Azure:** Azure AD Workload Identity — similar mechanism, with AKS as the OIDC provider and Entra ID as the IAM target.
- **GCP:** Workload Identity — GKE's pattern. Service accounts in the cluster are mapped to GCP IAM service accounts.

### Before: service-account JSON file mounted into the pod

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: meridian/care-coordinator:1.4.2
    volumeMounts:
    - name: gcp-creds
      mountPath: /etc/secrets
  volumes:
  - name: gcp-creds
    secret:
      secretName: gcp-service-account-json
```

The Kubernetes secret `gcp-service-account-json` contains the SA key file. Compromise of the cluster, of the namespace, or of the pod yields the credentials.

### After: Workload Identity

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: care-coordinator-sa
  annotations:
    iam.gke.io/gcp-service-account: care-coordinator@PROJECT.iam.gserviceaccount.com
---
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: care-coordinator-sa
  containers:
  - name: app
    image: meridian/care-coordinator:1.4.2
```

No mounted secret. The pod uses Kubernetes-native authentication; the cloud SDK transparently exchanges the projected token for GCP credentials.

### The AWS IRSA equivalent

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: care-coordinator-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/care-coordinator-app-role
---
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: care-coordinator-sa
  containers:
  - name: app
    image: meridian/care-coordinator:1.4.2
```

The role's trust policy accepts the projected service-account token from the EKS cluster's OIDC provider.

### What to migrate

In a typical Kubernetes environment:

- Mounted service-account JSON files / IAM access keys.
- Image-baked credentials.
- Configuration files containing cloud credentials.

Each is replaceable with workload identity for the cluster-to-cloud authentication. The remaining secrets (third-party API credentials, application-internal secrets) belong in a secrets manager mounted via External Secrets Operator or CSI Secret Driver.

### The pod-level scope discipline

Workload identity lets you grant *per-pod* (via service account) IAM identities. The discipline: each pod has the narrowest IAM role it needs.

- The application pod has the application's IAM role.
- The init container for migrations has a separate, more privileged role (DDL access).
- The sidecar for monitoring has its own IAM role for the monitoring service.

The shared `default` service account with a broad role is an anti-pattern. Each pod has its own service account.

References:
- [AWS EKS IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [Azure AKS Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
- [GCP GKE Workload Identity](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)

---

## IAM database authentication

The database-specific elimination pattern.

### Before: password in Secrets Manager

```python
import boto3
import psycopg2

def get_db_connection():
    sm = boto3.client('secretsmanager')
    secret = sm.get_secret_value(SecretId='prod/db/password')
    password = json.loads(secret['SecretString'])['password']
    return psycopg2.connect(
        host='db.example.com',
        user='app_user',
        password=password,
        sslmode='verify-full',
    )
```

There's a password. It's in Secrets Manager (better than `.env`), but it exists. Rotation is a chore; the application's Secrets Manager IAM grant is broad.

### After: IAM database authentication (PostgreSQL on RDS)

```python
import boto3
import psycopg2

def get_db_connection():
    rds = boto3.client('rds')
    token = rds.generate_db_auth_token(
        DBHostname='db.example.com',
        Port=5432,
        DBUsername='app_user',
        Region='us-east-1',
    )
    return psycopg2.connect(
        host='db.example.com',
        user='app_user',
        password=token,
        sslmode='verify-full',
    )
```

No password. The token is generated fresh each call (15-minute lifetime); it's a signature derived from the application's IAM credentials. The database is configured to accept IAM-authenticated connections.

### The IAM grant

The application's IAM role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "rds-db:connect",
    "Resource": "arn:aws:rds-db:us-east-1:ACCOUNT:dbuser:DB_RESOURCE_ID/app_user"
  }]
}
```

No `secretsmanager:GetSecretValue`. No password to rotate. No password to leak.

### What to migrate

Inventory database connection strings:

- Application connection pools.
- Migration scripts.
- ETL pipelines.
- Reporting tools.

Each is a candidate for IAM auth. The ones that can't migrate (legacy database engines, third-party tools without IAM support) are the candidates for the Secrets Manager broker pattern (per [database-security.md](../data-security/database-security.md)).

### The Azure AD authentication equivalent

For Azure SQL:

```python
from azure.identity import DefaultAzureCredential
import pyodbc

credential = DefaultAzureCredential()
token = credential.get_token('https://database.windows.net/.default')
conn = pyodbc.connect(
    f'DRIVER={{ODBC Driver 18 for SQL Server}};'
    f'SERVER=server.database.windows.net;DATABASE=mydb;Encrypt=yes',
    attrs_before={1256: token.token.encode('utf-16-le')}  # SQL_COPT_SS_ACCESS_TOKEN
)
```

The same pattern with Azure AD as the IAM substrate.

### The Cloud SQL IAM equivalent

For Cloud SQL with the Cloud SQL Auth Proxy:

```bash
./cloud_sql_proxy -instances=PROJECT:REGION:INSTANCE=tcp:5432 -enable_iam_login
```

```python
import psycopg2
import google.auth
credentials, _ = google.auth.default()
conn = psycopg2.connect(
    host='127.0.0.1',  # proxy
    user='care-coordinator@PROJECT.iam.gserviceaccount.com',
    password=credentials.token,
)
```

---

## Cross-account access via role assumption

The pattern: workload in account A needs to call a service in account B. Without it: a long-lived IAM user in account B with access keys in account A.

### Before: cross-account IAM user

```python
import boto3
client_b = boto3.client('s3',
    aws_access_key_id='AKIA...',
    aws_secret_access_key='...',
    region_name='us-east-1',
)
```

The credentials are long-lived. They're stored somewhere (probably Secrets Manager); they're rotated rarely; compromise is high-impact.

### After: cross-account role assumption

```python
import boto3

sts = boto3.client('sts')
response = sts.assume_role(
    RoleArn='arn:aws:iam::ACCOUNT-B:role/cross-account-s3-reader',
    RoleSessionName='care-coordinator-app',
    ExternalId='meridian-care-coordinator',
)
creds = response['Credentials']
client_b = boto3.client('s3',
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['SessionToken'],
    region_name='us-east-1',
)
```

The IAM role in account B has a trust policy accepting account A's principals:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT-A:role/care-coordinator-app-role"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"sts:ExternalId": "meridian-care-coordinator"},
      "Bool": {"aws:MultiFactorAuthPresent": "true"}
    }
  }]
}
```

The credentials are temporary (1 hour default). The `ExternalId` provides defense against confused-deputy attacks.

### What to migrate

Inventory cross-account credentials:

- IAM users created for cross-account access.
- Access keys stored in account A for use in account B.
- Service-account keys for cross-project access (GCP).
- Service principal credentials for cross-tenant access (Azure).

Each is replaceable with role assumption / cross-tenant federation. The pattern eliminates the static credential.

---

## Putting it together: the elimination playbook

The structured rollout of static-secret elimination.

### Phase 1: inventory (1–2 weeks)

- **Source-control scan** for stored credentials (per [../data-security/secret-and-pii-detection.md](../data-security/secret-and-pii-detection.md)).
- **CI provider audit** for stored secrets — list every secret in GitHub Actions / GitLab CI / CircleCI / Buildkite.
- **Cloud IAM user inventory** — every IAM user has credentials somewhere; identify the consumer.
- **Kubernetes secret inventory** — `kubectl get secrets -A`; identify which are cloud credentials.

### Phase 2: prioritize

- High-impact: CI credentials with broad cloud permissions (deploy roles, full-account admin).
- High-impact: long-lived database admin passwords.
- High-impact: cross-account credentials with broad permissions in the destination.
- Medium: workload credentials with scoped permissions.
- Lower: third-party API tokens (these often can't migrate; they stay in Secrets Manager).

### Phase 3: migrate (4–12 sprints)

Per credential, the pattern:

1. Set up the federation (OIDC provider, workload identity, IAM auth).
2. Test in non-production.
3. Migrate the consumer to the new auth pattern.
4. Verify operation.
5. Rotate the legacy credential to confirm nothing still uses it.
6. Delete the legacy credential.

The "rotate to confirm" step is critical. A legacy credential that's no longer in the code might still be in use by an obscure consumer (a forgotten cron job, a CI fork). Rotating breaks anything still depending on it; the breakage is the signal that the migration isn't complete.

### Phase 4: prevent regression

- **SCP / Org Policy** that prevents IAM user creation (for cross-account access patterns).
- **CI provider policy** that denies adding cloud-credential secrets (the credential's purpose can be served by federation).
- **Detection** for any new long-lived credentials being created.

### Phase 5: residual secrets management

Whatever remains (third-party API tokens, legacy database passwords that can't migrate) belongs in the secrets manager with the discipline from [secrets-manager-patterns.md](./), [rotation-patterns.md](./), and [secret-detection.md](./).

---

## Worked example: Meridian Health's secret-elimination story

Meridian's environment in early 2024 had ~250 stored cloud credentials across CI, Kubernetes secrets, and `.env` files. By mid-2026, ~40 remain.

### The starting inventory (Q1 2024)

- **GitHub Actions secrets:** 47 AWS access key pairs across workflow repos; 12 GCP service account JSON files; 8 Azure service principal credentials.
- **Kubernetes secrets:** 31 cloud-IAM secrets across EKS clusters (most were service-account JSONs or AWS keys for legacy cron jobs).
- **`.env` files in development environments:** ~80 across teams, most with cloud credentials for local development.
- **Cross-account IAM users:** 23 across the production accounts for service-to-service access.
- **Database passwords:** 18 in Secrets Manager, used by various workloads.

### The migration plan

Sprint 1–2: inventory + prioritization. Most-privileged credentials surfaced first.

Sprint 3–6: GitHub Actions OIDC federation across all workflows. The aws-actions/configure-aws-credentials migration was straightforward; the Azure and GCP migrations took more setup per workflow but followed.

Sprint 7–10: EKS clusters migrated to IRSA. Per-pod service accounts created; legacy AWS key secrets removed; ~25 Kubernetes secrets eliminated.

Sprint 11–14: cross-account IAM users replaced with role assumption. Trust policies designed per cross-account access pattern; ExternalIds added; IAM users deleted.

Sprint 15–18: IAM database authentication for PostgreSQL Aurora clusters; ~10 database passwords eliminated.

Sprint 19–20: SCP and policy enforcement to prevent regression. Workforce-side IAM users restricted to SSO-managed access.

### The remaining ~40 secrets (mid-2026)

- **Third-party API tokens** (Datadog API key, PagerDuty integration key, Slack webhook URLs, etc.) — ~25.
- **Legacy database passwords** for Microsoft SQL Server (no IAM auth support in the version Meridian runs) — 3.
- **Per-tenant API keys** for customers integrating Meridian's API (these are issued by Meridian, not consumed) — ~10, rotated quarterly.
- **One-off service-account keys for specific GCP integrations** that don't yet support Workload Identity — 2, planned for migration when the upstream service supports it.

The 40 remaining are managed via Secrets Manager / Vault with rotation, scanning, and audit. They are the irreducible static-secret core after federation; the protection patterns apply.

### The findings opened during the elimination

- **STATIC-001** (47 long-lived AWS access keys in GitHub Actions secrets). Closed by OIDC federation.
- **STATIC-002** (IAM users created for cross-account access without ExternalId; confused-deputy risk). Closed by ExternalId addition and (after migration) IAM user deletion.
- **STATIC-003** (Kubernetes secrets contained AWS keys for pods; per-pod IAM role available via IRSA). Closed by IRSA migration.
- **STATIC-004** (database passwords in Secrets Manager were rotated annually but the integration broke on rotation in two cases; rotation discipline was weak). Closed for the migratable databases by IAM auth; the rest got rotation-test discipline.
- **STATIC-005** (no SCP preventing creation of new long-lived IAM users). Closed by SCP at the workload OU.

---

## Anti-patterns

### 1. The "we'll add it to Secrets Manager and call it secure" deflection

The team responds to a credential-leak finding by moving the credential from `.env` to Secrets Manager. The credential still exists, still rotates rarely, and is still a leak risk via Secrets Manager access. The structural problem is unaddressed.

The fix: ask first if the credential needs to exist at all. Most CI credentials don't. Most cross-account credentials don't. Most Kubernetes-pod credentials don't.

### 2. The over-broad OIDC trust policy

The IAM role's trust policy accepts any OIDC token from `token.actions.githubusercontent.com` without `sub` condition. Any GitHub Actions workflow anywhere in any organization can assume the role.

The fix: `sub` condition scoping to specific repo + ref + environment. Tight conditions are the security control.

### 3. The "we'll federate later" delay

The team agrees federation is the right pattern but stays on long-lived credentials because the migration is "too much work right now." Six months pass; the migration hasn't started; a credential leaks.

The fix: federation is a sprint per pattern, not a quarter. Start with the highest-impact credentials; one workflow at a time.

### 4. The orphan credential

A credential was migrated. The legacy credential wasn't deleted. Someone added a new workflow using the legacy credential. The migration didn't prevent regression.

The fix: rotate-then-delete pattern. After migration, rotate the legacy credential to confirm no consumer remains; then delete it.

### 5. The federation-but-still-broad-permissions

The team migrates to OIDC; the new role has the same broad permissions the old user had. Federation made the credential ephemeral; permissions are still over-broad.

The fix: re-scope permissions at the migration. The new role should have only the permissions the specific workflow needs.

### 6. The mixed-workload Kubernetes service account

A pod uses the `default` service account in its namespace. Multiple pods share the SA; the SA has broad IAM access to cover all of them; per-pod least-privilege is lost.

The fix: per-pod service accounts. Each pod has its own SA with the narrowest IAM role.

### 7. The IAM-auth-not-tested rollout

The team migrates a database to IAM auth. The application change works in dev. Rotation behavior in production differs because the token-refresh logic wasn't tested under load; connections break under high concurrency.

The fix: test IAM auth under realistic load before production cutover. Token-refresh patterns matter.

### 8. The workforce-side static credential

The team did all the workload-side federation. Engineers still have `~/.aws/credentials` with long-lived access keys. The same leak vectors apply to engineer laptops.

The fix: workforce-side identity via AWS Identity Center (SSO), Azure SSO, GCP Identity. Engineers don't have long-lived cloud credentials; they have short-lived credentials via SSO + role assumption.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| KSS-001 | CI workflows use long-lived cloud access keys / service account JSON files | High | Migrate to OIDC federation; delete legacy credentials after rotation | DevOps + Security Eng |
| KSS-002 | OIDC trust policy lacks `sub` condition or other scoping | High | Add per-repo, per-ref, per-environment conditions | Security Eng |
| KSS-003 | Kubernetes workloads mount cloud-credential secrets | High | Migrate to IRSA / Workload Identity / Azure AD Workload Identity | Platform Eng + Workload Owner |
| KSS-004 | Databases use stored passwords where IAM auth is supported | Medium | Migrate to IAM database authentication; remove passwords | Workload Owner + DBA |
| KSS-005 | Cross-account access uses long-lived IAM users | High | Migrate to role assumption with ExternalId; delete IAM users | Security Eng + IAM Eng |
| KSS-006 | Engineers have long-lived `~/.aws/credentials` access keys | Medium | Migrate workforce to AWS Identity Center (SSO); same pattern for Azure / GCP | IAM Eng + IT |
| KSS-007 | Legacy credential not deleted after federation migration; orphan in use | Medium | Rotate-then-delete pattern; SCP prevents new IAM users | DevOps + Security Eng |
| KSS-008 | Per-pod service account discipline absent; shared default SA with broad permissions | Medium | Per-pod service accounts; per-pod IAM scoping | Platform Eng + Cluster Owner |
| KSS-009 | OIDC migration retained over-broad permissions from legacy credentials | Medium | Re-scope at migration; least-privilege per workflow | Security Eng + DevOps |
| KSS-010 | IAM database auth migration not load-tested; production rollout caused connection issues | Medium | Test under load before production cutover; document token-refresh patterns | Platform Eng + SRE |
| KSS-011 | No SCP preventing IAM user creation | Medium | Add SCP; document approved exceptions | IAM Eng + Security Eng |
| KSS-012 | Static secret count not tracked; no measurement of progress | Low | Quarterly secret-count metric; trend tracked in security dashboard | Security Eng |
| KSS-013 | Workload identity not used in EKS / AKS / GKE despite native support | Medium | Migrate to native workload identity for the cluster type | Platform Eng + Cluster Owner |
| KSS-014 | OIDC federation set up but not used; workflows still configured for static credentials | Low | Migrate workflows to the new auth method; delete legacy secrets | DevOps |
| KSS-015 | Third-party API tokens stored in long-lived secrets without rotation discipline | Medium | Rotation runbook; automated reminders; audit access | Security Eng + Workload Owner |
| KSS-016 | Per-tenant API keys for customers stored without rotation | Medium | Per-tenant rotation cadence; documented procedure | Customer Eng + Security Eng |
| KSS-017 | Workload-side federation complete; workforce-side identity still uses long-lived access | Medium | Workforce SSO migration; integrate with IAM Identity Center / Entra ID | IAM Eng |
| KSS-018 | Detection rules for new long-lived credentials creation absent | Medium | Alert on IAM user creation, on access key creation, on service-account-key creation | Security Eng + SOC |

---

## What this document is not

- **A complete federation guide.** Each cloud provider's OIDC / federation documentation has the exact procedures; this document covers the patterns and migration approach.
- **A workforce-IAM reference.** SSO setup, MFA enforcement, identity-provider integration is its own large topic; covered as it intersects with workload identity.
- **A Vault deployment guide.** Vault patterns are in [vault-patterns.md](./), coming.
- **A secret-rotation reference.** Rotation patterns are in [rotation-patterns.md](./), coming.
