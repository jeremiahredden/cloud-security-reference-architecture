# PaaS App Service Security

A practitioner's reference for securing managed application platforms — Azure App Service, AWS Elastic Beanstalk, GCP App Engine, GCP Cloud Run — side by side. PaaS is "I bring code, the platform handles the rest." That convenience hides a specific set of security trade-offs: the platform makes runtime patching automatic *and* hides version drift, makes deployment easy *and* makes deployment-slot misconfiguration a vector, makes scaling free *and* makes cost-DoS trivial. This document covers the controls that make PaaS as secure as IaaS without giving back the operational benefits.

This document closes a gap that [lambda-functions-security.md](./lambda-functions-security.md) explicitly does not cover: long-running managed application platforms rather than short-lived functions. The boundary is fuzzy (Cloud Run sits at the seam between FaaS and PaaS), so this document covers Cloud Run alongside the others. Where Cloud Run patterns overlap with Lambda, the function document is authoritative.

The honest framing: PaaS is the most under-attended category in cloud security. Because "the platform handles it," teams stop instrumenting; because the deployments are easy, teams accumulate dozens of forgotten App Services; because the runtime is managed, teams assume the runtime is current. None of those assumptions survive an actual review.

---

## When to read this document

**If you operate App Service / Elastic Beanstalk / App Engine / Cloud Run and aren't sure what the security baseline should be** — read top to bottom.

**If your team uses deployment slots / environments and you aren't sure how to think about them as a security control** — start with [Deployment slots and the slot-as-control pattern](#deployment-slots-and-the-slot-as-control-pattern).

**If you have App Services with no managed identity and your code holds connection strings** — start with [Managed identity attachment](#managed-identity-attachment).

**If you are auditing PaaS posture across a fleet** — start with [Findings checklist](#findings-checklist).

---

## Where PaaS sits in the cloud-compute spectrum

The mental model.

### The spectrum

```
IaaS  ─────────►  Containers  ────►  PaaS  ────►  FaaS
                                       │
                                       │  ← This document
                                       │
EC2 / VM         EKS / AKS         App       Lambda
                                   Service   Functions
                                   / EB /    / Cloud
                                   App       Functions
                                   Engine /
                                   Cloud Run
```

### What PaaS gives up vs IaaS

- **OS access:** none. You cannot SSH; you cannot install a daemon.
- **Network stack control:** limited. The platform owns the network; you configure endpoints.
- **Runtime choice:** constrained to supported versions.
- **Logging/metrics format:** dictated by platform.

### What PaaS gives in return

- **Patching:** OS, runtime, framework — usually automatic.
- **Scaling:** automatic, per-request.
- **Deployment ergonomics:** push code, get URL.
- **Observability baseline:** logs, metrics, traces ship by default.

### The security implications

| Property | Implication |
| --- | --- |
| Platform-managed runtime | Patching is fast, but you must monitor for deprecated versions before forced upgrade |
| Platform-managed network | Ingress controls are platform-specific; default is often "public internet" |
| Easy deployment | Forgotten apps accumulate; inventory becomes the hardest control |
| Logs / metrics by default | But not necessarily in SIEM by default; ingestion is your responsibility |
| Identity attachment | Managed identities exist for every platform; usage is uneven |

---

## The PaaS attack surface

What an attacker targets when the workload runs on App Service / Beanstalk / App Engine / Cloud Run.

### The identity attached to the app

- The app's managed identity (or service account) is what the app can do.
- Over-permissive = the app's compromise hands an attacker that scope.
- Same problem as Lambda execution roles; same solution: least privilege.

### The ingress

- A public URL exists by default.
- If the app is not meant to be internet-accessible, the URL must be restricted.
- IP allowlists, VNet integration with private endpoints, service tags, identity-aware proxies.

### The deployment pipeline

- Who can push code to the app?
- A compromised CI/CD pipeline pushing to App Service is equivalent to RCE in the app.
- See [../iac-security/policy-as-code.md](../iac-security/policy-as-code.md) for CI/CD gate patterns; this document covers the runtime-side controls.

### The application secrets

- Connection strings, API keys, OAuth secrets.
- In App Settings (the equivalent of Lambda env vars) — visible to anyone with `Microsoft.Web/sites/config/list/action`.
- The fix: Key Vault references for App Service; Secret Manager for App Engine; Cloud Run Secrets; Parameter Store / Secrets Manager for Beanstalk.

### The runtime version

- App Service / App Engine / Beanstalk surface a runtime version (Python 3.9, Node 18, etc.).
- Versions deprecate; forced upgrades happen on platform timeline.
- Apps running on deprecated runtimes are a posture risk *and* a sudden-failure risk.

### The configuration

- Diagnostic settings, logging, authentication, networking, deployment slots.
- Configuration drift between dev and prod is common.
- The fix: IaC for all configuration; drift detection in CI.

---

## Managed identity attachment

The single most-important PaaS security control. The same lesson Lambda taught.

### The principle

The app authenticates to other cloud services using a platform-attached identity. The application code never sees a connection string with credentials.

```
App                        Cloud Service (DB, Storage, Queue)
 │                                  │
 │  Managed Identity Token request  │
 │  ─────────────────────────────► │
 │                                  │
 │   Token                          │
 │  ◄─────────────────────────────  │
 │                                  │
 │   Resource call with token       │
 │  ─────────────────────────────► │
```

### Per platform

**Azure App Service:**
- System-assigned managed identity (created with the app, deleted with the app) or user-assigned managed identity (independent lifecycle).
- Default: prefer system-assigned for single-app uses; user-assigned for shared-identity-across-multiple-apps patterns.
- Attached via:

```bash
az webapp identity assign --name myapp --resource-group myrg
```

- Role assignments on the resulting service principal grant access:

```bash
az role assignment create \
  --assignee <principalId> \
  --role "Storage Blob Data Reader" \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<sa>
```

- App code uses `DefaultAzureCredential` from the Azure SDK; the SDK picks up the managed identity automatically.

**AWS Elastic Beanstalk:**
- Beanstalk environments run on EC2 instances; the instance profile is the identity.
- Configure via the EC2 instance profile attached to the environment.
- App code uses standard AWS SDK credential resolution; the SDK picks up the instance profile credentials.

**GCP App Engine:**
- Default service account: `<project>@appspot.gserviceaccount.com`.
- Strongly recommend replacing default with a custom service account (default has Editor on the project — over-broad).
- Configure via `app.yaml`:

```yaml
service_account: my-app-sa@my-project.iam.gserviceaccount.com
```

**GCP Cloud Run:**
- Per-service service account.
- Configure via the deployment:

```bash
gcloud run services update myservice \
  --service-account=my-app-sa@my-project.iam.gserviceaccount.com
```

- IAM bindings grant access:

```bash
gcloud projects add-iam-policy-binding my-project \
  --member=serviceAccount:my-app-sa@my-project.iam.gserviceaccount.com \
  --role=roles/storage.objectViewer
```

### The "no connection strings" baseline

The mature pattern across all four platforms:

1. App attached to managed identity / service account.
2. Database / storage / queue / KMS access granted to that identity at the platform's RBAC layer.
3. App code uses platform SDK credential resolution; no explicit credentials.
4. The App Settings / environment variables contain only non-sensitive configuration; secrets fetched via Key Vault references or runtime calls to the secrets manager.

This is the same kill-the-static-secret pattern that [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md) covers in depth. PaaS is one of the easiest places to land it; the platform support is uniformly strong.

### Anti-pattern: connection string in App Settings

```
App Settings (Azure App Service):
  DATABASE_CONNECTION_STRING = "Server=tcp:mydb.database.windows.net,1433;
                               Initial Catalog=mydb;
                               Persist Security Info=False;
                               User ID=appuser;
                               Password=hunter2!@#;
                               MultipleActiveResultSets=False;
                               Encrypt=True"
```

This is functionally equivalent to writing the password on the office whiteboard. Anyone with `read` permission on the App Service can pull the connection string.

The fix:

```
App Settings:
  DATABASE_SERVER = "mydb.database.windows.net"
  DATABASE_NAME = "mydb"
  # No credentials. App authenticates via managed identity.
```

Or, if connection-string-with-credentials is unavoidable (legacy SDK, third-party app):

```
App Settings:
  DATABASE_CONNECTION_STRING = @Microsoft.KeyVault(SecretUri=https://mykv.vault.azure.net/secrets/db-conn/)
```

The Key Vault reference resolves at runtime; the App Service's managed identity must have `Get` permission on the secret.

---

## Ingress restriction

What is reachable, by whom.

### The default is "public"

App Service, Beanstalk, App Engine, Cloud Run all default to publicly-accessible URLs. For apps that should be public (marketing sites, public APIs), this is fine. For apps that are internal-only, the default is wrong.

### Per platform — restricting to internal

**Azure App Service:**

- **Access restrictions** (formerly IP restrictions): allow/deny rules by IP, service tag, or VNet.
- **Private endpoint:** App Service is reachable only via private IP from the linked VNet.
- **VNet integration:** outbound from App Service to private resources.

Combination pattern: private endpoint (inbound) + VNet integration (outbound) = App Service that is internal-only.

**AWS Elastic Beanstalk:**

- Internal Beanstalk environments use an internal-only load balancer.
- Security groups on the load balancer restrict source IPs.
- No public ALB; the environment is reachable only from within the VPC.

```bash
eb create my-internal-env --vpc.id vpc-xxx --vpc.elbpublic false --vpc.publicip false
```

**GCP App Engine:**

- Ingress controls: `all`, `internal-and-cloud-load-balancing`, `internal-only`.
- Set in `app.yaml`:

```yaml
inbound_services:
- warmup
network:
  subnetwork_name: my-subnet
ingress:
  type: internal-only
```

**GCP Cloud Run:**

- Ingress: `all`, `internal`, `internal-and-cloud-load-balancing`.
- VPC connector for egress to private resources.

```bash
gcloud run services update myservice --ingress=internal
```

### When public ingress is correct

- A public-facing application (marketing site, customer portal, public API).
- With WAF in front (Front Door, CloudFront + WAF, GCP Cloud Armor + Load Balancer).
- With rate limiting at the edge.
- With authentication enforced at the edge or in the app.

The pattern is documented in [../zero-trust-cloud/identity-aware-access.md](../zero-trust-cloud/identity-aware-access.md) for the internal-app case (Cloudflare Access, AWS Verified Access, GCP IAP).

### The "public by default, internal by exception" anti-pattern

The opposite — "internal by default, public by exception" — should be the team's working model. Teams that don't enforce this end up with the situation in the worked example below: 47 App Services, all public, none of them needing to be.

---

## Deployment slots and the slot-as-control pattern

Deployment slots are the under-used PaaS feature that solves real release-engineering and security problems.

### What a slot is

- An additional environment within the same App Service / App Engine version / Cloud Run revision, with its own URL and configuration.
- The slot can be swapped with production atomically.
- The slot has its own configuration (including its own App Settings, including its own secrets).

### The release-engineering value

- Deploy to slot.
- Run smoke tests against slot URL.
- Swap slot with production; if anything is wrong, swap back.

### The security value

- **Per-slot identity:** the slot can have its own managed identity, distinct from production. Bugs in the slot don't access production data.
- **Per-slot secrets:** the slot's Key Vault references can point to dev secrets, not production.
- **Per-slot configuration:** the slot can have stricter logging, debug mode disabled, etc.

### Configuration that should be "slot-sticky"

A "slot-sticky" setting stays with the slot during swap. The swap brings the new code into production but leaves the slot-specific configuration behind. Use for:

- Connection strings to environment-specific resources.
- Per-environment feature flags.
- Per-environment auth settings.

### Anti-pattern: production secrets in the staging slot

The team mirrors all production App Settings into the staging slot for "convenience." Staging slot has production database credentials. Anyone with staging-slot read has production-data access.

The fix:
- Per-slot App Settings.
- Per-slot Key Vault references.
- Verify with `az webapp config appsettings list --name <app> --slot <slot>` — every secret reference should point to environment-appropriate storage.

### Per-platform deployment-slot equivalents

| Platform | Slot equivalent |
| --- | --- |
| Azure App Service | Deployment slots (built-in) |
| AWS Elastic Beanstalk | Multiple environments (per environment URL); blue/green via environment swap (`eb deploy` followed by `eb swap`) |
| GCP App Engine | Versions; traffic split via `gcloud app services set-traffic` |
| GCP Cloud Run | Revisions; traffic split via `gcloud run services update-traffic` |

The traffic-split pattern (App Engine, Cloud Run) is the most flexible: 0% / 1% / 10% / 100% rollouts are atomic and reversible.

---

## Runtime version hygiene

The thing that silently breaks PaaS.

### The problem

Every PaaS platform supports a list of runtimes (Python, Node, Java, .NET) at specific versions. Versions reach end-of-life. Apps running on EOL versions:

- Receive no security patches.
- Are subject to forced upgrade on platform timeline (may break the app).
- Are a compliance finding (running unsupported runtime).

### The discipline

1. **Inventory runtime versions across all apps.**

   Azure:
   ```bash
   az webapp list --query "[].{Name:name, Runtime:siteConfig.linuxFxVersion}" -o table
   ```

   AWS Beanstalk:
   ```bash
   aws elasticbeanstalk describe-environments \
     --query "Environments[].{Name:EnvironmentName, Platform:PlatformArn}"
   ```

   GCP App Engine:
   ```bash
   gcloud app versions list --format="table(service, id, runtime)"
   ```

   GCP Cloud Run:
   ```bash
   gcloud run services list --format="table(metadata.name, spec.template.spec.containers[0].image)"
   ```

2. **Subscribe to deprecation notices.** Azure App Service runtime updates, Beanstalk platform updates, App Engine deprecation policy, Cloud Run container image lifecycle.

3. **Per-quarter upgrade pass.** Each platform team upgrades to the latest supported runtime; release in a low-risk window.

4. **CI gate.** New deploys must specify a non-deprecated runtime.

### The "platform version" vs "runtime version" distinction (Beanstalk specific)

Elastic Beanstalk has two version concepts:
- **Platform version:** the Beanstalk-managed AMI / Docker image (includes OS + runtime).
- **Runtime version:** the language runtime within the platform.

A platform upgrade picks up OS patches; a runtime upgrade picks up runtime patches. Both matter. The Beanstalk console surfaces "managed updates" — enable them for production environments.

---

## Logging and detection

What ships, where, and what to look for.

### The default logging by platform

| Platform | Default logging | Where it goes |
| --- | --- | --- |
| Azure App Service | HTTP logs, console logs, application logs | App Service Diagnostic Settings → Log Analytics / Storage / Event Hub |
| AWS Elastic Beanstalk | Apache/Nginx access logs, application logs, system logs | CloudWatch Logs (must enable) |
| GCP App Engine | Request logs, application logs | Cloud Logging (default) |
| GCP Cloud Run | Request logs, container stdout/stderr | Cloud Logging (default) |

### The SIEM-ingestion baseline

All four platforms have first-class log destinations; the bug is that teams stop at "logs are visible in the console" and don't push them to the SIEM.

The pattern, per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md):

1. Logs land in the cloud-native log store (Log Analytics / CloudWatch / Cloud Logging).
2. A forwarder (Event Hub for Azure, Kinesis Firehose for AWS, Pub/Sub for GCP) ships selected log streams to the SIEM.
3. SIEM detections run on the streams.

### High-value detections for PaaS

- **Configuration change to a production App Service / environment** by an unexpected principal.
- **Deployment to production slot/environment** outside CI/CD pipeline (manual `az webapp deploy`).
- **App Settings modified** to add a secret (regex on the API call body in CloudTrail / Activity Log).
- **Ingress restriction removed** from an internal-only app (Microsoft.Web/sites/config/web/write events).
- **Managed identity role assignment added** for a sensitive scope (Storage Blob Data Contributor, KMS Crypto User).
- **Runtime stack changed** (could be malicious — attacker downgrades to vulnerable runtime).

These detections are written in detection-as-code, deployed via the same pipeline as the SIEM rules; see [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) for the pattern.

---

## TLS and custom-domain handling

### The platform-provided certificate

Every PaaS platform provides a free TLS certificate for its assigned hostname (`*.azurewebsites.net`, `*.elasticbeanstalk.com`, `*.appspot.com`, `*.run.app`). This is what every dev environment uses.

### Custom domains

Production apps almost always use a custom domain. The patterns:

**Azure App Service:**
- Custom domain via DNS CNAME or A record.
- Free managed certificate (App Service Managed Certificate) for the domain.
- Alternative: bring your own certificate from Key Vault.

**AWS Elastic Beanstalk:**
- Custom domain via Route 53 / DNS.
- Certificate via ACM (free), attached to the environment's load balancer.

**GCP App Engine / Cloud Run:**
- Custom domain via DNS verification.
- Managed certificate auto-provisioned (let's-encrypt-style flow).

### The TLS-version baseline

- **Minimum:** TLS 1.2.
- **Preferred:** TLS 1.3.
- **Disable:** TLS 1.0, TLS 1.1 (PCI requirement, broadly accepted security baseline).

Per platform:

- Azure App Service: `Microsoft.Web/sites/config/web` setting `minTlsVersion: 1.2` (Azure now enforces 1.2 as the floor).
- Elastic Beanstalk: configure on the load balancer (security policy `ELBSecurityPolicy-TLS13-1-2-2021-06` or newer).
- App Engine: TLS 1.2+ enforced by default; 1.0/1.1 can be disabled in app.yaml.
- Cloud Run: TLS 1.2+ enforced by default.

### HSTS

Set the `Strict-Transport-Security` header from the application. The platforms do not set it by default. Use `max-age=31536000; includeSubDomains` for production custom domains.

### Certificate-rotation hygiene

The platform-managed certificates auto-rotate. The "bring your own certificate" pattern requires explicit rotation. Monitor expiration via:

- Azure: Key Vault certificate expiry events.
- AWS: ACM expiration notifications.
- GCP: Cloud Asset Inventory + Cloud Monitoring on cert age.

The "let the certificate expire silently" failure mode is one of the most-common outages; not strictly a security control, but the security-on-call gets paged because the symptom looks like an attack.

---

## Cost-DoS and concurrency control

PaaS scales automatically; that's a feature unless an attacker exploits it.

### The risk

- An attacker drives request volume into the app.
- The platform scales up to handle load.
- The bill scales with it.
- The team is paged on the bill, not on a security event.

### The controls

**Azure App Service:**
- Scaling limits on the App Service Plan (`maximum elastic worker count`).
- Per-app rate limiting via Front Door / API Management.
- WAF rules at Front Door / Application Gateway.

**AWS Elastic Beanstalk:**
- Auto-scaling group max-instance cap.
- ALB rate limiting (via AWS WAF rate-based rules).
- WAF in front (CloudFront + WAF).

**GCP App Engine:**
- `automatic_scaling.max_instances` in app.yaml.
- Cloud Armor in front for rate limiting.

**GCP Cloud Run:**
- Max instance count per service.
- Cloud Armor in front.

### The baseline

Every production PaaS app has:
- A maximum-scale cap (instances or replicas).
- A WAF / rate-limiter in front, with at least a rate-based rule (100 req/min per IP, or per-app baseline).
- A billing alert on the App Service Plan / environment / project at 2x baseline cost.

The rate-limit baseline is covered in [../network-security/segmentation-patterns.md](../network-security/segmentation-patterns.md); the cost-alert pattern is covered in [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md).

---

## App-level authentication

Where the app needs auth and the platform can do it for you.

### The platform-provided auth pattern

**Azure App Service Authentication ("Easy Auth"):**
- Built-in auth that handles OIDC with Microsoft Entra ID, Google, GitHub, Apple, custom OIDC.
- App receives authenticated requests with claims in headers; app doesn't implement auth.
- Configuration is platform-level; updates don't require redeploy.

**AWS:**
- No equivalent in Beanstalk itself; use ALB authentication (`AuthenticateOidcConfig`, `AuthenticateCognitoConfig`).
- Or front the environment with API Gateway + Cognito.

**GCP:**
- Identity-Aware Proxy (IAP) in front of App Engine / Cloud Run.
- Configures via IAM bindings; the app receives authenticated requests with signed headers.

### When to use platform auth

- Internal-only apps where every user is in the org's identity provider.
- Apps where authentication is genuinely "is this user in our org or not" with no fine-grained app logic.

### When to implement auth in the app

- Customer-facing apps with custom registration, password reset, etc.
- Apps with fine-grained authorization tied to business data.
- Apps that need to support unauthenticated traffic for some routes.

The architectural choice is documented in [../zero-trust-cloud/identity-aware-access.md](../zero-trust-cloud/identity-aware-access.md); the relevant PaaS-side mechanics are above.

---

## Worked example — Meridian Health App Service review (Q2 2026)

The Meridian platform team operates ~120 App Services across three Azure subscriptions (corporate, regulated-workloads, sandbox). Security and Platform conducted a joint review.

### The findings (pre-review)

- 47 App Services public (no IP restriction, no private endpoint).
- 14 App Services holding database passwords in App Settings.
- 12 App Services without managed identity attachment.
- 8 App Services running deprecated runtimes (Python 3.7, Node 14).
- 22 App Services missing diagnostic settings (logs not shipping to Log Analytics).
- 6 App Services with deployment slots that mirrored production App Settings (including secrets).
- 3 App Services with TLS 1.0 still enabled (legacy customer integrations the team had forgotten about).

### The remediation campaign (six weeks)

**Week 1 — Inventory and triage.**
Built an App Service inventory dashboard (Azure Resource Graph query, refreshed daily). Classified every App Service by:
- Public vs internal-only.
- Production vs non-production.
- Owner (engineering team).
- Compliance scope (PHI / non-PHI).

**Week 2 — Ingress restriction.**
For all internal-only App Services: added Access Restrictions with the corporate IP ranges and the Azure VNet integration service tag. For the 8 public-but-shouldn't-be App Services: migrated to private endpoint behind Front Door.

**Week 3 — Managed identity attachment.**
For all 12 App Services without managed identity: created system-assigned identities. Migrated App Settings connection strings to Key Vault references; granted the managed identities `Get` on the appropriate secrets. Removed the connection-string App Settings.

**Week 4 — App Settings cleanup.**
Audited every App Service's App Settings for secret-like values. 14 App Services still had passwords; migrated to Key Vault references. Implemented a CI check (PR comment) that flags any App Settings key matching common secret patterns (`*PASSWORD*`, `*KEY*`, `*SECRET*`, `*TOKEN*`).

**Week 5 — Runtime upgrade.**
Upgraded the 8 deprecated-runtime App Services. Two required code changes (Python 3.7 → 3.11 broke a deprecated library); coordinated with the owning teams.

**Week 6 — Slot hygiene.**
Created per-slot App Settings for the 6 affected App Services. Staging slots now point to staging Key Vault; production slot points to production Key Vault. Documented slot-sticky settings in the deployment runbook.

### The findings (post-review)

- 0 public App Services that shouldn't be.
- 0 App Settings holding secrets.
- 120 / 120 App Services with managed identity.
- 0 deprecated runtimes.
- 120 / 120 App Services with diagnostic settings shipping to the central Log Analytics workspace.
- 0 slot-leakage findings.
- 0 App Services accepting TLS 1.0.

### Findings opened during the review

- **PAAS-001** (47 App Services public without need). Closed by ingress restriction.
- **PAAS-002** (database passwords in 14 App Settings). Closed by Key Vault reference migration.
- **PAAS-003** (12 App Services missing managed identity). Closed by attachment.
- **PAAS-004** (8 App Services on deprecated runtimes). Closed by upgrade.
- **PAAS-005** (22 App Services not shipping logs to Log Analytics). Closed by diagnostic settings baseline.
- **PAAS-006** (6 staging slots holding production secrets). Closed by per-slot App Settings.
- **PAAS-007** (3 App Services accepting TLS 1.0). Closed by minTlsVersion update; coordinated with legacy customers on cutover.

The total cost of the campaign (engineering hours): ~6 weeks of 1.5 FTE. Worth doing once; the maintenance cost (CI gates + quarterly review) is hours per quarter.

---

## Anti-patterns

### 1. "The app is internal, so it doesn't need a managed identity"

Internal-only apps still authenticate to databases, storage, queues. Connection strings with credentials are the alternative to managed identity. Internal-only does not make credentials acceptable.

The fix: managed identity is the baseline for every app, internal or public.

### 2. The mirror-production-App-Settings-into-staging-slot pattern

Convenient for the developer; gives the staging slot production credentials. Anyone with staging-slot read has production data.

The fix: per-slot App Settings; per-slot Key Vault references; environment-specific secrets.

### 3. "The App Service is behind Front Door, so ingress restriction doesn't matter"

If the App Service is reachable by direct URL (not just via Front Door), the WAF is bypassed by directly hitting the `.azurewebsites.net` URL. An attacker who learns the direct URL skips every WAF rule.

The fix: Access Restrictions that allow only Front Door's service tag + Front Door's `X-Azure-FDID` header. Verify with a curl from outside Front Door.

### 4. The "let the platform handle it" runtime-version drift

The team assumes "the platform patches the runtime." It does — until the runtime is EOL, at which point the team has weeks to upgrade or face forced migration.

The fix: subscribe to deprecation notices; quarterly upgrade pass.

### 5. The default-service-account App Engine pattern

App Engine apps default to using the App Engine default service account, which has Editor on the project. Every App Engine app can do anything in the project.

The fix: per-app custom service accounts; remove Editor from the default service account (and document the change carefully because it can break other GCP services that depend on it).

### 6. The "expose Cloud Run with `--allow-unauthenticated` for convenience" pattern

Cloud Run with public ingress + `--allow-unauthenticated` is the equivalent of a public Lambda function URL with no auth. The function is reachable by anyone.

The fix: `--no-allow-unauthenticated` for any service that isn't deliberately public; require authentication via Cloud IAM, or front with IAP for human-targeted apps.

### 7. The forgotten Beanstalk environment

A Beanstalk environment was created for a one-off proof-of-concept three years ago. It runs an unpatched runtime; the team has forgotten about it. Cost: $200/month and a posture finding.

The fix: per-environment owner tag; quarterly inventory review; auto-terminate environments without recent deployments.

### 8. The hand-edited App Service configuration

The team configured the App Service via the Azure Portal during incident response and never put the change in Terraform. Drift; the next IaC apply reverts the fix; the incident recurs.

The fix: IaC for all production App Services; drift detection in CI; emergency portal changes get a same-day Terraform PR.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| PAAS-001 | App Service / App Engine / Cloud Run publicly accessible without need | High | Apply ingress restriction (Access Restrictions, internal-only ingress, IAP) | Platform Eng + Security Eng |
| PAAS-002 | Secrets in App Settings / environment variables | High | Migrate to Key Vault / Secret Manager references | Application Eng + Security Eng |
| PAAS-003 | App lacks managed identity / custom service account | High | Attach managed identity; grant scoped permissions via RBAC | Platform Eng + Security Eng |
| PAAS-004 | App running deprecated runtime | High | Subscribe to deprecation notices; quarterly upgrade pass | DevOps + Application Eng |
| PAAS-005 | Diagnostic settings not configured; logs not in central log store | Medium | Diagnostic settings baseline; SIEM ingestion per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) | Security Eng + SOC |
| PAAS-006 | Deployment slot / non-prod environment holds production secrets | High | Per-slot App Settings; per-environment Key Vault | DevOps + Security Eng |
| PAAS-007 | App accepts TLS 1.0 / 1.1 | Medium | minTlsVersion 1.2 or higher; coordinate with legacy clients | Network Eng + Security Eng |
| PAAS-008 | App Service direct URL bypasses WAF | High | Access Restrictions to allow only WAF; verify X-Azure-FDID enforcement | Network Eng + Security Eng |
| PAAS-009 | App Engine app uses default service account (project Editor) | High | Custom service account; scoped permissions | Platform Eng + Security Eng |
| PAAS-010 | Cloud Run service deployed with `--allow-unauthenticated` without need | High | Require IAM authentication; or front with IAP | Platform Eng + Security Eng |
| PAAS-011 | Forgotten / unowned App Service or environment | Medium | Owner tag; quarterly inventory; auto-terminate idle environments | Platform Eng + Engineering Lead |
| PAAS-012 | Configuration drift between IaC and runtime | Medium | Drift detection in CI; emergency portal changes get same-day Terraform PR | DevOps + Platform Eng |
| PAAS-013 | App Service scaling not capped; cost-DoS risk | Medium | Max-scale limit; billing alert at 2x baseline | DevOps + FinOps |
| PAAS-014 | No WAF / rate limiter in front of public app | High | Front Door / API Gateway / Cloud Armor; baseline rate-based rule | Network Eng + Security Eng |
| PAAS-015 | App Settings written directly in portal without auditability | Medium | All changes via IaC; portal as read-only | DevOps |
| PAAS-016 | HSTS header not set on production custom domain | Low | Set Strict-Transport-Security in application response | Application Eng + Security Eng |
| PAAS-017 | Custom certificate not auto-rotating; expiration risk | Medium | Move to platform-managed cert; or monitor cert age via cloud monitoring | DevOps + Security Eng |
| PAAS-018 | App Service or App Engine app deployed outside CI/CD | High | Deployment via CI/CD only; manual deploys disabled by RBAC | DevOps + Security Eng |

---

## Adoption checklist

- [ ] Inventory all App Services / Beanstalk environments / App Engine versions / Cloud Run services across all subscriptions / accounts / projects.
- [ ] Classify each as public vs internal-only vs internal-with-external-auth (e.g., IAP).
- [ ] Verify each has a managed identity / custom service account attached.
- [ ] Verify each has no secrets in App Settings / environment variables.
- [ ] Verify each is on a supported (non-deprecated) runtime.
- [ ] Verify each has diagnostic settings shipping logs to the central log store.
- [ ] Verify each has TLS 1.2+ enforced.
- [ ] Verify each has a maximum-scale cap.
- [ ] For public apps: verify WAF / rate limiter in front; verify direct-URL bypass is blocked.
- [ ] For internal apps: verify ingress restriction (Access Restrictions, internal-only, IAP).
- [ ] For apps with slots: verify per-slot secrets; no slot-mirroring of production credentials.
- [ ] CI gate: secret-in-App-Settings check on every PR.
- [ ] CI gate: deprecated-runtime check on every PR.
- [ ] CI gate: drift detection between IaC and runtime configuration.
- [ ] Detection-as-code rule: configuration change by unexpected principal.
- [ ] Detection-as-code rule: ingress restriction removed from internal-only app.
- [ ] Detection-as-code rule: managed identity role assignment added at sensitive scope.
- [ ] Quarterly inventory pass; orphan / unowned environments terminated.

---

## What this document is not

- **A PaaS-platform tutorial.** Familiarity with at least one of App Service / Beanstalk / App Engine / Cloud Run is assumed.
- **A vendor comparison.** All four platforms appear because their security patterns rhyme; the choice belongs with broader cloud decisions.
- **An identity-aware-access reference.** [../zero-trust-cloud/identity-aware-access.md](../zero-trust-cloud/identity-aware-access.md) covers the external-auth-for-internal-apps pattern.
- **An IAM deep dive for PaaS workloads.** [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md) and [./serverless-iam-patterns.md](./serverless-iam-patterns.md) cover IAM design.
- **A WAF reference.** [../network-security/segmentation-patterns.md](../network-security/segmentation-patterns.md) covers edge-side rate limiting and WAF patterns.
- **A complete logging reference.** [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) covers SIEM-ingestion patterns; this document covers the PaaS-specific log sources.
