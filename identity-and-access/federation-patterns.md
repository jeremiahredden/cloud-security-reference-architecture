# Federation Patterns

A practitioner's reference for the federation mechanics that connect an identity provider to a cloud / SaaS consumer — SAML 2.0, OpenID Connect (OIDC), and SCIM 2.0. The patterns that get federation right (and the patterns that look right but silently widen access). This is the technical layer beneath [workforce-identity.md](./workforce-identity.md); the strategic choices live there, the mechanics live here.

The honest framing: federation in 2026 is mostly a solved problem at the protocol layer. The interesting failures are in claim mapping, group-to-role binding, certificate / key management, and the "we federated, we're done" pattern that skips the audit and authorization-mapping discipline. This document covers the failures that actually occur in production environments.

---

## When to read this document

**If you are setting up SAML / OIDC federation for a new app or cloud** — read top to bottom.

**If you have a federation working but you're not sure the claim mapping is correct** — start with [Claim mapping](#claim-mapping).

**If you need to federate across two cloud providers (AWS ↔ Azure, GCP ↔ AWS) without standing up a third IdP** — start with [Cross-cloud federation](#cross-cloud-federation).

**If you have a SCIM integration that creates users but never deactivates them** — start with [SCIM provisioning patterns](#scim-provisioning-patterns).

---

## SAML 2.0

The protocol most enterprise federation runs on.

### The shape

```
1. User → App: GET /protected-resource
2. App → User: redirect to IdP with SAML AuthnRequest
3. User → IdP: presents credentials
4. IdP → User: returns signed SAML Response (Assertion in the body)
5. User → App: POST /sso-callback with the SAML Response
6. App: validates Assertion (signature, audience, NotBefore/NotOnOrAfter)
7. App: extracts user identity + attributes from Assertion
8. App: establishes session for the user
```

### What the IdP signs

The SAML Response (and / or the Assertion within it) is signed with the IdP's signing certificate. The app verifies the signature against the public key it has on file for that IdP.

### What the App enforces

- **Signature validity:** signed by the trusted IdP key.
- **Issuer match:** `Issuer` in the Assertion matches the configured IdP.
- **Audience restriction:** `Audience` in the Assertion matches the app's expected audience URL.
- **Time window:** `NotBefore` and `NotOnOrAfter` are sane.
- **Subject:** the user identifier (NameID) is in the expected format.
- **Replay prevention:** the assertion ID hasn't been seen before within the validity window.

If the app skips any of these checks, the federation is exploitable. Most modern SAML libraries handle these correctly; the failure mode is misconfiguration that disables a check, or hand-rolled SAML that omits one.

### The certificate-rotation problem

The IdP's signing certificate has an expiration date. When it expires, signatures stop validating, sign-ins fail.

Patterns:
- **Manual rotation with calendar reminder:** common; fragile.
- **Multi-key support:** the IdP signs with the new key while the app trusts both old and new for a grace period; the app removes the old key after grace period.
- **IdP-metadata-URL-based trust:** the app re-fetches IdP metadata periodically; pulls the current key from the IdP. Modern pattern; supported by Okta / Entra ID metadata endpoints.

Anti-pattern: pinning a single certificate without rotation discipline. Expiration day = workforce outage.

### NameID format

SAML allows several NameID formats:
- `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` — email as the user identifier.
- `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` — a stable opaque identifier the IdP issues.
- `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` — a single-session identifier; not useful for stable mapping.

The choice matters. `emailAddress` is convenient but couples the identity to the email; renaming a user breaks the cloud-side identity binding. `persistent` is the recommended pattern for stable cross-system identity.

### Audience restriction is a security control

The SAML Assertion contains `Audience` claiming "this assertion is for application X." If an app accepts an Assertion intended for a different audience, an attacker who gets an Assertion for app B can replay it to app A.

Verify: every SAML SP (relying party) configures and enforces the `Audience` claim. Test by replaying an Assertion to a different SP — it should fail.

### The signed-only Response vs signed-Assertion-only modes

Some SAML implementations sign only the outer Response; some sign only the inner Assertion; some sign both. The SP should verify signatures on the Assertion specifically (the meaningful payload). "Response signed, Assertion not signed" is an attack vector (the Response wrapper is valid; the Assertion content can be tampered).

Verify with the SP's documentation; prefer SPs that enforce Assertion-level signature.

---

## OpenID Connect (OIDC)

The modern alternative; built on OAuth 2.0; the protocol you want for new integrations.

### The shape (Authorization Code flow with PKCE)

```
1. User → App: GET /protected-resource
2. App → User: redirect to IdP /authorize endpoint with:
     - client_id
     - redirect_uri
     - scope (openid + others)
     - state
     - code_challenge (PKCE)
3. User → IdP: presents credentials
4. IdP → User: redirect to App with code + state
5. App: validates state; sends code + code_verifier + client_secret to IdP /token
6. IdP → App: returns id_token (JWT) + access_token + refresh_token
7. App: validates id_token (signature, issuer, audience, exp, nonce)
8. App: extracts user identity + claims from id_token
9. App: establishes session
```

### What the id_token contains

A JWT signed by the IdP. Standard claims:
- `iss` — issuer.
- `sub` — subject (user identifier).
- `aud` — audience (client_id of the app).
- `exp` — expiration.
- `iat` — issued at.
- `nonce` — replay-prevention value.
- `email`, `name`, etc. — profile claims.
- Custom claims (groups, roles) per IdP configuration.

### What the app enforces

- **Signature:** signed by the IdP (verify against IdP's JWK set, retrieved from the issuer's `.well-known/openid-configuration`).
- **Issuer:** `iss` matches the IdP's expected issuer URL.
- **Audience:** `aud` matches the app's client_id.
- **Expiration:** `exp` in the future.
- **Nonce:** matches the nonce the app sent in the authorize request.

### Why OIDC > SAML for new integrations

- JSON instead of XML (smaller, easier to debug, fewer XML-canonicalization gotchas).
- JWKS endpoint for key rotation (the app fetches keys from the IdP at startup / cache-refresh).
- Built on OAuth 2.0; access_tokens for downstream API access fit cleanly.
- The mobile / SPA patterns (PKCE) are first-class.
- Native id_token introspection.

### Why SAML is still everywhere

- Most enterprise apps support SAML and not OIDC.
- Many compliance frameworks reference SAML by name.
- IdP-initiated SSO is more naturally SAML (OIDC supports it but the SAML flow is more common in enterprise contexts).

### Client_secret handling

OIDC clients (the apps) have a client_secret used to authenticate to the IdP's token endpoint. Treat it like any other secret:
- Store in a secrets manager.
- Rotate periodically.
- Public clients (SPAs, mobile apps) can't hold a client_secret — use PKCE-only flows.

### The implicit-flow trap

The OAuth 2.0 implicit flow (`response_type=token id_token` returned in URL fragment) was the SPA pattern in 2018. It's deprecated as of OAuth 2.1 because tokens leak through browser history / referrer headers.

The fix: use Authorization Code with PKCE for SPAs (modern pattern).

---

## Claim mapping

Where most federation deployments go wrong.

### The mapping problem

The IdP issues claims (attributes about the user). The app needs to map those claims to its internal model of users / groups / roles. The mapping is configurable on both sides. Misconfiguration leads to:

- **Silent over-grant:** the IdP issues a claim that the app interprets as "admin"; nobody noticed.
- **Silent under-grant:** the IdP issues a claim the app doesn't recognize; the user has fewer permissions than intended.
- **Cross-tenant leak:** the IdP issues a claim that, in the app's mapping, matches a different tenant's role.

### The discipline

- **Document every claim the IdP issues.** What attribute, what value, for what user population.
- **Document every claim the app consumes.** What does the app do with each claim.
- **Map them explicitly.** Avoid "the app does what makes sense by default." Default mappings are the source of surprises.
- **Test claim changes.** Adding a new attribute in the IdP is a change with downstream impact; test in a staging deployment.

### The group-to-role pattern

The most common mapping: IdP groups → cloud / app roles.

```
IdP groups (in Okta / Entra ID):
  meridian-aws-prod-power-user
  meridian-aws-prod-read-only
  meridian-aws-prod-kms-admin
  meridian-snowflake-data-engineer
  meridian-snowflake-analyst

  ↓ (SAML/OIDC assertion)

App-side claim:
  groups = [
    "meridian-aws-prod-power-user",
    "meridian-snowflake-analyst"
  ]

  ↓ (mapping in cloud / app)

AWS Identity Center:
  group "meridian-aws-prod-power-user" → Permission Set "PowerUser" in account prod

Snowflake:
  group "meridian-snowflake-analyst" → role "ANALYST"
```

The IdP-side group is the single source of truth. The app-side mapping is in IaC (Terraform, etc.). Changes to either go through a documented review process.

### The "SAML attribute is data, not identity" failure mode

A user can sometimes self-modify SAML attributes if the IdP exposes them via profile editing.

Example: a SaaS app maps `department = engineering` to "engineering team access." A user can change their own department in some HRIS sync flows. The user updates department in HRIS → IdP picks up → app grants engineering access.

The fix: any SAML attribute used for authorization decisions must be IdP-administered, not user-editable. Audit the attribute provenance.

### Wildcard role mapping

App admin maps `group: meridian-aws-* → AWS PowerUser`. A new group `meridian-aws-experimental` is created in the IdP; users assigned to it gain PowerUser on every AWS account.

The fix: explicit per-group mapping. No wildcards on the SP side.

### Static claims as security boundary

App treats `email = *@meridian.com` as the access decision. Anyone with a Meridian email gets in.

This is fine for some apps (intranet wiki). It's not fine for apps with sensitive data (admin console). The discipline: every app that handles sensitive data uses per-group / per-role mapping, not "anyone from this domain."

---

## Cross-cloud federation

When workloads or users in cloud A need to access resources in cloud B.

### Pattern 1 — Workload Identity Federation (cloud-to-cloud, no IdP needed)

Modern pattern: the source cloud issues a short-lived OIDC token; the target cloud accepts it as proof of identity, issues short-lived credentials in the target cloud.

**AWS ↔ GCP via Workload Identity Federation:**
- GCP workload (e.g., a Cloud Run service) needs AWS S3 access.
- GCP issues an OIDC token signed with GCP's key.
- AWS IAM trust policy on the role accepts tokens with `iss: https://accounts.google.com` and a specific subject.
- The workload exchanges the OIDC token for AWS STS credentials via `AssumeRoleWithWebIdentity`.
- Result: GCP-hosted workload calls AWS S3 with short-lived credentials, no long-lived AWS access keys.

**Azure ↔ AWS via OIDC:**
- Azure-hosted GitHub Actions or Azure VM with managed identity issues an OIDC token.
- AWS IAM trust policy accepts the Azure OIDC issuer.
- The workload exchanges for AWS STS credentials.

**AWS ↔ Azure via Workload Identity Federation:**
- AWS-hosted workload issues an OIDC token (via STS).
- Azure accepts via federated identity credential on a managed identity.

The pattern is symmetric across cloud pairs; the mechanics vary slightly per cloud.

### Pattern 2 — IdP as the trust broker

Both clouds federate to the same IdP. Workforce users have one identity; workload requests go through the IdP.

```
       Corporate IdP (Okta / Entra ID)
          │
   ┌──────┴────────┐
   ▼               ▼
 AWS             GCP
```

Workforce users sign into both clouds via the IdP. Cross-cloud workload requests go through workload identity federation (Pattern 1).

### Pattern 3 — Cross-tenant trust (Entra ID specific)

Entra ID supports cross-tenant B2B collaboration: users in tenant A can be invited as guests into tenant B.

Common for partner / vendor scenarios. The guest user authenticates with their home tenant's credentials; the host tenant sees them as a guest user with restricted permissions.

Anti-pattern: granting guest users broad permissions in the host tenant. Restrict scope; document the guest relationships; review quarterly.

### Pattern 4 — The "stand up a third IdP" anti-pattern

Some organizations layer a third IdP (e.g., Auth0 sitting between Okta and AWS). This is usually unnecessary and adds a failure mode.

The exceptions: complex multi-tenant scenarios where the third IdP is genuinely needed for tenant isolation; legacy reasons (the third IdP was added years ago and removal isn't justified).

Default: federate directly from the corporate IdP to the cloud / app. Add a layer only with explicit justification.

---

## SCIM provisioning patterns

The provisioning mechanism for federated apps.

### What SCIM does

```
IdP (source of truth)
   │
   │ SCIM API push
   ▼
App (sink)
   - create user record
   - update attributes
   - assign to groups
   - deactivate on offboarding
```

### The SCIM endpoints

- `POST /scim/v2/Users` — create user.
- `GET /scim/v2/Users/{id}` — read user.
- `PUT /scim/v2/Users/{id}` — replace user.
- `PATCH /scim/v2/Users/{id}` — partial update.
- `DELETE /scim/v2/Users/{id}` — deactivate or delete.
- Similar endpoints for groups.

### What gets synced

- **User attributes:** email, name, employee ID, department, manager.
- **Group memberships:** which groups the user belongs to.
- **Status:** active vs deactivated.

### Per-IdP / per-app variation

- Entra ID, Okta, Google Workspace all support SCIM as the source.
- Most modern SaaS supports SCIM as the sink (Snowflake, Slack, GitHub, Datadog, Atlassian, etc.).
- Some legacy apps support only just-in-time provisioning (user created on first sign-in); SCIM not supported.

### The deprovisioning discipline

SCIM provisioning is the easy part. SCIM deprovisioning is where deployments break.

- The IdP marks a user as deactivated.
- The IdP should push a `PATCH` to set `active: false` on the SCIM endpoint, or `DELETE` per app preference.
- The app should disable the user account, terminate active sessions, revoke API tokens.

Common failures:
- The IdP push fails silently (network / API change). The app keeps the user active.
- The app accepts `active: false` but doesn't terminate sessions. The user's session continues until expiry.
- The app accepts the push but doesn't revoke long-lived API tokens. The user's automation continues working.

The discipline:
- Per-app, verify that deactivation actually deactivates (test by deactivating a synthetic account).
- Per-app, verify that sessions terminate (the deactivated user's existing session should fail on next API call).
- Per-app, verify that API tokens are revoked (or document where they aren't, and reconcile separately).

### Reconciliation

The IdP and the app should agree on the user set. They won't always. Run a monthly reconciliation:

- Pull user list from IdP.
- Pull user list from app via SCIM `GET /Users`.
- Diff:
  - Users in app not in IdP → orphans, deactivate.
  - Users in IdP not in app → missed provisioning, fix the SCIM integration.
  - Users in both but with different attributes → sync drift, investigate.

Most teams discover that 5-15% of their app user lists are orphan records on first reconciliation. The cleanup is a one-time campaign; the ongoing reconciliation keeps drift small.

---

## Worked example — Meridian Health Snowflake federation (Q1 2026)

Meridian migrated Snowflake from local-auth to Okta-federated SAML + SCIM in eight weeks.

### Starting state

- ~120 Snowflake users (data engineers, analysts, application service users).
- All authenticated with local password + MFA (Snowflake's built-in MFA).
- No SSO; each user managed their own Snowflake password.
- No SCIM; user provisioning was a manual ticket flow.
- Departing users were sometimes deactivated promptly, sometimes weeks later.

### Week 1-2 — Federation design

- Decided: SAML 2.0 (Snowflake's SAML support is mature; OIDC is supported but SAML is the path-of-least-resistance).
- Designed claim mapping:
  - `NameID` = email (Snowflake's recommended pattern for SAML; mapped to Snowflake `LOGIN_NAME`).
  - `groups` claim issued by Okta, mapped to Snowflake roles.
- Defined Okta groups:
  - `snowflake-prod-account-admin` (small set, JIT-elevated)
  - `snowflake-prod-data-engineer`
  - `snowflake-prod-analyst`
  - `snowflake-staging-power-user`
  - ... etc.
- Documented per-group → per-Snowflake-role mapping in the IaC (Terraform).

### Week 3 — SAML configuration

- Generated Snowflake SCIM token; configured Okta SCIM with the token.
- Tested with a synthetic account: created in Okta, push to Snowflake, sign in via SAML, verified the role mapping fired.

### Week 4 — SCIM provisioning

- Bulk-imported existing Snowflake users into Okta groups based on their existing Snowflake role assignments.
- Verified SCIM sync: Okta group membership change reflected in Snowflake within minutes.

### Week 5-6 — User cutover

- Per-user cutover: enable SSO for the user; disable local password; the user signs in via Okta from now on.
- Phased rollout (small groups per day) so the helpdesk could absorb questions.
- Communications: Slack announcement, email, internal wiki update.

### Week 7 — Deactivation testing

- Tested SCIM deactivation: marked a synthetic account as `active: false` in Okta; verified Snowflake user disabled within minutes; verified existing Snowflake session failed on next query.
- Discovered a Snowflake-specific gap: long-lived service users (programmatic-only) didn't go through SCIM; needed a parallel cleanup track.

### Week 8 — Cleanup and detection

- Disabled local password authentication for all users (Snowflake `DISABLE_USERNAME_PASSWORD = TRUE`).
- Removed local MFA enrollment (Okta MFA is the source of truth now).
- Added SIEM detection on:
  - SAML assertion errors (someone trying to bypass).
  - Service-user authentication patterns (separate from human-user expected pattern).
- Documented the federation in a runbook.

### Findings opened during the campaign

- **FED-001** (Snowflake on local auth bypassed Okta conditional access). Closed by SAML federation.
- **FED-002** (Manual user provisioning had multi-day lag). Closed by SCIM auto-provisioning.
- **FED-003** (Inconsistent deactivation on offboarding). Closed by SCIM deactivation.
- **FED-004** (Service-user accounts not in SCIM scope). Documented; tracked in parallel cleanup.
- **FED-005** (No detection on SAML assertion errors). Closed by SIEM rule.

The campaign cost ~6 person-weeks of effort. Maintenance: ~0.1 FTE / quarter for ongoing operation.

---

## Anti-patterns

### 1. Wildcard role mapping on the SP side

`group: meridian-* → Admin`. Future group naming patterns inherit Admin unexpectedly.

The fix: explicit per-group mapping; review group→role mappings quarterly.

### 2. Trusting user-editable attributes for authorization

Department field that the user can change via HRIS self-service is mapped to access decisions. User changes department → access changes.

The fix: only IdP-administered attributes for authorization; review attribute provenance.

### 3. Skipping audience-restriction enforcement

SAML SP accepts assertions regardless of `Audience` claim. Attacker can replay an Assertion intended for app B against app A.

The fix: enforce audience restriction; test by attempting a replay.

### 4. The IdP-metadata-static-pin without rotation

The SP is configured with the IdP's certificate; the certificate is never rotated; expiration day = outage.

The fix: metadata-URL-based trust (SP re-fetches IdP metadata periodically), or scheduled key rotation with multi-key support.

### 5. SCIM provisioning without deprovisioning

Users get created; users don't get deactivated. Orphan accounts accumulate.

The fix: verify deactivation works; reconcile monthly.

### 6. Cross-tenant guest with broad permissions

Entra B2B guest user invited with default permissions = Member; the guest can read most resources in the host tenant.

The fix: guest users granted explicit narrow scope; quarterly review.

### 7. "We federated, the audit trail is in the IdP"

The team assumes IdP sign-in logs are the audit trail and doesn't ingest cloud-side post-authentication audit. Account compromise leaves only the IdP-side trail.

The fix: SIEM ingests both IdP logs and cloud-side audit; cross-system correlation.

### 8. Hand-rolled SAML / OIDC validation

A small Lambda / function that "validates SAML assertions" without using a tested library. Almost always missing one of the checks.

The fix: use a tested library; the major language ecosystems have one (passport-saml, python3-saml, ruby-saml, Microsoft.IdentityModel, etc.).

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| FED-001 | App on local-auth bypasses corporate IdP federation | High | Migrate to SAML / OIDC; disable local auth | Identity + App Owner |
| FED-002 | Manual user provisioning with multi-day lag | Medium | SCIM auto-provisioning; HRIS-to-IdP sync | Identity + HR |
| FED-003 | SCIM deactivation not verified to actually deactivate | High | Synthetic-account test; verify session termination + token revocation | Identity + App Owner |
| FED-004 | Service users / API tokens not covered by SCIM | Medium | Parallel cleanup track; document service-user inventory | Identity + Security Eng |
| FED-005 | No detection on SAML / OIDC assertion errors | Medium | SIEM rule on assertion-validation failures | Detection Eng + Identity |
| FED-006 | Wildcard role mapping on SP side | High | Explicit per-group mapping; quarterly review | Identity + App Owner |
| FED-007 | User-editable IdP attribute used for authorization | High | Restrict authorization to IdP-administered attributes | Identity + Security Eng |
| FED-008 | SAML audience restriction not enforced | High | Verify SP enforces `Audience`; test with replay | Security Eng |
| FED-009 | SAML signing certificate pinned without rotation discipline | Medium | Metadata-URL-based trust; or multi-key rotation | Identity + Security Eng |
| FED-010 | Orphan accounts in apps (SCIM sync failures) | Medium | Monthly reconciliation; cleanup; investigate sync gap | Identity |
| FED-011 | Entra B2B guest users have broad default permissions | Medium | Restrict guest scope; quarterly review | Identity + Security Eng |
| FED-012 | Cloud-side audit not ingested into SIEM | Medium | SIEM ingestion; cross-system correlation with IdP logs | Detection Eng |
| FED-013 | Hand-rolled SAML / OIDC validation in custom app | High | Migrate to tested library | App Owner + Security Eng |
| FED-014 | OAuth implicit flow in use for SPA | Medium | Migrate to Authorization Code + PKCE | App Owner + Security Eng |
| FED-015 | Client_secret not in secrets manager | Medium | Migrate to secrets manager; rotation policy | DevOps + Security Eng |
| FED-016 | NameID format = email; rename breaks identity binding | Low | Migrate to persistent NameID where supported | Identity + App Owner |
| FED-017 | Third IdP layered without justification | Medium | Re-evaluate; remove if not justified | Identity + Security Eng |
| FED-018 | Cross-cloud federation via long-lived access keys | High | Workload Identity Federation per [workload-identity.md](./workload-identity.md) | Security Eng + Cloud Foundation |

---

## Adoption checklist

- [ ] All apps on SAML or OIDC; no local-auth bypass paths.
- [ ] Per-app SCIM provisioning enabled where supported.
- [ ] Per-app SCIM deactivation verified by synthetic test.
- [ ] Monthly reconciliation between IdP and each app's user list.
- [ ] Per-app group-to-role mapping in IaC.
- [ ] No wildcard role mappings.
- [ ] Authorization based on IdP-administered attributes only.
- [ ] SAML audience restriction enforced per app.
- [ ] SAML signing certificate rotation pattern documented and tested.
- [ ] OAuth flows reviewed; no implicit flow; PKCE for SPAs.
- [ ] Client secrets in secrets manager; rotation policy.
- [ ] Cross-cloud workload access via Workload Identity Federation.
- [ ] Cross-tenant B2B guests have explicit narrow scope.
- [ ] SIEM ingests IdP sign-in logs + cloud audit + SaaS audit; cross-system correlation.
- [ ] SAML / OIDC assertion-error alerts in SIEM.
- [ ] No hand-rolled SAML / OIDC validation in custom code.
- [ ] IdP metadata refresh pattern: metadata-URL-based or scheduled rotation.
- [ ] Per-app federation runbook (configuration, rotation, recovery).

---

## What this document is not

- **A complete SAML / OIDC specification reference.** The relevant standards (SAML 2.0, RFC 6749, RFC 6750, OpenID Connect Core) are the authoritative source.
- **A SCIM specification reference.** RFC 7643 / 7644.
- **An IdP-administration guide.** Entra ID, Okta, Google Workspace each have their own administrative depth.
- **A complete workforce-identity guide.** [workforce-identity.md](./workforce-identity.md) covers the strategic layer.
- **A workload-identity guide.** [workload-identity.md](./workload-identity.md) covers service-to-cloud federation.
- **A SAML / OIDC library reference.** Per-language libraries have their own documentation.
