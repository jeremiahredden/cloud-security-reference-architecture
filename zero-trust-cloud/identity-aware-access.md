# Identity-Aware Access

A practitioner's reference for identity-aware proxies in cloud environments — Cloudflare Access, AWS Verified Access, GCP Identity-Aware Proxy, and homegrown patterns (envoyproxy + JWT, nginx + auth-request). The patterns here cover the "retire the corporate VPN" adoption sequence (the most user-visible Zero Trust win), the user-experience trade-offs that determine whether the rollout succeeds, and the integration with workforce identity that makes the pattern operate at scale.

This document opens the zero-trust-cloud folder. It is intentionally the first because the README is opinionated: workforce identity-aware access is the first move in any ZT adoption — it retires the corporate VPN, which produces the most user-visible benefit, which produces the political capital for subsequent moves. The patterns here are mature in 2026; the adoption is mostly about sequencing rather than capability gaps.

For the workload-side identity that makes service-to-service ZT work, see [workload-identity-zt.md](./workload-identity-zt.md). For the broader ZT adoption sequence, see [zt-adoption-sequence.md](./zt-adoption-sequence.md). For the IAM patterns this builds on, see [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md) and the broader workforce-IAM context.

---

## When to read this document

**If your organization still uses a corporate VPN for internal-application access** — read top to bottom. The VPN-retirement pattern via identity-aware access is the high-leverage first move.

**If your leadership wants a Zero Trust roadmap** — start with [The retire-the-VPN sequence](#the-retire-the-vpn-sequence). It's the visible win that justifies further investment.

**If you've deployed an identity-aware proxy but adoption stalled** — start with [The user-experience pitfalls](#the-user-experience-pitfalls). Most stalled rollouts trace to UX issues that the team could have anticipated.

**If you are auditing identity-aware access posture** — start with [Findings checklist](#findings-checklist).

---

## What identity-aware access is

The classic remote access pattern:

```
User → VPN → Corporate network → Application
```

The user connects to a VPN; once inside the corporate network, they reach internal applications. The VPN authenticates the user once (at connection); subsequent access is implicit (the user is "inside").

The identity-aware access pattern:

```
User → Identity-aware proxy → Application
```

Every request to the application is authenticated by the proxy. The user's identity, device, and context are evaluated for each request (or at least each session). There is no "inside" — every request is authenticated and authorized.

### What the proxy provides

- **Authentication** at every request (or session, with refresh).
- **Authorization** based on user identity, group membership, device posture, context.
- **Audit logging** per request.
- **Session management** with re-authentication on context changes.
- **No corporate network membership required** — the user can be anywhere on the internet.

### Why this matters

The VPN model has well-known problems:

- **Implicit trust** once inside the corporate network. A compromised user account or device has broad lateral access.
- **Operational complexity** — VPN concentrators, certificates, routing, DNS.
- **User experience** — VPN client install, connection management, performance issues.
- **Bypass for remote workers** — many users complain about VPN; some find ways around (split tunneling misconfigurations, unauthorized SaaS use).

Identity-aware access addresses all four; the trade is configuring per-application access policies and integrating with the workforce identity provider.

---

## The retire-the-VPN sequence

The structural play for most organizations. Adoption in phases.

### Phase 1: pilot with the highest-value internal application

- Identify one internal application that's high-value (heavily used) and contained.
- Deploy the identity-aware proxy in front of it.
- Make it accessible *without* VPN.
- Let users opt in.

Within weeks, users report better experience for that application. Word spreads.

### Phase 2: expand to the next ~10 applications

- Add more internal applications behind the proxy.
- Users still need VPN for the rest; the migration is gradual.
- Each application's policy is configured per its needs.

### Phase 3: retire the VPN for the migrated user population

- For users whose primary internal-access needs are now via the proxy, retire the VPN.
- Keep VPN available for legacy applications not yet migrated.

### Phase 4: continue migration; eventually deprecate VPN

- All internal applications behind the proxy.
- VPN deprecated for general use.
- VPN may remain for specific scenarios (legacy networking, third-party tools that don't speak HTTP).

The sequence takes 6–18 months for a typical organization. The first phase produces measurable user-experience improvement; subsequent phases build on that momentum.

### What "internal application" means

Applications hosted on the organization's infrastructure (cloud or on-prem) that should be accessible only to organizational users:

- Internal wikis, dashboards, admin UIs.
- Engineering tools (Jira, Confluence, internal Grafana).
- Developer environments (internal Kubernetes dashboards, internal SaaS).
- Customer-support tools.

Applications already accessible via the public internet with their own auth (e.g., the SaaS product itself) are out of scope; they're already not behind the VPN.

---

## The tool options

The dominant identity-aware access products in 2026.

### Cloudflare Access

- Part of the Cloudflare Zero Trust suite.
- Routes traffic through Cloudflare's edge.
- Integrates with Okta, Azure AD, Google Workspace, SAML, OIDC.
- Per-application access policies.
- Strong device-posture integration (with Cloudflare's WARP client).

Best for: SaaS organizations, organizations with a Cloudflare relationship, multi-cloud environments.

### AWS Verified Access

- AWS-native identity-aware proxy.
- Routes traffic through AWS infrastructure.
- Integrates with IAM Identity Center, Okta, SAML.
- Per-application access policies via Cedar policy language.
- Strong integration with AWS-hosted applications.

Best for: AWS-centric organizations with internal applications on AWS.

### GCP Identity-Aware Proxy (IAP)

- GCP-native identity-aware proxy.
- Routes traffic through Google's infrastructure.
- Integrates with Google Workspace, third-party IdPs.
- Per-resource IAM policies.
- Tightest integration with GCP-hosted applications.

Best for: GCP-centric organizations; Google Workspace-heavy organizations.

### Azure App Proxy / Entra Application Proxy

- Microsoft's identity-aware proxy.
- Routes traffic through Microsoft's edge.
- Integrates tightly with Entra ID / Azure AD.
- Per-application Conditional Access policies.

Best for: Microsoft-heavy organizations; on-prem applications needing Entra ID-aware access.

### Homegrown patterns

For organizations preferring an open-source / custom approach:

- **Envoy + JWT validation.** Envoy proxy in front of applications; validates JWTs issued by the IdP.
- **nginx + auth-request.** nginx with `auth_request` directive calling an auth service.
- **OAuth2 proxy.** Reverse proxy in front of applications; handles OAuth/OIDC flow.

Best for: organizations with strong open-source preference; specific integration needs that productized solutions don't cover.

### The decision

For most organizations: a productized solution. Cloudflare Access if multi-cloud or already-Cloudflare; Verified Access for AWS-centric; IAP for GCP-centric; Entra App Proxy for Microsoft-centric.

Homegrown patterns are reserved for teams that have engineering capacity and specific reasons to avoid the productized options.

References:
- [Cloudflare Access](https://www.cloudflare.com/products/zero-trust/access/)
- [AWS Verified Access](https://aws.amazon.com/verified-access/)
- [GCP IAP](https://cloud.google.com/iap)
- [Entra App Proxy](https://learn.microsoft.com/en-us/entra/identity/app-proxy/)

---

## The user-experience pitfalls

Most stalled Zero Trust rollouts trace to UX issues. The patterns to avoid.

### 1. Re-authentication too often

The proxy re-authenticates on every request, or on a very short session. Users see auth prompts constantly; the experience is worse than VPN; adoption stalls.

The fix: long-lived sessions (8–24 hours) with risk-based re-evaluation. Re-auth on context changes (new IP, new device, sensitive action), not on every request.

### 2. SSO integration that requires re-entry

The proxy's SSO integration redirects to the IdP; the IdP requires the user to enter credentials again even though they're already signed in elsewhere.

The fix: silent SSO (the IdP recognizes the existing session and signs the user in without prompts).

### 3. The "different from VPN" learning curve

Users are accustomed to "connect VPN; reach everything." The proxy model requires per-application access; users find the mental model unfamiliar.

The fix: bookmark / launcher tooling that surfaces all accessible applications in one place. Documentation. Onboarding sessions.

### 4. The "broken on mobile" rollout

The proxy works on laptops but mobile users hit different issues (browser SSO, mobile-app integrations).

The fix: test mobile early; per-platform UX validation; mobile-app integration via OIDC where possible.

### 5. The over-strict device posture

Device-posture checks (e.g., requiring a specific OS version, requiring MDM enrollment) block legitimate users. Engineers on personal laptops, contractors, third-party support — all locked out.

The fix: graduated posture — different tiers of access based on device posture. Strict posture for sensitive applications; lax posture for general access.

### 6. The break-glass that takes forever

A user can't reach an application; the help-desk has to provision a temporary bypass; it takes hours or days.

The fix: self-service break-glass with MFA + manager approval; documented escalation path.

### 7. The slow proxy

The proxy adds latency. For latency-sensitive applications, the user experience degrades.

The fix: edge-based proxies (Cloudflare, IAP) minimize latency; regional proxies for AWS Verified Access.

### 8. The "still need VPN for one thing" frustration

Users have moved most access to the proxy. One legacy application still requires VPN. Users keep the VPN client installed and active "just in case." The VPN-retirement value is partially lost.

The fix: priority migration of remaining VPN-required applications; communicate the timeline; commit to retiring VPN by a specific date.

---

## Per-application access policies

The proxy enforces policies per application.

### Policy elements

- **Identity:** which users, which groups.
- **Device:** OS version, MDM enrollment, EDR present, disk encryption.
- **Context:** time of day, geolocation, IP reputation.
- **Authentication strength:** MFA required, hardware-key required.
- **Session:** session length, re-auth triggers.

### Example: AWS Verified Access policy

Verified Access uses Cedar:

```cedar
permit (
    principal in IamIdentityCenter::Group::"engineering",
    action == VerifiedAccess::Action::"http",
    resource == VerifiedAccess::Endpoint::"internal-grafana"
)
when {
    context.identity.user.email like "*@meridian.health" &&
    context.device.compliance.required == true &&
    context.mfa.authenticated == true
};
```

The policy allows users in the `engineering` IAM Identity Center group to reach `internal-grafana` if:

- Email is `@meridian.health` domain.
- Device is MDM-compliant.
- MFA authenticated.

### Example: Cloudflare Access policy

Cloudflare's policy syntax:

```
Include: Emails ending in "@meridian.health"
Include: Groups: Engineering
Require: Multi-factor authentication
Require: Healthy device (Cloudflare WARP)
Require: Country not in [list of restricted countries]
```

### Tiered policies per application sensitivity

- **Low-sensitivity internal apps:** SSO only; long session.
- **Medium-sensitivity:** SSO + MFA; medium session.
- **High-sensitivity (admin tools, financial systems):** SSO + MFA + healthy device; short session.
- **Privileged:** SSO + hardware-key MFA + device + manager approval per session.

The tiering aligns access strength to application risk.

---

## Workforce identity integration

Identity-aware access is only as good as the identity provider behind it.

### The IdP options

- **Okta:** widely deployed; rich integration ecosystem.
- **Entra ID (Azure AD):** Microsoft-native; tight integration with Microsoft tools.
- **Google Workspace:** Google-native.
- **JumpCloud, OneLogin, Auth0:** alternatives.

### The integration pattern

- IdP is the source of truth for users and groups.
- Identity-aware access proxy delegates authentication to the IdP via OIDC or SAML.
- Group membership in IdP drives access policy in the proxy.
- IdP MFA is the MFA factor for the proxy.

### Group-based access

Application access is policy-driven by group membership:

- `engineering` group can reach engineering tools.
- `customer-success` group can reach customer-data tools.
- `finance` group can reach financial systems.
- `admin` group can reach admin tools (typically with additional MFA / device requirements).

The discipline: per-application access policy references groups; group membership is managed in the IdP via standard provisioning flows.

### Just-in-time access

For privileged access: just-in-time (JIT) elevation:

- User requests temporary access to a sensitive application.
- Manager approves via the IdP's workflow.
- IdP adds user to a time-bound group.
- Identity-aware access proxy honors the new group membership; user has access for the duration.
- After the time expires, the group membership is removed; access drops.

The pattern: standing privileged access becomes time-bound; the audit trail is clear.

Tools: Okta Privileged Access, AWS IAM Identity Center JIT, custom workflows with IdP APIs.

---

## Device posture

Identity-aware access can be paired with device posture for stronger conditional access.

### What device posture signals

- **OS version** — patched / unpatched.
- **MDM enrollment** — managed / unmanaged.
- **Disk encryption** — encrypted / unencrypted.
- **EDR present** — yes / no.
- **Configuration compliance** — patched, antivirus, firewall, etc.

The signals come from the device's MDM agent or from the IdP's device trust mechanism (Okta Device Trust, Entra Conditional Access, Cloudflare WARP).

### Per-application device requirements

- **General-access applications:** no device requirements (any device with valid SSO).
- **Standard applications:** managed device.
- **Sensitive applications:** managed device + healthy posture.
- **Privileged applications:** managed device + hardware key + healthy posture.

The graduation aligns device requirements to application risk.

### The BYOD trade-off

For organizations supporting Bring Your Own Device:

- Users can access general-access applications from any device.
- Higher-tier applications require company-issued or company-managed device.
- BYOD users can use VDI / browser-isolation for higher-tier access.

The pattern: don't try to enforce strict device posture on BYOD; offer alternative paths (VDI, browser isolation) for those who need elevated access without a company-managed device.

---

## Continuous authorization (briefly)

The deeper Zero Trust ideal — beyond authentication at session start, continuous re-evaluation.

### What continuous authorization adds

- **Mid-session re-evaluation:** the user's session is re-validated against current device posture.
- **Step-up authentication:** sensitive actions trigger additional auth (re-MFA, biometric verification).
- **Context-aware revocation:** if the user's device falls out of compliance mid-session, access drops.
- **Risk scoring:** behavioral signals (anomalous access patterns, geo-distance violations) trigger re-auth.

### Tool support

- **Okta Identity Engine** supports continuous authorization patterns.
- **Entra Conditional Access** has continuous-access-evaluation.
- **Cloudflare Zero Trust** has session-re-evaluation features.

### The under-engineered state

Most organizations in 2026 stop at the session-establishment authentication and don't implement continuous re-evaluation. The pattern is feasible; the engineering investment is meaningful.

For detail on continuous authorization patterns: [continuous-authorization.md](./continuous-authorization.md).

---

## Worked example: Meridian Health's identity-aware access

Meridian deployed Cloudflare Access in 2024 for internal applications, retiring the corporate VPN for most users over 12 months.

### The starting state (early 2024)

- Corporate VPN (Cisco AnyConnect) for all internal access.
- ~50 internal applications behind the VPN.
- Frequent user complaints about VPN reliability and performance.
- Workforce identity in Okta.

### The deployment

- **Cloudflare Access** deployed; integrated with Okta for SSO.
- **Per-application policies** authored.
- **Cloudflare WARP client** for device posture.

### Phase 1 pilot (Sprint 1–2)

Selected the internal Grafana dashboard (heavily used by SRE; contained; non-sensitive). Deployed behind Cloudflare Access. Allowed engineering-group access without VPN.

Result: SRE users adopted immediately. Anecdotal feedback was overwhelmingly positive. "Why doesn't everything work this way?"

### Phase 2 expansion (Sprints 3–10)

Added 30 internal applications:

- Internal wikis (Confluence, Notion).
- Engineering tools (Jira, internal Argo CD, internal Sentry).
- Customer-success tools (internal admin dashboards).
- Finance tools (read-only access to internal cost dashboards).

Each application's policy was tuned to its needs:

- Wikis: SSO only; long session.
- Engineering tools: SSO + MFA.
- Customer-success and finance: SSO + MFA + managed device.
- Admin tools: SSO + MFA + managed device + hardware key.

### Phase 3 VPN retirement (Sprints 11–14)

For users whose access needs were met by the proxy, VPN was disabled. About 70% of the workforce had no VPN need by the end of Phase 3.

### Phase 4 ongoing (Sprint 15+)

Remaining 20% of users still need VPN for specific legacy applications (some on-prem services that don't speak HTTP, some third-party tools that require IP allowlisting). Migration of these continues.

### Per-application policies

Example for the internal admin dashboard:

```
Identity: User in Okta group "platform-admins"
Authentication: MFA required (hardware key or Okta Verify)
Device: WARP installed; OS version current; disk encrypted
Session: 8-hour session; re-auth on new IP
```

### Findings opened during the IAA audit

- **IAA-001** (corporate VPN was the only remote-access mechanism; all-or-nothing access model). Closed by Cloudflare Access deployment.
- **IAA-002** (no per-application access policies; everyone-or-no-one for each application). Closed by tiered policies aligned to application sensitivity.
- **IAA-003** (no device-posture integration; access from any device). Closed by WARP integration for managed devices.
- **IAA-004** (just-in-time access not available for privileged applications; standing privileged access). Closed by Okta Privileged Access integration.
- **IAA-005** (session length set to 1 hour for all applications; users complained of constant re-auth). Closed by tiered session length per application sensitivity.
- **IAA-006** (audit logs not consumed by SIEM; access patterns invisible). Closed by Cloudflare Logpush to Splunk.

---

## Anti-patterns

### 1. The keep-the-VPN-as-fallback indefinite

The team deploys identity-aware access for some applications but never retires the VPN. Users keep the VPN client; the dual-mode produces no operational simplification.

The fix: commit to VPN retirement timeline; migrate remaining applications; deprecate VPN on schedule.

### 2. The over-strict policy that locks users out

Policies require managed devices and hardware keys for general access. Users without those (most users) are locked out. The proxy is "deployed" but unusable.

The fix: tiered policies aligned to application sensitivity; general access has lower requirements.

### 3. The under-strict policy that's just SSO

Every application uses the same policy: SSO only, no MFA, no device check. The proxy is a more elaborate version of "the user is logged in." No real Zero Trust posture.

The fix: tiered policies; MFA at minimum for non-public applications.

### 4. The audit-log-not-consumed

Access events go to the proxy's logs; nobody consumes them. Detection signal absent.

The fix: SIEM consumption; detection rules on access patterns.

### 5. The forgot-mobile rollout

The rollout focused on laptops. Mobile users hit different issues; help-desk burden grows.

The fix: per-platform testing during pilot; mobile-app integration planned.

### 6. The break-glass that's a Slack message

Users locked out file Slack requests; help-desk manually grants access. The break-glass is informal; audit trail is poor.

The fix: formal break-glass workflow with MFA + manager approval; documented; audited.

### 7. The single-point-of-failure proxy

The proxy is the sole access path. A proxy outage takes all internal applications offline.

The fix: proxy HA (built into productized solutions); fallback path for emergencies.

### 8. The forever-pilot

The team deploys identity-aware access for the pilot application; never expands. The momentum is lost; the broader migration doesn't happen.

The fix: timeboxed pilot with explicit success criteria; commitment to expansion phase.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| IAA-001 | Corporate VPN is the only remote-access mechanism | High | Deploy identity-aware proxy; phased VPN retirement | IT + Security Eng |
| IAA-002 | No per-application access policies; everyone-or-no-one | High | Tiered policies aligned to application sensitivity | IT + Security Eng |
| IAA-003 | No device-posture integration; access from any device | Medium | Device-trust integration (WARP, Okta Device Trust, Entra Conditional Access) | IT + Security Eng |
| IAA-004 | No just-in-time access for privileged applications; standing privileged access | High | JIT pattern via Okta PA / IAM Identity Center JIT / custom workflow | Security Eng + IAM Eng |
| IAA-005 | Session length not tuned per application sensitivity | Low | Tiered session length: long for low-sensitivity, short for high | Security Eng |
| IAA-006 | Audit logs not consumed by SIEM | Medium | Log shipping; detection rules on access patterns | Security Eng + SOC |
| IAA-007 | MFA not required for non-public applications | High | MFA required for all internal applications | Security Eng + IAM Eng |
| IAA-008 | VPN retirement timeline absent; pilot stalled | Medium | Commit to retirement date; migrate remaining applications | IT + Security Eng |
| IAA-009 | Break-glass workflow informal (Slack messages) | Medium | Formal break-glass with MFA + manager approval; audit trail | IT + Security Eng |
| IAA-010 | Proxy without HA; single point of failure | High | Productized solutions are HA; verify; fallback path for emergencies | Platform Eng + IT |
| IAA-011 | Mobile experience not tested; help-desk burden | Low | Per-platform UX validation; mobile app integration | IT |
| IAA-012 | Per-application policies hand-managed; drift over time | Medium | Policy-as-code; IaC for policy management | DevOps + Security Eng |
| IAA-013 | Group-based access via static groups; no JIT or temporary elevation | Medium | JIT group membership via IdP; time-bound elevation | IAM Eng + Security Eng |
| IAA-014 | Continuous authorization not implemented; session re-evaluation absent | Low | Continuous authorization patterns; per [continuous-authorization.md](./continuous-authorization.md) | Security Eng + IAM Eng |
| IAA-015 | Device-posture requirements too strict; legitimate users blocked | Medium | Tiered posture by application; BYOD path via VDI / browser isolation | IT + Security Eng |
| IAA-016 | Identity-aware access works for HTTP only; legacy non-HTTP services still need VPN | Low | Identify legacy services; modernize or accept VPN tail; document | Architecture + IT |
| IAA-017 | IdP integration fragile; SSO breaks if IdP fails | Medium | IdP HA; documented IdP-outage response; emergency bypass | IT + IAM Eng |
| IAA-018 | Policy review absent; policies drift from current security posture | Medium | Quarterly review; verify policies match current sensitivity and group membership | Security Eng |

---

## What this document is not

- **A complete Cloudflare / Verified Access / IAP administration reference.** Vendor documentation covers operational depth.
- **A workforce IdP guide.** Okta, Entra ID, Google Workspace administration are their own large topics.
- **A device-management reference.** MDM choice (Jamf, Intune, Kandji) belongs with endpoint management.
- **A complete Zero Trust adoption guide.** The full adoption sequence lives in [zt-adoption-sequence.md](./zt-adoption-sequence.md); this document focuses on identity-aware access specifically.
