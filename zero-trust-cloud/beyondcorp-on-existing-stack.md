# BeyondCorp on an Existing Stack

A practitioner's reference for landing the BeyondCorp / Zero Trust vision in an environment that already exists — corporate VPN, on-prem applications, mixed-cloud, legacy apps, SAML federation in production. The honest framing: most Zero Trust failures aren't technical, they're scope. Teams adopt a greenfield ZT platform that requires every app to migrate before delivering value; that migration takes years and gets cancelled. The additive-overlay pattern delivers value in months without ripping out anything.

This document closes a gap in the zero-trust-cloud folder: [identity-aware-access.md](./identity-aware-access.md), [workload-identity-zt.md](./workload-identity-zt.md), [microsegmentation.md](./microsegmentation.md), [mtls-everywhere.md](./mtls-everywhere.md), [continuous-authorization.md](./continuous-authorization.md), and [zt-adoption-sequence.md](./zt-adoption-sequence.md) all cover the building blocks of a Zero Trust posture. This document covers the meta-strategy: how to assemble those blocks when your starting point is "we already have VPN, Okta, 80 internal apps, and a Cisco ASA in 2026."

The reason this document is its own: the BeyondCorp papers from Google describe the destination beautifully but skip the migration. The "rip-and-replace" SaaS-ZT vendors describe a migration that, in real environments, doesn't complete. The pattern that *does* work — additive overlay, app-by-app retirement of VPN dependencies — is under-documented; this document fills that gap.

---

## When to read this document

**If you have an existing corporate VPN and a directive to "implement Zero Trust"** — read top to bottom.

**If you have a greenfield-ZT vendor RFP on the table and want to evaluate whether it makes sense** — start with [The greenfield-ZT trap](#the-greenfield-zt-trap).

**If you've started ZT, made some progress, and are stuck on legacy applications** — start with [Legacy-app patterns](#legacy-app-patterns).

**If you're sequencing the rollout for executive sign-off** — start with [The six-quarter adoption arc](#the-six-quarter-adoption-arc).

---

## The BeyondCorp destination, briefly

Where you're trying to end up. The full destination is documented across the other zero-trust-cloud docs; the summary:

- **Identity replaces network as the trust anchor.** "Connected to the VPN" no longer implies access; "this identity, with this device posture, requesting this resource" implies access.
- **Every request is authenticated and authorized at the application layer.** No "trusted internal network."
- **Device posture is a real signal.** A managed, patched, enrolled device with disk encryption is permitted scopes a personal phone is not.
- **Network controls are still present as defense in depth.** Segmentation, mTLS, egress control — but they're not the primary access decision.
- **Access decisions are reevaluated continuously.** Login + token isn't the end of authorization; signals during the session can revoke access.

If you read the Google BeyondCorp papers, this is the model. The papers focus on the corporate-IT use case (employee accessing internal apps); the model extends to workload-to-workload (covered in [workload-identity-zt.md](./workload-identity-zt.md)).

---

## The greenfield-ZT trap

Why the most-visible-and-expensive option is usually wrong.

### The vendor pitch

"Replace your VPN and your existing identity infrastructure with our ZT platform. Every app is reachable only through us; we enforce identity, device, and policy. You'll never need network controls again."

The platforms exist (Zscaler ZPA, Palo Alto Prisma Access, Netskope Private Access, Cloudflare One, AWS Verified Access for the cloud-native cousin). They're capable products. They're also a multi-year migration with two failure modes:

1. **The "we can't migrate the SCADA app" failure.** The legacy app has a thick-client requirement, weird port behaviors, or active-directory deep dependencies that don't fit the ZT platform's connector model. The migration stalls. The VPN stays for "just this one app." Then "just these five apps." Then forever.

2. **The "we replaced the VPN with another single point of failure" failure.** All app access flows through one vendor's connector cloud. If the vendor has an outage, no internal app is reachable. The "no more network" promise is technically true and operationally identical to "now we have one big network controlled by the vendor."

### Why teams pick it anyway

- Executive directive ("Zero Trust by Q4") and the vendor's pitch deck makes the timeline plausible.
- Procurement preference for "one throat to choke."
- The team genuinely doesn't have the engineering bandwidth to assemble the pieces.

### When the greenfield-ZT vendor IS the right answer

- The environment is small enough that all-at-once migration is feasible (under 50 internal apps, no exotic legacy).
- The team genuinely lacks the engineering capacity for incremental rollout and a vendor with a managed connector model is the only realistic path.
- A specific compliance or regulatory requirement names the vendor or names a capability only the vendor delivers.
- The existing identity provider doesn't support the modern OIDC / OAuth patterns and replacement is in scope anyway.

### When the greenfield-ZT vendor is NOT the right answer

- A large existing app portfolio (100+ internal apps) with a long tail of legacy.
- An existing identity provider (Entra ID, Okta, Google Workspace) that supports the modern patterns.
- A team that wants to retain control over the architecture (and the budget).
- A risk profile where "vendor outage = no internal apps reachable" is unacceptable.

For most teams the additive overlay pattern, below, gets to the same destination with more flexibility and less risk.

---

## The additive overlay pattern

The strategy that works on existing stacks.

### The principle

Don't replace the existing access path. Add a parallel path. Migrate apps to the new path one at a time. Retire the old path when the last app is migrated.

```
                                    ┌─────────────────┐
                                    │  Internal App   │
                                    └────────▲────────┘
                                             │
                              ┌──────────────┴───────────────┐
                              │                              │
                  ┌───────────┴───────────┐    ┌─────────────┴──────────────┐
                  │  Existing VPN path    │    │   New IAP path             │
                  │  (still works)        │    │   (additive)               │
                  └───────────▲───────────┘    └─────────────▲──────────────┘
                              │                              │
                              │                              │
                  ┌───────────┴───────────────────────────────┴──────────────┐
                  │                  User on managed laptop                  │
                  └──────────────────────────────────────────────────────────┘
```

### The properties

- **No "big bang."** Apps migrate when they're ready.
- **Always-on rollback.** If the new path fails for an app, the VPN path is still there.
- **Measurable progress.** "N apps on the new path, M apps still on VPN" is a metric leadership can act on.
- **Incremental learning.** Each app migration teaches the team about edge cases. The first ten apps are slow; the next ninety are fast.

### The retirement

Once the last app migrates off VPN, the VPN is retired. The retirement is the punctuation mark on the adoption arc, not the trigger for it. Many teams retire VPN at month 18-24; some keep a VPN for specific edge cases (third-party contractor access, vendor remote-hands, legacy SCADA) indefinitely. Both are fine.

### What this gives up

The "we can fire the network team" narrative. The additive overlay keeps the existing network operational throughout the migration. That's a feature (less risk) and a cost (continued operational expense). Most teams don't actually want to fire the network team; they want the network team to spend time on better problems than VPN tickets.

---

## The components you assemble

What goes into the overlay.

### 1. Identity-aware proxy (IAP)

The front door to internal apps. Apps move behind the IAP one at a time.

Pattern documented in [identity-aware-access.md](./identity-aware-access.md). Options:
- **Cloudflare Access:** rich device-posture and per-app policy, managed connectors, lowest engineering lift.
- **AWS Verified Access:** native to AWS, good for AWS-hosted apps, weaker for hybrid.
- **GCP Identity-Aware Proxy:** native to GCP, similar trade-offs.
- **Pomerium / Tailscale Access / Teleport:** self-hosted alternatives, good when vendor-cloud is not acceptable.
- **Envoy / nginx + JWT validator:** roll-your-own, highest engineering lift, most control.

The choice is one of the few major decisions in the overlay; the rest of the pattern is mostly the same regardless.

### 2. Identity provider (existing)

You probably have Okta / Entra ID / Google Workspace. Don't replace it. The IAP integrates with it via OIDC or SAML. The existing federation contracts (SAML-to-internal-app, OIDC-to-SaaS) continue working alongside the IAP path.

If the existing IdP doesn't support modern patterns (e.g., legacy AD FS without OIDC), that's the one piece worth modernizing before starting; otherwise leave it alone.

### 3. Device posture signal

The IAP needs a signal: is this device managed?

- **Okta Verify** (Okta) or **Microsoft Authenticator** (Entra ID) or **Google Endpoint** (Google Workspace) — these provide a device-trust attribute the IAP can read.
- **CrowdStrike Falcon Zero Trust Assessment** or **SentinelOne** — EDR products with ZT-signal integrations.
- **Cloudflare WARP client** — Cloudflare's device-posture agent.
- **Jamf / Intune / Workspace ONE** — MDM-attested signals.

The pattern: the IAP queries the device-posture provider on access; if the device isn't managed, the IAP denies (or steps up auth).

### 4. Per-app policy

The IAP's policy engine: who can access what, under what conditions.

The starting policy: every authenticated user with a managed device. Tighten per-app:
- HR app: only HR team.
- Finance app: only Finance team + audit role.
- Production database admin tool: only DBA team, with hardware-token MFA.

The policy lives in IaC (Terraform provider for the IAP); changes go through PR review.

### 5. Network controls (existing, simplified)

The existing network controls (VPC security groups, on-prem firewalls, NAT, ALB) stay in place. The IAP fronts the app; the app's network policy is whatever it was. Over time, network policy can tighten to "only the IAP can reach this app" — but that's a follow-on, not a prerequisite.

### 6. Workload-identity migration (parallel track)

Workload-to-workload access (services calling other services) is the other half of ZT. Pattern in [workload-identity-zt.md](./workload-identity-zt.md). Runs as a parallel migration: every service moves off long-lived credentials to SPIFFE / managed-identity / workload-identity-federation.

The two tracks (human access via IAP, service access via workload identity) are independent — sequence them in parallel.

---

## Legacy-app patterns

The thing that makes or breaks the adoption.

### Pattern 1 — modern web app

The easy case. The app speaks HTTP, supports OIDC / SAML, is reachable by IP or hostname.

Migration:
- Front the app with the IAP.
- Configure the IAP to inject OIDC / SAML headers the app understands; or configure the IAP to enforce auth and pass through anonymous traffic (the app is now trusting the IAP for auth).
- Test with a small user group.
- Update internal docs and bookmarks.
- Block VPN-direct access to the app.

Time per app: 1-2 days of engineering.

### Pattern 2 — legacy web app without modern auth

The app is HTTP but only knows about basic-auth or its own session cookies. No OIDC support.

Migration approach 1: **Header injection.** The IAP authenticates the user, injects a header (`X-Forwarded-User: alice@meridian.com`); the app trusts the header and authenticates the user from it. Works if the app can be configured (or patched) to trust a header.

Migration approach 2: **Reverse-proxy with session translation.** The IAP authenticates; a small adapter sits between the IAP and the app; the adapter translates the IAP's identity into the app's session cookie. Heavier-weight; only worth it for important apps.

Migration approach 3: **Leave it on VPN.** If the app is rarely used and slated for retirement, don't fight it. Document the exception; track the retirement date.

Time per app: 2-10 days depending on app cooperation.

### Pattern 3 — thick-client app

The app is a desktop installer talking to a server over a non-HTTP protocol (Citrix, native AD apps, line-of-business apps with proprietary protocols).

Migration approach 1: **Replace the thick-client with a web version.** Some apps have web equivalents. Migrate users to the web version, then migrate the web version behind the IAP.

Migration approach 2: **Use a ZTNA connector for the protocol.** Most ZT platforms (Cloudflare Tunnels, Tailscale subnet routers, Cloudflare ZTNA) support arbitrary TCP. The IAP authenticates the user; the connector forwards arbitrary traffic to the app.

Migration approach 3: **Leave it on VPN.** Same exception pattern as #2.

Time per app: highly variable, from 1 day (drop in a tunnel) to "this app's network protocol fundamentally requires LAN-attached access."

### Pattern 4 — SCADA / industrial / IoT

Industrial systems with hardcoded VPN dependencies, certificate-based mutual auth that the IAP can't intermediate, vendor-prescribed network configurations.

Migration approach: **Network segmentation with a small, well-defined VPN remnant.** Keep these systems on the VPN; tighten the VPN's scope to *only* these systems; add monitoring and just-in-time access for the VPN.

The honest position: not every system can be Zero Trust. Acknowledge the exception, scope it tightly, monitor it carefully, plan for the long-term retirement of the underlying system rather than the network around it.

### Pattern 5 — third-party / contractor / vendor access

External users who need access to internal apps.

Migration: the IAP supports external IdPs (B2B federation, OAuth with Google / GitHub, etc.). Add the external user pool to the IAP. The external user authenticates with their own identity, gets the per-app policy applied. No third-party VPN account needed.

Time: identity-provider work to onboard the external pool, then per-app policy.

---

## The six-quarter adoption arc

The sequencing that delivers visible value early.

### Quarter 1 — Foundation

**Goals:**
- IAP selected, contracted, deployed.
- Initial integration with the existing IdP.
- Device-posture signal source identified and tested.
- One high-value, easy-to-migrate app on the IAP (proof of concept).

**Visible value:** "We can demonstrate IAP-based access to one app. The team can use it; the VPN still works as fallback."

### Quarter 2 — Web-app migration wave

**Goals:**
- 10-30 modern web apps migrated to the IAP.
- IAP-direct access becomes the documented norm.
- VPN still operational; usage starts to decline as more apps are reachable via IAP.

**Visible value:** "30% of the internal app portfolio is on the IAP. Engineers report not needing VPN for daily work."

### Quarter 3 — Legacy-app and policy wave

**Goals:**
- The not-easy modern apps (legacy auth, thick-client) addressed with whichever pattern fits.
- Per-app policy tightened beyond the "any authenticated user with managed device" baseline.
- Audit and quality control: per-quarter access review.

**Visible value:** "70% of the app portfolio is on the IAP. Per-app access policies in place. Quarterly access reviews documented."

### Quarter 4 — VPN scope reduction

**Goals:**
- VPN-allowed IP ranges narrowed to the specific apps still on VPN.
- VPN-direct access to apps already on IAP is blocked at the network layer.
- The "VPN is the bypass" risk closed.

**Visible value:** "VPN is no longer the universal back door. Only apps that genuinely need VPN are reachable through it."

### Quarter 5 — Workload-identity wave

**Goals:**
- Service-to-service authentication migrated off long-lived credentials per [workload-identity-zt.md](./workload-identity-zt.md).
- Workload-identity-federation for CI / IaC pipelines.
- Eliminate static cross-service secrets.

**Visible value:** "Zero long-lived service credentials in production. The audit-finding around 'service accounts with non-rotating keys' is closed."

### Quarter 6 — Retirement decisions

**Goals:**
- Identify the remaining VPN-required apps; build the retirement plan (replace, refactor, or accept as long-term exception).
- VPN scope reduced to its long-term steady-state (which may be "retired entirely" or "exists for ten apps only").
- Continuous-authorization patterns from [continuous-authorization.md](./continuous-authorization.md) layered onto the IAP for highest-value apps.

**Visible value:** "The Zero Trust migration is steady-state. Future work is per-quarter incremental, not a project."

### What gets cut

Not every team can do all of the above. The minimum-viable variant:
- Quarters 1-2 produce real value.
- Quarters 3-4 produce strategic value.
- Quarters 5-6 produce posture value.

A team forced to ship faster can stop at Q4 and have a measurably better posture than they started; the remaining work can pick up next year.

---

## Worked example — Meridian Health ZT overlay (2025-2026)

The Meridian platform team adopted the additive-overlay pattern over 18 months. Snapshot of the starting state, the 18-month arc, and the result.

### Starting state (early 2025)

- Cisco AnyConnect VPN; ~1200 employees use it daily.
- ~80 internal apps reachable only via VPN.
- Okta as the identity provider; SAML federation to some internal apps, but ~30 apps still on local auth.
- No device-posture enforcement; any device with VPN credentials can connect.
- Long tail of legacy systems (the EHR vendor's thick-client app, two SCADA systems in the imaging lab, a finance batch system with hardcoded IPs).
- Several near-miss security incidents traced to "lost laptop with VPN credentials" — the trigger for the ZT initiative.

### Q1 2025 — Foundation

- Selected Cloudflare Access as the IAP (chosen over ZPA and Verified Access for the strength of the Okta integration and the bring-your-own-cert flexibility).
- Stood up Cloudflare Access in the corporate Cloudflare account.
- Configured Okta as the IdP.
- Cloudflare WARP client deployed for device-posture signal (combined with Okta Verify on personal devices).
- One app migrated: the internal wiki (Confluence). Engineers can reach the wiki via `wiki.meridian.com` from any network, with Okta auth + managed-device check; VPN no longer required for wiki.

### Q2 2025 — Web-app migration

- 18 web apps migrated: Jira, GitHub Enterprise, internal Grafana, internal Splunk, monitoring tools, build dashboards, several internal admin consoles.
- Per-app policies layered in: GitHub requires SSO + MFA, Splunk requires the "soc" group, build dashboards open to all engineers.
- VPN usage starts to decline; engineers report needing VPN only for a small number of apps now.

### Q3 2025 — Legacy and policy

- 22 more apps migrated. 10 of them required header-injection patterns (legacy local auth replaced with IAP-injected headers).
- Two thick-client apps moved to Cloudflare Tunnels with arbitrary-TCP support.
- The EHR vendor's app: vendor support refused; left on VPN; documented exception with vendor escalation in progress.
- Quarterly access reviews stood up; the first review identified 14 stale group memberships and 3 over-permissive policies.

### Q4 2025 — VPN reduction

- VPN configuration narrowed: VPN clients can no longer reach apps that have been migrated to IAP. The VPN now provides reachability *only* to the eight remaining VPN-required systems.
- "VPN is the back door" risk closed: an attacker with VPN credentials can reach the eight remaining apps, not the 60 already on IAP.
- Detection layered on the VPN-only apps: SIEM rule on unusual access patterns.

### Q1 2026 — Workload identity

- The cross-account / cross-service credential cleanup track (started earlier as part of broader IAM hygiene) continued in parallel. GitHub Actions, Azure DevOps Pipelines, Glue jobs, and Lambda functions all moved to OIDC / workload-identity-federation. Per [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md).
- The number of service accounts with long-lived access keys dropped from 47 to 3 (the three exceptions are documented and tracked for retirement).

### Q2 2026 — Steady state

- 8 apps remain on VPN: the EHR thick-client, two SCADA systems, the finance batch system, and four niche vendor-provided apps with hardcoded VPN dependencies.
- Retirement plan for the EHR: vendor has committed to a web-based version by Q4 2026; finance batch system to be replaced with a cloud-native equivalent in 2027.
- SCADA systems are accepted as long-term exception; network segmentation + dedicated VPN segment + intensive monitoring is the compensating control.
- VPN no longer the universal-access tool; it's now scoped to a small network segment hosting the exception apps.
- IAP handles ~95% of internal-app access; ~1200 employees use it daily; the "any device with VPN creds = full corporate access" risk is closed.

### Findings opened and closed

- **BC-001** (no device-posture enforcement on VPN). Closed by IAP migration; VPN-remnant restricted to managed devices via Okta Verify enforcement.
- **BC-002** (no per-app access policy; "in VPN = access"). Closed by per-app IAP policy.
- **BC-003** (~80 apps reachable from any VPN-connected device). Closed by VPN scope reduction.
- **BC-004** (~30 apps using local auth, not SSO). Closed by IAP-fronted SSO (header injection).
- **BC-005** (third-party contractor VPN accounts with no MFA, no posture check). Closed by external-identity federation via IAP.
- **BC-006** (no quarterly access review). Closed by per-quarter review process.
- **BC-007** (47 service accounts with long-lived access keys). Closed by workload-identity migration (parallel track).

The 18-month arc cost ~3 FTE-quarters of platform engineering + ~1 FTE-quarter of security engineering. Operational cost steady-state: a Cloudflare Access subscription (low five figures annually) and a fraction of an FTE for ongoing maintenance.

---

## Anti-patterns

### 1. The "boil the ocean" rip-and-replace

Adopt a greenfield ZT vendor; require all 80 apps to migrate in 6 months. Migration stalls at app 30. Eight months in, the project is a budget item nobody wants to defend. Eighteen months in, the project is quietly cancelled.

The fix: additive overlay; visible value in Q1; cancel-resistance built by ongoing delivery.

### 2. The "VPN goes away on date X" mandate

Executive deadline: "VPN turned off January 1st." On January 1st: the EHR thick-client breaks; clinical workflows degrade; the VPN is turned back on. The deadline is missed and the project's credibility takes a hit.

The fix: VPN retirement is the *result* of completing migrations, not the *cause* of them. Retire when the last app is migrated, not before.

### 3. The "single IAP for everything"

Pick one IAP and require every app to fit its connector model. Some apps don't fit. The "exceptions list" grows. The IAP claims to handle 100% of traffic; reality is 75%; the other 25% lives in shadow VPN remnants.

The fix: pick the IAP for the dominant use case; acknowledge that some apps will use other patterns (different IAP, tunnels, leave-on-VPN as exception). Don't force-fit.

### 4. The "no device posture means we did it wrong"

Some teams over-rotate on device posture; require BYOD users to install heavy MDM; trigger user revolt; back off; lose the device-posture signal entirely.

The fix: tiered device-posture. Managed devices get full access. BYOD with attested posture (Okta Verify, etc.) gets limited access (wiki, email, low-sensitivity tools). BYOD without attestation gets web-only access to specific apps. The user experience scales with the trust level.

### 5. The "we'll do workload identity later" deferral

Human-to-app ZT is shipped; the service-to-service track is deferred. Three years later, the audit finds ten thousand long-lived service credentials. The deferral becomes its own multi-quarter project.

The fix: run the workload-identity track in parallel from Q1; it's a separate technical track with its own engineers; doesn't compete for the same people as the IAP rollout.

### 6. The "ZT means firewall is gone"

The ZT vendor's marketing implies network controls are obsolete. The team disables VPC security groups, removes WAF, stops the egress-control project. Then a compromised IAP token gets used to do whatever the user's policy permits — and there's no defense in depth.

The fix: ZT is layered, not exclusive. Network controls remain as defense in depth. The IAP enforces the access decision; the network controls limit the blast radius if the access decision is wrong.

### 7. The "no measurement" rollout

The team does the work but doesn't measure: number of apps on IAP, % of VPN traffic to migrated apps, MTTR for new app onboarding. Without metrics, leadership can't tell if the project is going well, going badly, or stalled.

The fix: per-quarter scorecard. Number of apps, % traffic shift, user-experience NPS, audit-finding closure. The scorecard is the project's defense against budget cuts.

### 8. The "policy as theater" pattern

Apps are on the IAP; per-app policies exist; the policies all say "any authenticated user with managed device." Functionally equivalent to "any employee can access any app." The ZT migration has happened; the access control has not.

The fix: per-app policies should reflect actual need-to-know. Finance app only to Finance; production DB only to DBAs; etc. Use a quarterly access review to tighten policies based on observed usage.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| BC-001 | No device-posture enforcement on internal-app access | High | IAP with device-posture provider integration | Security Eng + IT |
| BC-002 | "VPN connected = full access" model with no per-app policy | High | Per-app policy via IAP; access scoped by group / role | Security Eng + Platform Eng |
| BC-003 | VPN reachability includes apps already migrated to alternative path | High | VPN configuration narrowed to apps still requiring it | Network Eng + Security Eng |
| BC-004 | Internal apps using local auth not federated to SSO | Medium | IAP-fronted SSO; header injection for legacy apps | Security Eng + App Owners |
| BC-005 | Third-party / contractor access via VPN account with no MFA / posture | High | External IdP federation through IAP; MFA + posture enforcement | Security Eng + IT |
| BC-006 | No quarterly access review for internal apps | Medium | Per-quarter review process; documented closure of findings | Security Eng + App Owners |
| BC-007 | No workload-identity migration in flight; long-lived service credentials persist | High | Parallel workload-identity track per [workload-identity-zt.md](./workload-identity-zt.md) | Security Eng + Platform Eng |
| BC-008 | Greenfield-ZT vendor commitment without legacy-app retirement plan | High | Re-evaluate as additive overlay; identify legacy-app exceptions | Security Eng + Sponsor |
| BC-009 | ZT rollout has no per-quarter metric / scorecard | Medium | Number of apps on IAP, % VPN-traffic shift, NPS, audit-closure | Security Eng + PM |
| BC-010 | Apps on IAP but per-app policy is "any authenticated user" | Medium | Tighten policies to need-to-know; quarterly review | Security Eng + App Owners |
| BC-011 | No detection on IAP policy changes | Medium | SIEM rule on IAP policy modifications by non-IaC principal | Detection Eng + SOC |
| BC-012 | Legacy / SCADA exception apps not formally documented | Low | Per-exception ticket; quarterly review of exception status | Security Eng + Network Eng |
| BC-013 | Apps on IAP but VPN-direct path still reachable (bypass risk) | High | Network controls to block VPN-direct access to IAP-migrated apps | Network Eng + Security Eng |
| BC-014 | Tunnel-based access (Cloudflare Tunnels, etc.) lacks audit logging | Medium | Tunnel-access logs ingested into SIEM; per-tunnel ownership | Detection Eng + Network Eng |
| BC-015 | Continuous-authorization signals (impossible travel, device changes) not consumed | Medium | Layer continuous-auth per [continuous-authorization.md](./continuous-authorization.md) | Security Eng + Detection Eng |
| BC-016 | BYOD users have full access equivalent to managed devices | Medium | Tiered policy; BYOD scoped to lower-sensitivity apps | Security Eng + IT |
| BC-017 | IAP configuration not in IaC | Medium | Terraform / equivalent for all IAP policies; CODEOWNERS | DevOps + Security Eng |
| BC-018 | No tested break-glass for IAP outage | Medium | Documented break-glass; quarterly tabletop | Security Eng + IT |

---

## Adoption checklist

- [ ] Inventory: list every internal app currently reachable via VPN; tag by complexity (modern web / legacy auth / thick-client / SCADA / vendor).
- [ ] Identity provider audit: confirm OIDC / SAML support; modernize if absent.
- [ ] Device-posture source identified and tested.
- [ ] IAP selected and deployed; integrated with IdP and posture source.
- [ ] First app migrated to IAP (Q1 visible value).
- [ ] Per-app policy structure: groups in IdP, policy in IAP IaC.
- [ ] Per-quarter migration target set (e.g., 10-20 apps per quarter for the first three quarters).
- [ ] Header-injection pattern documented for legacy-auth apps.
- [ ] Tunnel pattern documented for thick-client / arbitrary-TCP apps.
- [ ] Exception process for SCADA / vendor-dependent apps; each exception has a documented retirement plan or accepted long-term status.
- [ ] VPN configuration narrowed as apps migrate; VPN-direct access blocked for IAP-fronted apps.
- [ ] External identity federation for third parties / contractors.
- [ ] Quarterly access review process stood up.
- [ ] Workload-identity track running in parallel per [workload-identity-zt.md](./workload-identity-zt.md).
- [ ] Per-quarter scorecard: # apps on IAP, % VPN-traffic shift, NPS, findings closed.
- [ ] IAP detection: configuration changes, anomalous access patterns.
- [ ] Continuous-authorization signals layered for highest-value apps per [continuous-authorization.md](./continuous-authorization.md).
- [ ] Break-glass procedure for IAP outage tested quarterly.

---

## What this document is not

- **A complete BeyondCorp reference.** The Google papers are the canonical source for the destination; this document covers the migration to that destination on an existing stack.
- **A vendor recommendation.** Cloudflare Access, ZPA, AWS Verified Access, Tailscale, Pomerium, etc. all work; the choice depends on your existing stack, your engineering bandwidth, and your risk profile.
- **A network-segmentation manual.** [microsegmentation.md](./microsegmentation.md) covers segmentation patterns; this document treats network as defense-in-depth.
- **A workload-identity guide.** [workload-identity-zt.md](./workload-identity-zt.md) and [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md) cover that track.
- **A continuous-authorization deep dive.** [continuous-authorization.md](./continuous-authorization.md) covers continuous-auth signals; this document layers them onto the migration arc.
- **A change-management playbook.** The technical migration is half the work; communications, training, helpdesk readiness are not in scope here.
