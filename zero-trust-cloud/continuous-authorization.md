# Continuous Authorization

A practitioner's reference for continuous authorization in cloud environments — device-trust signals (Okta Verify, Entra Conditional Access, Cloudflare Zero Trust), session re-evaluation, the step-up authentication pattern, the OPA-as-policy-decision-point reference architecture, and the under-engineered controls that most Zero Trust programs defer. The patterns here are the deepest of the ZT layers — the ones most teams reach last because each layer's prerequisites need to be in place first.

This document is the under-engineered tail of Zero Trust. Most organizations implement identity-aware access ([identity-aware-access.md](./identity-aware-access.md)) and stop. The continuous-authorization layer is what turns ZT from "authentication at session start" into "authentication and authorization continuously as context changes." It's the layer that catches the case where a user authenticated cleanly an hour ago but their device went out of compliance since.

For the workforce identity layer this builds on, see [identity-aware-access.md](./identity-aware-access.md). For the workload identity that pairs with it, see [workload-identity-zt.md](./workload-identity-zt.md). For the adoption sequence that positions continuous authorization in the broader ZT plan, see [zt-adoption-sequence.md](./).

---

## When to read this document

**If your Zero Trust adoption has stalled at "users authenticate once and we're done"** — read top to bottom. The continuous layer is where ZT's promise actually lives.

**If you have device-trust signals but they don't propagate to runtime decisions** — start with [Device-trust signals](#device-trust-signals). The pattern of "evaluate at session start, ignore thereafter" misses the case the controls are designed for.

**If you are designing the policy-decision architecture** — start with [OPA as policy-decision point](#opa-as-policy-decision-point). The pattern is mature; the engineering investment is meaningful.

**If you are auditing continuous-authorization posture** — start with [Findings checklist](#findings-checklist).

---

## What continuous authorization is

The Zero Trust ideal: every action is evaluated against current context, not against a session-start snapshot.

### What "continuous" means in practice

Not literally every request is fully re-authenticated:

- The user authenticates at session start (with MFA, device check, etc.).
- The user gets a session token.
- Subsequent requests use the token; lightweight validation per request.
- **At key moments**, the system re-evaluates: device-state changes, sensitive actions, time-based re-check.

The continuous-authorization layer is about those key moments. What counts as a key moment is the design decision.

### Examples of continuous-authorization events

- **Device falls out of compliance:** OS patch missing, EDR disabled, MDM enrollment lost. Active sessions should be terminated or restricted.
- **User attempts a sensitive action:** changes admin settings, reads sensitive data, accesses privileged systems. Step-up authentication is triggered.
- **Anomalous behavior:** impossible travel (login from US, then from Russia 5 minutes later), unusual access patterns, geo-location violation. Session is re-evaluated or terminated.
- **Time elapsed:** sessions older than N hours are required to re-authenticate.
- **Policy change:** a user's group membership changed; access should reflect the new state.

For each event: the system either re-validates or terminates the session.

---

## Device-trust signals

The data sources that feed continuous authorization.

### What signals matter

- **Patch level:** OS and application patches current.
- **MDM enrollment:** device managed by the organization.
- **Disk encryption:** enabled and functioning.
- **EDR present:** endpoint detection running.
- **Firewall enabled:** local firewall configured.
- **Screen lock:** active when idle.
- **Specific configurations:** browser policies, password manager, etc.

### Sources of these signals

- **MDM platforms:** Jamf, Intune, Kandji, Workspace ONE. The source of truth for managed devices.
- **EDR platforms:** CrowdStrike, SentinelOne, Carbon Black. Endpoint security state.
- **IdP-integrated device trust:** Okta Device Trust, Entra Conditional Access device compliance, Google Endpoint Verification.
- **Cloudflare WARP client:** Cloudflare's device posture client.
- **JumpCloud, similar:** smaller-vendor options.

### Signal propagation

The chain:

1. **Endpoint** has the agents (MDM, EDR).
2. **MDM / EDR backends** aggregate the state.
3. **IdP** queries or receives the state.
4. **Identity-aware proxy / application** receives the user's identity + device state at session establishment.
5. **Application** evaluates policy.

For continuous authorization: the chain needs to fire more than once per session. Most deployments evaluate at session start only.

### The propagation patterns

- **Session refresh:** the IdP re-evaluates the session periodically and pushes updates to dependent services.
- **Webhook on state change:** MDM / EDR pushes events to the IdP; IdP propagates to the proxy.
- **Polling:** the proxy periodically polls the IdP for current device state.

The propagation latency is the gap: even with continuous authorization, the delay between an event and the policy response is bounded by the propagation mechanism.

---

## Session re-evaluation

The pattern that turns session-establishment authn into continuous authn.

### Session lifetime trade-offs

- **Long session (8-24 hours):** good UX; less frequent re-auth. Less responsive to context changes.
- **Short session (15-60 minutes):** more responsive; worse UX (constant prompts).
- **Medium session with re-evaluation:** the goal — long session in good conditions, re-auth triggered by signals.

### Re-evaluation triggers

When the session should be re-evaluated:

- **Time-based:** every N minutes, re-evaluate. Often combined with sliding-window expiration.
- **Action-based:** sensitive actions trigger step-up.
- **Context-change-based:** new IP, new device, new geo trigger re-evaluation.
- **Risk-score-based:** behavior analytics raise a risk score; re-evaluate when score exceeds threshold.

### Implementation patterns

- **OIDC token lifetime:** the access token has a short TTL; refresh requires re-evaluation.
- **Webhook to invalidate sessions:** the IdP pushes a session-revoke event when device state changes.
- **Policy-decision-point integration:** every request goes through a PDP that consults current state.

### Continuous Access Evaluation (CAE)

Microsoft's pattern (and increasingly an industry pattern):

- Identity provider issues short-lived tokens.
- Dependent services validate tokens against current state on each evaluation.
- Token revocation propagates in near-real-time (vs the old "wait for token to expire" model).

For Microsoft-heavy environments: CAE is the operational pattern. For others: similar patterns via custom integration.

References:
- [Microsoft Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)

---

## Step-up authentication

The pattern that requires stronger authentication for sensitive actions.

### The trigger

The user attempts a sensitive action:

- Accessing an admin panel.
- Reading highly sensitive data (PHI, customer PII).
- Initiating a privileged operation (cloud-admin actions, financial transactions).

The system requires additional authentication:

- Re-enter password.
- Re-perform MFA.
- Perform hardware-key verification.
- Biometric verification (mobile device).

Once the step-up is satisfied, the action proceeds.

### The pattern's value

- **Reduces blast radius of compromised sessions.** A compromised session token doesn't grant access to the most sensitive actions without the step-up.
- **Aligns authentication strength to action sensitivity.** General actions use lightweight auth; sensitive actions require strong auth.
- **Audit clarity.** Sensitive-action audit logs include the step-up event, providing strong evidence of intentional action.

### Implementation patterns

- **OIDC `acr` (Authentication Context Reference):** the authentication strength required by an action; the IdP validates the session meets the required level.
- **AMR (Authentication Methods References):** which authentication methods were used; the application checks for required methods.
- **Application-layer prompts:** the application detects the sensitive action and prompts for re-auth directly.

For most modern stacks: OIDC ACR/AMR is the pattern.

### Per-application ACR mapping

- **General access:** `acr_values=urn:openid:catalog:level1` (password + MFA).
- **Admin actions:** `acr_values=urn:openid:catalog:level3` (hardware key + recent re-auth).

Applications request the required ACR; the IdP enforces; the application receives confirmation in the token.

### The user-experience consideration

Step-up authentication adds friction. The discipline:

- Step-up only on truly sensitive actions, not as a blanket pattern.
- Cache the step-up result for a reasonable window (15-30 minutes) so users don't re-auth for every related action.
- Document which actions trigger step-up; users learn the pattern.

---

## OPA as policy-decision point

The reference architecture for policy-driven continuous authorization.

### The PDP pattern

- **Policy Decision Point (PDP):** evaluates policies; returns allow/deny.
- **Policy Enforcement Point (PEP):** the place in the request path where the decision is enforced (gateway, sidecar, application).
- **Policy Information Point (PIP):** sources of context that the PDP queries (IdP, device state, etc.).

The PEP calls the PDP for each request (or at key moments); the PDP returns a decision based on policy + context.

### OPA (Open Policy Agent)

OPA is the dominant open-source PDP:

- Policy language: Rego (declarative).
- Deployment: sidecar or central service.
- Performance: fast (in-process Go evaluator).
- Ecosystem: integrations with Kubernetes, Envoy, Istio, application SDKs.

### A continuous-authorization OPA policy

```rego
package authz

import future.keywords.in

# Default deny
default allow := false

# Allow if all conditions met
allow if {
    # User must be authenticated
    input.user.authenticated == true

    # User must be in the required group
    input.user.groups[_] == required_group_for_resource(input.resource)

    # Device must be compliant
    input.device.compliance.status == "compliant"

    # Session must be recent enough
    session_age(input.session.established) < max_session_age(input.resource)

    # If sensitive action, require step-up
    not is_sensitive_action(input.action)
    or input.session.acr >= required_acr_for_action(input.action)
}

# Required group per resource
required_group_for_resource(resource) := group if {
    group_mapping := {
        "internal-grafana": "engineering",
        "admin-panel": "platform-admins",
        "finance-dashboard": "finance",
    }
    group := group_mapping[resource]
}

# Required session age per resource
max_session_age(resource) := age if {
    age_mapping := {
        "internal-grafana": 28800,    # 8 hours
        "admin-panel": 3600,           # 1 hour
        "finance-dashboard": 14400,    # 4 hours
    }
    age := age_mapping[resource]
}

is_sensitive_action(action) if {
    action in ["delete", "transfer", "approve", "elevate"]
}

required_acr_for_action(action) := acr if {
    acr_mapping := {
        "delete": 2,
        "transfer": 3,
        "approve": 3,
        "elevate": 4,
    }
    acr := acr_mapping[action]
}
```

The policy evaluates:

- User authentication and group membership.
- Device compliance.
- Session age relative to the resource's max session age.
- Step-up ACR if the action is sensitive.

Each evaluation is per-request; context-aware; identity-aware.

### Where the PEP sits

- **API gateway:** the PEP calls OPA before forwarding the request.
- **Service mesh sidecar:** Istio's authorization layer can call OPA.
- **Application middleware:** the application calls OPA before handling the request.

Each location enforces; the choice depends on the architecture.

References:
- [Open Policy Agent](https://www.openpolicyagent.org/)
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- [OPA Envoy plugin](https://www.openpolicyagent.org/docs/latest/envoy-introduction/)

---

## Risk-based authorization

The pattern that uses behavioral signals.

### Risk signals

- **Impossible travel:** login from US, then immediately from Europe.
- **Anomalous access pattern:** user accessing systems they don't typically use.
- **Unusual time:** access at 3 AM local time for a user who typically works 9-5.
- **High-risk user:** account flagged by SOC for previous incidents.
- **Compromise indicators:** credentials seen in breach corpora.

### Risk-score-driven policies

The PDP includes risk scoring:

- **Low risk:** standard access.
- **Medium risk:** additional MFA, shorter session.
- **High risk:** require manager approval; or terminate session; or page SOC.

### Tools that provide risk scoring

- **Okta Risk Engine:** ML-driven risk score.
- **Entra ID Identity Protection:** Microsoft's risk-based AccessConditional access.
- **CrowdStrike Identity Protection:** integration with endpoint risk.
- **Custom:** SIEM-driven risk computation.

### The discipline

Risk-based authorization is powerful but produces false positives:

- A legitimate trip becomes "impossible travel."
- A new role legitimately requires unusual access patterns.
- Late-night work isn't anomalous for some users.

The pattern: risk signals trigger additional auth, not blocking. False positives result in a re-auth (inconvenience) rather than denial (incident).

---

## Worked example: Meridian Health's continuous authorization

Meridian operates a continuous-authorization layer combining Okta-driven session evaluation, OPA policy-decision-point, and risk-based step-up.

### The PDP layer

- **OPA** deployed as a sidecar to internal API gateways and to Istio sidecars.
- **Policies** in Rego, version-controlled in Git, deployed via CI.
- **PIPs:**
  - Okta for user identity and group membership.
  - Jamf (MDM) for device compliance.
  - CrowdStrike for endpoint risk.
  - SIEM for behavioral signals.

### The session-evaluation pattern

- **Cloudflare Access** issues session tokens with 8-hour lifetime.
- **Continuous re-evaluation:** Cloudflare polls Okta for device state and group membership every 5 minutes.
- **Webhook from Jamf:** device state changes (out of compliance) immediately notify Cloudflare; sessions on the device are flagged.
- **Risk-based termination:** SOC-flagged users have their sessions terminated immediately on flag.

### Step-up authentication patterns

- **General internal apps:** Okta MFA at session start; 8-hour session; no step-up.
- **Customer-data tools:** Okta MFA at session start; step-up to hardware key for record export.
- **Admin tools:** hardware key at session start; step-up to manager approval for destructive actions.
- **Financial systems:** hardware key + manager approval for transactions over $10K.

### The OPA policies

Per-application policies stored in `meridian-policies` repo:

```
meridian-policies/
├── internal-grafana/
│   └── policy.rego
├── customer-admin/
│   └── policy.rego
├── finance-portal/
│   └── policy.rego
└── shared/
    ├── identity.rego
    └── device.rego
```

Common identity / device evaluation in `shared/`; per-application logic in app folders. CI tests each policy with synthetic inputs.

### Behavioral risk integration

- Splunk computes risk score per user per hour.
- Risk score above threshold pushes a session-flag to Okta.
- Okta propagates to Cloudflare; sessions step up to MFA.
- High-risk score (above harder threshold) pages SOC.

### Findings opened during the continuous-authorization audit

- **CA-001** (sessions established once and not re-evaluated; device-state changes ignored). Closed by Cloudflare polling Okta + webhook from Jamf.
- **CA-002** (no step-up authentication; all actions require same auth level). Closed by step-up patterns for sensitive actions.
- **CA-003** (PDP layer absent; policies in application code, inconsistent). Closed by OPA deployment.
- **CA-004** (risk signals from SOC weren't actionable in real-time). Closed by Splunk → Okta integration.
- **CA-005** (session lifetime was 24 hours uniformly; high-sensitivity apps had same lifetime as low-sensitivity). Closed by per-app session lifetime.
- **CA-006** (admin actions on financial systems lacked manager-approval workflow). Closed by step-up-with-approval pattern.

---

## Anti-patterns

### 1. The session-establishment-only authn

Users authenticate at session start; nothing re-evaluates. A user whose device went out of compliance retains full access for the session lifetime.

The fix: continuous re-evaluation; device-state webhooks; session refresh.

### 2. The session-too-long without re-evaluation

24-hour sessions are convenient. Without re-evaluation, they create a 24-hour window for compromised sessions.

The fix: re-evaluation triggers; risk-based shortening.

### 3. The step-up-without-cache

Step-up requires re-auth on every sensitive action. UX is so bad users avoid the sensitive actions or find workarounds.

The fix: cache step-up result for a reasonable window (15-30 minutes); user re-auths once per session per sensitivity tier.

### 4. The policy-in-application-code

Each application implements its own authz logic. Policies are inconsistent; updates require code changes; centralized review impossible.

The fix: PDP pattern; centralized policy; per-application enforcement.

### 5. The risk-signal-without-action

The SIEM computes risk scores. No system acts on them. The signals are observability, not control.

The fix: risk-signal-to-policy integration; step-up or session-termination on high risk.

### 6. The false-positive-causing-denial

Risk signals cause access denial. Legitimate users are blocked; help-desk volume increases; eventually risk signals are bypassed.

The fix: risk signals trigger additional auth, not denial. Denial is reserved for extreme cases (confirmed compromise).

### 7. The device-state-not-propagated

MDM has the device state. The IdP doesn't query it. The proxy doesn't see it. The signal is collected but not used.

The fix: end-to-end propagation; MDM → IdP → proxy → PDP.

### 8. The continuous-authn-without-monitoring

The continuous layer is implemented. Nobody monitors policy decisions, step-up events, session terminations. False positives accumulate; gaps in coverage invisible.

The fix: observability on PDP decisions; metrics on step-up frequency; periodic review.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| CA-001 | Session established once without re-evaluation; device changes ignored | High | Continuous re-evaluation; MDM webhook integration | IT + Security Eng |
| CA-002 | No step-up authentication for sensitive actions | High | Step-up pattern for admin / financial / data-sensitive actions | Security Eng + IAM Eng |
| CA-003 | Authorization logic in application code; inconsistent; centralized review impossible | High | PDP pattern (OPA); centralized policy | Security Eng + DevOps |
| CA-004 | Risk signals from SOC / SIEM not actionable in real-time | Medium | Risk-signal-to-IdP integration; session flag | Security Eng + SOC |
| CA-005 | Session lifetime uniform across applications | Medium | Per-application session lifetime aligned to sensitivity | Security Eng |
| CA-006 | Privileged actions lack manager-approval workflow | Medium | Step-up-with-approval pattern for high-impact actions | Security Eng + IAM Eng |
| CA-007 | Device state collected by MDM not propagated to PDP | High | End-to-end propagation; webhook or polling integration | IT + IAM Eng |
| CA-008 | Risk-based authorization causes denial; legitimate users blocked | Medium | Risk triggers step-up, not denial; denial reserved for confirmed compromise | Security Eng |
| CA-009 | Step-up requires re-auth on every action; UX issue | Low | Cache step-up result; 15-30 minute window per sensitivity tier | Security Eng + UX |
| CA-010 | PDP observability absent; policy-decision metrics invisible | Medium | Metrics on allow/deny rates; alert on patterns | Observability + Security Eng |
| CA-011 | Continuous Access Evaluation not used in Microsoft-heavy environment | Low | Adopt CAE patterns; token revocation propagates | IT + IAM Eng |
| CA-012 | Sessions terminated without user notification; confusing UX | Low | Notification on session termination; reason where possible | UX + IT |
| CA-013 | Step-up authentication uses same factor as session start; no real strengthening | Medium | Step-up uses stronger factor (hardware key for non-key sessions) | Security Eng + IAM Eng |
| CA-014 | Time-based session lifetime only; no risk-based shortening | Low | Risk-based session lifetime; high-risk users get shorter sessions | Security Eng + IAM Eng |
| CA-015 | Policy changes deployed without testing | Medium | CI tests for policies with synthetic inputs; staging deployment first | DevOps + Security Eng |
| CA-016 | Impossible-travel detection causes user friction (legitimate travel flagged) | Low | Step-up rather than denial; user notification | Security Eng + IT |
| CA-017 | PDP single point of failure; PDP outage blocks all access | High | PDP HA; tested failover; fail-open or fail-closed decision documented | Platform Eng + Security Eng |
| CA-018 | Policy library not version-controlled; deployment ad-hoc | Medium | IaC; PR review; CI deployment | Security Eng + DevOps |

---

## What this document is not

- **A complete OPA tutorial.** OPA's documentation covers Rego depth.
- **A complete CAE reference.** Microsoft's documentation covers their pattern.
- **A risk-engine vendor comparison.** Okta / Entra / CrowdStrike risk engines are mentioned; the choice belongs with broader identity-tool decisions.
- **A behavioral analytics deep dive.** UBA / UEBA (User and Entity Behavior Analytics) is its own large topic; this document covers integration patterns at the high level.
