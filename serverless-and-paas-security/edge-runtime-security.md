# Edge Runtime Security

A practitioner's reference for securing edge-runtime workloads — CloudFront Functions, Lambda@Edge, Azure Front Door rules engine, Cloudflare Workers, Akamai EdgeWorkers. The patterns here cover the identity-and-secrets model in edge runtimes, the rate-limit-at-edge-vs-origin pattern, and the supply-chain risk of edge runtimes where compromised code at edge runs everywhere instantly.

This document closes the serverless-and-paas-security batch. Edge runtimes are a distinct security domain from regional serverless. The patterns differ: identity models are different (often no per-request identity); secret-handling is different (often limited or no integration with cloud secrets managers); blast radius is different (a Cloudflare Worker compromise runs in 300+ edge locations within seconds). Treating edge runtimes as "just like Lambda but smaller" is the most common failure mode.

For the regional serverless patterns this complements, see [lambda-functions-security.md](./lambda-functions-security.md). For the API Gateway layer that often sits adjacent to edge, see [api-gateway-security.md](./api-gateway-security.md).

---

## When to read this document

**If you operate any edge-runtime workload** — read top to bottom. The constraints are different from Lambda; the team's intuitions transfer imperfectly.

**If you have Cloudflare Workers running production logic** — start with [The supply-chain blast radius](#the-supply-chain-blast-radius).

**If you are evaluating edge runtimes for a new workload** — start with [When edge is the right answer](#when-edge-is-the-right-answer). It's often the wrong answer for use cases that look right.

**If you are auditing edge-runtime posture** — start with [Findings checklist](#findings-checklist).

---

## What edge runtimes are

Code that runs at CDN-edge locations, close to users.

### The deployment model

- Code uploaded to the CDN / edge platform.
- Replicated to edge locations (10s to 100s of locations globally).
- Triggered by HTTP requests reaching that edge.
- Executes with very tight latency (microseconds to milliseconds).

### The major edge runtimes

- **CloudFront Functions (AWS):** JavaScript-only; very limited (no external HTTP, no state); microsecond-latency.
- **Lambda@Edge (AWS):** Lambda-like; runs at CloudFront edge; can make external HTTP; millisecond latency.
- **Azure Front Door rules engine:** declarative rules; very limited.
- **Cloudflare Workers:** JavaScript / TypeScript / Rust; can make HTTP; KV / Durable Objects / R2 storage; substantial capability.
- **Akamai EdgeWorkers:** JavaScript; similar shape.

### What edge is used for

- **Request routing and rewriting.**
- **Authentication / authorization at edge** (verify JWT before reaching origin).
- **A/B testing / feature flags.**
- **Static-content modification** (HTML injection, headers).
- **Bot detection / rate limiting at edge.**
- **Full applications** (Cloudflare Workers can host full apps with KV storage).

---

## When edge is the right answer

The use cases that justify edge.

### Latency-critical operations

- **Global routing decisions** where adding the origin's latency would be noticeable.
- **Authentication / authorization checks** before forwarding to origin (saves origin compute on invalid requests).
- **Bot detection at edge** (cheaper than at origin).

### Distributed read patterns

- **Cloudflare Workers + KV** for globally-replicated key-value reads.
- **Origin-shield patterns** where edge caches and serves; origin is contacted rarely.

### Cost optimization

- **Origin offload:** edge handles the request without origin compute / bandwidth.

### When edge is the wrong answer

- **For a full application:** the operational model is different; debugging is harder; secrets are constrained.
- **For workloads with rich backend dependencies:** every dependency requires per-edge configuration.
- **For workloads that need cloud-native integration (Secrets Manager, IAM):** edge runtimes have limited integration.

---

## The identity-and-secrets model

The constraint that shapes edge security.

### What edge runtimes don't have

- **Per-request identity** at the edge: the request doesn't carry credentials to invoke other services.
- **Native cloud-IAM:** edge runtimes generally don't have IRSA / Workload Identity / Managed Identity equivalents.
- **Secrets manager integration:** Cloudflare has Secrets; AWS has limited support in Lambda@Edge; others are minimal.

### What this means

- Edge code can't call cloud APIs that require IAM (no `aws s3` calls).
- Edge code can't fetch secrets from the cloud's secrets manager directly.
- Edge can call public HTTPS endpoints (Cloudflare Workers, Lambda@Edge); the calls are unauthenticated unless the code adds API tokens.

### How edge gets credentials

- **Cloudflare Workers Secrets:** static secrets bound to the Worker; accessed via `env.SECRET_NAME`.
- **Lambda@Edge environment-style configuration:** more limited than regular Lambda.
- **JWT-passed-through:** the user's JWT is in the request; edge validates and forwards.
- **Static API keys:** the worst pattern; secrets in code or in headers.

### The pattern

- Edge does authentication (validate JWT, check signature).
- Edge doesn't typically initiate calls requiring secrets.
- If edge needs secrets: minimal, rotation-discipline, monitored.

---

## The supply-chain blast radius

The key risk that's specific to edge.

### What happens when edge code is compromised

- Compromised Worker is deployed.
- Cloudflare replicates to ~300 edge locations within seconds.
- Every request to a fronted domain runs the compromised code.
- An attacker has near-instant global presence at the user-facing perimeter.

### Why this is worse than Lambda

- A compromised Lambda only runs when triggered; affected pods are bounded.
- A compromised edge Worker runs on every request to every fronted domain; the trigger surface is "every web request."

### The supply-chain protection

- **Strict CI/CD for edge code:** the same image-signing / Cosign / admission pattern as Kubernetes per [../kubernetes-and-container-security/image-supply-chain.md](../kubernetes-and-container-security/image-supply-chain.md).
- **Code review on every change.**
- **Limited deployer access:** the set of people who can deploy to edge is small.
- **Canary deployment patterns:** new code goes to a small fraction of edge first.
- **Quick rollback capability:** the deployment system must support rapid rollback.
- **Per-environment edge configuration:** dev / staging / prod with their own deployment paths.

### The "blast-radius mitigation"

For high-stakes edge code:

- **Multiple-eyes deployment:** no single person can push to production edge.
- **Staged rollouts:** 1% → 10% → 50% → 100% with monitoring.
- **Automated kill-switch:** detection on error spikes triggers automatic rollback.

---

## Per-platform patterns

The specific security baselines per platform.

### CloudFront Functions (AWS)

- Very limited: JavaScript; no external HTTP; no async; no state.
- Use cases: header manipulation, URL rewriting, simple authentication checks.
- Security: limited attack surface (no external calls); strict deployment via IaC.

### Lambda@Edge (AWS)

- Lambda-like runtime at CloudFront edge.
- Can make external HTTP; can use Secrets Manager (limited).
- Use cases: complex request/response manipulation; authentication; A/B testing.
- Security: same patterns as regional Lambda; tighter constraints on cold start (less context to fetch secrets).

### Azure Front Door rules engine

- Declarative rules; no code execution.
- Limited but predictable.
- Security: rule configuration matters; misconfigurations are the main risk.

### Cloudflare Workers

- Full JavaScript / TypeScript / Rust runtime.
- Can call HTTP / connect to Cloudflare R2, KV, Durable Objects.
- Use cases: full applications, complex edge logic.
- Security:
  - Secrets via `wrangler secret put`.
  - Per-Worker bindings (KV, R2, Durable Objects with named access).
  - Cloudflare Access integration for authenticated access.
  - Wrangler-based deployments; strict source-control / CI discipline.

### Akamai EdgeWorkers

- JavaScript runtime; similar shape to Cloudflare Workers.
- Less capability than Workers but enterprise-supported.
- Security: similar disciplines.

---

## Rate limiting at edge

A common use case: rate-limit at the edge before the request reaches the origin.

### Why rate-limit at edge

- **Reduces origin load:** rejected requests never reach origin.
- **Faster response:** the edge can reject in milliseconds.
- **Geo-aware:** can limit per-region.

### Common patterns

- **Per-IP rate limit:** simple; vulnerable to distributed attacks.
- **Per-user (JWT-based) rate limit:** more sophisticated; requires JWT validation.
- **Behavioral rate limit:** anomaly detection; harder to bypass.

### Cloudflare-specific

- **Rate Limiting rules** at the dashboard / API level.
- **Workers + Durable Objects** for per-key custom rate limits.
- **WAF rules** for known-bad patterns.

### Origin-side defense-in-depth

Even with edge rate limits: origin should have its own rate limiting. Don't trust edge entirely; distributed attacks bypass.

---

## Edge logging and observability

### What you get

- **Cloudflare Workers:** Wrangler tail; Logpush to external destinations; Analytics Engine.
- **Lambda@Edge:** CloudWatch logs (per-edge-location).
- **CloudFront Functions:** CloudWatch logs.

### What's challenging

- Per-edge-location logging means N times the volume.
- Correlation across edges requires the SIEM to aggregate.
- Cost can be meaningful at scale.

### The discipline

- Ship logs to central archive (Logpush to S3 / R2 / GCS).
- Per-Worker structured logging (JSON).
- Detection rules in SIEM on edge-relevant patterns.

---

## Worked example: Meridian Health's edge-runtime posture

Meridian uses Cloudflare Workers for two edge-runtime workloads.

### Workload 1: WAF + rate-limit + JWT validation at edge

- Workers in front of Meridian's public APIs.
- Validates JWT; rate-limits per user; rejects known-bad patterns.
- Reduces origin load by ~30%.

### Workload 2: per-tenant routing

- Workers route requests to tenant-specific Cloudflare Tunnels.
- Tenant-aware routing without origin lookup.
- Stateless; reads tenant configuration from KV.

### Deployment

- Wrangler-based; CI/CD via GitHub Actions.
- OIDC federation: Cloudflare API token retrieved via short-lived OIDC.
- Per-environment Workers (dev, staging, prod).
- Canary deployment via Cloudflare gradual rollout.

### Secrets

- API tokens (e.g., for backend services) in Cloudflare Secrets.
- Rotation: quarterly.
- Audit: Wrangler logs every Secret access (limited; supplemented by application logging).

### Supply-chain protection

- Code reviews required.
- Deployment requires two-person approval (Wrangler in CI; gated by GitHub branch protection).
- Canary 1% for 1 hour before 100% promotion.
- Automated kill-switch: error rate spike → automatic rollback.

### Logging

- Logpush to S3 (in Meridian's log-archive account).
- Per-request fields: user ID, action, latency, response code.
- SIEM detection on anomalous patterns.

### Findings opened during the edge-runtime audit

- **EDGE-001** (Workers deployed via Wrangler in CI; long-lived Cloudflare API tokens). Closed by OIDC federation.
- **EDGE-002** (no canary deployment; updates went 100% immediately). Closed by gradual rollout.
- **EDGE-003** (no automated rollback on error spike). Closed by Cloudflare's automated rollback configuration.
- **EDGE-004** (Worker code lacked secret-scanning in CI). Closed by Gitleaks integration.
- **EDGE-005** (Worker secrets rotation manual; no schedule). Closed by quarterly rotation.
- **EDGE-006** (Worker logs not in central archive; per-edge logs only). Closed by Logpush to S3.

---

## Anti-patterns

### 1. The edge-runs-everything overshoot

Team adopts edge for full application logic. Operational pain ensues; debugging is hard; cold-start (yes, even at edge) hurts.

The fix: use edge for the specific edge use cases; origin for the application.

### 2. The instant-100% deployment

Edge code deployed to all locations at once. Bad code is in production at all edges within seconds.

The fix: canary deployment; gradual rollout; automated kill-switch.

### 3. The static-secrets-in-code

API keys or other secrets in the Worker code. Anyone with deploy access reads them; git history reveals.

The fix: Cloudflare Secrets (Wrangler put secret); rotation discipline.

### 4. The unrestricted-deployer set

Many engineers can deploy Workers. A compromise of any deploys to production.

The fix: limited deployer set; multi-person approval; CI/CD gate.

### 5. The forgotten supply-chain protection

Edge code accepted without same Cosign / signing discipline as Kubernetes images.

The fix: signing + verification at deployment; same patterns as image supply chain.

### 6. The over-broad rate-limit reliance

Team relies entirely on edge rate-limit. Distributed attack bypasses; origin saturates.

The fix: edge rate-limit + origin rate-limit; defense-in-depth.

### 7. The unmonitored deploy

Edge deploy happens; no monitoring on the immediate behavior. Bad deploys cause incidents before manual detection.

The fix: per-deploy monitoring; automated rollback on error.

### 8. The logs-stay-at-edge

Worker logs in Cloudflare's dashboard only. SIEM doesn't see them; detection is impossible.

The fix: Logpush to central archive; SIEM detection rules.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| EDGE-001 | Edge runtime deployment uses long-lived API tokens | High | OIDC federation; short-lived tokens in CI | DevOps + Security Eng |
| EDGE-002 | No canary deployment pattern; instant 100% rollouts | High | Gradual rollout (1% → 10% → 50% → 100%); automated kill-switch | DevOps + Security Eng |
| EDGE-003 | No automated rollback on error spike | High | Error-rate monitoring; automated rollback configuration | DevOps + SRE |
| EDGE-004 | Edge code not in CI secret-scanning | Medium | Gitleaks per [../secrets-and-keys/secret-detection.md](../secrets-and-keys/secret-detection.md) | DevOps + Security Eng |
| EDGE-005 | Edge secrets rotation manual; no schedule | Medium | Quarterly rotation; documented procedure | Security Eng + Platform Eng |
| EDGE-006 | Edge logs not in central archive; per-edge only | Medium | Logpush to S3 / R2; SIEM ingestion | Security Eng + Observability |
| EDGE-007 | Edge code lacks signing / verification at deployment | High | Same Cosign / signature pattern as container images | DevOps + Security Eng |
| EDGE-008 | Many engineers can deploy edge code | Medium | Restricted deployer set; multi-person approval; gated CI | Security Eng + DevOps |
| EDGE-009 | Edge as only rate-limit; origin unprotected against distributed attack | High | Origin rate-limit as defense-in-depth | Application Eng + SRE |
| EDGE-010 | Edge runtime used for full-application logic where origin would be better | Low | Evaluate edge fit; migrate non-edge use cases to origin | Architecture + Application Eng |
| EDGE-011 | Edge per-request authentication weak; tokens not validated | High | JWT validation; signature verification; expiration check | Application Eng + Security Eng |
| EDGE-012 | Edge code includes static API keys for backend services | High | Cloudflare Secrets / equivalent; rotation discipline | Application Eng + Security Eng |
| EDGE-013 | No code review on edge changes; supply-chain risk | High | PR review required; CI gate | DevOps + Security Eng |
| EDGE-014 | Edge code's dependencies not scanned for vulnerabilities | Medium | Dependency scanning in CI; per-language tooling | DevOps + Security Eng |
| EDGE-015 | Per-edge logging volume not budgeted; cost surprise | Low | Cost monitoring; sampling where appropriate | FinOps + Observability |
| EDGE-016 | Worker / function uses third-party npm package without review | Medium | Vetted dependency list; review of new deps | Application Eng + Security Eng |
| EDGE-017 | KV / Durable Objects access not least-privilege | Medium | Per-Worker bindings to specific resources | Platform Eng + Security Eng |
| EDGE-018 | Edge deploy events not in change-management log | Low | Deploy events to central audit; reviewed | DevOps |

---

## What this document is not

- **A Cloudflare Workers tutorial.** Cloudflare documentation covers depth.
- **A Lambda@Edge reference.** AWS documentation covers depth.
- **An edge-runtime vendor comparison.** Choice depends on existing CDN / WAF relationships.
- **A complete CDN reference.** CDN-specific patterns are out of scope.
