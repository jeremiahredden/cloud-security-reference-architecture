# API Gateway Security

A practitioner's reference for securing API-gateway layers — AWS API Gateway, Azure API Management, GCP Apigee, and the alternative patterns (Application Load Balancer, Azure Front Door, Cloudflare). The patterns here cover authentication (IAM, Cognito, custom authorizer, JWT validator, OIDC), rate limiting, WAF integration, request validation, and the SSRF-via-misconfigured-integration anti-pattern that turns a benign-looking gateway into a request-forwarding gadget.

This document is the public-facing edge companion to [lambda-functions-security.md](./lambda-functions-security.md). Lambda is the compute; API Gateway is what people reach to invoke it. Most production serverless APIs live behind one of the gateway products.

The honest framing: API Gateway is more security-relevant than most teams treat it. The gateway holds the authentication, the rate limiting, the WAF integration, the request validation, the CORS handling, and the routing — five distinct security domains, each with their own configuration. A misconfigured gateway is a misconfiguration in five places at once.

---

## When to read this document

**If you operate API Gateway / API Management / Apigee and aren't sure what the baseline should be** — read top to bottom.

**If you've seen "request validation" in the docs and aren't sure what it actually does** — start with [Request validation](#request-validation).

**If you have an integration that takes a URL from the request and forwards** — start with [The SSRF anti-pattern](#the-ssrf-anti-pattern). This is the most common single critical misconfiguration.

**If you are auditing API Gateway posture** — start with [Findings checklist](#findings-checklist).

---

## What an API gateway is, security-wise

The gateway sits between external clients and backend services. It handles:

- **Authentication** (validating the caller).
- **Authorization** (per-endpoint access policy).
- **Rate limiting** (per-caller, per-API throttling).
- **Request validation** (schema, headers, query parameters).
- **Routing** (URL → backend service).
- **Transformation** (request / response modification).
- **CORS** (cross-origin policy).
- **Caching** (for GET responses).
- **Observability** (logs, metrics, tracing).
- **WAF integration** (often combined with CDN / WAF service).

Each is a security domain. A baseline-secure gateway gets all of them right.

---

## Authentication patterns

The pattern depends on the caller.

### IAM authentication (machine-to-machine within the cloud)

For service-to-service calls within the cloud:

- API Gateway requires SigV4-signed requests.
- The caller's IAM role must have permission to invoke the API.
- The gateway validates the signature.

```yaml
# AWS API Gateway resource policy
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/internal-service-role"},
    "Action": "execute-api:Invoke",
    "Resource": "arn:aws:execute-api:us-east-1:ACCOUNT:API-ID/*/*/*"
  }]
}
```

For Azure: API Management with Managed Identity.
For GCP: Apigee with IAM authentication.

Best for: internal service-to-service; no end-user authentication needed.

### Cognito / Entra ID user pool (user authentication)

For user-facing APIs:

- User authenticates with Cognito / Entra ID / Google Identity.
- Returns a JWT (access token, ID token).
- API Gateway validates the JWT before forwarding to backend.

```yaml
# API Gateway Cognito authorizer
authorizers:
  cognito-auth:
    type: cognito_user_pools
    providerARNs:
      - arn:aws:cognito-idp:us-east-1:ACCOUNT:userpool/POOL-ID

endpoints:
  /api/v1/coordinator:
    authorizer: cognito-auth
    scopes: [coordinator.read, coordinator.write]
```

Best for: user-facing APIs where Cognito / Entra ID handles authentication.

### JWT validator (third-party identity provider)

For APIs authenticating against a third-party IdP (Auth0, Okta, custom):

- API Gateway validates the JWT signature against the IdP's public key (JWKS).
- Verifies claims (issuer, audience, expiration).
- Forwards if valid.

```yaml
authorizers:
  okta-auth:
    type: jwt
    issuer: https://meridian.okta.com
    audience: care-coordinator-api
```

Best for: Okta / Auth0 / OIDC-based authentication.

### Custom authorizer (Lambda authorizer)

For complex authentication that built-in options don't cover:

- API Gateway invokes a Lambda function (the authorizer).
- Authorizer returns allow / deny + context.
- Gateway forwards based on the decision.

```yaml
authorizers:
  custom-auth:
    type: token
    function: care-coordinator-authorizer
    identitySource: $request.header.Authorization
    cacheTtl: 300
```

The Lambda receives the request, validates whatever it needs to validate, returns the decision.

Best for: business-logic authentication (e.g., "validate this token + check tenant entitlement + verify license").

### The "no authentication" anti-pattern

API exposed without any authentication. The blast radius is whatever the backend exposes.

The fix: every internet-facing API requires authentication; internal-only APIs use IAM or mTLS.

---

## Rate limiting

Protection against abuse and DoS.

### Per-API rate limits

API-wide throttling:

```yaml
throttle:
  burstLimit: 200
  rateLimit: 100  # requests per second
```

For burst handling and steady-state rate limiting.

### Per-API-key rate limits

For APIs with API keys (paid tiers, partner integrations):

```yaml
usage_plans:
  - name: standard
    throttle:
      burstLimit: 100
      rateLimit: 50
    quota:
      limit: 1000000  # per month
      period: MONTH
  - name: premium
    throttle:
      burstLimit: 500
      rateLimit: 200
    quota:
      limit: 10000000
      period: MONTH
```

API keys assigned to clients; per-key tracking; quota enforcement.

### Per-user rate limits (custom)

For per-user limits (free vs paid tiers):

- Lambda authorizer returns user context.
- Application enforces per-user limits.
- Or: API Gateway + DynamoDB tracking.

### What rate limiting protects

- **DoS attempts.** Mass requests blocked at the gateway.
- **Cost-DoS.** Each request might trigger expensive backend operations; rate-limiting bounds cost.
- **Abuse.** Scraping, credential stuffing, enumeration.

### What rate limiting doesn't protect

- **Sophisticated distributed attacks.** Rate limits are per-source; distributed sources bypass.
- **Application-layer abuse.** Each request is "valid" but the workflow is abuse.

The defenses: WAF (next section), CDN integration, application-layer monitoring.

---

## WAF integration

A WAF (Web Application Firewall) inspects requests for malicious patterns.

### AWS WAF integration

AWS WAF integrates with:

- CloudFront (in front of API Gateway).
- Application Load Balancer.
- API Gateway directly.

```yaml
# WAF web ACL
rules:
  - aws-managed-rules-common-rule-set
  - aws-managed-rules-known-bad-inputs
  - rate-based-rule:
      limit: 2000  # requests per 5 minutes per IP
  - custom-sql-injection-rule
```

The pattern: managed rules (AWS / Cloudflare / Azure provide curated sets) + custom rules for application-specific patterns.

### Azure API Management + Front Door

Azure Front Door + WAF in front of API Management:

- Front Door is the edge; WAF is the protection.
- API Management is the API layer.

### GCP Cloud Armor + Apigee

Cloud Armor in front of Apigee; provides DDoS protection and WAF rules.

### What WAF catches

- SQL injection attempts.
- XSS attempts.
- Known-bad request patterns.
- IP-based reputation.
- Geo-based blocking.

### What WAF doesn't catch

- Application logic bugs.
- Business-logic abuse.
- Authenticated-but-malicious-user actions.
- Zero-day patterns not yet in rule sets.

WAF is one layer; application-layer security is the other.

---

## Request validation

Validate requests before they reach the backend.

### Schema-based validation

API Gateway validates against a JSON schema:

```yaml
schemas:
  CreateCoordinationRequest:
    type: object
    properties:
      patient_id:
        type: string
        pattern: '^MERID-[0-9]{7}$'
      coordinator_id:
        type: string
        format: uuid
      priority:
        type: string
        enum: [low, normal, high, urgent]
      notes:
        type: string
        maxLength: 5000
    required: [patient_id, coordinator_id, priority]
    additionalProperties: false

endpoints:
  /api/v1/coordination:
    post:
      requestSchema: CreateCoordinationRequest
```

Requests that don't match the schema are rejected at the gateway; backend doesn't see invalid data.

### Header validation

Required headers (auth tokens, content-type, tracing IDs):

```yaml
endpoints:
  /api/v1/coordination:
    post:
      requestParameters:
        method.request.header.Authorization: true
        method.request.header.X-Tenant-Id: true
        method.request.header.Content-Type: true
```

Missing required headers = rejected.

### Query parameter validation

Similar pattern for query parameters.

### Why this matters

- **Defense-in-depth:** even if the backend has validation, gateway-layer validation catches a class of issues earlier.
- **Cost protection:** invalid requests don't hit the backend; less compute consumed.
- **Backend simplification:** backend can assume valid inputs.

The pattern: schema-based validation for every body-accepting endpoint.

---

## The SSRF anti-pattern

The most common critical API Gateway misconfiguration.

### The pattern

API Gateway has an integration that takes a URL from the request:

```yaml
endpoints:
  /api/v1/proxy:
    get:
      integration:
        type: http_proxy
        uri: $request.querystring.url   # ← anti-pattern
```

The caller submits `?url=http://internal-service`; the gateway forwards. The gateway is now an SSRF gadget.

### Why this happens

- A developer needed a quick proxy; built it with URL-from-query.
- An integration with a third-party requires URL templating; the URL ends up controllable.
- The "proxy" pattern is convenient for some use cases.

### The fix

- **Never take URLs from caller-controlled inputs.** Hardcode backend URLs in the integration.
- **If templating is needed:** validate the template against an allowlist; never accept arbitrary URLs.
- **If the use case is "make HTTP calls based on caller input":** that's a sandbox problem, not a gateway problem.

### Detection

- Audit gateway integration configurations.
- Look for `$request.querystring` or `$request.body` in `uri` fields.
- Look for `path` parameters in integration URIs.

The audit catches the misconfiguration; fix or remove.

### Beyond URL-in-query

Other SSRF surfaces in gateways:

- **Webhook proxy patterns** that take target URLs.
- **Generic-proxy endpoints** for "internal use only."
- **Open-redirect endpoints** (`?redirect=...`).

All require validation; none should accept arbitrary inputs.

---

## CORS handling

Cross-Origin Resource Sharing.

### The default-permissive failure mode

```yaml
cors:
  allowOrigins: ["*"]
  allowMethods: ["*"]
  allowHeaders: ["*"]
```

The API is reachable from any origin. CSRF protection depends on application code; defense-in-depth is weakened.

### The tight pattern

```yaml
cors:
  allowOrigins:
    - https://app.meridian.health
    - https://admin.meridian.health
  allowMethods: [GET, POST, PUT, DELETE]
  allowHeaders: [Authorization, Content-Type, X-Tenant-Id]
  allowCredentials: true
  maxAge: 3600
```

Specific origins; specific methods; specific headers.

### Per-environment CORS

- Production: tight specific origins.
- Dev: localhost + dev origins.
- No production with `*`.

---

## Custom domain and TLS

API Gateway endpoints have default domains (e.g., `apiid.execute-api.us-east-1.amazonaws.com`). Production APIs use custom domains.

### TLS configuration

- Minimum TLS 1.2; TLS 1.3 preferred.
- Modern cipher suites only.
- HSTS header on responses.
- Certificate via ACM (or Cloudflare's universal certificate; or Azure Front Door's).

### Certificate management

- ACM-managed certificate for automatic rotation.
- Per-domain certificate; not wildcards where avoidable.
- Certificate expiration monitoring.

### Per-environment domains

- Production: `api.meridian.health`
- Staging: `api-staging.meridian.health`
- Dev: `api-dev.meridian.health`

Each with its own certificate; per-environment TLS configuration.

---

## Worked example: Meridian Health's API Gateway posture

Meridian's external APIs use API Gateway + WAF + Cloudflare in front.

### Architecture

```
Client → Cloudflare (DDoS + WAF + bot management)
       → AWS CloudFront (CDN, WAF Web ACL)
       → AWS API Gateway (auth, rate limiting, validation)
       → Backend (Lambda or ALB to ECS)
```

Each layer adds protection.

### Authentication

- **User-facing APIs:** Cognito User Pools; JWT validation at gateway.
- **Partner APIs:** Per-partner API keys with usage plans.
- **Internal-only APIs:** IAM authentication via SigV4.

### Rate limiting

- Per-API key for partner APIs (per usage plan).
- API-wide for user-facing APIs.
- Custom per-user rate limits enforced in Lambda authorizer for sensitive endpoints.

### WAF

- Cloudflare WAF: managed rules + custom rules for known bots / scrapers.
- CloudFront WAF: AWS managed rules + rate-based rules per IP.
- API Gateway: no WAF directly (handled upstream).

### Request validation

- Every body-accepting endpoint has a JSON schema.
- Required headers documented per endpoint.
- Per-endpoint quotas and timeouts.

### SSRF prevention

- No integration uses caller-controlled URLs.
- Audit pass every quarter on integration configurations.
- Detection on attempted SSRF patterns (rare; mostly automated scanners).

### CORS

- Tight per-API: specific origins only.
- Production never uses `*`.
- Per-environment CORS configurations.

### Findings opened during the API Gateway audit

- **APIGW-001** (~20 APIs had `*` in CORS allowOrigins). Closed by per-API tightening.
- **APIGW-002** (3 APIs had `AuthType: NONE`; no authentication). Closed by adding Cognito / API key.
- **APIGW-003** (One internal API had `$request.querystring.url` in integration; SSRF possible). Closed by removing the URL-templating pattern.
- **APIGW-004** (rate limiting absent on 5 high-traffic APIs). Closed by per-API throttle configuration.
- **APIGW-005** (request validation absent on body-accepting endpoints). Closed by JSON schemas + validation.
- **APIGW-006** (TLS 1.0 / 1.1 supported on some APIs). Closed by minimum TLS 1.2 baseline.
- **APIGW-007** (WAF rules sparse; only AWS-managed common). Closed by additional rule sets including bot management.

---

## Anti-patterns

### 1. The unauthenticated public API

API exposed without authentication. Backend is the blast radius.

The fix: every internet-facing API requires authentication.

### 2. The CORS-allow-everything

`allowOrigins: ["*"]` on a production API.

The fix: specific origins per environment.

### 3. The SSRF gadget

Integration takes URL from query / body / path.

The fix: hardcoded backend URLs; allowlists for templating.

### 4. The unlimited rate

No throttling; cost-DoS possible.

The fix: per-API throttle baseline; per-key for partner APIs.

### 5. The skipped request validation

Body-accepting endpoints have no schema. Backend gets arbitrary input.

The fix: JSON schema for every body endpoint.

### 6. The hardcoded API key

API keys distributed via documentation; the same key used by many clients.

The fix: per-client API keys; rotation cadence.

### 7. The forgotten authorizer cache

Lambda authorizer returns a decision; cached for 5 minutes. Permissions change but cached decisions remain.

The fix: cache TTL aligned to authorization-data freshness needs; short TTL for high-sensitivity APIs.

### 8. The deprecated-TLS support

API accepts TLS 1.0 / 1.1 for compatibility. Compliance audit fails.

The fix: TLS 1.2 minimum; TLS 1.3 preferred.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| APIGW-001 | CORS `allowOrigins` uses `*` on production API | High | Tighten to specific origins per environment | Application Eng + Security Eng |
| APIGW-002 | API exposed without authentication | High | Add Cognito / JWT / API key / IAM authentication | Application Eng + Security Eng |
| APIGW-003 | Integration uses caller-controlled URL; SSRF possible | High | Hardcode backend URL; allowlist for templating | Application Eng + Security Eng |
| APIGW-004 | Rate limiting absent on high-traffic API | Medium | Per-API throttle configuration; cost-DoS protection | Platform Eng + FinOps |
| APIGW-005 | Request validation absent on body-accepting endpoints | Medium | JSON schemas; gateway-level validation | Application Eng + Security Eng |
| APIGW-006 | TLS 1.0 / 1.1 supported | High | Minimum TLS 1.2; TLS 1.3 preferred | Platform Eng + Security Eng |
| APIGW-007 | WAF rules sparse; only managed common rules | Medium | Additional rule sets (bot management, custom rules) | Security Eng |
| APIGW-008 | Lambda authorizer cache TTL too long; permission changes don't propagate | Medium | Align TTL with authorization-data freshness; short for high-sensitivity | Security Eng + Application Eng |
| APIGW-009 | API keys shared across many clients; no per-client tracking | Medium | Per-client API keys; usage plans; rotation cadence | Platform Eng + Customer Eng |
| APIGW-010 | API Gateway logs not consumed by SIEM | Medium | Log shipping; detection rules on unusual patterns | Security Eng + SOC |
| APIGW-011 | Per-API monitoring absent; outage patterns invisible | Low | Per-API metrics; SLO tracking | SRE + Platform Eng |
| APIGW-012 | Custom domain certificate near expiration; rotation manual | Medium | ACM-managed certificate; automatic rotation; expiry monitoring | Platform Eng + Security Eng |
| APIGW-013 | API spec / contract not version-controlled | Medium | OpenAPI / API definition in source control; CI deployment | DevOps + Application Eng |
| APIGW-014 | Stage-specific configurations missing; production = dev config | Medium | Per-stage config (auth, rate, CORS); production hardened | DevOps |
| APIGW-015 | Backend-level authentication absent; trusting gateway entirely | Medium | Defense-in-depth: backend validates auth too | Application Eng + Security Eng |
| APIGW-016 | OPTIONS preflight requests bypass authentication; potential info leak | Low | Preflight responses minimal; no sensitive info in headers | Application Eng |
| APIGW-017 | Error responses leak internal details (stack traces, paths) | Medium | Generic error responses externally; details in logs only | Application Eng + Security Eng |
| APIGW-018 | No detection on attempted SSRF patterns | Low | SIEM rules on suspicious integration-call patterns | Security Eng + SOC |

---

## What this document is not

- **An API Gateway / API Management / Apigee tutorial.** Vendor documentation covers operational depth.
- **A WAF rule-writing guide.** WAF-rule depth lives with the WAF vendor's documentation.
- **A complete REST API design guide.** API design patterns are out of scope.
- **A complete OAuth / OIDC reference.** Authentication-protocol depth lives in identity-management documentation.
