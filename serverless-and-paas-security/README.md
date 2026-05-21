# Serverless and PaaS Security

## What this folder is

A practitioner's reference for securing serverless and PaaS workloads — AWS Lambda, Azure Functions, GCP Cloud Functions and Cloud Run, API Gateway / API Management / Apigee, App Service, Container Apps, and edge runtimes (CloudFront Functions, Lambda@Edge, Cloudflare Workers). The material here is what I put in front of a team when the question is: *our serverless workloads have IAM roles with `*` actions, no rate limits, and event sources we cannot enumerate — how do we apply real security to a runtime that does not have a host?*

## The organizing principle

Serverless security is both easier and harder than IaaS security. Easier because the platform handles patching, OS hardening, runtime isolation, and a significant slice of the network-security responsibility. Harder because the controls move into IAM, into API Gateway configuration, into event-source policies, and into application code — places that traditional cloud-security tooling reads less well, and that the standard security-engineering instincts apply less reliably to. A misconfigured Lambda permission can hand an attacker access to a database. A misconfigured API Gateway can become a free open-redirect or SSRF gadget. A Cloud Function with a publicly-invokable URL is a public endpoint, regardless of whether anybody on the team thinks of it that way.

The folder is opinionated about three things. First, that **serverless IAM is more sensitive than IaaS IAM**, not less — a Lambda function with an over-permissive role is a more compact privilege-escalation primitive than an over-permissive EC2 instance role, because the function is event-driven and the trigger surface is wider. Second, that **event-source security is the under-attended control in 2026** — most teams audit the function role and the API Gateway, and quietly leave the SNS topic / SQS queue / EventBridge bus that triggers the function with permissive resource policies. Third, that **edge runtimes are a distinct security domain** from regional serverless — CloudFront Functions, Lambda@Edge, and Cloudflare Workers run with different identity models, different rate-limit options, and a much larger blast radius if compromised, and the patterns reflect that.

## Planned documents

- **lambda-functions-security.md** *(coming)* — AWS Lambda, Azure Functions, GCP Cloud Functions side by side. Execution-role design, environment-variable handling (never secrets, use a secrets manager), VPC integration vs no-VPC, dead-letter queue patterns, the cold-start vs warm-start security implications, function URLs and when they are appropriate.
- **api-gateway-security.md** *(coming)* — AWS API Gateway, Azure API Management, GCP Apigee, and the alternative patterns (Application Load Balancer, Azure Front Door, Cloudflare). Authentication (IAM, Cognito, custom authorizer, JWT validator, OIDC), rate limiting, WAF integration, request validation, the SSRF-via-misconfigured-integration anti-pattern.
- **event-source-security.md** *(coming)* — Event source policies (SNS, SQS, EventBridge, Event Grid, Pub/Sub), the cross-account event-source patterns, the "who can invoke this function" inventory problem, and the event-replay / dead-letter / poison-message patterns that affect both reliability and security.
- **paas-app-service-security.md** *(coming)* — Azure App Service, AWS Elastic Beanstalk, GCP App Engine, GCP Cloud Run. Managed identity / IRSA / Workload Identity attachment, ingress restriction, custom domain and TLS handling, the deploy-slot pattern as a security control, and the runtime-platform-version hygiene that lapses silently in PaaS environments.
- **edge-runtime-security.md** *(coming)* — CloudFront Functions, Lambda@Edge, Azure Front Door rules engine, Cloudflare Workers, Akamai EdgeWorkers. The identity-and-secrets model in edge runtimes, the rate-limit-at-edge-vs-origin pattern, and the supply-chain risk of edge runtimes (compromised code at edge runs everywhere instantly).
- **serverless-detection.md** *(coming)* — Detection patterns for serverless: CloudWatch / Application Insights / Cloud Logging, the "every function is also an audit-log generator" pattern, anomaly detection on invocation patterns, and the cost-as-detection-signal that catches runaway invocations.
- **serverless-iam-patterns.md** *(coming)* — Least-privilege IAM specifically for serverless: per-function roles (always), the "no role attached to multiple functions" baseline, the role-inheritance-via-environment-variable anti-pattern, and the IAM Access Analyzer workflow applied to function roles.

## How to use this section

**If you are designing a new serverless workload**, `serverless-iam-patterns.md` and `event-source-security.md` together cover the controls you want before the first invocation. The IAM model is easier to get right at design time than to retrofit.

**If you are operating an existing serverless estate**, `lambda-functions-security.md` and `api-gateway-security.md` together cover the audit pass. Most teams find that the function-URL inventory and the API-Gateway integration inventory each surface findings.

**If you are running edge workloads**, `edge-runtime-security.md` is the destination. The patterns for edge are genuinely different from regional serverless; treating them as the same is the most common failure mode I see.

## What this section is not

- **A complete serverless tutorial.** Working familiarity with Lambda / Functions / Cloud Functions is assumed. Where syntax appears, it is illustrative.
- **A FaaS-platform comparison.** Where specific platforms are named, they illustrate patterns. The folder is agnostic on procurement choice.
