# Vulnerable Examples — Intentionally Misconfigured IaC

Intentionally misconfigured IaC bundles that the policy-as-code pipeline rejects. Each bundle pairs with a corresponding secure example in [../examples/](../examples/) and is the negative test of the patterns documented in [../policy-as-code.md](../policy-as-code.md) and [../iac-pipeline-gates.md](../iac-pipeline-gates.md).

The bundles mirror the `demo-app/` pattern from the sibling AppSec repo, but for cloud infrastructure rather than application code: they exist so that scanners have something to find, so that pipelines have a known-failing case to test, and so that engineers can see what the failure modes look like.

> **WARNING:** Do NOT deploy these bundles. They are intentionally insecure. The vulnerabilities are not subtle. Use them only for scanner validation and engineer education.

## Bundles

- **[aws-landing-zone-vulnerable/](./aws-landing-zone-vulnerable/)** — AWS landing zone with intentional vulnerabilities: missing CloudTrail integrity controls, S3 buckets with public access, IAM policies with wildcards, KMS keys with broad principal grants.
- **[azure-subscription-vulnerable/](./azure-subscription-vulnerable/)** — Azure subscription with intentional vulnerabilities: Storage with public network access enabled, Key Vault without private endpoint, MGs without baseline policies.
- **[gcp-project-vulnerable/](./gcp-project-vulnerable/)** — GCP project with intentional vulnerabilities: default service account in use, public GCS buckets, Compute instances with external IPs.

## How they're used

1. **CI test:** the IaC CI pipeline runs against these bundles; expected output is "scanners detect N findings."
2. **Engineer education:** show engineers what the failure modes look like in IaC form.
3. **Tool evaluation:** when evaluating a new scanner, see if it catches the documented vulnerabilities.

## What's intentionally not here

- Real credentials, account IDs, or production resource names.
- Vulnerabilities that would result in immediate exploitation if deployed (e.g., we don't include actual exposed access keys; just patterns).

Per-bundle: the intentional vulnerabilities are documented in `findings.md`.

## See also

- [../examples/](../examples/) — the corresponding secure bundles.
- [../policy-as-code.md](../policy-as-code.md) — the scanners that catch these.
- [../iac-pipeline-gates.md](../iac-pipeline-gates.md) — the pipeline that should fail on these.

## Status

The bundles are illustrative documentation artifacts. The actual vulnerable IaC code-snippets appear inline in [../policy-as-code.md](../policy-as-code.md), [../terraform-security-patterns.md](../terraform-security-patterns.md), [../secure-modules.md](../secure-modules.md), and [../iac-pipeline-gates.md](../iac-pipeline-gates.md). The structure documented here is the template for an organization that wants to build these into actual deployable-but-rejected bundles.

For organizations adopting this pattern: build the bundles in your own monorepo; run them through your scanners; catalogue what each scanner catches and misses. The result is your scanner-tuning baseline.
