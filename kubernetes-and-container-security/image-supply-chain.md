# Image Supply Chain

A practitioner's reference for the container image supply chain — image scanning (Trivy, Grype, vendor scanners), registry security (private registries, immutable tags, retention), Cosign / Sigstore signing, SLSA provenance, the keyless-signing-with-OIDC pattern, in-toto attestation, and admission-controlled image policy. The patterns here cover the chain from "engineer writes a Dockerfile" through "image is signed and attested" to "admission rejects unsigned or vulnerable images."

This document closes the kubernetes-and-container-security batch. It is the most-discussed and least-implemented area of cloud security in 2026 — every team agrees supply chain matters; few teams have actually deployed the full pattern. The honest framing: the Cosign-keyless + admission-enforced pattern is the single highest-leverage move; if a team does only one thing in supply chain, do that.

For the registry security context, see the section in this document. For broader container patterns, see [eks-aks-gke-baselines.md](./eks-aks-gke-baselines.md) and [pod-security.md](./pod-security.md). For the secret-scanning that prevents secrets in images, see [../secrets-and-keys/secret-detection.md](../secrets-and-keys/secret-detection.md).

---

## When to read this document

**If your cluster admits images from any registry without verification** — read top to bottom. The supply chain is wide open; the closing patterns are well-defined.

**If you have image scanning but unsigned images still deploy** — start with [The signing-enforcement pattern](#the-signing-enforcement-pattern). Scanning catches known vulnerabilities; signing prevents unauthorized images entirely.

**If your team uses `:latest` tags or non-pinned image references** — start with [Image-reference discipline](#image-reference-discipline). Pinning to digests is the prerequisite for everything else.

**If you are auditing supply-chain posture** — start with [Findings checklist](#findings-checklist). The common findings (no scanning, no signing, no admission enforcement, no SBOM) are universal.

---

## What "supply chain" means here

The container image supply chain is the sequence:

1. **Source code** in a repository.
2. **Dependencies** pulled at build time (npm, pypi, apt packages, Go modules).
3. **Base image** the Dockerfile starts from.
4. **Build environment** (CI runner, build tool).
5. **Image** produced by the build.
6. **Registry** that stores the image.
7. **Cluster admission** that pulls and runs the image.
8. **Runtime** where the container executes.

Each step is an attack surface. The supply chain patterns close the steps in sequence:

- Source: source-control discipline (per [../iac-security/](../iac-security/)).
- Dependencies: dependency scanning, SBOM generation.
- Base image: trusted base images, regular updates.
- Build environment: isolated, reproducible builds.
- Image: vulnerability scanning, signing.
- Registry: private registry, retention, immutable tags.
- Admission: signature verification, vulnerability gating, image-source allowlisting.
- Runtime: per [runtime-security.md](./), coming.

This document covers steps 5–7 with overlap into the others.

---

## Image-reference discipline

The prerequisite for everything else.

### The image-reference forms

```
nginx                                              # implicit :latest
nginx:1.27                                         # tag (mutable)
nginx@sha256:abc123def456...                       # digest (immutable)
nginx:1.27@sha256:abc123def456...                  # tag + digest (best practice)
public.ecr.aws/nginx/nginx:1.27@sha256:abc123...   # full registry + tag + digest
```

The pattern: **always pin to a digest**. The tag is a human-readable label; the digest is the cryptographic guarantee that the image content is what you expect.

### Why `:latest` is broken

- The tag is mutable; `nginx:latest` today is not the same as `nginx:latest` next week.
- A pod restart pulls the current `:latest`, potentially with different code.
- Rollback by image is meaningless; you have to know which `:latest` was running when.
- Security scans become unreliable; what you scanned isn't what you're running.

The admission policy that rejects `:latest` (per [admission-control.md §The common-policy library](./admission-control.md#the-common-policy-library)) is the structural fix.

### Why digest-pinning matters

A digest is the SHA256 of the image manifest. Two images with the same digest are byte-identical; two images with different digests are different.

The discipline:

- CI builds tag and push the image with both tag and digest.
- Kubernetes manifests reference the image by digest (often via tag + digest for human readability).
- Image-update workflows (Renovate, Dependabot, similar) update both the tag and the digest atomically.

```yaml
# Good
image: meridian-registry.local/care-coordinator-supervisor:v2.4.1@sha256:abc123def456...

# Acceptable (tag-only with admission policy rejecting :latest)
image: meridian-registry.local/care-coordinator-supervisor:v2.4.1

# Anti-pattern
image: meridian-registry.local/care-coordinator-supervisor:latest
```

### The mutable-tag risk

A specific failure: a team uses `nginx:1.27`. The maintainers push a new build with the same `1.27` tag (replacing the original). The team's deployments now run a different image than they tested.

The fix: digest pinning; or, if not feasible, the image-pull policy `Always` combined with explicit version awareness in the deployment.

---

## Vulnerability scanning

The starting move for most teams; necessary but not sufficient.

### The two scanning points

**Build-time scanning:** in the CI pipeline before the image is pushed.

- **Pro:** catches vulnerabilities before they reach the registry.
- **Pro:** the build fails on critical findings.
- **Con:** point-in-time; doesn't catch CVEs disclosed after the build.

**Registry / runtime scanning:** scans images in the registry and re-scans periodically as new CVEs are disclosed.

- **Pro:** catches the "we built clean but a new CVE was disclosed" case.
- **Pro:** continuous visibility.
- **Con:** finding doesn't block the original deploy; remediation is rebuild + redeploy.

Both are needed. Build-time prevents new bad images; registry/runtime detects evolving CVE landscape against deployed images.

### Common scanning tools

- **Trivy** (Aqua) — open source; widely adopted; fast; supports container images, IaC, SBOM, secret detection.
- **Grype** (Anchore) — open source; fast; SBOM-driven scanning.
- **Snyk Container** — commercial; integrated with developer tools.
- **Aqua Security** — commercial; broader CNAPP.
- **Wiz Container Scanning** — part of Wiz CNAPP.
- **AWS Inspector** (for ECR images) — managed scanning integrated with ECR.
- **Azure Defender for Containers** (for ACR).
- **GCP Artifact Registry vulnerability scanning** — for Artifact Registry.

The pattern: cloud-native tools for the registry-side (AWS Inspector for ECR, etc.); Trivy or Grype for build-time (open source, runs locally).

### Severity-to-action mapping

Not every CVE is equally important. The standard mapping:

| Severity | Action | Build behavior |
| --- | --- | --- |
| Critical | Block | Build fails |
| High | Block (with override for documented exception) | Build fails; override requires approval |
| Medium | Warn; track for remediation | Build proceeds; ticket created |
| Low | Log; periodic review | Build proceeds; aggregated |
| Unknown | Treat as Medium | Build proceeds; ticket created |

The pattern: critical and high block the build; medium and low get tracked but don't block. Adjust based on the team's risk tolerance and operational maturity.

### The false-positive management

Vulnerability scanners produce false positives:

- Vulnerability not actually exploitable in this image's usage.
- Vulnerability in a base image that the application doesn't trigger.
- Vulnerability already mitigated by other controls.

The discipline:

- **Allowlist mechanism** for documented false positives.
- **Justification required** for each allowlist entry (CVE, why not applicable, who reviewed).
- **Expiration** on each allowlist entry (re-review quarterly).
- **Bulk allowlisting** prohibited (each CVE evaluated individually).

Without false-positive management: scanners produce alert fatigue; teams ignore findings.

### SBOM generation

Software Bill of Materials lists every component in the image:

- Operating system packages.
- Language-specific packages (npm, pip, gems, etc.).
- Versions and licenses.

Tools (Trivy, Syft, Grype) generate SBOMs in standard formats (SPDX, CycloneDX).

The value:

- **Vulnerability tracking** — when a new CVE is disclosed, query SBOMs to find affected images.
- **Compliance** — required by some frameworks (e.g., Executive Order 14028 for federal contractors).
- **License tracking** — identify GPL or other licenses in commercial products.

The pattern: generate SBOM at build time; attach to the image as an attestation (see SLSA below); store for queryability.

---

## Registry security

The image registry is a critical asset.

### Private vs public registry

- **Public registries** (Docker Hub public, GitHub Container Registry public, ECR Public Gallery) host images for anyone to pull. Suitable for the team's open-source releases; not for internal application images.
- **Private registries** (private ECR, private ACR, private Artifact Registry, internal Harbor / Quay) host images for authenticated users. Standard for organizational images.

The discipline: organizational images in private registries only. Public registries used only for the team's open-source artifacts.

### Pull-secret management

Pulling from private registries requires authentication. The patterns:

- **Cloud-native:** IRSA / Workload Identity grants pods permission to pull from the cloud registry without explicit secrets.
- **imagePullSecret:** Kubernetes Secret containing registry credentials. Workable but a static secret to manage.

The cloud-native pattern is strongly preferred (per [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md)).

### Immutable tags

Many registries support **tag immutability** — once a tag is pushed, it cannot be overwritten. The benefits:

- Eliminates the mutable-tag risk above.
- Forces version discipline; every push requires a new tag.
- Audit trail is clear.

Enable on private registries for production-target tags.

### Retention policies

Registries accumulate images. The patterns:

- **Production images:** retain indefinitely (or per regulatory requirement, typically 1–7 years).
- **CI-built images** that didn't go to production: retain 30–90 days; then prune.
- **Untagged images:** prune aggressively (orphan layers).

Storage cost compounds without retention; security risk of stale-vulnerable images in the registry is real (they may still be referenced by old deployments).

### Registry-level scanning and access logs

- **Vulnerability scanning** at the registry (AWS Inspector for ECR, Defender for ACR, etc.) continuous; alerts on new CVEs.
- **Access logs** on the registry; capture pulls and pushes; ship to central log archive.

Detection rules look for unusual pull patterns (a workload pulling an image it doesn't normally use; potential lateral movement indicator) or unexpected pushes (compromised CI pushing malicious images).

### Image-registry-as-IaC

Registry configuration (repository policies, lifecycle rules, scan configurations) lives in IaC. Hand-configured registries drift; IaC-managed registries are consistent.

---

## Signing with Cosign / Sigstore

The critical pattern. If a team does one thing in supply chain, this is it.

### What signing provides

A digital signature on an image attests:

- **Who** signed it (the signing identity).
- **When** it was signed.
- **What** was signed (the specific image digest).

Verification at admission ensures only signed images are admitted.

### Keyed signing (traditional)

The team maintains a signing key:

- Generate a public/private key pair.
- Private key in the signing system (CI's key vault).
- Build pipeline signs each image with the private key.
- Admission policy verifies signatures with the public key.

Pros: simple to understand.
Cons: the private key is a high-value target; rotation is operationally complex.

### Keyless signing with OIDC (Sigstore)

The Sigstore approach — sign without long-lived keys:

- CI pipeline obtains an OIDC token from the CI provider (GitHub Actions, GitLab CI, etc.).
- Cosign uses the OIDC token to obtain a short-lived signing certificate from Fulcio (the Sigstore CA).
- The image is signed with the short-lived key.
- The signature, certificate, and OIDC claim are recorded in Rekor (the Sigstore transparency log).
- The short-lived key is discarded.

The verification:

- Verifier checks the signature against the certificate.
- Verifier checks the certificate was issued by Fulcio.
- Verifier checks the OIDC identity matches the expected (e.g., a specific GitHub repo + workflow).
- Verifier checks Rekor for the inclusion proof.

Pros: no long-lived signing keys; identity-bound (the GitHub repo / workflow is part of the signature); transparency log provides audit trail.
Cons: relies on Sigstore infrastructure (Fulcio, Rekor); newer than keyed signing.

The recommendation: **keyless signing with Sigstore for new deployments**. The pattern is mature in 2026; the lack of long-lived keys is structurally simpler.

### A keyless signing example (GitHub Actions)

```yaml
- name: Install Cosign
  uses: sigstore/cosign-installer@v3

- name: Build and push image
  id: build
  run: |
    docker build -t meridian-registry.local/care-coordinator-supervisor:${{ github.sha }} .
    docker push meridian-registry.local/care-coordinator-supervisor:${{ github.sha }}
    DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' meridian-registry.local/care-coordinator-supervisor:${{ github.sha }})
    echo "digest=$DIGEST" >> $GITHUB_OUTPUT

- name: Sign image with Cosign
  env:
    COSIGN_EXPERIMENTAL: 1
  run: cosign sign --yes ${{ steps.build.outputs.digest }}
```

The `--yes` flag accepts the prompt for keyless signing. The signature is published to Rekor automatically.

### The verification policy

Kyverno's verifyImages policy (introduced in [admission-control.md](./admission-control.md)):

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-meridian-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-images
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences:
            - "meridian-registry.local/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/meridian-health/*/.github/workflows/build.yaml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
```

Pods using images from `meridian-registry.local` must have a Cosign signature from a GitHub Actions workflow in the `meridian-health` org, on the `main` branch, signing via the `build.yaml` workflow. Other signing sources are rejected.

The pattern: signing identity is tied to specific repo + workflow + branch. An attacker who compromises one workflow can sign images attributable to that workflow only; cross-workflow forgery is impossible.

References:
- [Sigstore](https://www.sigstore.dev/)
- [Cosign](https://docs.sigstore.dev/cosign/overview/)
- [Kyverno verifyImages](https://kyverno.io/docs/writing-policies/verify-images/)
- [Connaisseur](https://sse-secure-systems.github.io/connaisseur/) (alternative admission-controller for signature verification)
- [Sigstore Policy Controller](https://docs.sigstore.dev/policy-controller/overview/) (Sigstore's dedicated admission controller)

---

## SLSA provenance and attestation

Signing proves who built the image. SLSA (Supply-chain Levels for Software Artifacts) goes deeper — attesting the build process itself.

### What SLSA provides

The SLSA framework defines levels of supply-chain integrity:

- **Level 1:** source and build are documented.
- **Level 2:** source and build use authenticated provenance (signed build records).
- **Level 3:** hardened build platform; non-falsifiable provenance.
- **Level 4:** two-party review and hermetic / reproducible builds.

For most organizations: SLSA Level 3 is the practical target. Level 4 requires significant build-platform engineering.

### In-toto attestation

SLSA uses **in-toto attestation** — signed statements about the build process:

- Build platform identity.
- Source repository and commit SHA.
- Builder identity (the CI runner / image).
- Build steps (in some patterns, the full build trace).
- Output artifact digest.

The attestation is signed (often via the same Cosign keyless flow as the image signature) and attached to the image.

### Generation in CI

```yaml
- name: Generate SLSA provenance
  uses: slsa-framework/slsa-github-generator@v2
  with:
    base64-subjects: "${{ steps.build.outputs.digest }}"

- name: Sign attestation with Cosign
  env:
    COSIGN_EXPERIMENTAL: 1
  run: cosign attest --predicate slsa-provenance.json --yes ${{ steps.build.outputs.digest }}
```

The attestation is signed and pushed alongside the image.

### Verification at admission

The admission policy can verify both signature and attestation:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-slsa-attestation
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-attestation
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences:
            - "meridian-registry.local/*"
          attestations:
            - type: https://slsa.dev/provenance/v0.2
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/meridian-health/*"
                        issuer: "https://token.actions.githubusercontent.com"
              conditions:
                - all:
                    - key: "{{ slsa.builder.id }}"
                      operator: Equals
                      value: "https://github.com/actions/runner@v2"
```

The policy verifies the attestation predicate matches expectations (built by GitHub Actions, from the expected repo, etc.).

### The audit-trail benefit

With signing + attestation:

- **Audit:** every deployed image traces to a specific commit, specific CI run, specific signed attestation.
- **Forensics:** if a vulnerability is found, the build trail tells you when the vulnerability was introduced.
- **Compliance:** SBOM + attestation satisfies many supply-chain regulatory requirements.

---

## Base image discipline

The base image (the `FROM` line in the Dockerfile) is the foundation; vulnerabilities in the base inherit to the image.

### Trusted base images

- **Distroless** (Google) — minimal base images with no shell, no package manager. Very small attack surface.
- **Chainguard Images** (formerly Wolfi) — commercial; aggressively maintained; near-zero CVEs.
- **Official upstream images** (the project's official Docker Hub images) — typically well-maintained for major projects.
- **Cloud-vendor images** (AWS-maintained Amazon Linux containers, Microsoft-maintained mariner) — vendor-maintained; suitable for vendor-aligned workloads.

The pattern: prefer minimal, well-maintained base images. The bigger the base, the more inherited surface.

### Base-image refresh cadence

Base images are versioned. The discipline:

- **Pin base images** to specific tags + digests in Dockerfiles.
- **Automated updates** via Dependabot / Renovate; PRs to bump base versions.
- **Regular rebuilds** of dependent images on base updates.
- **CVE-driven rebuilds** when a new CVE in the base is disclosed.

Without this discipline, base images age silently; vulnerabilities accumulate.

### The team's own base images

Some teams build their own base images for organizational consistency:

- Standard OS configuration.
- Pre-installed organizational tools (monitoring agents, security agents).
- Approved base for downstream Dockerfiles.

If the team does this: the same scanning + signing + attestation discipline applies to the team's base images.

---

## Worked example: Meridian Health's image supply chain

Meridian operates an end-to-end signed-image pipeline: GitHub Actions builds, Cosign keyless signs, SLSA attestations are generated and signed, ECR stores, Kyverno admission verifies before pod creation.

### The build pipeline

```yaml
name: Build and Push Image
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write   # for OIDC federation
  packages: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure AWS via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::ACCOUNT:role/meridian-image-builder
          aws-region: us-east-1

      - name: Login to ECR
        run: aws ecr get-login-password | docker login --username AWS --password-stdin meridian-registry.local

      - name: Build image
        run: docker build -t meridian-registry.local/care-coordinator-supervisor:${{ github.sha }} .

      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@v0
        with:
          image-ref: meridian-registry.local/care-coordinator-supervisor:${{ github.sha }}
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Push image
        run: docker push meridian-registry.local/care-coordinator-supervisor:${{ github.sha }}

      - name: Get digest
        id: digest
        run: echo "DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' meridian-registry.local/care-coordinator-supervisor:${{ github.sha }})" >> $GITHUB_OUTPUT

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign image (keyless)
        env:
          COSIGN_EXPERIMENTAL: 1
        run: cosign sign --yes ${{ steps.digest.outputs.DIGEST }}

      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator@v2
        with:
          base64-subjects: ${{ steps.digest.outputs.DIGEST }}

      - name: Attest SBOM
        env:
          COSIGN_EXPERIMENTAL: 1
        run: |
          trivy image --format spdx-json --output sbom.json ${{ steps.digest.outputs.DIGEST }}
          cosign attest --predicate sbom.json --type spdxjson --yes ${{ steps.digest.outputs.DIGEST }}
```

### The cluster admission policy

Per [admission-control.md](./admission-control.md), the cluster's Kyverno policy:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-meridian-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences:
            - "meridian-registry.local/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/meridian-health/*/.github/workflows/build.yaml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
          attestations:
            - type: https://slsa.dev/provenance/v0.2
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/meridian-health/*"
                        issuer: "https://token.actions.githubusercontent.com"
```

### The ECR configuration

- **Private repositories** for all Meridian images.
- **Tag immutability** enabled.
- **Lifecycle policies:** retain production tags indefinitely; expire untagged after 14 days; expire non-prod tagged images after 90 days.
- **AWS Inspector** scanning enabled; alerts on new CVEs in stored images.
- **CloudTrail** captures registry access; ships to central log archive.

### Third-party images

Meridian also uses third-party images (open-source dependencies, vendor tools). The pattern:

- **Vetted catalog:** approved third-party images listed in a Meridian-internal allowlist.
- **Mirror to internal registry:** approved images copied (with their original signatures preserved) to a Meridian sub-registry.
- **Admission policy:** allows images from the mirror; rejects images directly from public registries.

This prevents `kubectl create deployment --image=random-image:latest` patterns.

### The migration story

Meridian's clusters originally pulled images from various sources without verification. Migration over 6 sprints:

- Sprint 1: deploy Cosign signing in CI; backfill signatures for production images.
- Sprint 2: deploy Kyverno verifyImages policy in audit mode.
- Sprint 3: backfill SLSA attestations.
- Sprint 4: implement third-party image catalog.
- Sprint 5: switch admission policy to enforce mode on dev / staging.
- Sprint 6: switch to enforce mode on production.

Result: every production image is signed by a known CI workflow; every image's deploy path traces to a specific commit; SBOM available for vulnerability queries.

### Findings opened during the supply-chain audit

- **IMG-001** (production images not signed). Closed by Cosign keyless signing in CI.
- **IMG-002** (admission did not verify image signatures). Closed by Kyverno verifyImages policy.
- **IMG-003** (images used `:latest` tag in some workloads). Closed by digest-pinning discipline and admission policy.
- **IMG-004** (third-party images pulled directly from public registries). Closed by vetted-catalog + mirror approach.
- **IMG-005** (SBOM not generated; CVE tracking required manual scanning). Closed by SBOM attestations.
- **IMG-006** (registry retention not configured; storage costs growing). Closed by lifecycle policies.
- **IMG-007** (no SLSA attestation; build provenance unverifiable). Closed by SLSA generator + attestation.
- **IMG-008** (build pipeline used static AWS credentials). Closed by OIDC federation (per [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md)).

---

## Anti-patterns

### 1. The pull-from-anywhere cluster

The cluster admits images from any registry without verification. A compromised registry or a typo on a docker pull command can introduce malicious code.

The fix: image-source allowlist; signature verification; vetted third-party catalog.

### 2. The mutable-tag deployment

Workloads reference images by mutable tag (`:latest`, `:1.27`). What deployed yesterday may not be what runs today.

The fix: digest-pinning; admission policy rejects non-digest references.

### 3. The signing-without-verification gap

The team signs images in CI; the cluster doesn't verify signatures at admission. Signing is decoration.

The fix: admission policy enforces verification. Signing without verification is no security improvement.

### 4. The over-broad allowlist

The verification policy accepts signatures from any GitHub Actions workflow. A compromised workflow in any repo can sign images that pass verification.

The fix: scope the verification to specific repos, specific workflows, specific branches.

### 5. The vulnerability-allowlist creep

Allowlists for known false positives accumulate; no expiration; eventually most CVEs are allowlisted; scanning provides no real signal.

The fix: per-CVE justification; expiration; quarterly review; allowlist count tracked as a metric.

### 6. The forgotten base-image refresh

Dockerfiles pin base images to specific versions and never update. Months later, the base has known CVEs; the team is unaware.

The fix: Dependabot / Renovate for base updates; CVE-driven rebuilds; quarterly base-image refresh review.

### 7. The image-built-with-secret

A secret was baked into an image via `ARG` or `COPY .env`. The secret is in image layers; pulling the image yields the secret.

The fix: secret-scanning of images (Trivy, Grype); admission policy rejects images with detected secrets; secrets at runtime via Secrets Manager (per [../secrets-and-keys/secrets-manager-patterns.md](../secrets-and-keys/secrets-manager-patterns.md)).

### 8. The orphan-tags accumulating

Registries grow; pruning never happens; storage cost compounds; stale-vulnerable images linger.

The fix: lifecycle policies; periodic pruning; production tags retained, ephemeral tags expired.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| IMG-001 | Images not signed; admission accepts unsigned images | High | Implement Cosign keyless signing in CI; deploy admission verification | Platform Eng + Security Eng |
| IMG-002 | Admission policy does not verify image signatures | High | Kyverno verifyImages or Sigstore Policy Controller; align with [admission-control.md](./admission-control.md) | Platform Eng + Security Eng |
| IMG-003 | Pods reference images by mutable tag (`:latest`, version-only) | High | Digest-pinning; admission policy rejects non-digest references | Platform Eng + Workload Owner |
| IMG-004 | Third-party images pulled directly from public registries | Medium | Vetted-catalog + mirror approach; admission policy restricts image sources | Platform Eng + Security Eng |
| IMG-005 | No SBOM generation for built images; CVE tracking manual | Medium | Trivy / Syft SBOM generation in CI; attach as Cosign attestation | DevOps + Security Eng |
| IMG-006 | Registry lifecycle policies missing; storage costs growing | Low | Lifecycle policies: retain production, expire ephemeral, prune untagged | FinOps + Platform Eng |
| IMG-007 | No SLSA attestation; build provenance unverifiable | Medium | SLSA generator + Cosign attestation; admission verifies | DevOps + Security Eng |
| IMG-008 | CI build pipeline uses static cloud credentials | High | OIDC federation per [../secrets-and-keys/kill-the-static-secret.md](../secrets-and-keys/kill-the-static-secret.md) | DevOps + Security Eng |
| IMG-009 | Vulnerability scanning catches CVEs but allowlist creep dilutes signal | Medium | Per-CVE justification; expiration; quarterly review | Security Eng |
| IMG-010 | Base images not refreshed; CVEs accumulate in stale base | Medium | Renovate / Dependabot for base updates; CVE-driven rebuilds | DevOps + Platform Eng |
| IMG-011 | Container secret-scanning absent; images carry baked-in secrets | High | Trivy / Grype secret scanning in CI; admission rejects images with secrets | DevOps + Security Eng |
| IMG-012 | Signing verification scoped over-broadly (any GitHub workflow) | Medium | Scope to specific repos, workflows, branches | Security Eng |
| IMG-013 | Public registry used for organizational images | Medium | Move to private registry; access controlled | Platform Eng + Security Eng |
| IMG-014 | Tag immutability not enabled on registries | Low | Enable tag immutability; new versions require new tags | Platform Eng |
| IMG-015 | Registry access logs not consumed by SIEM | Medium | Ingest pull / push events; alert on unusual patterns | Security Eng + SOC |
| IMG-016 | Base image lacks minimum-surface choice (distroless, Wolfi) | Low | Migrate to minimal base images for new builds | DevOps + Security Eng |
| IMG-017 | CI build doesn't fail on critical CVEs | High | Severity-to-action mapping per [Vulnerability scanning](#vulnerability-scanning); critical and high block build | DevOps + Security Eng |
| IMG-018 | SBOM not stored for queryability when new CVE disclosed | Medium | Centralized SBOM store; query for affected images on new CVE | Security Eng |

---

## What this document is not

- **A complete Sigstore reference.** Sigstore's documentation covers Fulcio, Rekor, Cosign in depth.
- **A SLSA framework guide.** SLSA's documentation covers the framework's levels and requirements.
- **A vulnerability-database reference.** OSV, NVD, vendor advisory feeds are mentioned; their full operational depth lives in vendor / project documentation.
- **A complete registry-tool comparison.** ECR / ACR / Artifact Registry / Harbor / Quay / Nexus all play the role.
