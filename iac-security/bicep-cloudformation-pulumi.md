# Bicep, CloudFormation, and Pulumi

A practitioner's reference for the non-Terraform IaC tools — Azure Bicep (and its ARM-template roots), AWS CloudFormation (and its newer flavor CDK), and Pulumi (multi-cloud TypeScript / Python / Go IaC). Where the same security patterns translate; where they don't; per-tool gotchas; and the policy-as-code coverage for each.

This document is the third leg of the IaC trilogy: [terraform-security-patterns.md](./terraform-security-patterns.md) covers Terraform-side patterns, [policy-as-code.md](./policy-as-code.md) covers the policy layer that spans tools, and this document covers the non-Terraform tools' equivalents. The patterns rhyme — state management, policy enforcement, secure modules, pipeline gates — but the per-tool mechanics differ.

The honest framing: Terraform is the dominant IaC tool in 2026, but Bicep is Microsoft's first-party Azure tool (significant adoption in Azure-heavy environments), CloudFormation is AWS's first-party tool (significant adoption in AWS-heavy environments), and Pulumi is the de-facto choice for teams that want IaC in real programming languages. Multi-tool environments are common; this document covers what's specific to each.

---

## When to read this document

**If you're choosing between Terraform / Bicep / CloudFormation / Pulumi** — read top to bottom.

**If you're on Bicep and want the security patterns** — start with [Bicep](#bicep).

**If you're on CloudFormation and want the security patterns** — start with [CloudFormation](#cloudformation).

**If you're on Pulumi and want the security patterns** — start with [Pulumi](#pulumi).

**If you're choosing the policy-as-code tooling for each** — start with [Policy-as-code per tool](#policy-as-code-per-tool).

---

## The IaC tool decision in 2026

Quick framing.

### The major options

| Tool | Strength | Notes |
| --- | --- | --- |
| Terraform / OpenTofu | Multi-cloud; mature ecosystem; HCL DSL | Default for most |
| Bicep | Native Azure; cleaner than ARM JSON | Best for Azure-heavy or Microsoft-shop |
| CloudFormation | Native AWS; rich state mgmt; well-integrated | Best for AWS-only or where Terraform overlap is contentious |
| Pulumi | Real programming languages (TS / Python / Go / .NET); CrossGuard | Best for app teams preferring programming languages |
| CDK (AWS / Azure / Terraform) | Synthesizes to CFN / Bicep / Terraform | Used as a higher-level abstraction over the underlying tool |

### Decision factors

1. **Cloud-vendor alignment:** Bicep wins Azure; CloudFormation wins AWS for some teams; Terraform / Pulumi are multi-cloud.
2. **Team skill:** existing investment.
3. **Multi-cloud needs:** Terraform / Pulumi for multi-cloud; per-cloud tools for single-cloud.
4. **Programming model:** Pulumi if real languages; HCL / DSL if declarative is preferred.
5. **State model:** Pulumi / Terraform manage state explicitly; CloudFormation manages state internally; Bicep has incremental deployment model.

### The multi-tool reality

Many organizations end up with a mix:
- Bicep for some Azure projects (native ALZ uses Bicep).
- CloudFormation for some AWS projects (AWS Control Tower uses CloudFormation StackSets).
- Terraform for the bulk of cross-cloud work.
- Pulumi for specific app-team projects.

The discipline: each tool gets its own pipeline + policy-as-code coverage; ownership clearly defined.

---

## Bicep

Microsoft's Azure-native IaC. Compiles to ARM JSON.

### What Bicep is

- DSL that compiles to Azure Resource Manager templates.
- First-party to Azure; Microsoft maintains it.
- Cleaner syntax than raw ARM JSON.
- Type-checked; IDE support.

### State model

Bicep doesn't manage state directly. Each deployment is an ARM operation that compares the template to the current state and applies the diff.

Implications:
- No state file to protect (different threat model from Terraform).
- Deployment history visible via Azure Activity Log.
- "Drift" is the difference between the last-deployed template and the current resource state — detected via `bicep what-if` or ARM-side deployment history.

### Pre-deploy validation

`bicep build` — syntax check.
`bicep lint` — best-practices.
`az deployment group validate` — Azure-side validation.
`az deployment group what-if` — diff against current state (Bicep's "plan" equivalent).

### Security patterns

#### 1. Parameter file separation

Bicep parameters in a separate `.bicepparam` file (or inline JSON). Keep secrets out of `.bicepparam`.

```bicep
// secure-storage.bicep
param storageAccountName string
param location string = resourceGroup().location

@allowed(['public', 'internal', 'confidential', 'regulated'])
param dataClass string

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_GRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: dataClass == 'public'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: dataClass == 'regulated' ? 'Disabled' : 'Enabled'
  }
  tags: {
    DataClass: dataClass
    Owner: 'data-platform-team'
  }
}
```

Decorators (`@allowed`, `@minLength`, etc.) enforce input constraints; equivalent to Terraform's `validation`.

#### 2. Secrets via Key Vault reference

```bicep
@secure()
param adminPassword string

// In .bicepparam:
// "adminPassword": {
//   "reference": {
//     "keyVault": { "id": "<kv-resource-id>" },
//     "secretName": "admin-password"
//   }
// }
```

The secret is fetched from Key Vault at deploy time; never appears in the Bicep file or the deployment record.

#### 3. Modules

Bicep modules are first-class:

```bicep
module networking 'modules/network.bicep' = {
  name: 'networkDeployment'
  params: {
    vnetName: 'meridian-vnet'
    addressSpace: '10.0.0.0/16'
  }
}
```

Module versioning: Bicep modules can be published to a private Bicep registry (`br:<registry>/<module>:<version>`). Consumers pin to specific versions:

```bicep
module networking 'br:meridianacr.azurecr.io/bicep/network:v2.1.0' = {
  // ...
}
```

#### 4. Deployment scope

Bicep supports tenant / management group / subscription / resource group scopes. Per-scope deployments enable hierarchical policy application.

```bicep
targetScope = 'subscription'

// resources at subscription scope (e.g., role assignments)
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  // ...
}
```

#### 5. Conditional and loop constructs

```bicep
// Conditional
resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableDiagnostics) {
  name: 'diagnostics'
  // ...
}

// Loop
@batchSize(1)  // serial deployment
resource subnets 'Microsoft.Network/virtualNetworks/subnets@2022-09-01' = [for subnet in subnets: {
  // ...
}]
```

### Policy-as-code for Bicep

- **Checkov:** supports Bicep (in addition to Terraform).
- **Azure Policy:** post-deploy enforcement at MG / subscription / RG scope; deny on non-compliant.
- **PSRule for Azure:** PowerShell-based static analysis.
- **`az deployment what-if`:** pre-deploy preview.

Pipeline pattern:

```yaml
- name: Bicep build + lint
  run: |
    bicep build template.bicep
    bicep lint template.bicep

- name: Checkov scan
  uses: bridgecrewio/checkov-action@master
  with:
    file: template.bicep

- name: ARM validation + what-if
  run: |
    az deployment group validate --resource-group $RG --template-file template.bicep
    az deployment group what-if --resource-group $RG --template-file template.bicep
```

### Bicep gotchas

- **No drift detection in the tool itself.** Drift requires `what-if` against the current state; not built into routine deployment.
- **Deployment history accumulates.** Old deployment records remain in Azure; quarterly cleanup.
- **Some resource properties are not idempotent.** Updating certain resources triggers replacement; can be destructive.
- **Cross-scope deployments require careful planning.** Subscription-scope and resource-group-scope deployments have different syntax.

---

## CloudFormation

AWS's native IaC. JSON / YAML templates.

### What CloudFormation is

- First-party AWS IaC.
- Templates in JSON or YAML.
- Stack-based state model (each stack tracks its own resources).
- Deeply integrated with AWS (CloudFormation Hooks, StackSets, Drift Detection).

### State model

Each CloudFormation stack maintains its own state. AWS manages the state internally; no separate state file to protect.

Implications:
- Stack outputs / parameters can contain sensitive values; protected by IAM.
- Stack-level drift detection is built-in.
- Cross-stack references via Outputs / Imports.

### Pre-deploy validation

- `aws cloudformation validate-template`.
- `cfn-lint` (open-source linter).
- `cfn-nag` (security linter).
- `aws cloudformation create-change-set` (the "plan" equivalent).

### Security patterns

#### 1. Parameter validation

```yaml
Parameters:
  BucketName:
    Type: String
    AllowedPattern: '^meridian-[a-z]+(-[a-z]+)*$'
    Description: Bucket name must follow naming convention.

  DataClass:
    Type: String
    AllowedValues:
      - public
      - internal
      - confidential
      - regulated
```

Validation enforced by CloudFormation before deployment.

#### 2. Secrets via Secrets Manager / SSM Parameter Store

```yaml
Resources:
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword:
        !Join
          - ''
          - - '{{resolve:secretsmanager:'
            - !Ref DBSecretArn
            - ':SecretString:password}}'
```

The secret is fetched from Secrets Manager at deploy time; not in the template.

#### 3. Conditions and Mappings

```yaml
Conditions:
  IsRegulatedData: !Equals [!Ref DataClass, 'regulated']
  IsConfidentialData: !Equals [!Ref DataClass, 'confidential']
  RequiresVersioning: !Or [!Condition IsRegulatedData, !Condition IsConfidentialData]

Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: !If [RequiresVersioning, 'Enabled', 'Suspended']
```

Conditional behavior based on parameters; enforces data-class-aware defaults.

#### 4. Nested stacks and StackSets

Nested stacks: a stack within a stack. Useful for shared modules.

StackSets: deploy a stack template across multiple accounts / regions / OUs. Used by AWS Control Tower for landing-zone baseline deployment.

```yaml
# StackSet deployment via Terraform or CLI
aws cloudformation create-stack-set \
  --stack-set-name baseline-controls \
  --template-body file://baseline.yaml \
  --deployment-targets OrganizationalUnitIds=ou-abc-12345 \
  --regions us-east-1 us-west-2
```

#### 5. CloudFormation Hooks

CloudFormation Hooks let you run pre- or post-provision checks on stack operations. Example: a hook that denies any stack creation containing a public S3 bucket.

```bash
aws cloudformation register-type \
  --type RESOURCE \
  --type-name 'AWS::S3::Bucket::PublicAccessGuard' \
  --schema-handler-package <package>
```

Hooks are AWS-native equivalent of pre-deploy policy-as-code.

### Policy-as-code for CloudFormation

- **`cfn-lint`:** linting.
- **`cfn-nag`:** security-focused linting.
- **Checkov:** supports CloudFormation.
- **CloudFormation Guard:** AWS's native policy language (Rego-inspired).
- **CloudFormation Hooks:** pre-/post-provision policy enforcement.

Pipeline pattern:

```yaml
- name: cfn-lint
  run: cfn-lint template.yaml

- name: cfn-nag
  run: cfn_nag_scan --input-path template.yaml

- name: Checkov
  uses: bridgecrewio/checkov-action@master
  with:
    file: template.yaml

- name: Validate template
  run: aws cloudformation validate-template --template-body file://template.yaml

- name: Create change set
  run: aws cloudformation create-change-set --stack-name <name> --template-body file://template.yaml --change-set-name pr-<pr-number>
```

### CloudFormation gotchas

- **Stack-level deletion is irrevocable.** `aws cloudformation delete-stack` removes all resources; no rollback after delete.
- **Resource replacement vs update.** Some property changes trigger replacement; understand which.
- **DependsOn vs implicit dependencies.** Implicit dependencies (via Ref / GetAtt) are inferred; explicit DependsOn is needed for some cases.
- **Stack drift detection.** Built-in but not real-time; runs on-demand.
- **CDK abstraction.** Many teams use AWS CDK (TypeScript / Python / Java / .NET / Go) which synthesizes to CloudFormation. Patterns rhyme but tools / process differ.

---

## Pulumi

Real programming languages for IaC.

### What Pulumi is

- IaC in TypeScript / JavaScript / Python / Go / .NET / Java.
- Multi-cloud (AWS / Azure / GCP / many others).
- State managed by Pulumi (Pulumi Cloud SaaS or self-hosted backend).
- Crossguard policy-as-code.

### State model

Pulumi maintains state in a backend:
- **Pulumi Cloud:** SaaS; managed; default.
- **Self-hosted:** S3 / Azure Blob / GCS.
- **Local:** dev only.

Per-stack state (a "stack" is Pulumi's per-environment unit).

### Pre-deploy validation

- `pulumi preview` — the "plan" equivalent.
- `pulumi up --diff` — show diff during apply.
- Language-specific linting (eslint / pylint / etc.).
- Crossguard policies (`pulumi policy publish`, `pulumi policy enable`).

### Security patterns

#### 1. Secret handling

```typescript
import * as pulumi from "@pulumi/pulumi";

const config = new pulumi.Config();
const dbPassword = config.requireSecret("dbPassword");

// dbPassword is marked secret; encrypted in state.
const db = new aws.rds.Instance("db", {
    masterPassword: dbPassword,
    // ...
});
```

Secrets are encrypted in state. The encryption key:
- Pulumi Cloud: managed by Pulumi.
- Self-hosted: KMS key in your account.
- Local: passphrase.

#### 2. Crossguard policies

Crossguard policies are TypeScript / Python policies that evaluate against resources.

```typescript
// policy/index.ts
import * as policy from "@pulumi/policy";

new policy.PolicyPack("aws-policies", {
    policies: [{
        name: "s3-encryption",
        description: "S3 buckets must have encryption enabled.",
        enforcementLevel: "mandatory",
        validateResource: policy.validateResourceOfType(aws.s3.Bucket, (bucket, args, reportViolation) => {
            if (!bucket.serverSideEncryptionConfiguration) {
                reportViolation("S3 bucket must have server-side encryption enabled.");
            }
        }),
    }],
});
```

Crossguard policies enforce constraints at `pulumi up` time.

#### 3. Stack references for cross-environment

```typescript
const networkStack = new pulumi.StackReference("organization/network/production");
const vpcId = networkStack.getOutput("vpcId");

const subnet = new aws.ec2.Subnet("subnet", {
    vpcId: vpcId,
    // ...
});
```

Cross-stack references enable modular architectures while keeping state per-stack.

#### 4. Component resources (modules)

```typescript
class SecureBucket extends pulumi.ComponentResource {
    public readonly bucket: aws.s3.Bucket;

    constructor(name: string, args: SecureBucketArgs, opts?: pulumi.ComponentResourceOptions) {
        super("meridian:storage:SecureBucket", name, args, opts);

        if (args.dataClass === "regulated" && !args.kmsKey) {
            throw new Error("Regulated data class requires kmsKey.");
        }

        this.bucket = new aws.s3.Bucket(name, {
            // secure defaults
        }, { parent: this });

        new aws.s3.BucketPublicAccessBlock(`${name}-pab`, {
            bucket: this.bucket.id,
            blockPublicAcls: true,
            // ...
        }, { parent: this });

        // ... other resources with secure defaults
    }
}
```

ComponentResource is Pulumi's module equivalent.

### Policy-as-code for Pulumi

- **Crossguard:** native; TypeScript / Python.
- **Conftest:** can run against Pulumi's state output.
- **Custom linting:** language-specific linters.

### Pulumi gotchas

- **State backend security:** if self-hosted, the backend (S3 / blob / GCS) is the security-critical component.
- **Encryption-key management:** secrets in state are only as protected as the encryption key.
- **Programming-language flexibility = larger attack surface.** Real languages mean real dependency vulnerabilities (npm / pip / go modules); supply-chain risk applies.
- **`pulumi destroy` is irrevocable.** Same caveat as Terraform / CloudFormation.

---

## Policy-as-code per tool

Cross-tool coverage matrix.

| Tool | Native policy-as-code | Third-party PAC | Notes |
| --- | --- | --- | --- |
| Terraform | OPA / Conftest | Checkov, Trivy, Sentinel, tfsec | Mature ecosystem |
| Bicep | Azure Policy (runtime) | Checkov, PSRule | Native at runtime; pre-deploy via 3rd party |
| CloudFormation | CFN Guard, CFN Hooks | Checkov, cfn-nag | Native AWS options strong |
| Pulumi | Crossguard | Conftest (less common) | Programming-language native |

### The portfolio recommendation

For mixed-tool environments:

- **Checkov as the cross-tool baseline.** Supports Terraform, Bicep, CloudFormation, ARM, Kubernetes manifests.
- **Per-tool native tools as the deep layer.** CFN Guard for CloudFormation, Crossguard for Pulumi, Azure Policy for Bicep at runtime.
- **Conftest + OPA for cross-cutting policies.** Org-wide rules that span tools (e.g., naming conventions).

The pattern: Checkov in the CI for everything; tool-native for tool-specific deep policies.

---

## Multi-tool environment patterns

How organizations with mixed IaC tools manage them.

### Pattern 1 — Per-team tool choice

Each team picks the tool that fits their workflow. The platform team supports all.

Pros: team autonomy.
Cons: per-tool infrastructure (CI, modules, policies); cost multiplies.

### Pattern 2 — Per-workload-type tool choice

Choose tool by workload type. E.g., Azure-native workloads use Bicep; multi-cloud uses Terraform; app-team-owned uses Pulumi.

Pros: tool aligns with workload's needs.
Cons: teams sometimes work across multiple tools.

### Pattern 3 — One tool with exceptions

Standardize on one tool (typically Terraform); allow exceptions when justified.

Pros: most consistency; smallest infrastructure footprint.
Cons: some workloads fit other tools better; exceptions may be denied unnecessarily.

### Recommendation

For most organizations: **Pattern 3 with documented exceptions.** Terraform as default; Bicep for ALZ-specific work; CloudFormation for StackSets / Control Tower; Pulumi for app-team projects with explicit justification.

---

## Worked example — Meridian Health IaC tool landscape (Q2 2026)

Meridian's IaC tools after 18 months of standardization.

### The tools

- **Terraform:** ~85% of resources. The default.
- **Bicep:** Azure Landing Zone (ALZ) baseline; ~10% of resources.
- **CloudFormation:** AWS Control Tower StackSets; ~3% of resources.
- **Pulumi:** one app team's API platform; ~2% of resources.

### Per-tool ownership

- Terraform: platform team owns shared modules; per-workload-team owns workload resources.
- Bicep: cloud-foundation team owns ALZ; some app teams own Bicep for Azure-native apps.
- CloudFormation: cloud-foundation team only; the only legitimate use case is StackSets / Control Tower.
- Pulumi: the api-platform team owns; one of the rare team-specific tools.

### Per-tool policy-as-code

- Terraform: Checkov + Conftest + custom OPA rules.
- Bicep: Checkov + PSRule for Azure + Azure Policy (runtime).
- CloudFormation: Checkov + cfn-nag + CFN Guard + CFN Hooks.
- Pulumi: Crossguard + language-specific linting.

### Per-tool pipeline

All four tools use the same shape: validate → plan/preview → policy → cost → review → apply → post-apply.

The per-tool specifics differ; the shape is consistent.

### Findings opened during standardization

- **MT-001** (~12 tools used across teams; inconsistent). Closed by tool-choice policy (Pattern 3 with exceptions).
- **MT-002** (Per-tool policy-as-code inconsistent). Closed by Checkov as cross-tool baseline.
- **MT-003** (Per-tool pipeline shape varied). Closed by standardized pipeline template per tool.
- **MT-004** (No documented decision criteria for tool choice). Closed by tool-choice policy.
- **MT-005** (Bicep modules not in central registry). Closed by Azure Container Registry-based Bicep registry.
- **MT-006** (CloudFormation StackSets used without policy review). Closed by Control Tower governance review.
- **MT-007** (Pulumi state backend on Pulumi Cloud SaaS without org review). Closed by self-hosted backend in S3.

---

## Anti-patterns

### 1. Tool proliferation without governance

Each team picks a tool; no central standard. Per-tool infrastructure cost multiplies.

The fix: Pattern 3 with documented exceptions.

### 2. Tool-specific policy-as-code gaps

The org has policy-as-code for Terraform; Bicep / CloudFormation / Pulumi resources slip through.

The fix: Checkov as cross-tool baseline.

### 3. Per-tool pipeline divergence

Each tool's CI pipeline diverges in shape. Cross-tool reviews are hard.

The fix: standardized pipeline shape; per-tool implementation.

### 4. State backend without security

Pulumi state in Pulumi Cloud without org review; CloudFormation stack outputs containing secrets in plaintext.

The fix: per-tool state security review; encryption + access control.

### 5. Tool-choice debate without criteria

Endless meetings about which tool to use. No documented decision criteria.

The fix: tool-choice policy document; per-workload review against the criteria.

### 6. Multi-tool shared modules

Same module re-written in Terraform, Bicep, Pulumi. Drift between implementations.

The fix: per-cloud canonical implementation; consumers adopt as their preferred tool permits.

### 7. Per-tool secrets handling drift

Terraform uses one secrets pattern, Bicep uses another; Pulumi a third. Cross-tool work confused.

The fix: per-cloud central secret store (Secrets Manager / Key Vault / Secret Manager); each tool retrieves from there.

### 8. CDK abstraction obscuring underlying tool

The team uses AWS CDK (synthesizes to CloudFormation) without understanding the CloudFormation it produces. Debugging is hard.

The fix: CDK is a higher-level abstraction; the team still needs to know CloudFormation; review the synthesized output.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| MT-001 | Tool proliferation without governance | Medium | Tool-choice policy (Pattern 3 default); documented exceptions | Cloud Foundation + Security Eng |
| MT-002 | Per-tool policy-as-code coverage inconsistent | High | Checkov as cross-tool baseline; tool-native as deep layer | Security Eng + DevOps |
| MT-003 | Per-tool pipeline shape divergent | Medium | Standardized pipeline template per tool | DevOps |
| MT-004 | No documented tool-choice criteria | Low | Tool-choice policy doc; per-workload review | Cloud Foundation |
| MT-005 | Bicep modules not in central registry | Medium | ACR-based registry; consumers pin to versions | DevOps + Security Eng |
| MT-006 | CloudFormation StackSets used without governance review | Medium | Control Tower / StackSets governance; per-stackset review | Cloud Foundation + Security Eng |
| MT-007 | Pulumi state backend choice not security-reviewed | Medium | Per-tool state backend review; encryption + access control | Security Eng + Platform Eng |
| MT-008 | Bicep secret handling without Key Vault reference | High | Key Vault references for secrets; not in Bicep file | Security Eng + DevOps |
| MT-009 | CloudFormation secrets in template parameters | High | Secrets Manager / SSM Parameter Store references | Security Eng + DevOps |
| MT-010 | Pulumi secrets in plaintext state without encryption key review | High | Per-tool encryption key; access control on state backend | Security Eng + Platform Eng |
| MT-011 | Per-tool drift detection absent | Medium | Per-tool drift check; alert on unexpected drift | DevOps + Security Eng |
| MT-012 | CDK synthesized output not reviewed | Low | CDK consumers review synthesized CloudFormation | DevOps |
| MT-013 | Tool migration without timeline / exit criteria | Low | Per-migration: timeline; exit criteria; rollback plan | Platform Eng + Sponsor |
| MT-014 | Multi-tool shared modules duplicated; drift between | Medium | Per-cloud canonical implementation; no cross-tool duplication | DevOps |
| MT-015 | Per-tool deployment role over-broad | High | Per-tool, per-environment role; narrow scope | Security Eng + DevOps |
| MT-016 | Tool-specific gotchas not documented per-team | Low | Per-tool gotcha doc; onboarding materials | DevOps |
| MT-017 | No metric on per-tool adoption / cost / posture | Low | Per-quarter metric; tool-portfolio review | Security Eng + FinOps |
| MT-018 | Cross-tool review processes inconsistent | Medium | Standardized review process; per-tool reviewers | Security Eng + DevOps |

---

## Adoption checklist

- [ ] Tool-choice policy documented (Pattern 3 with exceptions).
- [ ] Per-tool owner identified.
- [ ] Per-tool pipeline (validate → plan → policy → cost → review → apply → verify).
- [ ] Checkov as cross-tool policy-as-code baseline.
- [ ] Tool-native policy-as-code as deep layer (CFN Guard, Crossguard, Azure Policy).
- [ ] Per-tool state / backend security review.
- [ ] Per-tool secret handling via central secret store.
- [ ] Per-tool module / registry pattern (Bicep registry, Terraform Registry, Pulumi packages).
- [ ] Per-tool deployment role: per-environment scope; OIDC federation; narrow permissions.
- [ ] Per-tool drift detection.
- [ ] Per-tool gotcha documentation; onboarding materials.
- [ ] Per-quarter tool-portfolio review: adoption, cost, posture.
- [ ] Multi-tool shared modules avoided (per-cloud canonical implementation).
- [ ] CDK consumers review synthesized output (CloudFormation / Bicep / Terraform).

---

## What this document is not

- **A complete Bicep / CloudFormation / Pulumi tutorial.** Vendor documentation covers each.
- **A Terraform reference.** [terraform-security-patterns.md](./terraform-security-patterns.md) covers Terraform-specific patterns.
- **A policy-as-code product comparison.** [policy-as-code.md](./policy-as-code.md) covers the policy layer.
- **A pipeline-architecture reference.** [iac-pipeline-gates.md](./iac-pipeline-gates.md) covers the pipeline.
- **A migration playbook.** Per-tool migration (e.g., CloudFormation → Terraform) is a project; out of scope.
- **A vendor procurement guide.** Tool selection involves licensing, support, training; covered in cost-benefit analysis but not procurement specifics.
