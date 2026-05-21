# Log Architecture

A practitioner's reference for the AWS log pipeline that feeds detection, IR, and audit — organization-level CloudTrail, VPC Flow Logs, AWS Config, GuardDuty, Security Hub, IAM Access Analyzer findings, ALB/CloudFront/WAF access logs, S3 access logs, EKS audit logs, RDS / Aurora audit logs, and the SIEM integration patterns. The document is AWS-first; Azure (Activity Logs, Diagnostic Settings) and GCP (Audit Logs, Log Sinks) are named at the end for cross-reference.

This document covers the log architecture; the detection logic on top of the architecture lives in [custom-detections.md](./) *(coming)*, and the incident response runbooks that consume the logs live in this folder's runbook documents (`runbook-leaked-iam-key.md`, `runbook-exposed-storage.md`, etc.).

---

## The design problem

A working cloud log pipeline has to satisfy four concerns simultaneously:

1. **Coverage.** Every API call across every account and every region is captured. Every network flow that matters for security is captured. Every configuration change is captured. Gaps in coverage are silent (a finding that the team would otherwise have caught simply does not surface).

2. **Integrity.** The logs cannot be tampered with by a compromised principal in the source account. The audit trail has to be trustworthy under adversarial conditions; otherwise it does not serve detection or forensics, and it does not satisfy regulated compliance frameworks (HIPAA §164.312(b), PCI 10.5, SOC 2 CC7.2 all require tamper-evident logs).

3. **Operability.** The platform team can query the logs efficiently. Detections fire on real-time streams. Forensic investigations can reconstruct timelines from historical data. The pipeline does not require a dedicated team to maintain.

4. **Cost discipline.** Log volume in a moderate-size AWS environment is significant (terabytes per month for the audit-relevant streams alone). Indiscriminate retention is expensive; aggressive deletion creates blind spots. The retention policy needs to be deliberate.

The architecture below addresses the four concerns together. It is structured as a hub-and-spoke pipeline: every account in the Organization emits logs to a centralized LogArchive account (for integrity), the LogArchive routes copies to the Security Tooling account's detection services (for operability), and a separate retention tier holds historical logs in Athena-queryable form (for forensics).

---

## When to read this document

**If you are designing a log pipeline from scratch** — read top to bottom; the document is structured as a sequence.

**If you are evaluating an existing pipeline** — start with [The coverage checklist](#the-coverage-checklist). Most pipelines have at least one gap.

**If you are responding to an incident** — start with [Forensic queries](#forensic-queries). The Athena queries in that section are the most-used commands during cloud IR.

**If you are optimizing log cost** — start with [Cost discipline](#cost-discipline). The savings from retention policy and storage class are usually material.

---

## The target architecture

```
                    Workload Accounts (many)
                              │
                              │ Org Trail + per-account services
                              ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                  LogArchive Account                          │
   │                                                              │
   │   Inbound (write-only from source accounts):                 │
   │   ┌──────────────────────────────────────────────────────┐  │
   │   │ s3://meridian-cloudtrail-logs/    (Org CloudTrail)   │  │
   │   │ s3://meridian-vpcflowlogs/         (VPC Flow Logs)   │  │
   │   │ s3://meridian-config-history/      (AWS Config)      │  │
   │   │ s3://meridian-alb-logs/            (ALB/CLB access)  │  │
   │   │ s3://meridian-cloudfront-logs/     (CF access)       │  │
   │   │ s3://meridian-waf-logs/            (WAF)             │  │
   │   │ s3://meridian-s3-access-logs/      (S3 server)       │  │
   │   │ s3://meridian-eks-audit/           (EKS audit, K8s)  │  │
   │   │ s3://meridian-rds-audit/           (RDS audit)       │  │
   │   │                                                       │  │
   │   │ All buckets: Object Lock COMPLIANCE, KMS CMK,        │  │
   │   │ SCP prevents deletion (see baseline-guardrails.md    │  │
   │   │ Guardrails 2.1 and 2.2).                             │  │
   │   └──────────────────────────────────────────────────────┘  │
   │                                                              │
   │   Outbound (replication and routing):                        │
   │   ┌──────────────────────────────────────────────────────┐  │
   │   │ S3 Replication →  DR region copy                     │  │
   │   │ S3 Event Notification → SQS → Lambda → SIEM forwarder│  │
   │   │ AWS Glue Crawler → Athena tables for forensic query  │  │
   │   └──────────────────────────────────────────────────────┘  │
   └────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                  Security Tooling Account                      │
   │                                                                │
   │   Real-time / near-real-time consumers:                        │
   │     - GuardDuty (delegated admin, ingests org-wide)            │
   │     - Security Hub (delegated admin, aggregates findings)      │
   │     - IAM Access Analyzer (org-level + per-account)            │
   │     - EventBridge rules on CloudTrail Insights                 │
   │     - Lambda functions for auto-remediation                    │
   │                                                                │
   │   Forensic / analytical consumers:                             │
   │     - Athena workspace pointed at LogArchive's S3              │
   │     - QuickSight dashboards for trend analysis                 │
   │     - Detective for graph-based investigation                  │
   └────────────────────────────────────────────────────────────────┘
                                │
                                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                  External SIEM                                 │
   │                  (Splunk / Sentinel / Chronicle / etc.)        │
   │                                                                │
   │   Subscribes to:                                               │
   │     - High-priority Security Hub findings                      │
   │     - All GuardDuty findings                                   │
   │     - Specific CloudTrail event categories                     │
   │                                                                │
   │   Does not receive: raw VPC Flow Logs (too much volume; routed │
   │   only on demand for active investigations).                   │
   └────────────────────────────────────────────────────────────────┘
```

The architecture treats the LogArchive S3 buckets as the source of truth and the other consumers (GuardDuty, SIEM, Athena) as derivative views. The source-of-truth pattern is important: in any forensic investigation, the team can fall back to the LogArchive S3 data if a derivative is unavailable, incomplete, or under suspicion.

References:
- [AWS Logging Architecture](https://docs.aws.amazon.com/whitepapers/latest/logging-and-monitoring-best-practices/welcome.html)
- [Centralized logging on AWS](https://aws.amazon.com/solutions/implementations/centralized-logging/)

---

## The coverage checklist

The log streams that a regulated SaaS environment needs to capture:

| Stream | Captures | How to enable | Coverage gap if missing |
| --- | --- | --- | --- |
| **Organization CloudTrail (management events)** | Every API call across every account and region | Set up org-level trail from management account; routes to LogArchive S3 | Audit trail is missing; no forensic baseline |
| **CloudTrail data events** (S3, Lambda) | S3 object-level access; Lambda invocations | Configure per-data-event-source on the org trail | Object-level access to S3 is invisible; Lambda invocation patterns are invisible |
| **CloudTrail Insights** | Unusual API call patterns detected by ML | Enable Insights on the org trail | Anomaly detection layer is missing |
| **VPC Flow Logs** | Every network flow (5-tuple + bytes + action) within VPCs | Enable on every VPC; route to LogArchive S3 in Parquet format | Network forensics is impossible; egress to attacker infrastructure is invisible |
| **AWS Config** | Configuration state and changes for every supported resource | Enable in every account, every region; route to Config aggregator | Configuration drift is invisible; "what did this resource look like yesterday" cannot be answered |
| **GuardDuty** | Threat-intelligence-driven findings | Enable in every account, every region; delegated admin to Security Tooling | Known-bad indicators are not detected |
| **Security Hub** | Aggregates findings from GuardDuty, Inspector, Macie, Access Analyzer, third-party | Enable in every region; delegated admin | Finding consolidation is missing; team chases siloed dashboards |
| **IAM Access Analyzer (external)** | Resources externally accessible | Enable at the Organization level | External access findings are missed |
| **IAM Access Analyzer (unused)** | IAM roles/users/permissions not used recently | Enable per-account | Permission-tightening data is missing |
| **ALB / CloudFront / WAF access logs** | HTTP-layer access to public endpoints | Enable per-load-balancer / distribution | Web-layer forensics is impossible |
| **S3 access logs (server access logging)** | Object-level access for specific buckets | Enable per-bucket; route to a centralized audit bucket | Bucket-access forensics on the specific buckets is impossible (data events are a richer alternative) |
| **EKS audit logs** | Every Kubernetes API call | Enable in EKS cluster control-plane logging | Kubernetes-layer forensics is impossible |
| **RDS / Aurora audit logs** | Database queries and connection events | Enable RDS audit plugin or Aurora advanced logging | Database-layer forensics is impossible |
| **Route 53 query logs** | DNS queries for private and public hosted zones | Enable per-zone; route to CloudWatch Logs | DNS-based detection (DGA domains, exfil via DNS) is missing |
| **GuardDuty Malware Protection** | Malware scans on EBS volumes and S3 objects | Enable as a GuardDuty feature | Malware detection on cloud workloads is missing |

The list above is the recommended minimum for a regulated SaaS. Some environments can defer some streams (e.g., S3 server access logs when S3 data events cover the same buckets) but the coverage gaps are predictable from the table.

---

## Organization CloudTrail design

CloudTrail is the foundation of the entire pipeline. Three design decisions:

**1. Organization trail, not per-account trails.** A single trail at the Organization level captures events from every account. Per-account trails are redundant for the audit-trail use case and produce a per-account configuration that drifts (one account has a trail, another does not, the inconsistency is invisible). Adopt the organization trail; delete per-account trails except where they serve a distinct purpose (e.g., a higher-frequency or higher-detail trail for one specific workload).

**2. Multi-region trail.** Set `IsMultiRegionTrail=true`. AWS sometimes adds new regions; a multi-region trail picks them up automatically.

**3. Routes to LogArchive S3, not to the Security Tooling account.** The destination is the LogArchive account's S3 bucket with Object Lock. The Security Tooling account reads from LogArchive for detection; it does not own the audit trail.

The Terraform for the org trail:

```hcl
resource "aws_cloudtrail" "org" {
  name                          = "meridian-org-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true

  kms_key_id = aws_kms_key.cloudtrail.arn

  # Insights catch unusual API call patterns.
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }
  insight_selector {
    insight_type = "ApiErrorRateInsight"
  }

  # Data events for high-value resource types.
  advanced_event_selector {
    name = "S3 data events"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    # Optionally scope to specific bucket prefixes to manage cost.
  }

  advanced_event_selector {
    name = "Lambda invocations"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::Lambda::Function"]
    }
  }
}
```

**The data-events cost consideration.** CloudTrail data events are billed per event ($0.10 per 100,000 events for S3 data events as of 2024). For a busy S3 bucket, this adds up — a bucket with 10M object-access events per day costs ~$10 per day per data-event source. The pattern is to enable data events selectively: high-value buckets (regulated data, audit-relevant data) get data events; high-volume / low-value buckets (caches, public assets) do not. The selectivity has to be documented in the trail configuration.

**Enable log-file validation.** The `enable_log_file_validation = true` setting produces hash chains over the log files that allow detection of post-write modification. The validation is checked on retrieval; tampering is detectable.

References:
- [CloudTrail organization trail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html)
- [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [CloudTrail Insights](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-insights-events-with-cloudtrail.html)

---

## VPC Flow Logs design

VPC Flow Logs capture every network flow at the VPC, subnet, or ENI level. Three design decisions:

**1. VPC-level, not subnet or ENI level.** VPC-level captures every flow in the VPC; subnet- and ENI-level produce gaps when traffic moves between scopes. The exception is workloads where per-subnet or per-ENI capture is required for cost reasons or for high-cardinality forensics; those are unusual.

**2. Parquet format, not raw text.** Parquet compresses 5-10x better than the default plain-text format and is faster to query in Athena. The cost savings are material at scale.

**3. Routes to LogArchive S3, not to CloudWatch Logs.** S3 is cheaper for the volume; CloudWatch Logs is appropriate only when real-time alerting on flows is required (which it usually is not, because GuardDuty and the network firewall handle the real-time detection).

```hcl
resource "aws_flow_log" "vpc" {
  for_each = toset(var.vpc_ids)

  vpc_id               = each.value
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "arn:aws:s3:::meridian-vpcflowlogs/AWSLogs/${data.aws_caller_identity.current.account_id}/vpcflowlogs/"

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr} $${region} $${az-id} $${sublocation-type} $${sublocation-id} $${pkt-src-aws-service} $${pkt-dst-aws-service} $${flow-direction} $${traffic-path}"

  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }
}
```

The custom `log_format` captures the extended fields (TCP flags, packet-source addresses for NAT-traversed flows, region, AZ, AWS service names for traffic to AWS services). The extended fields are essential for forensics in VPCs with NAT Gateways or interface endpoints.

References:
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [VPC Flow Logs in Parquet](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3.html#flow-logs-s3-cost)

---

## AWS Config design

AWS Config records the configuration state and changes for every supported resource type. The pipeline:

```
   Workload Account
   ┌──────────────────┐
   │ Config Recorder  │ (records every supported resource type)
   │     │            │
   │     ▼            │
   │ Delivery Channel │ (every 15 min, plus on-change)
   │     │            │
   └─────┼────────────┘
         │
         ▼
   LogArchive S3 (config history)
         │
         ▼
   Security Tooling Account
   ┌──────────────────┐
   │ Config Aggregator│ (read-only view of all accounts' Config)
   │     │            │
   │     ▼            │
   │ Conformance Packs│ (CIS, HIPAA, Foundational Best Practices)
   │     │            │
   │     ▼            │
   │ Custom Rules     │ (organization-specific compliance)
   └──────────────────┘
```

**Why all supported resource types.** The default Config configuration records only a subset; the audit-readiness need is "we can describe any resource's configuration at any point in time." This requires recording every resource type. The cost is higher than the default — Config charges per configuration item — but the forensic value is worth it.

**Conformance packs.** The conformance pack is a collection of Config rules that map to a compliance framework. The AWS-managed packs include:
- CIS AWS Foundations Benchmark
- HIPAA Security Rule
- PCI-DSS v3.2.1
- AWS Foundational Security Best Practices
- NIST 800-53 Rev 5

The pack runs every applicable rule in every account, and the findings flow into Security Hub. The output is a continuous compliance dashboard rather than a quarterly compliance scan.

References:
- [AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html)
- [Config aggregator](https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html)
- [Conformance packs](https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html)

---

## GuardDuty + Security Hub + Access Analyzer delegation

The three detection services are delegated to the Security Tooling account so the platform team operates them from there rather than from the management account.

```bash
# From the management account, delegate GuardDuty admin.
aws guardduty enable-organization-admin-account \
  --admin-account-id <security-tooling-account-id>

# From the management account, delegate Security Hub admin.
aws securityhub enable-organization-admin-account \
  --admin-account-id <security-tooling-account-id>

# From the management account, delegate Access Analyzer.
aws organizations register-delegated-administrator \
  --account-id <security-tooling-account-id> \
  --service-principal access-analyzer.amazonaws.com
```

From the Security Tooling account, after delegation:

```bash
# Enable GuardDuty in every region; auto-enable for new accounts.
aws guardduty update-organization-configuration \
  --auto-enable \
  --detector-id <detector-id>

# Enable the Foundational, CIS, and PCI standards in Security Hub.
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    "StandardsArn=arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices/v/1.0.0" \
    "StandardsArn=arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.2.0"

# Enable Access Analyzer with an Organization-level scope.
aws accessanalyzer create-analyzer \
  --analyzer-name org-external-access \
  --type ORGANIZATION
```

**GuardDuty feature plans.** GuardDuty has multiple feature plans, each priced separately:
- Standard (foundational threat detection)
- Malware Protection (EBS / S3 / RDS)
- EKS Protection (audit log monitoring + runtime monitoring)
- Lambda Protection
- RDS Protection

For regulated SaaS workloads, enable the Standard plus Malware Protection plus EKS Protection plus RDS Protection. The Lambda Protection plan is optional based on Lambda workload patterns.

**Security Hub standards.** Enable AWS Foundational Security Best Practices everywhere. Enable CIS AWS Foundations in environments where CIS-compliance is a customer requirement. Enable PCI-DSS only where PCI-CDE workloads exist.

References:
- [GuardDuty Organization configuration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_organizations.html)
- [Security Hub administrator](https://docs.aws.amazon.com/securityhub/latest/userguide/designate-orgs-admin-account.html)

---

## SIEM integration patterns

Most regulated environments forward a subset of cloud logs to an external SIEM (Splunk, Microsoft Sentinel, Google Chronicle, Elastic, Datadog SIEM). The pattern:

**What to forward:**
- Security Hub findings (high-priority and critical).
- All GuardDuty findings.
- CloudTrail events for specific event categories: IAM modifications, KMS key actions, security group changes, S3 bucket policy changes, GuardDuty / Security Hub / CloudTrail modifications.
- Failed authentication events (from CloudTrail and from application logs).

**What not to forward:**
- Raw CloudTrail (too much volume for most SIEMs to ingest economically). Forward selectively.
- Raw VPC Flow Logs (terabytes per month; most SIEMs cannot handle the volume cost-effectively). Query on-demand from Athena instead.
- AWS Config history (queryable from Config aggregator; SIEM duplication is rarely worth the cost).
- ALB / CloudFront access logs (high volume; route to a separate logging product like Loggly or use Athena).

**Forwarding architecture:**

```
LogArchive S3
     │
     ├─→ EventBridge rule "high-priority Security Hub finding"
     │        │
     │        ▼
     │   Kinesis Firehose → SIEM ingest endpoint
     │
     ├─→ S3 Event Notification on new GuardDuty finding
     │        │
     │        ▼
     │   Lambda forwarder → SIEM HTTP/syslog endpoint
     │
     └─→ CloudWatch Logs subscription filter on specific CloudTrail patterns
              │
              ▼
         Kinesis Firehose → SIEM ingest endpoint
```

The Firehose pattern is appropriate for high-volume streams; the Lambda forwarder is appropriate for low-volume streams where filtering or enrichment is required.

**Cost framing.** A typical AWS environment generates 10-100 GB/day of audit logs; ingest cost at the SIEM is usually the dominant cost. The selective-forwarding pattern can reduce ingest by 90-95% while still covering the audit-relevant events. The deselected events remain queryable from Athena; on-demand queries against historical data are dramatically cheaper than indiscriminate forwarding.

References:
- [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876)
- [Microsoft Sentinel AWS connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-aws)
- [Google Chronicle AWS feed](https://chronicle.security/blog/posts/google-cloud-aws-integration/)

---

## Forensic queries

Athena queries against LogArchive S3 are the primary forensic tool during incidents. The pattern:

```
LogArchive S3
     │
     ▼
AWS Glue Crawler (defines schema for CloudTrail, VPC Flow Logs, Config history)
     │
     ▼
Athena tables (queryable by SQL)
```

The Glue crawler runs daily; the schemas are stable and the partition structure (year/month/day/account/region) makes time-bounded queries fast.

**Example: who accessed this S3 bucket?**

```sql
SELECT
  eventTime,
  userIdentity.arn,
  userIdentity.sessionContext.sessionIssuer.userName,
  eventName,
  sourceIPAddress,
  resources
FROM cloudtrail_logs
WHERE
  eventSource = 's3.amazonaws.com'
  AND eventName IN ('GetObject', 'PutObject', 'DeleteObject')
  AND requestParameters LIKE '%meridian-phi-bucket%'
  AND eventTime BETWEEN current_timestamp - interval '7' day AND current_timestamp
ORDER BY eventTime DESC
LIMIT 1000;
```

**Example: what did this IAM principal do in the last 24 hours?**

```sql
SELECT
  eventTime,
  eventSource,
  eventName,
  awsRegion,
  sourceIPAddress,
  errorCode,
  errorMessage,
  resources
FROM cloudtrail_logs
WHERE
  userIdentity.arn = 'arn:aws:iam::123456789012:role/PatientApiRole'
  AND eventTime > current_timestamp - interval '24' hour
ORDER BY eventTime DESC
LIMIT 5000;
```

**Example: what egress traffic left this VPC to non-AWS destinations?**

```sql
SELECT
  start_time,
  account_id,
  interface_id,
  srcaddr,
  dstaddr,
  dstport,
  protocol,
  bytes,
  pkt_dst_aws_service
FROM vpc_flow_logs
WHERE
  vpc_id = 'vpc-0abc1234'
  AND flow_direction = 'egress'
  AND action = 'ACCEPT'
  AND pkt_dst_aws_service IS NULL  -- excludes traffic to AWS services
  AND start_time BETWEEN timestamp '2026-05-21 00:00:00' AND timestamp '2026-05-21 23:59:59'
ORDER BY bytes DESC
LIMIT 100;
```

**Example: what configuration changes happened in this account in the last hour?**

```sql
SELECT
  configurationItemCaptureTime,
  resourceType,
  resourceId,
  configurationItemStatus,
  awsRegion,
  configuration
FROM aws_config
WHERE
  account_id = '123456789012'
  AND configurationItemCaptureTime > current_timestamp - interval '1' hour
ORDER BY configurationItemCaptureTime DESC
LIMIT 1000;
```

The queries take seconds to minutes depending on data volume and time range. Athena's pricing is per-data-scanned, so partition pruning (specifying the year/month/day/account/region in the WHERE clause) is essential for cost-effective queries.

The forensic-query repository (a git repo with the team's canonical queries) is itself an artifact worth maintaining. During an incident, the team should reach for a tested query, not write one from scratch.

References:
- [Athena CloudTrail integration](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [Athena VPC Flow Logs integration](https://docs.aws.amazon.com/athena/latest/ug/vpc-flow-logs.html)

---

## Cost discipline

A regulated SaaS environment with 100-300 accounts generates approximately:
- CloudTrail management events: 1-5 GB/day per account (the management trail aggregates this).
- CloudTrail S3 data events: 10-1000 GB/day depending on the data-event configuration.
- VPC Flow Logs: 5-50 GB/day per VPC.
- AWS Config: 1-10 GB/day per account.
- ALB / CloudFront / WAF logs: 1-100 GB/day depending on traffic volume.

The annual storage cost for the full retention is significant. The cost discipline:

**1. Storage class transition.** S3 lifecycle policies move logs from Standard (the default ingestion class) to Standard-IA after 30 days, to Glacier Instant Retrieval after 90 days, and to Glacier Deep Archive after 365 days. The transition reduces storage cost by 80-95% for the older data. The retrieval cost on Deep Archive is higher, but for audit-trail data that is rarely retrieved, the trade is correct.

The Object Lock retention is independent of the storage class; objects in Deep Archive are still subject to the compliance-mode retention, so the cost optimization does not weaken the integrity guarantee.

```hcl
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "cloudtrail-tiering"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
  }
}
```

**2. Selective data events.** As noted in the CloudTrail design section, data events are billed per event. Enable them for high-value buckets only.

**3. VPC Flow Logs format.** Parquet over the default text format reduces storage by 5-10x and reduces Athena query cost proportionally.

**4. Athena query partition pruning.** Queries that specify the partitions (year, month, day, account, region) read a small slice of the data; queries that omit the partitions scan everything. The partition-pruning discipline is the dominant Athena cost driver.

**5. SIEM ingest selectivity.** As covered in the SIEM section; the dominant cost in most SIEM-integrated cloud-logging setups is the SIEM ingest fee, and selective forwarding is the largest lever.

The cost discipline above brings the typical log-pipeline cost from "uncomfortable" to "defensible." A team that does not apply the discipline can easily spend more on logging than on the workloads being logged; a team that does apply the discipline keeps logging cost to 1-3% of total cloud spend.

---

## Findings checklist

Findings IDs use the `LOG-` prefix.

| ID | Finding | Severity | Remediation |
| --- | --- | --- | --- |
| LOG-001 | No organization-level CloudTrail | Critical | Set up org trail to LogArchive S3 with Object Lock. |
| LOG-002 | CloudTrail log-file validation disabled | High | Enable validation; verify the hash chain. |
| LOG-003 | CloudTrail is not multi-region | High | Set IsMultiRegionTrail=true. |
| LOG-004 | No CloudTrail data events for high-value S3 buckets | High | Enable selectively per business-critical bucket. |
| LOG-005 | CloudTrail Insights not enabled | Medium | Enable on the org trail. |
| LOG-006 | VPC Flow Logs disabled on production VPCs | Critical | Enable per-VPC; Parquet format; route to LogArchive S3. |
| LOG-007 | AWS Config not enabled in some accounts | High | Enable in every account, every region; verify via aggregator. |
| LOG-008 | GuardDuty not enabled in some regions | High | Enable per region; verify auto-enable on new accounts. |
| LOG-009 | Security Hub administrator not delegated | Medium | Delegate to Security Tooling account. |
| LOG-010 | IAM Access Analyzer external-access findings ignored | High | Review weekly; remediate or document exception. |
| LOG-011 | ALB / CloudFront access logs disabled | Medium | Enable per resource; route to LogArchive. |
| LOG-012 | EKS audit logging disabled | High | Enable on every EKS cluster's control plane. |
| LOG-013 | RDS / Aurora audit logging disabled | Medium | Enable audit plugin or advanced logging. |
| LOG-014 | No Athena tables for forensic query | Medium | Set up Glue crawler against LogArchive; verify table integrity. |
| LOG-015 | LogArchive S3 missing Object Lock or KMS CMK | Critical | Set up Object Lock COMPLIANCE mode + KMS CMK (see baseline-guardrails.md). |
| LOG-016 | Log retention shorter than compliance requirement | Critical | Adjust retention to exceed the longest applicable compliance window. |
| LOG-017 | No storage-class tiering on LogArchive buckets | Medium | Set lifecycle policies for cost optimization. |
| LOG-018 | SIEM is being fed raw CloudTrail | Medium | Switch to selective forwarding; query historical from Athena. |

---

## Anti-patterns

**Anti-pattern 1: The "logs go to a CloudWatch Logs group in the same account" pattern.** Each account has its own CloudTrail trail; the trail writes to CloudWatch Logs in the same account. Failure mode: the audit trail is in the account that owns the workload; a compromised principal in the account can delete the logs. Corrective: org-level CloudTrail to LogArchive S3.

**Anti-pattern 2: The "we will turn on data events later" deferral.** S3 data events are deferred because of cost concerns. Failure mode: object-access forensics is impossible when an incident requires it. Corrective: enable data events selectively on high-value buckets at minimum; the cost is bounded by the selectivity.

**Anti-pattern 3: The "GuardDuty in some regions only" misconfiguration.** GuardDuty is enabled in active regions; inactive regions are ignored. Failure mode: an attacker who creates resources in an inactive region (cryptomining, exfiltration) operates in a blind spot. Corrective: GuardDuty in every region, even denied ones.

**Anti'-pattern 4: The "forward everything to the SIEM" anti-pattern.** All CloudTrail, all VPC Flow Logs, all Config history forwarded to the SIEM "in case we need it." Failure mode: SIEM ingest cost dominates the security budget; ingestion lags real-time; the SIEM team disables forwarding pieces to stay under budget. Corrective: selective forwarding; Athena for the rest.

**Anti-pattern 5: The "Config is too expensive" disablement.** Config is disabled or recording only a subset of resource types because of cost. Failure mode: when an incident asks "what did this resource look like yesterday," there is no answer. Corrective: keep Config recording all supported types; manage cost via the storage tier and the aggregator configuration.

**Anti-pattern 6: The "raw text VPC Flow Logs" suboptimal format.** Flow logs in the default text format. Failure mode: 5-10x larger than Parquet; Athena queries are 5-10x more expensive. Corrective: Parquet.

**Anti-pattern 7: The "forensic queries written from scratch during incidents" anti-pattern.** The team has no canonical query library; every incident starts with someone writing queries while the IR clock is running. Failure mode: incidents take longer; query mistakes produce wrong conclusions. Corrective: maintain a forensic-query repository; the queries are part of the IR runbook.

**Anti-pattern 8: The "we will fix the gaps after the next audit" deferral.** Coverage gaps are known but deferred because the audit has not asked about them. Failure mode: the next incident reveals the gap; the post-incident review identifies it as a contributing factor. Corrective: close the gaps now.

---

## Azure equivalent

For Azure environments, the equivalent pipeline is built around **Activity Logs**, **Diagnostic Settings**, **Microsoft Sentinel**, and **Azure Monitor**:

| AWS pattern | Azure equivalent |
| --- | --- |
| Organization CloudTrail | Activity Logs at the tenant + Diagnostic Settings forwarding to Log Analytics workspace |
| LogArchive S3 | Storage Account with immutability policies (equivalent to Object Lock) |
| GuardDuty | Microsoft Defender for Cloud (with the various Defender plans) |
| Security Hub | Microsoft Defender for Cloud security recommendations + Microsoft Sentinel |
| Athena queries | Kusto Query Language (KQL) in Log Analytics or Sentinel |
| Config | Azure Resource Graph + Azure Policy compliance |

The Azure architecture is structurally similar (centralize, retain, route to SIEM, query historical) but the service names and the specific configuration are different. The full Azure treatment lives in the eventual `azure-management-groups.md` and an Azure log-architecture document.

---

## GCP equivalent

For GCP environments, the equivalent is built around **Cloud Audit Logs**, **Log Sinks**, **Security Command Center**, and **BigQuery**:

| AWS pattern | GCP equivalent |
| --- | --- |
| Organization CloudTrail | Cloud Audit Logs at the Organization scope (Admin Activity + Data Access) |
| LogArchive S3 | GCS bucket with retention policies + Bucket Lock |
| GuardDuty | Security Command Center Premium / Enterprise |
| Security Hub | Security Command Center as the aggregator |
| Athena queries | BigQuery queries against the log sink |
| Config | Cloud Asset Inventory + Asset Feeds |

GCP's audit-log architecture is in some respects more mature than AWS's — Cloud Audit Logs has been the default since GCP's launch, and the Data Access logs (the equivalent of CloudTrail data events) are well-integrated rather than billed separately. The full GCP treatment will live in the eventual `gcp-organization-design.md`.

---

## Further reading

- [AWS Logging and Monitoring Best Practices Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/logging-and-monitoring-best-practices/welcome.html)
- [Centralized logging on AWS solution](https://aws.amazon.com/solutions/implementations/centralized-logging/)
- [CloudTrail Best Practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html)
- [VPC Flow Logs documentation](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- This repo:
  - [../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md) — the LogArchive account that this pipeline targets.
  - [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) — Guardrails 2.1 and 2.2 that protect the LogArchive.
  - [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) — the IR runbook that uses the queries from this document.
  - [custom-detections.md](./) *(coming)* — the detection logic that consumes the pipeline.
