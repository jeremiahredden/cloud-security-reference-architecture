# Runtime Security

A practitioner's reference for runtime security in Kubernetes — Falco, Tetragon, eBPF-based detection, vendor EDR for containers, the rule-selection and rule-tuning workflow, integration with detection-and-response, and the runtime-detection-vs-EDR boundary in container environments. The patterns here are about what runs *during* execution: detecting anomalous behavior that admission control couldn't prevent and observability couldn't predict.

Runtime security is the third layer in a defense-in-depth Kubernetes posture. Admission control ([admission-control.md](./admission-control.md)) prevents bad pods from starting; network policies ([network-policies.md](./network-policies.md)) restrict what they can reach; runtime security catches what they actually *do* once running. Each layer catches what the others miss; runtime is the layer that catches novel attacks and zero-days that the preventive layers couldn't have known about.

For the workload-isolation patterns this builds on, see [pod-security.md](./pod-security.md) and [network-policies.md](./network-policies.md). For the IR runbooks that respond to runtime-detected incidents, see [../cloud-detection-response/](../cloud-detection-response/).

---

## When to read this document

**If your cluster has no runtime detection** — read top to bottom. The gap is real; deployment is bounded.

**If you have Falco / Tetragon but most alerts are ignored** — start with [The rule-tuning workflow](#the-rule-tuning-workflow). Alert fatigue is the dominant failure mode; tuning is the fix.

**If you have vendor EDR for laptops but not for containers** — start with [The runtime-vs-EDR boundary](#the-runtime-vs-edr-boundary). The two are different in containers; the EDR pattern from laptops doesn't transfer cleanly.

**If you are auditing runtime-security posture** — start with [Findings checklist](#findings-checklist).

---

## What runtime security catches

Runtime monitoring observes the actual behavior of containers and detects:

- **Unexpected process execution** — a shell spawning inside a pod that shouldn't have a shell; `nsenter`, `nmap`, `curl` to anomalous destinations.
- **File-system anomalies** — writes to sensitive paths (`/etc/passwd`, `/root/.ssh/`), reads of cloud-IAM metadata files.
- **Network anomalies** — connections to known C2, lateral movement attempts, anomalous outbound to crypto-mining pools.
- **Privilege escalation attempts** — setuid invocations, capability use, kernel module loads.
- **Cryptocurrency mining** — high CPU + specific process signatures.
- **Container escapes** — patterns indicating an attempt to break out of the container namespace.

These are detection signals, not prevention. The pod is doing the thing; runtime security observes and alerts.

### What runtime security doesn't replace

- **Admission control** — preventing bad pods from starting is structurally cheaper than detecting bad behavior after the fact.
- **Network policies** — runtime detection sees connections; network policies *block* them.
- **Pod security** — runtime is the safety net for what the preventive layers missed; it's not a substitute.

A team without admission + network policies has a runtime layer that fires constantly on what should have been prevented; a team with all three has a runtime layer that fires on actual incidents.

---

## The tool landscape

The dominant runtime security tools in 2026.

### Falco

- **Open source**, the canonical Kubernetes runtime-detection tool.
- Originally kernel-module-based; modern deployments use eBPF.
- Rule language is YAML-based; community rule libraries available.
- Output: alerts via syslog, gRPC, HTTP, or via the Falcosidekick fan-out (Slack, PagerDuty, SIEM, etc.).
- Mature operationally; widely deployed.

Best for: most teams' starting point; default open-source choice.

### Tetragon

- **Open source** (Cilium project); eBPF-based; integrates with Cilium NetworkPolicy.
- More performant than Falco for high-throughput environments (deeper eBPF integration).
- Rule language is YAML (TracingPolicies); can also enforce (kill processes, not just alert).
- Newer than Falco; smaller community.

Best for: Cilium-heavy environments; teams needing enforcement actions in addition to detection.

### Vendor EDR / CNAPP

- **CrowdStrike Falcon Container Runtime**, **Sysdig Secure**, **Aqua Runtime**, **Wiz Runtime**, **Microsoft Defender for Cloud**, etc.
- Commercial; managed; deeper integration with vendor's broader security platform.
- Often pair with vendor's CSPM and CWPP capabilities.

Best for: organizations with existing vendor relationships; managed-service preference; specific compliance requirements.

### eBPF-based custom tools

For high-customization needs:

- **bpftrace** for ad-hoc tracing.
- **Custom eBPF programs** for specific detection logic.

Reserved for security-engineering teams with eBPF expertise; rarely the right first move.

### The tool-stack recommendation

For most teams:

- **Falco** as the runtime-detection foundation (open source, mature, well-documented).
- **Optional vendor EDR** alongside Falco for organizations with existing CrowdStrike / Wiz / similar deployments (the two coexist; the vendor adds correlation with other security signals).
- **Tetragon** when Cilium is the CNI and the team wants enforcement actions.

References:
- [Falco](https://falco.org/)
- [Tetragon](https://tetragon.io/)
- [Sysdig](https://sysdig.com/)
- [CrowdStrike Falcon Container Runtime](https://www.crowdstrike.com/products/cloud-security/cloud-workload-protection/)

---

## Falco deployment

The canonical pattern.

### Architecture

- **DaemonSet** on every node — Falco runs on each node, observing kernel events via eBPF.
- **Output channels** — alerts routed to Falcosidekick (a fan-out service) which forwards to Slack, PagerDuty, S3, SIEM, etc.
- **Rule files** — local + community rule libraries.

### Helm-based deployment

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl="$SLACK_WEBHOOK" \
  --set falcosidekick.config.elasticsearch.hostport="$ES_HOST"
```

The Falco namespace is configured with the PSA `privileged` profile (per [pod-security.md](./pod-security.md)) because runtime monitoring requires kernel-level access.

### Rule libraries

Falco ships with default rules; the community maintains additional rule sets. Common rule files:

- `falco_rules.yaml` — built-in core rules.
- `application_rules.yaml` — application-specific patterns.
- `k8s_audit_rules.yaml` — Kubernetes API audit-event rules.
- Custom rules in `local_rules.yaml` for organization-specific patterns.

### A representative rule

```yaml
- rule: Detect Shell in Container
  desc: A shell was spawned in a container with an attached terminal
  condition: >
    spawned_process and
    container and
    shell_procs and
    proc.tty != 0
  output: >
    A shell was spawned in a container with an attached terminal
    (user=%user.name user_loginuid=%user.loginuid %container.info
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline
    terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: NOTICE
  tags: [container, shell, mitre_execution]
```

The rule fires when a shell process (`bash`, `sh`, `zsh`) is spawned in a container with an attached terminal — typical of an interactive exec (e.g., `kubectl exec -it ...` or, much more concerning, a reverse shell from a compromised pod).

### Output integration

Falcosidekick fans out alerts to multiple destinations:

- **Slack** for team visibility.
- **PagerDuty** for high-priority alerts.
- **SIEM** (Splunk, Sentinel, Elastic) for correlation and long-term retention.
- **S3** for archival.

For most teams: PagerDuty for critical/error severity; Slack channel for notice/warning; SIEM for everything for retention and querying.

References:
- [Falco Rules](https://falco.org/docs/rules/)
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick)

---

## The rule-tuning workflow

The single most-important operational discipline. Without it, runtime tools produce overwhelming noise and the team learns to ignore them.

### The default-rule baseline

Falco's default rules cover the well-known attack patterns:

- Shell spawned in container.
- Unexpected file access in sensitive directories.
- Outbound connection to specific IP ranges (the Falco default list).
- Privilege escalation patterns (setuid, capability changes).
- Crypto-mining pool connection patterns.

The defaults are tuned for *general* environments. In a specific environment, some patterns are normal (e.g., a CI runner pod that does exec shells; a backup pod that writes to sensitive paths). Without tuning, these legitimate operations generate alerts.

### The tuning sequence

1. **Deploy in monitor-only mode.** Alerts go to a log; nothing pages.
2. **Collect 2–4 weeks of baseline data.** Categorize alerts by source pod / namespace / pattern.
3. **Identify false positives.** Patterns that fire frequently and are legitimate.
4. **Add exceptions per rule.** Most Falco rules support `exceptions:` to suppress specific patterns.
5. **Add custom rules for organization-specific patterns.** Detection that the defaults don't cover.
6. **Switch to enforce mode.** Now alerts go to the team.

The tuning takes weeks per cluster; it is bounded; the result is a low-noise, high-signal stream.

### A tuned exception example

The default "Shell in container" rule fires on `kubectl exec`. Engineers exec into production pods rarely but it happens. The exception:

```yaml
- list: known_admin_users
  items: ["ops-admin", "platform-engineer-1", "platform-engineer-2"]

- rule: Detect Shell in Container
  desc: A shell was spawned in a container with an attached terminal
  condition: >
    spawned_process and
    container and
    shell_procs and
    proc.tty != 0 and
    not user.name in (known_admin_users)
  # ... rest of rule
```

The exception narrows the rule: shells spawned by known admin users (their `kubectl exec` activity) don't alert; shells spawned by anyone else (or from a process not initiated by `kubectl exec`) still alert.

### The "always log, sometimes page" pattern

Falco alerts have severities. The pattern:

- **Notice / Informational:** logged to the central archive; not paged. Useful for forensics.
- **Warning:** logged + visible in dashboard; review during weekly security standup.
- **Error / Critical:** paged via PagerDuty.

The severities are part of the rule; tuning includes adjusting severity for organization-specific context (e.g., a default-Notice rule might be Critical in this environment because of the workload's regulatory context).

### The "rule that fires once a year is forgotten" pattern

A common failure: rules tuned aggressively, alerts rare. When an alert fires, the team has forgotten the runbook. Investigation is slow.

The fix: even rare-alert rules have documented runbooks; runbooks are reviewed annually; on-call drills include runtime-alert simulations.

---

## Common detection rules

Beyond the defaults, the rules every Kubernetes runtime monitor should have.

### Container escape attempts

- **Process executes from unusual paths** (e.g., `/tmp/`, `/dev/shm/`).
- **`mount` invocations** inside containers (rare in normal operation).
- **Capability use** (CAP_SYS_ADMIN, CAP_NET_RAW) for pods that shouldn't need them.
- **`nsenter` invocations** (used to enter other namespaces).
- **`/proc/*/exe` reads** for processes the pod shouldn't be inspecting.

### Crypto-mining detection

- **High sustained CPU** combined with **outbound connection to known mining pool FQDNs**.
- **Process name patterns** matching common mining tools (`xmrig`, `cgminer`, `minerd`).
- **GPU-resource consumption** by non-GPU-intended workloads (where GPUs exist).

### Reverse shell / C2 patterns

- **Outbound connection from non-typical processes** (e.g., `bash` initiating a network connection rather than the application binary).
- **Long-lived connections to anomalous destinations** (per DNS firewall and egress firewall integration).
- **TLS connections to known C2 infrastructure** (threat-intel feed integration).

### Credential theft patterns

- **Access to cloud metadata service** (`169.254.169.254`) from non-typical processes.
- **Reading `/var/run/secrets/kubernetes.io/serviceaccount/token`** from non-application processes.
- **AWS credential file access** (`/root/.aws/credentials`, `/home/*/.aws/credentials`).
- **SSH key file access** (`/root/.ssh/id_rsa`, `/home/*/.ssh/id_rsa`).

### Persistence patterns

- **Cron job creation** inside containers (atypical for ephemeral workloads).
- **systemd unit file modifications** (containers shouldn't be managing systemd).
- **`authorized_keys` modifications.**

### Lateral-movement patterns

- **Connection to Kubernetes API from non-typical processes.**
- **Service-account token use from processes other than the application.**
- **Reading Kubernetes secrets via the API.**

---

## The runtime-vs-EDR boundary

For organizations with vendor EDR (Endpoint Detection and Response) for laptops, the question is whether the EDR vendor's container-runtime capability replaces Falco.

### What vendor EDR provides

- **Correlation with broader security context** (the same vendor watches laptops, endpoints, cloud).
- **Threat-intel integration** from the vendor's broader visibility.
- **Managed alert tuning** (the vendor's SOC sometimes handles initial triage).
- **Compliance / regulatory** alignment for some certifications.

### What Falco provides

- **Open source** (no vendor lock-in; rules portable).
- **Community rule libraries** for common patterns.
- **Direct customization** at the rule level.
- **Lower cost** (no licensing).

### The coexistence pattern

Many organizations run both:

- **Vendor EDR** for the breadth and the SOC integration.
- **Falco** for Kubernetes-specific patterns and direct customization.

The two produce overlapping alerts on some patterns; tune deduplication at the SIEM layer.

### When Falco-only is the right choice

- Smaller organizations without existing vendor EDR investments.
- Teams with strong open-source preference.
- Cost-sensitive deployments.
- Environments where Falco's rule customizability is specifically valuable.

### When vendor EDR-only is the right choice

- Organizations where vendor EDR is already deployed and the contract covers containers.
- Compliance requirements specifying named EDR products.
- Teams without operational capacity to tune and maintain Falco.

For most production multi-tenant clusters: at least Falco; vendor EDR additionally where the organization has it.

---

## Integration with detection-and-response

Runtime alerts are only valuable if they reach the response chain.

### The alert flow

1. **Runtime tool detects** an event matching a rule.
2. **Alert dispatched** via Falcosidekick / vendor's alert channel.
3. **PagerDuty / similar** pages the on-call security engineer for critical severity.
4. **SIEM ingests** the event for correlation and retention.
5. **Investigation** per the relevant IR runbook ([../cloud-detection-response/](../cloud-detection-response/)).

### The IR runbooks for runtime alerts

Specific runbooks should exist for:

- **EKS pod compromise** (see [../cloud-detection-response/runbook-eks-pod-compromise.md](../cloud-detection-response/runbook-eks-pod-compromise.md)).
- **Cryptomining detection** (see [../cloud-detection-response/runbook-cryptomining.md](../cloud-detection-response/runbook-cryptomining.md)).
- **Container escape attempt.**
- **Credential theft pattern detected.**
- **Mass-deletion or lateral-movement patterns.**

Each runbook covers: triage, containment, eradication, recovery, lessons learned.

### The metric: time-to-detection

For runtime security, the operational metric is **time-to-detection** — how long between an event occurring and the team being aware. Targets:

- **Critical events:** detection within minutes (PagerDuty integration).
- **High-severity events:** detection within an hour (Slack channel with on-call rotation).
- **Lower-severity events:** detection within a day (dashboard review).

Time-to-detection includes the rule-tuning quality (a rule that doesn't fire on the event detects it never).

### Detection on the runtime tool itself

A subtle pattern: the runtime tool is itself a target. An attacker who can disable Falco can run their attack uninterrupted.

The detection:

- **Falco DaemonSet pod count** matches node count. Sudden drop = pods killed.
- **Falco-process-killed alerts** from the broader observability layer.
- **Audit-log events** for changes to the Falco namespace, ClusterRoleBinding, DaemonSet.

The pattern: runtime tools are protected by admission policies, RBAC restrictions, and observability on the tools themselves.

---

## Worked example: Meridian Health's runtime security

Meridian operates Falco across EKS clusters with custom rules for Meridian-specific patterns and Falcosidekick fan-out to PagerDuty, Slack, and the central SIEM.

### Deployment

- **Falco DaemonSet** on every node in every production cluster.
- **Falcosidekick** fan-out service deployed alongside.
- **PSA `privileged`** profile on the `falco` namespace (Falco requires kernel-level access).
- **RBAC** restricting `falco` namespace administration to platform-team SREs only.
- **Admission policy** preventing changes to the Falco DaemonSet or namespace by non-platform principals.

### Rule library

Active rules:

- **Falco default rules** (with tuned exceptions per Meridian environment).
- **Cryptomining patterns** with the Meridian's threat-intel cryptomining-pool FQDN list.
- **EKS-specific patterns** (kubectl exec to production pods; cloud-metadata access from pods).
- **Meridian custom rules:**
  - Detection of access to `/var/run/secrets/care-coordinator/...` from non-care-coordinator processes.
  - Detection of `pgrep`, `pkill` invocations (indicate process discovery).
  - Detection of `kubectl` binary in pods (pods shouldn't run kubectl).
  - Detection of access to AWS / Azure / GCP IMDS endpoints from non-application processes.

### Tuning history

Initial deployment in Q2 2024 produced ~3000 alerts/day across all clusters; ~95% were legitimate operations (engineers' kubectl execs, backup jobs writing to expected paths, etc.).

Tuning over 6 weeks:

- Categorized alerts by source / pattern.
- Added exceptions for legitimate patterns.
- Built custom rules for Meridian-specific signals.
- Reduced alert volume to ~50/day; ~10 high-severity.

Post-tuning: most alerts are investigated within hours; high-severity alerts are paged.

### Integration

- **Falcosidekick → PagerDuty** for critical/error severity.
- **Falcosidekick → Slack #soc-runtime-alerts** for warning/notice severity.
- **Falcosidekick → Kafka → Splunk** for SIEM ingestion (all severities).
- **PagerDuty → Security on-call** with 15-minute response SLA.

### The IR-runbook coverage

Meridian has runbooks for runtime-detected scenarios:

- Pod compromise (per [../cloud-detection-response/runbook-eks-pod-compromise.md](../cloud-detection-response/runbook-eks-pod-compromise.md)).
- Cryptomining detection (per [../cloud-detection-response/runbook-cryptomining.md](../cloud-detection-response/runbook-cryptomining.md)).
- Container-escape attempt.
- Credential-theft pattern.

Each runbook is exercised quarterly via tabletop or live simulation.

### Findings opened during the runtime-security audit

- **RT-001** (no runtime detection in any cluster). Closed by Falco deployment.
- **RT-002** (default Falco rules deployed without tuning; alert fatigue led to ignored alerts). Closed by the tuning sprint.
- **RT-003** (alerts went to a logging channel without paging integration). Closed by Falcosidekick → PagerDuty for critical.
- **RT-004** (no Meridian-specific rules; missed signals on internal patterns). Closed by custom rule development.
- **RT-005** (Falco DaemonSet itself not protected; admin could disable). Closed by admission policy + RBAC restrictions.
- **RT-006** (no runbook coverage for runtime-detected scenarios). Closed by runbook development.

---

## Anti-patterns

### 1. The deployed-but-untuned tool

The team installs Falco; default rules produce thousands of alerts daily; the team learns to ignore. Detection is theoretical.

The fix: rule-tuning sprint. Monitor-only mode → identify false positives → add exceptions → switch to enforce.

### 2. The alerting without runbooks

Alerts fire; the on-call engineer doesn't know what to do; investigation is improvised; response is slow.

The fix: every alert class has a runbook. Runbooks reviewed quarterly; on-call drills include simulations.

### 3. The runtime-tool single point of failure

Falco runs as a single Pod (not DaemonSet); a node failure means no detection on that node; an attacker exploiting the gap goes undetected.

The fix: DaemonSet on every node; monitoring on the DaemonSet's pod count.

### 4. The unprotected runtime tool

Falco's namespace is unprotected. An attacker with sufficient permissions disables Falco; runs the attack undetected.

The fix: RBAC restricting Falco namespace administration; admission policies preventing DaemonSet changes; observability on the Falco-tool itself.

### 5. The vendor-EDR-and-Falco duplicate

Both tools fire on the same events; SOC receives duplicate alerts; deduplication burden.

The fix: deduplication at SIEM layer; tune one tool's coverage to complement the other (e.g., vendor EDR for general patterns; Falco for Kubernetes-specific patterns).

### 6. The high-severity-for-everything

All Falco rules are set to Critical priority. Everything pages. PagerDuty becomes noise; engineers learn to dismiss without investigation.

The fix: severity tuning per rule based on actual risk. Notice for routine observations; Warning for investigate-but-don't-page; Critical for genuine emergencies.

### 7. The eBPF-incompatible node

A team has nodes running old kernel versions that don't support eBPF; Falco can't deploy; some nodes have no runtime detection.

The fix: kernel version requirements documented; cluster upgrades include kernel-compatibility check; node pools enforce minimum kernel versions.

### 8. The forgotten exception expiry

Exceptions were added for legitimate patterns. The patterns changed (workload retired, pod renamed); exceptions still in place; signal degradation.

The fix: exceptions have expiration; quarterly review; stale exceptions removed.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| RT-001 | No runtime detection deployed (Falco, Tetragon, vendor EDR) | High | Deploy Falco (or vendor EDR) as DaemonSet; integrate with central alerting | Platform Eng + Security Eng |
| RT-002 | Runtime tool deployed with default rules; alert fatigue led to ignored alerts | High | Tuning sprint: monitor-only mode; identify false positives; add exceptions | Security Eng + SOC |
| RT-003 | Alerts go to a log only; no paging integration | High | Falcosidekick / vendor integration → PagerDuty for critical; Slack for warnings | Security Eng + SOC |
| RT-004 | Organization-specific rules absent; defaults miss internal patterns | Medium | Custom rules for org-specific patterns (secret paths, internal binaries, etc.) | Security Eng |
| RT-005 | Runtime-detection DaemonSet not protected; admin can disable | High | RBAC restrictions; admission policy prevents DaemonSet changes; monitoring on DaemonSet pod count | Platform Eng + Security Eng |
| RT-006 | No IR runbooks for runtime-detected scenarios | High | Runbooks per scenario: pod compromise, cryptomining, container escape, credential theft | Security Eng + SOC |
| RT-007 | Rule severities miscalibrated (all critical, or none critical) | Medium | Severity tuning per rule based on actual risk | Security Eng |
| RT-008 | Exceptions for false positives lack expiration; signal degradation | Low | Expiration on exceptions; quarterly review | Security Eng |
| RT-009 | eBPF-incompatible node versions; runtime detection unavailable on some nodes | Medium | Minimum kernel version requirements; node pool enforcement | Platform Eng |
| RT-010 | Runtime tool DaemonSet count doesn't match node count; some nodes uncovered | High | Monitoring on DaemonSet pod count; alert on count mismatch | Platform Eng + SRE |
| RT-011 | Critical detection signals (cryptomining, IMDS access) not in active rules | High | Verify rule coverage for known attack patterns; add custom rules where defaults miss | Security Eng |
| RT-012 | Runtime alerts not consumed by SIEM; correlation across signals impossible | Medium | SIEM ingestion (Splunk / Sentinel / Elastic); correlation rules | Security Eng + SOC |
| RT-013 | Vendor EDR + Falco duplicate alerting; deduplication absent | Low | Deduplication at SIEM; tune coverage to complement | Security Eng + SOC |
| RT-014 | Rule library not updated; new attack patterns missed | Medium | Community rule library sync; quarterly review of new patterns | Security Eng |
| RT-015 | No tabletop exercises for runtime-detected incidents | Medium | Quarterly tabletop with runbook execution; on-call drills | Security Eng + SOC |
| RT-016 | Falco namespace lacks PSA privileged profile; Falco can't start | High | Configure namespace with `pod-security.kubernetes.io/enforce: privileged` | Platform Eng |
| RT-017 | Falco logs ship to non-immutable storage; tampering possible during incident | Medium | Logs ship to immutable storage (S3 Object Lock or equivalent) | Security Eng + Platform Eng |
| RT-018 | Cluster baseline lacks runtime detection in the standard module | Medium | Add Falco to the cluster-baseline Helm / Terraform module | Platform Eng |

---

## What this document is not

- **A Falco rule-writing tutorial.** Falco documentation covers the rule language; this document focuses on the operational patterns around rules.
- **A complete eBPF reference.** eBPF is the underlying technology; this document covers the security-tool layer above it.
- **A vendor EDR comparison.** CrowdStrike / Wiz / Sysdig / etc. are mentioned; the choice belongs with broader security-tool decisions.
- **A complete IR reference.** Detection signals go to IR runbooks; the runbooks themselves live in [../cloud-detection-response/](../cloud-detection-response/).
