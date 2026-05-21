# Runbook — EKS Pod Compromise

Incident response runbook for a compromised pod in an EKS cluster (the patterns apply equally to AKS / GKE with platform-specific command substitutions). The runbook covers the cases where a pod is exhibiting suspicious behavior: unexpected process execution, anomalous network egress, attempted privilege escalation, attempted access to the cluster's API server beyond the pod's role, or runtime alerts from Falco / Tetragon. The cause may be a vulnerability in the application code, a vulnerability in a base image, a supply-chain compromise of a dependency, an injected attack via an exposed API, or a compromised credential that was used to deploy malicious code.

The runbook is one of a set; see also [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md), [runbook-exposed-storage.md](./runbook-exposed-storage.md), `runbook-account-takeover.md`, and `runbook-cryptomining.md`. The structure is consistent across the runbook set.

---

## Quick reference

```
   ┌──────────────────────────────────────────────────────────────────┐
   │ STEP                ACTION                              TIME      │
   ├──────────────────────────────────────────────────────────────────┤
   │ 1. Verify alert     Confirm the pod is compromised        10 min    │
   │ 2. Contain          Isolate via NetworkPolicy             10 min    │
   │ 3. Preserve         Capture pod / container state         15 min    │
   │ 4. Scope            Determine lateral-movement reach      30 min    │
   │ 5. Forensic         What did the pod do / access          60 min    │
   │ 6. Eradicate        Delete the pod; patch the cause       30 min    │
   │ 7. Recover          Replace with hardened pod             30 min    │
   │ 8. Communicate      Notify per the comms matrix           30 min    │
   │ 9. Post-incident    PIR; image-supply-chain review        2-5 days  │
   └──────────────────────────────────────────────────────────────────┘
```

Total time-to-containment target: 20 minutes from alert. The forensic step is more involved than IAM-key incidents because pod compromise can involve filesystem, process, and network forensics that take longer to complete.

The runbook adds a step ("Preserve") between Containment and Scope because EKS containers are ephemeral by design — once the pod is killed, the filesystem and process state are gone. Preserving the state before further action is essential for forensics.

---

## Detection signals

| Signal | Source | Default severity |
| --- | --- | --- |
| GuardDuty: `Execution:EKS/AnomalousBehavior.RuntimeAlert` | GuardDuty EKS Protection | High |
| GuardDuty: `Persistence:Kubernetes/MaliciousIPCaller` | GuardDuty EKS | High |
| GuardDuty: `PrivilegeEscalation:Kubernetes/PrivilegedContainer` | GuardDuty EKS | Critical |
| GuardDuty: `CredentialAccess:Kubernetes/MaliciousIPCaller` | GuardDuty EKS | High |
| Falco rule: "Container escape" / "Privilege escalation" | Falco runtime | Critical |
| Falco rule: "Crypto miner execution" | Falco runtime | High |
| Falco rule: "Suspicious file read in container" | Falco runtime | Medium |
| Tetragon: anomalous syscall pattern | Tetragon runtime | Variable |
| AWS Network Firewall: pod-source egress to known-bad IP | Network firewall | High |
| Kubernetes audit log: pod made request to apiserver outside its role | EKS audit | High |
| Internal alert: developer notices unusual pod behavior | Manual | Medium |
| External notification: customer reports application anomaly | External | High |

---

## Step 1 — Verify the alert (target: 10 minutes)

Confirm the pod is actually exhibiting compromise indicators, not benign anomaly.

**1. Get the pod's current state.**

```bash
POD_NAME=patient-api-7d4f5b8c9-xkqz2
NAMESPACE=meridian-app

kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o yaml > "pod-state-${POD_NAME}.yaml"
kubectl describe pod "$POD_NAME" -n "$NAMESPACE" > "pod-describe-${POD_NAME}.txt"
```

**2. Check the pod's recent logs.**

```bash
kubectl logs "$POD_NAME" -n "$NAMESPACE" --tail=500 > "pod-logs-${POD_NAME}.txt"

# If the pod has restarted, get the previous container logs.
kubectl logs "$POD_NAME" -n "$NAMESPACE" --previous --tail=500 \
  > "pod-logs-previous-${POD_NAME}.txt"
```

**3. Confirm the runtime alert details.**

For Falco / Tetragon alerts, retrieve the specific rule that fired and the syscall / process information. For GuardDuty alerts, retrieve the finding details:

```bash
aws guardduty get-findings \
  --detector-id <detector-id> \
  --finding-ids <finding-id> \
  --output json
```

The finding includes the pod identifier, the namespace, the suspicious action, and the source IP if applicable.

**4. Check for lateral indicators.**

Has the pod's IAM role made unusual AWS API calls?

```sql
SELECT eventTime, sourceIPAddress, eventName, errorCode, resources
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE concat('%', 'patient-api', '%')
  AND eventTime > current_timestamp - interval '1' hour
ORDER BY eventTime DESC;
```

Has the pod attempted unusual cluster API calls?

```sql
-- From EKS audit logs in CloudWatch Logs (or a copy in LogArchive).
SELECT @timestamp, user.username, verb, objectRef.resource, objectRef.name, sourceIPs
FROM eks_audit_logs
WHERE user.username = 'system:serviceaccount:meridian-app:patient-api'
  AND @timestamp > current_timestamp - interval '1' hour
ORDER BY @timestamp DESC;
```

**Decision point.** Three outcomes:

1. **False positive.** The behavior is benign (a new release exercising new functionality; the runtime rule is overly broad). Document and close.
2. **Confirmed compromise, contained scope.** The behavior is malicious, but limited to the pod itself (e.g., a cryptominer in the container with no apparent lateral movement). Advance to Step 2.
3. **Confirmed compromise, broad scope.** The pod has assumed AWS roles to access other resources, has made cluster-API calls outside its scope, or has established network connections to other pods / nodes. Escalate to incident commander before Step 2; broader containment may be needed.

---

## Step 2 — Contain (target: 10 minutes)

Isolate the pod at the network layer. Two patterns:

**Pattern A: NetworkPolicy isolation (preferred for forensic preservation).**

Apply a deny-all NetworkPolicy to the pod by label:

```yaml
# isolation-networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ir-isolate-patient-api-xkqz2
  namespace: meridian-app
spec:
  podSelector:
    matchLabels:
      ir-isolation: "true"
  policyTypes:
  - Ingress
  - Egress
  # No ingress or egress rules → all blocked.
```

```bash
# Label the pod for the policy to match.
kubectl label pod "$POD_NAME" -n "$NAMESPACE" ir-isolation=true

# Apply the policy.
kubectl apply -f isolation-networkpolicy.yaml
```

The pod is now isolated: no ingress, no egress. The container continues running (which preserves the in-memory state for forensic capture in Step 3) but cannot communicate with anything.

**Pattern B: Pod deletion (faster but destroys forensic state).**

If the urgency is high and the forensic state is less important (e.g., a known cryptominer where the malicious behavior is well-understood):

```bash
kubectl delete pod "$POD_NAME" -n "$NAMESPACE" --force --grace-period=0
```

The deployment's ReplicaSet will replace the pod. If the replacement also exhibits the compromise (because the image itself is compromised), repeat with the next instance — the eradication step addresses the underlying image.

**For broader-scope compromises** (Step 1 outcome 3), additional containment may be needed:

- **Cordon the node** if the compromise indicates host-level compromise: `kubectl cordon <node-name>`.
- **Drain the node** to evacuate other workloads: `kubectl drain <node-name> --ignore-daemonsets`.
- **Revoke the pod's AWS role's active sessions** if the pod assumed roles that need session-level revocation (see [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) Step 2).

**Decision point.** Containment is verified when the pod cannot communicate (NetworkPolicy verified by `kubectl exec ... -- curl <any-external-target>` failing) or the pod is deleted.

---

## Step 3 — Preserve (target: 15 minutes)

Capture the pod's state for forensic analysis. The patterns:

**1. Capture an image of the running container's filesystem.**

```bash
# Run an ephemeral container that has access to the target container's filesystem.
kubectl debug "$POD_NAME" -n "$NAMESPACE" \
  --target=<container-name> \
  --image=ubuntu:24.04 \
  --share-processes \
  -- sleep 3600

# Within the ephemeral container, capture the target's filesystem.
# (The target's root filesystem is mounted at /proc/<target-pid>/root.)
```

The ephemeral container has access to the target's filesystem and processes via `--share-processes`. A forensic image can be tarballed and copied out via `kubectl cp`.

For older kubectl versions without `kubectl debug`, the equivalent is to schedule a new pod on the same node with `hostPID: true` and `hostPath` volumes pointing to the container's filesystem (more complex; the modern `kubectl debug` is preferred).

**2. Capture the container's process state.**

```bash
# Within the ephemeral container or via kubectl exec.
ps -auxf > /tmp/processes.txt
netstat -tnlp > /tmp/netstat.txt
ss -tnlp > /tmp/ss.txt
cat /proc/<target-pid>/maps > /tmp/memory-map.txt
```

**3. Capture the container's recent runtime audit trail.**

If Falco or Tetragon is running, retrieve their recent events for the pod:

```bash
# Falco events from CloudWatch Logs (if forwarded) or the Falco backend.
aws logs filter-log-events \
  --log-group-name /aws/eks/meridian-prod/falco \
  --filter-pattern "{ $.output_fields.container_id = \"$CONTAINER_ID\" }" \
  --start-time $(date -d '1 hour ago' +%s)000
```

**4. Snapshot the EBS volumes the pod was using.**

If the pod used persistent volumes (EBS-backed PVCs), snapshot them:

```bash
PV_NAME=$(kubectl get pvc -n "$NAMESPACE" <pvc-name> -o jsonpath='{.spec.volumeName}')
EBS_VOLUME=$(kubectl get pv "$PV_NAME" -o jsonpath='{.spec.csi.volumeHandle}')

aws ec2 create-snapshot \
  --volume-id "$EBS_VOLUME" \
  --description "IR snapshot for ${POD_NAME} on $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --tag-specifications "ResourceType=snapshot,Tags=[{Key=incident,Value=$INCIDENT_ID}]"
```

The snapshot can be attached to a forensic-analysis instance later.

**5. Capture the cluster audit log entries for the pod.**

The EKS audit logs (if enabled in the cluster's logging configuration) contain every Kubernetes API call. Filter for the pod's ServiceAccount:

```sql
SELECT @timestamp, user.username, verb, objectRef, sourceIPs, requestObject
FROM eks_audit_logs
WHERE user.username = concat('system:serviceaccount:', '$NAMESPACE', ':', '<sa-name>')
  AND @timestamp > current_timestamp - interval '24' hour
ORDER BY @timestamp DESC;
```

**Decision point.** Preservation is complete when the team has:
- A copy of the container's filesystem.
- The container's process state.
- The runtime audit trail.
- Snapshots of any persistent volumes.
- The cluster audit log entries.

These artifacts go to the incident's evidence bucket in LogArchive (or a dedicated forensic bucket). After preservation, the pod can be deleted in Step 6 without losing forensic state.

---

## Step 4 — Scope (target: 30 minutes)

Determine how far the compromise reached.

**Did the pod's IAM role do anything?**

```sql
SELECT eventTime, sourceIPAddress, eventName, requestParameters, errorCode
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE concat('%', '<role-name>', '%')
  AND eventTime > current_timestamp - interval '7' day
ORDER BY eventTime DESC;
```

The pod's IRSA / Pod Identity role has bounded permissions; the question is whether the compromise exercised them maliciously. If the pod's role is tight (per [../identity-and-access/least-privilege-workflow.md](../identity-and-access/least-privilege-workflow.md)), the blast radius is limited to what the role can do. If the role is broad, the blast radius is wider.

**Did the pod access other pods?**

VPC Flow Logs and the cluster's network policies determine what was reachable. If NetworkPolicy was deny-default in the namespace (it should have been), the lateral reach is constrained to the explicitly-allowed peers.

```sql
SELECT srcaddr, dstaddr, dstport, bytes, action
FROM vpc_flow_logs
WHERE srcaddr = '<pod-ip>'
  AND start_time > current_timestamp - interval '24' hour
  AND action = 'ACCEPT'
ORDER BY bytes DESC;
```

The flow logs reveal every accepted connection from the pod. Investigate each destination.

**Did the pod write data anywhere persistent?**

If the pod has volumes mounted (EBS PVCs, S3 access, RDS access), the writes are persistent and may carry the compromise forward. Examine the volumes for unexpected files; examine the S3 buckets for unexpected uploads; examine the database for unexpected modifications.

**Did the pod attempt to read secrets?**

If the cluster mounts Kubernetes Secrets into the pod, the secrets are on the pod's filesystem (at `/var/run/secrets/...`). A compromised pod has access to those secrets. The Secrets that the pod could have read need to be rotated.

**Decision point.** The scope analysis produces:
- A list of AWS resources the role accessed.
- A list of pods / IPs the pod connected to.
- A list of volumes / buckets / databases that may have been modified.
- A list of secrets that need rotation.

Each item drives an eradication step.

---

## Step 5 — Forensic (target: 60 minutes)

Determine how the pod was compromised in the first place. This step often takes the longest because root-cause analysis requires careful investigation.

**Common compromise vectors:**

1. **Vulnerability in the application code.** An RCE in the application's HTTP handler, an SSRF combined with IMDSv1 (which should not exist; see [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) Guardrail 4.2), a deserialization flaw. Forensic: review the application's recent requests around the time of compromise.

2. **Vulnerability in a dependency.** A known CVE in a library the application uses. Forensic: identify the dependencies in the image (the SBOM, if available); cross-check against CVE databases for the time window.

3. **Vulnerability in the base image.** A package in the base image with a known vulnerability. Forensic: scan the image (Trivy / Grype / vendor scanner).

4. **Supply-chain compromise.** A malicious dependency was added (a typosquatted package, a compromised maintainer's release). Forensic: review the dependency change history; check for unusual additions.

5. **Compromised CI / build pipeline.** The image was built from clean source but the build pipeline injected malicious content. Forensic: review the build's provenance (SLSA attestation, if available); review the CI pipeline's recent changes.

6. **Compromised credential used to deploy.** A leaked CI credential was used to push a malicious image. Forensic: review the deployment audit log; cross-check with [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) if a credential leak is suspected.

**For each vector, the forensic artifact:**

- For vectors 1-2, the application logs and the request that exploited the vulnerability.
- For vector 3, the image scan output identifying the vulnerable package.
- For vectors 4-6, the build / deploy audit trail.

The forensic conclusion drives the eradication step. If the compromise was vector 3, eradication includes rebuilding the image from a patched base; if it was vector 6, eradication includes credential rotation and pipeline hardening.

---

## Step 6 — Eradicate (target: 30 minutes)

Remove the compromised pod and the underlying cause.

**1. Delete the compromised pod (if not already deleted in Step 2).**

```bash
# Confirm preservation is complete before deletion.
kubectl delete pod "$POD_NAME" -n "$NAMESPACE" --force --grace-period=0
```

The ReplicaSet will replace the pod automatically. If the replacement also exhibits the compromise, scale the deployment to zero until the image is fixed:

```bash
kubectl scale deployment <deployment-name> -n "$NAMESPACE" --replicas=0
```

**2. Address the root cause.**

- For application vulnerability: deploy the patched application code.
- For dependency vulnerability: update the dependency in the application; rebuild the image.
- For base image vulnerability: rebuild from a patched base image.
- For supply-chain compromise: remove the malicious dependency; rebuild.
- For CI compromise: rotate the CI credentials; review CI pipeline integrity.
- For credential compromise: complete [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) in parallel.

**3. Rotate any secrets the pod could have accessed.**

The Kubernetes Secrets mounted into the pod must be assumed compromised. Rotate the underlying credentials:
- Database passwords: rotate via the database's password-change procedure.
- Third-party API keys: rotate via the third-party's console / API.
- TLS private keys: re-issue.

**4. Audit other workloads using the same image.**

If the compromise was image-level (vectors 3-5), every pod using the same image is potentially compromised. Identify the affected pods:

```bash
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | \
  grep "$COMPROMISED_IMAGE"
```

For each affected pod, repeat the runbook (or apply the patched image to its deployment).

**5. Remove any persistence the attacker established.**

- New cluster-level resources (ClusterRoles, ClusterRoleBindings, custom resources) created by the attacker.
- New IAM principals or policies created if the pod's role had IAM permissions.
- Backdoors in code, configuration, or persistent volumes.

The persistence-removal step is where the forensic catalogue from Step 4 is exercised.

---

## Step 7 — Recover (target: 30 minutes)

Restore the legitimate workload with the patched configuration.

**1. Deploy the patched image.**

```bash
kubectl set image deployment/<deployment-name> \
  -n "$NAMESPACE" \
  <container-name>=<registry>/<image>:<patched-tag>
```

Wait for the rollout to complete:

```bash
kubectl rollout status deployment/<deployment-name> -n "$NAMESPACE"
```

**2. Scale the deployment back to its normal replica count.**

```bash
kubectl scale deployment <deployment-name> -n "$NAMESPACE" --replicas=3
```

**3. Verify the application is functioning normally.**

Integration tests, smoke tests, and a manual check of the application's primary user flows. The recovery is not complete until the application is fully operational.

**4. Verify the runtime alerts are now quiet.**

Falco / Tetragon / GuardDuty should not be firing on the new pods. Watch the alert channels for 15-30 minutes; absence of alerts is the recovery signal.

---

## Step 8 — Communicate

The communication matrix:

| Audience | Trigger | Channel | Timing |
| --- | --- | --- | --- |
| Internal: incident channel | Always | Slack / IR channel | At alert verification |
| Internal: security leadership | Confirmed compromise (any scope) | Direct + page | Immediately |
| Internal: legal | Customer data exposure | Direct + page | If data exposure confirmed |
| Internal: executive | Production impact OR significant scope | Email + meeting | Within 1 hour |
| Affected customers | Customer-data exposure confirmed OR service disruption | Per customer-notification policy | Per regulation OR SLA |
| Regulators | Per the applicable regulation | Per regulatory timeline | As applicable |
| Image / dependency maintainer | If a CVE was exploited | Coordinated disclosure | Per CVE handling policy |
| AWS Support | If AWS infrastructure misbehavior contributed | AWS Support case | As needed |

The image-maintainer communication is sometimes overlooked: if the pod was compromised via a known-but-unpatched CVE in a public image or dependency, the maintainer benefits from the report (other consumers of the image are at risk).

---

## Step 9 — Post-incident review

**Standard PIR questions:**

1. **How was the pod compromised?** The specific vulnerability or vector.
2. **Why did the image scanner not catch the vulnerability before deployment?** Image-scanning gap analysis.
3. **Why did admission control not reject the image?** If image signing is required, was the policy enforced?
4. **Why did runtime detection not fire earlier?** Falco / Tetragon / GuardDuty timing analysis.
5. **How long was the pod compromised before detection?**
6. **How long from detection to containment?** Target: under 20 minutes.
7. **What was the blast radius?** AWS resources, other pods, secrets, data.
8. **What is the broader exposure?** Other pods using the same image, other workloads with the same vulnerability class.
9. **What changes prevent recurrence?**

**Standard prevention-recurrence actions:**

- **Image-scanning improvements.** Stricter Trivy / Grype policies; CVE-severity thresholds.
- **Admission policy improvements.** Require Cosign-signed images; require SLSA provenance attestation; require non-root user.
- **NetworkPolicy improvements.** Tighter default-deny; explicit egress allowlists per workload.
- **Pod Security Admission improvements.** Move from `baseline` to `restricted`; remove privileged-pod exemptions.
- **Runtime detection improvements.** Falco rule additions; Tetragon policy tightening.
- **Image-supply-chain improvements.** Pin dependency versions; review dependency-update PRs more carefully; adopt SBOM-based monitoring.

The image supply chain is the most-common recurrence vector. A PIR that concludes with image-supply-chain improvements is usually the right outcome.

---

## Worked example: Meridian Health's pod compromise

A condensed example:

**Alert.** 2026-07-15 03:42 UTC. Falco rule `Cryptominer Activity` fires for pod `data-pipeline-9f4b6c2d-mxhqz` in namespace `meridian-data`. GuardDuty also fires `CryptoCurrency:EC2/BitcoinTool.B!DNS` against the underlying EKS node.

**Step 1 (03:43 UTC).** Responder confirms: the pod is running an XMRig cryptominer process. The pod's logs show the application started normally; the cryptominer was launched 18 minutes after pod start.

**Step 2 (03:48 UTC).** Responder applies the NetworkPolicy isolation. Verified — the pod can no longer egress.

**Step 3 (04:03 UTC).** Forensic preservation: `kubectl debug` captures the container filesystem. The miner binary is at `/tmp/.xmrig`. EBS volumes snapshotted. The cluster audit log shows the pod made no apiserver calls.

**Step 4 (04:35 UTC).** Scope analysis: the pod's IRSA role had only S3 read access on the data pipeline's input bucket. No AWS API calls were made beyond the legitimate pipeline operations. The pod connected only to its expected dependencies and to two known mining-pool IPs. No lateral movement detected.

**Step 5 (05:35 UTC).** Root cause: the application image was built from a base image (`python:3.11-slim`) two months ago. A CVE in `libxml2` (the base image's version) was exploited via the application's XML parsing functionality when the application processed an attacker-crafted XML upload. The XML was uploaded via the data pipeline's normal ingestion endpoint by an authenticated user whose credentials were apparently compromised — the upload originated from an unknown geography for that user.

**Step 6 (06:05 UTC).** Eradicate: image rebuilt from a patched `python:3.11-slim` (libxml2 CVE patched). User credentials for the suspected compromised user rotated. Forensic findings show no successful escape from the container — the cryptominer was the only persistence achieved.

**Step 7 (06:35 UTC).** Recovery: patched image deployed; data pipeline back to normal operation by 06:50 UTC.

**Step 8 (07:00 UTC).** Communication: internal incident channel, security leadership, the affected user's customer-success team (the user's credentials were rotated). No data exposure occurred; no customer notification required.

**Step 9 (within 5 days).** PIR identifies:
- Base image vulnerability scanning was running but with a 7-day re-scan cadence; the libxml2 CVE was published 4 days before the incident. Scan cadence tightened to daily.
- Admission policy did not require image signing; signing was a nice-to-have but unenforced. Cosign-signing requirement promoted to enforced.
- The user's credential compromise indicates a broader issue (the user's environment may have been compromised); the security team engages the customer-success team to support the user's full security review.
- Runtime detection time (alert at minute 18 from pod-start) was acceptable but could be faster; Falco rule for mining-process patterns added.

The incident resolved without external impact. The PIR drove three structural improvements.

---

## Pre-incident preparation

The runbook depends on:

1. **EKS audit logging enabled** in the cluster's logging configuration.
2. **GuardDuty EKS Protection enabled** in every EKS-running region.
3. **Falco or Tetragon deployed** as a DaemonSet with rule coverage for the cluster's threat model.
4. **NetworkPolicy default-deny** in every namespace (so the isolation policy is additive to existing policies).
5. **Image scanning** in CI; CVE-severity policies that block known-bad images.
6. **Image signing** via Cosign / Sigstore; admission policy requires signed images.
7. **The `kubectl debug` tool** available; the platform team has practiced its use.
8. **Forensic-evidence bucket** in LogArchive (or a dedicated forensic account) with appropriate Object Lock.
9. **Quarterly tabletop exercises** against the pod-compromise scenario.

---

## Azure AKS / GCP GKE equivalent

The runbook patterns apply to AKS and GKE with platform-specific substitutions:

| AWS / EKS | Azure / AKS | GCP / GKE |
| --- | --- | --- |
| GuardDuty EKS Protection | Microsoft Defender for Containers | Security Command Center / GKE Security Posture |
| CloudTrail | Activity Logs | Cloud Audit Logs |
| EBS snapshots | Managed Disk snapshots | Persistent Disk snapshots |
| IRSA / Pod Identity | Workload Identity | Workload Identity |
| `kubectl debug` | Same (kubernetes-native) | Same |
| Falco / Tetragon | Same (kubernetes-native) | Same |

The structure (verify → contain → preserve → scope → forensic → eradicate → recover → communicate → PIR) is identical.

---

## Further reading

- [GuardDuty EKS Protection](https://docs.aws.amazon.com/guardduty/latest/ug/kubernetes-protection.html)
- [Kubernetes audit logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Falco runtime security](https://falco.org/)
- [Tetragon runtime observability](https://tetragon.io/)
- [kubectl debug](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/#ephemeral-container)
- [Cosign / Sigstore image signing](https://www.sigstore.dev/)
- This repo:
  - [log-architecture.md](./log-architecture.md) — the EKS audit log pipeline.
  - [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) — if the compromise was via credential.
  - [../kubernetes-and-container-security/](../kubernetes-and-container-security/) — the pre-incident hardening patterns.
  - [../identity-and-access/least-privilege-workflow.md](../identity-and-access/least-privilege-workflow.md) — the IRSA role-tightening that bounds the blast radius.
