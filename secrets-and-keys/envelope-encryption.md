# Envelope Encryption

A practitioner's reference for envelope encryption patterns in cloud applications — data key generation, data key caching, multi-region key materials, the AWS Encryption SDK / Google Tink / age-as-CLI patterns, and the decision tree for when to use the cloud KMS directly versus through an SDK abstraction. The patterns here are operational; the cryptographic primitives are well-understood.

This document picks up where [../data-security/kms-strategy.md](../data-security/kms-strategy.md) leaves off. The KMS hierarchy and master-key strategy are settled; the question is how applications actually perform encryption operations. The envelope-encryption pattern (encrypt data with a data key; encrypt the data key with the master key; ship the wrapped data key with the encrypted data) is the dominant pattern for any non-trivial-size data; this document is the operational depth on it.

For the master-key strategy this builds on, see [../data-security/kms-strategy.md](../data-security/kms-strategy.md). For the BYOK / HYOK decisions that affect where envelope encryption fits, see [../data-security/byok-hyok-cmk.md](../data-security/byok-hyok-cmk.md). For application-layer encryption via a service (Vault transit engine), see [vault-patterns.md](./vault-patterns.md).

---

## When to read this document

**If your application encrypts data and the team has not made the encrypt-via-KMS-directly vs encrypt-via-SDK decision** — read top to bottom. The choice has performance, complexity, and security implications.

**If your application's encryption operations are showing up as a KMS cost line** — start with [Data key caching](#data-key-caching). Envelope encryption with proper caching keeps KMS calls bounded; without caching, the cost compounds with traffic.

**If you are implementing client-side encryption for cross-region data** — start with [Multi-region envelope encryption](#multi-region-envelope-encryption). The KMS multi-region keys + Encryption SDK pattern is the cleanest.

**If you are auditing application-layer encryption** — start with [Findings checklist](#findings-checklist). The common findings (no key rotation, no data-key caching, plaintext data keys in logs) recur in environments that built their own encryption rather than using an SDK.

---

## The envelope-encryption pattern

The pattern that almost every production data encryption uses, often without the team realizing.

### The mechanics

1. **Application has data to encrypt.** A document, a file, a database column, a streaming event payload.
2. **Application requests a data key from KMS.** `kms:GenerateDataKey` returns:
   - A plaintext data key (e.g., 256-bit AES key).
   - The same data key encrypted by the master key.
3. **Application encrypts the data** locally using the plaintext data key (AES-GCM is the standard).
4. **Application stores the encrypted data alongside the encrypted data key.** The plaintext data key is discarded from memory.
5. **For decryption,** application calls KMS to decrypt the encrypted data key; uses the resulting plaintext data key to decrypt the data; discards the plaintext key.

The pattern shifts the expensive operation (KMS API call) from per-byte to per-encryption-batch. The local encryption (AES-GCM) is fast (gigabytes per second on modern hardware); KMS is the bottleneck only at the key-issuance point.

### Why not just call KMS to encrypt everything

KMS `Encrypt` and `Decrypt` APIs work directly on data — no envelope. But:

- **Size limit.** AWS KMS `Encrypt` accepts a maximum payload of ~4 KB. Larger payloads require envelope.
- **Cost.** Direct KMS encrypt is per-API-call; envelope is one call per batch.
- **Latency.** Direct KMS is a network round-trip per encryption; envelope is one round-trip per batch.

For small payloads (configuration values, individual secrets), direct KMS encrypt is fine. For anything larger or higher-volume, envelope is the right pattern.

### The vendor-provided SDKs

Implementing envelope encryption by hand is error-prone. The cloud-provider and Google SDKs do it correctly:

- **AWS Encryption SDK** — handles envelope encryption with AWS KMS; supports keyrings (multi-key, multi-region patterns); language bindings for Python, Java, Go, JavaScript, C/C++, .NET.
- **Google Tink** — cross-cloud cryptographic library; supports envelope encryption with AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault, and other backends.
- **age** (`age-encryption.org`) — CLI tool and library for envelope encryption with various recipient types; conceptually similar to GPG but simpler.

The recommendation: **use an SDK**. The probability of writing correct envelope encryption from primitives is low; the probability of using the SDK correctly is high.

---

## When to use which SDK

| SDK | Best when | Avoid when |
| --- | --- | --- |
| **AWS Encryption SDK** | Single-cloud AWS environments; deep integration with AWS KMS multi-region keys, keyrings. | Multi-cloud or non-cloud environments. |
| **Google Tink** | Multi-cloud environments; want one library across AWS / Azure / GCP / Vault. Strong cryptographic primitives. | Niche cloud KMS that Tink doesn't support. |
| **age** | CLI use cases (file encryption, backup encryption, transferring files between systems); recipient-list use cases (encrypt to multiple recipients without per-recipient encryption). | Application-runtime use cases (Tink is the better choice for that). |
| **Direct KMS API** | Small data (< 4 KB); low-volume encryption (rare); when SDK overhead is undesirable. | Anything else. |

For most application-runtime envelope encryption: **AWS Encryption SDK** (AWS-only) or **Google Tink** (multi-cloud). The SDKs handle key derivation, IV generation, authenticated encryption — the cryptographic details that hand-rolled code gets wrong.

### A minimal Tink example (cross-cloud)

```python
import tink
from tink import aead
from tink.integration import awskms

aead.register()

# Register the AWS KMS keyring
kms_uri = "aws-kms://arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID"
client = awskms.AwsKmsClient(kms_uri, "")
tink.register_kms_client(client)

# Encrypt
keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
aead_primitive = keyset_handle.primitive(aead.Aead)
ciphertext = aead_primitive.encrypt(plaintext=b"sensitive data", associated_data=b"context")

# Decrypt
plaintext = aead_primitive.decrypt(ciphertext=ciphertext, associated_data=b"context")
```

The same code works against Azure Key Vault or GCP KMS by changing the keyring URI.

### A minimal AWS Encryption SDK example

```python
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

client = aws_encryption_sdk.EncryptionSDKClient(
    commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(
    key_ids=["arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID"]
)

ciphertext, encryptor_header = client.encrypt(
    source=b"sensitive data",
    key_provider=key_provider,
    encryption_context={"workload": "care-coordinator", "field": "phi"}
)

plaintext, decryptor_header = client.decrypt(
    source=ciphertext,
    key_provider=key_provider
)
```

The encryption context is a critical pattern — it's authenticated additional data (AAD); it must match between encrypt and decrypt. The pattern lets the application bind decryption to a specific context (workload, tenant, purpose); a key compromise still cannot decrypt across contexts without matching the AAD.

References:
- [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html)
- [Google Tink](https://developers.google.com/tink)
- [age](https://age-encryption.org/)

---

## Data key caching

The single most-impactful operational pattern. Envelope encryption without caching is slow and expensive; with caching, it's fast and cheap.

### Without caching

Every encrypt operation calls KMS for a new data key. For a workload doing 1000 encryptions per second:

- 1000 KMS API calls per second.
- KMS rate limits: typically 5,500–10,000 per second per region (varies by account).
- Cost: 1000 calls/sec × 86,400 sec/day × $0.03/10,000 calls = ~$259/day per workload.

The latency is also high — every encryption pays the KMS round-trip.

### With caching

The application keeps a data key cache:

- First encrypt: KMS call returns a data key; cache it.
- Subsequent encrypts (within cache TTL or batch limit): use the cached data key.
- Periodic refresh: KMS call returns a new data key; replace the cached one.

For the same 1000 enc/sec workload with a 5-minute or 1000-message cache:

- ~3 KMS calls per second (one per cache refresh).
- Cost reduction: ~99.7%.
- Latency reduction: encryption operations are local AES-GCM (microseconds), not KMS round-trips (tens of milliseconds).

### The AWS Encryption SDK data key cache

```python
from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager

# Cache configuration
cache = LocalCryptoMaterialsCache(capacity=100)

caching_manager = CachingCryptoMaterialsManager(
    master_key_provider=key_provider,
    cache=cache,
    max_age=300.0,                 # 5 minutes
    max_messages_encrypted=1000,   # up to 1000 messages per data key
    max_bytes_encrypted=10**9,     # up to 1 GB per data key
)

ciphertext, _ = client.encrypt(
    source=data,
    materials_manager=caching_manager,
    encryption_context={"workload": "care-coordinator"}
)
```

The cache parameters:

- `max_age`: time-based TTL.
- `max_messages_encrypted`: limit on data key reuse count.
- `max_bytes_encrypted`: limit on bytes encrypted with one data key.

The reuse limits matter for security — reusing a data key indefinitely weakens the security guarantee (collision risk for AES-GCM at very high message counts). The SDK enforces sensible defaults; tune for your throughput.

### Cache invalidation considerations

The cache invalidates on:

- **Time expiration** (`max_age` reached).
- **Message count limit** (`max_messages_encrypted` reached).
- **Byte limit** (`max_bytes_encrypted` reached).
- **Encryption context change** (different context = different cache entry).

The encryption context is the cache key. Different contexts get different cached data keys; a workload encrypting for multiple tenants gets per-tenant cache entries (which is correct — you don't want to share data keys across tenants).

### Cache storage

- **In-process** (default): the cache is per-application-process. Restarts lose the cache.
- **Local disk** (some SDKs): persist across restarts. Useful for fast restart in some workloads.
- **Distributed** (rare): cache shared across instances. Generally not recommended; complicates the cryptographic guarantees.

In-process is the right default for most workloads.

---

## Multi-region envelope encryption

For data that needs to be decryptable across multiple regions (cross-region replication, DR scenarios, global applications), the multi-region pattern.

### AWS multi-region keys

A multi-region CMK (per [../data-security/kms-strategy.md](../data-security/kms-strategy.md)) has a primary in one region with replicas in others. All replicas share the same key material; encrypted ciphertext from one region decrypts in another.

The AWS Encryption SDK natively supports multi-region keys:

```python
key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(
    key_ids=[
        "arn:aws:kms:us-east-1:ACCOUNT:key/MULTI-REGION-KEY-ID",
    ]
)
```

The SDK can decrypt in any region where a replica exists.

### Multi-keyring patterns (Tink, AWS Encryption SDK)

For multi-cloud or multi-key patterns:

- **Multi-keyring** encrypts the data key with multiple master keys.
- A single ciphertext can be decrypted by any of the configured keys.
- Use case: cross-cloud DR (encrypt with AWS + GCP key; decrypt with either).

The pattern adds storage overhead (each encrypted data key takes space) but provides redundancy.

### The cross-cloud encryption example

For a workload that needs to be decryptable on both AWS and GCP:

```python
# Tink multi-keyring approach
import tink
from tink import aead
from tink.integration import awskms, gcpkms

aead.register()
awskms.AwsKmsClient.register_client("aws-kms://arn:aws:kms:us-east-1:...", "")
gcpkms.GcpKmsClient.register_client("gcp-kms://projects/PROJECT/locations/.../keys/KEY", "")

# A keyset with both keys
# Encrypted ciphertext can be decrypted by either
```

The pattern is rare but useful for specific cross-cloud DR scenarios.

---

## Encryption context (AAD) patterns

Authenticated Additional Data is a critical security pattern in envelope encryption.

### What encryption context provides

- The context is passed to the encrypt operation.
- The context becomes part of the AEAD (Authenticated Encryption with Associated Data) authenticity tag.
- Decryption requires the same context; mismatched context fails authentication.

The benefit: encryption is **bound to a context**. A data key compromised in one context (e.g., workload A's per-tenant key for tenant 1) cannot decrypt data from another context (workload A's data for tenant 2) even if the underlying key material is the same.

### Common context patterns

```python
encryption_context = {
    "workload": "care-coordinator",
    "environment": "prod",
    "data_class": "phi",
    "tenant_id": "hospital_a",
    "record_id": "12345",
}
```

The context is plaintext (it's not encrypted); it's stored alongside the ciphertext or derivable from the data's location.

### Why context matters

A workload encrypts a million records. Each record has its tenant ID in the encryption context. An attacker who compromises one tenant's decryption capability cannot decrypt other tenants' records — the context mismatch fails authentication, even though the underlying KMS key is the same.

The pattern is "tenant-scoped decryption with a shared master key." Useful when per-tenant master keys would be operationally expensive.

### Context discipline

- **Document the context schema** per encryption operation.
- **Consistent context shape** across encrypt and decrypt; mismatches fail.
- **Don't put secrets in the context** — it's plaintext.
- **Bind context to the data** — record_id, file path, tenant ID, purpose, anything that distinguishes the data's intended use.

---

## age for CLI / backup use cases

The CLI tool and library for envelope encryption.

### What age is

`age` is a modern encryption tool (like GPG but simpler). Use cases:

- **Encrypt files for transfer** between systems.
- **Encrypt backups** with multiple recipient keys (encrypt to all team members; any can decrypt).
- **Pipeline encryption** — `cat data.txt | age -r RECIPIENT > data.age`.

age supports recipients of various types:

- **X25519 keys** (default; generate with `age-keygen`).
- **SSH keys** (use existing SSH keys as encryption keys).
- **Plugins for KMS** (`age-plugin-yubikey`, `age-plugin-tpm`, AWS KMS plugin, etc.).

### When age fits

- **File-at-rest encryption** with manual workflow.
- **Backup encryption** where the recipient set is humans, not services.
- **Cross-system file transfer** where TLS isn't the right primitive.

### When age does not fit

- **Application-runtime encryption** (Tink or AWS Encryption SDK is the right choice).
- **High-throughput** workloads (age is designed for batch / CLI use, not throughput).

For most cloud workloads, age is a complementary tool for specific use cases, not the primary application-encryption library.

---

## Worked example: Meridian Health's envelope encryption

Meridian's Care Coordinator workload uses AWS Encryption SDK with data key caching and multi-region keys for cross-region replicated PHI data.

### The configuration

- **Multi-region CMK** `mrk-care-coordinator-prod-phi` (primary in `us-east-1`; replicas in `us-west-2`, `eu-central-1`, `eu-west-1`).
- **AWS Encryption SDK** in every workload that encrypts PHI.
- **Data key cache** with 5-minute TTL, 1000-message limit, 1 GB byte limit.
- **Encryption context** includes `workload`, `environment`, `data_class`, `tenant_id`, `record_id`.

### Application code pattern

```python
class PHIEncryptor:
    def __init__(self):
        self.client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
        )
        self.key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(
            key_ids=["arn:aws:kms:us-east-1:ACCOUNT:key/mrk-care-coordinator-prod-phi"]
        )
        cache = LocalCryptoMaterialsCache(capacity=100)
        self.materials_manager = CachingCryptoMaterialsManager(
            master_key_provider=self.key_provider,
            cache=cache,
            max_age=300.0,
            max_messages_encrypted=1000,
        )

    def encrypt_phi(self, plaintext, tenant_id, record_id):
        encryption_context = {
            "workload": "care-coordinator",
            "environment": "prod",
            "data_class": "phi",
            "tenant_id": tenant_id,
            "record_id": record_id,
        }
        ciphertext, _ = self.client.encrypt(
            source=plaintext,
            materials_manager=self.materials_manager,
            encryption_context=encryption_context
        )
        return ciphertext

    def decrypt_phi(self, ciphertext, tenant_id, record_id):
        expected_context = {
            "workload": "care-coordinator",
            "environment": "prod",
            "data_class": "phi",
            "tenant_id": tenant_id,
            "record_id": record_id,
        }
        plaintext, header = self.client.decrypt(
            source=ciphertext,
            materials_manager=self.materials_manager
        )
        # Verify the encryption context matches expected
        if header.encryption_context != expected_context:
            raise ValueError("Encryption context mismatch")
        return plaintext
```

The encryption context binding ensures tenant_id A's data cannot be decrypted by passing tenant_id B (even with the same key — the AAD authentication fails).

### Cross-region pattern

Data encrypted in `us-east-1` and replicated to `us-west-2` (via S3 cross-region replication) is decryptable in `us-west-2` because the multi-region key replica has the same key material. No re-encryption needed.

### KMS cost impact

Pre-caching: ~50K KMS calls per hour on the PHI workload. Post-caching: ~1K KMS calls per hour. Cost reduction: ~98%. Latency reduction: encryption is now microseconds (local AES-GCM) instead of milliseconds (KMS round-trip).

### age for backup encryption

For one-off backups (database export to S3 for retention, for example), Meridian uses age with the team's SSH keys as recipients:

```bash
pg_dump care_coordinator | age -R team-recipients.txt > care_coordinator_export.sql.age
```

Any team member listed in `team-recipients.txt` can decrypt with their SSH key. The pattern is appropriate for ad-hoc exports; production backups go through the structured backup pipeline ([../data-security/backup-and-data-residency.md](../data-security/backup-and-data-residency.md)).

### Findings opened during the encryption audit

- **ENV-001** (Care Coordinator was using direct KMS `Encrypt` for PHI records; rate-limit issues at peak). Closed by migration to Encryption SDK with caching.
- **ENV-002** (no encryption context on encrypt operations; cross-tenant decryption was theoretically possible). Closed by adding tenant-scoped context binding.
- **ENV-003** (the analytics workload was using AWS SDK's `kms.encrypt` directly without envelope pattern; large payloads were being broken into chunks manually). Closed by migration to Encryption SDK.
- **ENV-004** (data key cache TTL was 1 hour; rotation took 1 hour to propagate to encryption operations). Closed by reducing TTL to 5 minutes to align with rotation cadence.
- **ENV-005** (ad-hoc database exports were using OpenSSL encryption with shared passwords). Closed by migration to age with team SSH-key recipients.

---

## Anti-patterns

### 1. The roll-your-own envelope encryption

The team implements envelope encryption from primitives. The implementation has subtle bugs (IV reuse, missing AAD, missing context binding, weak modes). A security review finds the bugs years later.

The fix: use the AWS Encryption SDK, Tink, or age. The cryptography is handled correctly.

### 2. The no-caching envelope encryption

Envelope encryption is in place but every encryption operation calls KMS for a new data key. Cost is high; KMS rate limits are hit; latency is poor.

The fix: data key cache with sensible TTL and reuse limits.

### 3. The over-cached data key

The cache TTL is 24 hours. One data key encrypts millions of messages. Cryptographic guarantees weaken; if the data key is somehow exposed, the blast radius is huge.

The fix: bounded TTL (5 minutes typical), bounded message count (1000 default), bounded byte count.

### 4. The missing encryption context

Encrypt operations don't pass encryption context. The AAD authentication doesn't bind to anything specific; cross-context decryption is possible.

The fix: always include encryption context; bind it to the data's meaningful context (tenant, record, workload).

### 5. The encryption-context mismatch silent fail

Decrypt operation passes a different context than the encrypt operation used. Some SDKs / configurations don't strictly verify; decryption succeeds with wrong context.

The fix: strict context verification. The AWS Encryption SDK enforces; the application explicitly verifies the context in the returned header.

### 6. The plaintext data key in logs

Application logs the data key for debugging. The log archive now contains plaintext encryption keys.

The fix: never log key material; redact in logging frameworks; verify with log-archive scanning.

### 7. The cross-region encryption failure

Data is encrypted in `us-east-1` with a single-region key. Cross-region replication copies the ciphertext to `us-west-2`. Decryption in `us-west-2` fails because the key isn't accessible.

The fix: multi-region keys for cross-region replicated data; or per-region keys with re-encryption at replication.

### 8. The over-engineered cross-cloud encryption

The team uses Tink with a multi-keyring across AWS, Azure, and GCP for data that only lives in AWS. The complexity is unjustified.

The fix: match SDK complexity to the actual cross-cloud requirement. Single-cloud applications use the cloud-native SDK.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| ENV-001 | Application uses direct KMS `Encrypt`/`Decrypt` for large payloads or high volume | Medium | Migrate to envelope encryption via AWS Encryption SDK / Tink | Workload Owner + Platform Eng |
| ENV-002 | Envelope encryption rolled-from-primitives rather than via SDK | High | Migrate to AWS Encryption SDK / Tink / age; deprecate custom code | Workload Owner + Security Eng |
| ENV-003 | No data key cache; KMS calls per encryption operation | Medium | Add data-key cache with TTL, message count, byte count limits | Workload Owner + Platform Eng |
| ENV-004 | Data key cache TTL too long; rotation latency too high | Medium | Reduce TTL to align with rotation cadence (typically 5–15 min) | Security Eng + Workload Owner |
| ENV-005 | Encrypt operation does not pass encryption context | High | Add encryption context bound to data's meaningful identifiers (tenant, record, workload) | Security Eng + Workload Owner |
| ENV-006 | Decrypt operation does not verify the encryption context matches expected | High | Strict context verification; application checks header.encryption_context | Workload Owner + Security Eng |
| ENV-007 | Plaintext data keys logged or echoed by application | High | Redact key material in logs; verify with log-archive scanning | Workload Owner + Security Eng |
| ENV-008 | Cross-region replicated data encrypted with single-region key | High | Migrate to multi-region keys or re-encrypt at replication | Platform Eng + Security Eng |
| ENV-009 | Multi-cloud encryption (Tink multi-keyring) used where single-cloud SDK would suffice | Low | Simplify to cloud-native SDK; multi-cloud only where DR / portability requires | Architecture + Security Eng |
| ENV-010 | Encryption context schema undocumented; engineers add fields inconsistently | Low | Document per encryption operation; enforce in code | Security Eng + Workload Owner |
| ENV-011 | Data key reuse limits not configured; default may be too permissive | Medium | Set explicit `max_messages_encrypted`, `max_bytes_encrypted`; align with throughput | Security Eng |
| ENV-012 | AWS Encryption SDK commitment policy is permissive (`FORBID_ENCRYPT_ALLOW_DECRYPT`) | Medium | Migrate to `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` for new code | Security Eng + Workload Owner |
| ENV-013 | age / gpg used for production workload-runtime encryption | Medium | Migrate to Tink / Encryption SDK for runtime; age for CLI / backup use only | Workload Owner + Security Eng |
| ENV-014 | SDK version pinning absent; encryption library updates not tracked | Low | Pin SDK version; track CVEs; quarterly updates | Workload Owner + DevOps |
| ENV-015 | Old encrypted data uses deprecated algorithm; not re-encrypted | Low | Migration plan for legacy ciphertext; envelope to current algorithm | Workload Owner + Security Eng |
| ENV-016 | KMS API rate-limit issues during peak; envelope caching not in place | High | Implement caching; size for peak; consider per-tenant cache scoping | Platform Eng + Workload Owner |
| ENV-017 | Cross-tenant data shares data key cache; key reuse across tenants | Medium | Per-tenant encryption context; SDK cache keys on context so per-tenant cache entries | Security Eng + Workload Owner |
| ENV-018 | Encryption performance not measured; bottleneck unclear | Low | Benchmark encryption / decryption; size cache; identify hot paths | Performance Eng + Workload Owner |

---

## What this document is not

- **A cryptography primer.** AES, GCM, AEAD, key derivation — covered only at the decision-relevant level. For depth, NIST SP 800-38D (GCM specification) is authoritative.
- **A complete SDK reference.** AWS Encryption SDK, Tink, age — their documentation covers the operational depth.
- **A KMS reference.** The KMS hierarchy and master-key strategy live in [../data-security/kms-strategy.md](../data-security/kms-strategy.md).
- **A Vault transit-engine guide.** Application-as-a-service encryption via Vault transit is mentioned in [vault-patterns.md](./vault-patterns.md); this document is client-side envelope encryption with cloud KMS.
