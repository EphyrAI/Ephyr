# Task-Scoped Portable Identity for AI Agents

**Ephyr v0.2 Whitepaper**

*March 2026*

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [The Problem](#2-the-problem)
3. [Design Principles](#3-design-principles)
4. [Trust Architecture](#4-trust-architecture)
5. [Token Design](#5-token-design)
6. [Identity Scheme](#6-identity-scheme)
7. [Revocation Model](#7-revocation-model)
8. [Capability Envelopes](#8-capability-envelopes)
9. [Validation](#9-validation)
10. [Performance Analysis](#10-performance-analysis)
11. [Integration Test Results](#11-integration-test-results)
12. [Comparison with Existing Approaches](#12-comparison-with-existing-approaches)
13. [Roadmap](#13-roadmap)
14. [Conclusion](#14-conclusion)

---

## 1. Abstract

As AI agents move from single-turn API consumers to multi-step infrastructure
operators, the identity systems we use to govern their access have not kept
pace. Agents today authenticate as coarse-grained service accounts or API key
holders, with no concept of a discrete "task run" as a security boundary.
Ephyr v0.2 introduces **task-scoped portable identity** as a first-class
primitive: each agent task receives a cryptographically signed token (CTT-E)
that carries a ULID-based task identifier, a capability envelope constraining
what the task may do, and a lineage chain that enables hierarchical revocation
without per-token blocklists. The system is built on a three-tier Ed25519
trust model with delegation certificates, epoch watermark revocation, and
monotonic capability attenuation -- all implemented in ~3,500 lines of Go with
zero external cryptographic dependencies beyond the standard library. This
paper describes the design, rationale, implementation, and measured performance
of the task identity system, and situates it against existing approaches to
workload identity.

---

## 2. The Problem

### 2.1 The Agent Identity Gap

Modern AI agents -- LLM-based systems that plan and execute multi-step tasks
across infrastructure -- operate in an identity vacuum. Consider the typical
access pattern:

```
Agent Service Account ---[API Key]---> Infrastructure
                                       - SSH hosts
                                       - HTTP services
                                       - Databases
                                       - Other agents
```

The API key authenticates the agent *service*, not the agent *task*. Every
request the agent makes, across every task it runs, carries the same identity.
This creates four concrete security failures.

### 2.2 Failure 1: No Blast Radius Containment

When an agent is compromised -- through prompt injection, tool abuse, or a
vulnerability in the agent framework -- the attacker inherits the full
permissions of the agent's service account. There is no way to limit damage to
the specific task that was compromised.

**Scenario:** An LLM agent running a monitoring task gets prompt-injected via
a crafted log message. The attacker can now use the agent's credentials to
SSH into production hosts, make HTTP requests to internal services, and
interact with every system the agent has ever been authorized to touch.
The monitoring task needed read access to Grafana; the attacker gets
write access to everything.

### 2.3 Failure 2: No Audit Correlation

When an agent runs five concurrent tasks, the audit log shows five
interleaved streams of actions under a single identity. Reconstructing which
action belonged to which task requires heuristic timestamp correlation --
fragile, error-prone, and often impossible when tasks overlap in time and
target.

**Scenario:** A post-incident review reveals that an agent deleted a
production database record. The audit log shows the agent's API key made
the request. But the agent was running three tasks concurrently: a data
migration, a cleanup job, and a reporting task. Which one caused the
deletion? Without task-level identity, the answer requires manual
forensics.

### 2.4 Failure 3: No Delegation Control

When agent A spawns agent B to handle a subtask, agent B typically receives
either (a) the same credentials as agent A, or (b) its own independent
credentials that are unrelated to the parent task. Neither is correct. The
child should receive credentials that are (i) scoped to a subset of the
parent's permissions and (ii) traceable back to the parent task that spawned
it.

**Scenario:** An orchestrator agent delegates a "check server health" subtask
to a worker agent. The worker receives the orchestrator's full credentials
because there is no delegation primitive. The worker -- a simpler, less
audited model -- now has permissions far exceeding what the health check
requires.

### 2.5 Failure 4: No Targeted Revocation

When a specific task must be stopped -- because it is misbehaving, because
the user changed their mind, or because a security event was detected -- the
only option is to revoke the agent's entire API key. This kills all tasks,
including those that are operating correctly.

**Scenario:** An agent is running a 30-minute deployment task and a 5-minute
audit task concurrently. The deployment task hits an error loop and starts
making thousands of failing SSH requests. To stop it, the operator must
revoke the agent's API key, which also kills the audit task. There is no
way to surgically revoke the deployment task alone.

### 2.6 The Root Cause

These failures share a root cause: **identity is bound to the agent, not the
task**. Service accounts, API keys, OAuth2 client credentials, and even
SPIFFE workload identities all operate at the workload or service level. None
of them model the concept of a discrete task run as an identity boundary.

This is the gap Ephyr v0.2 fills.

---

## 3. Design Principles

The task identity system is governed by five principles that constrain every
design decision.

### 3.1 Task as Identity Unit

The fundamental unit of identity is the *task*, not the agent. An agent may
run many tasks; each task is a separate security principal with its own
identifier, capabilities, lifetime, and revocation status. Actions are
attributed to tasks, not agents. Audit logs correlate to tasks, not agents.
Revocation targets tasks, not agents.

### 3.2 Monotonic Attenuation

Capabilities can only decrease as they flow from parent to child. A child
task's capability envelope must be a subset of (or equal to) its parent's
envelope. This is enforced cryptographically: the `IsSubsetOf` check runs
at delegation time, before the child token is signed. There is no mechanism
to escalate privileges through delegation.

### 3.3 Lineage-Aware Audit

Every task carries its full lineage: the chain of task IDs from the root
task down to itself. This enables:

- **Correlation:** All actions by a task or any of its descendants can be
  queried by root task ID.
- **Blame attribution:** For any action, the exact task and its full
  ancestry are known.
- **Cascading operations:** Revoking a task automatically invalidates
  all descendants, because validation walks the lineage chain.

### 3.4 Zero External Dependencies

The cryptographic stack uses only the Go standard library (`crypto/ed25519`,
`crypto/rand`, `crypto/sha256`, `encoding/json`) and `golang.org/x/crypto`
for SSH certificate signing and bcrypt. There are no external JWT libraries,
no JOSE frameworks, no Protocol Buffer dependencies. The ULID implementation
is written from scratch. This is a deliberate choice: every line of
security-critical code is auditable in the repository.

### 3.5 Graceful Degradation

The task identity system is additive. Agents that do not use task tokens
continue to work exactly as before -- the system falls back to API key
authentication with full agent-level permissions. This ensures that deploying
task identity is a progressive enhancement, not a breaking change. The broker
detects at startup whether the signer supports delegation; if it does not,
task tools are simply not registered.

---

## 4. Trust Architecture

### 4.1 Three-Tier Model

Ephyr separates key custody, policy enforcement, and agent interaction into
three tiers:

```
+--------------------------------------------------------------------+
|                        TIER 1: ROOT CA                             |
|                                                                    |
|  +--------------------+                                            |
|  |   ephyr-signer    |  Holds Ed25519 root private key            |
|  |                    |  Signs SSH certificates                    |
|  |  /etc/ephyr/ca_key|  Signs delegation certificates             |
|  +--------+-----------+  Exposes Unix socket IPC only              |
|           |                                                        |
|     Unix socket                                                    |
|     /run/ephyr/signer.sock                                        |
|           |                                                        |
+-----------|--------------------------------------------------------+
            |
+-----------|--------------------------------------------------------+
|           v             TIER 2: BROKER                             |
|  +--------+-----------+                                            |
|  |   ephyr-broker    |  Holds ephemeral Ed25519 signing key       |
|  |                    |  Enforces RBAC policy                      |
|  |  Delegation cert   |  Signs CTT-E tokens locally                |
|  |  rotates every 50m |  Proxies SSH, HTTP, MCP                    |
|  +--------+-----------+  Exposes MCP server (port 8554)            |
|           |              Exposes dashboard (port 8553)             |
|           |                                                        |
+-----------|--------------------------------------------------------+
            |
+-----------|--------------------------------------------------------+
|           v             TIER 3: AGENTS                             |
|  +--------+-----------+                                            |
|  |   AI Agents        |  Authenticate via API key                  |
|  |                    |  Create tasks, receive CTT-E tokens        |
|  |  Claude, GPT, etc. |  Present tokens with each request          |
|  +--------------------+  Never see raw credentials                 |
|                                                                    |
+--------------------------------------------------------------------+
```

### 4.2 Key Custody Guarantees

**Tier 1 (Signer):** The root Ed25519 private key (`/etc/ephyr/ca_key`,
permissions 0600) never leaves the signer process. The signer exposes exactly
four IPC actions over a Unix domain socket: `ping`, `sign` (SSH certs),
`sign_delegation` (delegation certs), and `root_public_key`. The signer has
no network listener. The Unix socket is the only attack surface.

**Tier 2 (Broker):** The broker generates an ephemeral Ed25519 keypair
locally using `crypto/rand` and sends only the public key to the signer.
The signer returns a delegation certificate -- a signed payload binding the
broker's public key to a broker ID, issuance time, and expiry time. The
broker uses its ephemeral private key to sign CTT-E tokens. No IPC round-trip
is needed per token signing; only one round-trip per delegation rotation.

**Tier 3 (Agents):** Agents authenticate via API key (bcrypt-hashed, with
SHA-256 auth cache). They never receive the broker's signing key, the root
key, or any backend credential. They receive opaque CTT-E tokens that they
present with subsequent requests.

### 4.3 Delegation Lifecycle

The delegation cycle ensures the broker always has a valid signing key
without requiring continuous access to the signer:

```
    Broker                              Signer
      |                                   |
      |  1. Generate Ed25519 keypair      |
      |     (pub, priv) = GenerateKey()   |
      |                                   |
      |  2. sign_delegation(pub, id, ttl) |
      |---------------------------------->|
      |                                   |  3. Generate cert ID
      |                                   |  4. Build canonical payload:
      |                                   |     {broker_id, cert_id,
      |                                   |      expires_at, issued_at,
      |                                   |      public_key}
      |                                   |  5. Sign with root private key
      |  6. (cert_id, sig, timestamps,    |
      |      root_pub_key)                |
      |<----------------------------------|
      |                                   |
      |  7. Store: priv + DelegationCert  |
      |  8. Register cert in Validator    |
      |  9. Sign CTT-E tokens locally     |
      |                                   |
      |  ... 50 minutes pass ...          |
      |                                   |
      |  10. Rotation: repeat steps 1-8   |
      |      Move old key to prev slot    |
      |---------------------------------->|
      |<----------------------------------|
      |                                   |
```

**Timing defaults:**

| Parameter     | Default | Purpose                                    |
|---------------|---------|---------------------------------------------|
| Delegation TTL | 1 hour  | Maximum lifetime of a delegation cert       |
| Refresh At    | 50 min  | When to rotate (before expiry)              |
| Max Token TTL | 30 min  | Maximum lifetime of a CTT-E token           |
| Task Max TTL  | 1 hour  | Maximum lifetime of a task                  |

**Key rollover:** On rotation, the old private key is moved to a `prev` slot.
Tokens signed with the old key remain valid (the old delegation cert is still
registered in the validator) until the delegation cert itself expires.

**Failure handling:** If the signer is unavailable during rotation, the broker
logs the error and continues using the existing key. The old key remains valid
until its delegation cert expires. This ensures transient signer outages do
not cause cascading failures.

### 4.4 Why Two Keys?

A simpler design would have the signer sign every CTT-E token directly. This
was rejected for three reasons:

1. **Latency:** Token signing is on the hot path of every agent request.
   Unix socket IPC adds ~1ms per round-trip. With delegation, token signing
   is a local Ed25519 operation: sub-microsecond.

2. **Availability:** The signer is a single point of failure. If it goes
   down, a direct-signing design would halt all agent operations. With
   delegation, the broker can continue signing tokens for the remaining
   lifetime of its delegation cert (up to 1 hour).

3. **Blast radius:** If the broker process is compromised, the attacker gets
   the ephemeral signing key -- valid for at most 1 hour. The root CA key
   remains safe in the signer process. Without delegation, a broker
   compromise would expose the root key.

---

## 5. Token Design

### 5.1 CTT-E Format

CTT-E (Ephyr Task Token -- Execution) is a compact JWT with an EdDSA
signature. The format was chosen for three reasons: compact wire
representation, well-understood validation semantics, and compatibility
with existing JWT tooling for debugging (while not depending on it for
operation).

A CTT-E token is three Base64url-encoded segments separated by dots:

```
<header>.<payload>.<signature>
```

### 5.2 Header

```json
{
  "alg": "EdDSA",
  "typ": "CTT-E",
  "kid": "a3f7b2c1d4e5f6a7b8c9d0e1f2a3b4c5"
}
```

| Field | Type   | Description                                           |
|-------|--------|-------------------------------------------------------|
| `alg` | string | Always `EdDSA` (Ed25519). No algorithm negotiation.   |
| `typ` | string | `CTT-E` for execution tokens, `CTT-D` for delegation (Phase 2b). |
| `kid` | string | Delegation certificate ID. Links the token to the signing key's delegation cert, which chains to the root CA. |

**Algorithm fixed at EdDSA.** There is no algorithm negotiation. The
validator rejects any token with `alg` not equal to `EdDSA`. This
eliminates the entire class of JWT algorithm confusion attacks (e.g.,
`alg: none`, RSA/HMAC confusion).

### 5.3 Payload

```json
{
  "iss": "ephyr:broker-prod-01",
  "sub": "claude-agent",
  "aud": "ephyr-broker",
  "iat": 1741878000,
  "exp": 1741879800,
  "jti": "cte_01JQKX7M3NFGP4R5S6T7V8W9XY",
  "task": {
    "id":           "01JQKX7M3NFGP4R5S6T7V8W9XY",
    "root_id":      "01JQKX7M3NFGP4R5S6T7V8W9XY",
    "parent_id":    "",
    "depth":        0,
    "lineage":      ["01JQKX7M3NFGP4R5S6T7V8W9XY"],
    "initiated_by": "ephyr:apikey:ak_claude",
    "description":  "Deploy monitoring stack to dockerhost"
  },
  "envelope": {
    "targets":  ["dockerhost", "hugoblog"],
    "roles":    ["operator", "read"],
    "services": ["grafana", "portainer"],
    "remotes":  ["demo-tools"],
    "methods":  ["GET", "POST"]
  }
}
```

**Field-by-field walkthrough:**

| Field | Type | Description |
|-------|------|-------------|
| `iss` | string | Issuer. Format: `ephyr:<broker-instance-id>`. Identifies which broker signed the token. |
| `sub` | string | Subject. The agent name from RBAC policy. |
| `aud` | string | Audience. Always `ephyr-broker`. Prevents tokens from being accepted by unrelated services. |
| `iat` | int64 | Issued At. Unix timestamp. Used by revocation watermarks. |
| `exp` | int64 | Expires At. Unix timestamp. Hard upper bound on token lifetime. |
| `jti` | string | JWT ID. Format: `cte_<ULID>` for execution tokens. Globally unique. |
| `task.id` | string | 26-character ULID identifying this task. |
| `task.root_id` | string | ULID of the root task in the hierarchy. Equals `id` for root tasks. |
| `task.parent_id` | string | ULID of the parent task. Empty for root tasks. |
| `task.depth` | int | Depth in the task tree. 0 for root tasks. |
| `task.lineage` | []string | Ordered list of task IDs from root to self. Used by revocation watermark check. |
| `task.initiated_by` | string | URN identifying the bootstrap identity that created this task. |
| `task.description` | string | Human-readable description for audit logs. |
| `envelope.*` | []string | Capability arrays. See Section 8. |

### 5.4 Signature

The signature is computed as:

```
signature = Ed25519.Sign(broker_private_key, base64url(header) + "." + base64url(payload))
```

Ed25519 signatures are 64 bytes, deterministic (no nonce), and verified in
constant time. The broker's private key is the ephemeral key whose public key
is bound in the delegation certificate.

### 5.5 Why JWT + EdDSA?

**Why JWT at all?** Three reasons:

1. **Debuggability.** Operations teams can decode a CTT-E with `base64 -d`
   and `jq` without any custom tooling. When an agent reports a permissions
   error, the support path is "paste the token into jwt.io" (or its
   offline equivalent), not "send the binary blob to the security team."

2. **Structured claims.** JWT's claim format (issuer, audience, expiry) is
   well-understood. Security reviewers know what to look for. The `aud`
   claim prevents cross-service token confusion without inventing a
   custom mechanism.

3. **Extensibility.** Adding new claims to the payload is a backward-
   compatible change. No schema evolution, no version negotiation.

**Why EdDSA specifically?**

- **Performance:** Ed25519 signing takes ~50us on modern hardware (measured
  at sub-millisecond in production, including JSON serialization). RSA-2048
  signing takes ~1ms; ECDSA-P256 ~0.5ms. For a system that signs tokens on
  every task creation, this matters.

- **Deterministic signatures:** Ed25519 produces the same signature for the
  same input. This simplifies testing and eliminates a class of
  implementation bugs where non-deterministic nonce generation produces
  different signatures on retry.

- **Key size:** Ed25519 keys are 32 bytes (public) + 64 bytes (private).
  RSA-2048 keys are 256 bytes (public) + ~1200 bytes (private). In a system
  that rotates keys every 50 minutes and holds prev + current, memory
  footprint matters.

- **Fixed algorithm:** By choosing a single algorithm and rejecting all
  others, we eliminate algorithm confusion attacks entirely. This is the
  single most common JWT vulnerability, and we close it by construction.

### 5.6 Why Not Macaroons?

Macaroons (Birgisson et al., 2014) are an attractive alternative for
capability-bearing tokens. They support contextual caveats, third-party
attenuation, and efficient verification. We considered them and may adopt
them in a future version. The current design uses JWT for three reasons:

1. **Familiarity.** Security teams reviewing Ephyr are far more likely to
   have JWT experience than macaroon experience. Lowering the audit barrier
   is worth the tradeoff.

2. **Explicit envelopes.** Ephyr's capability model uses explicit arrays
   (targets, roles, services, methods, remotes), not arbitrary predicates.
   Macaroon caveats are more expressive than we need today, and that
   expressiveness creates a larger verification surface.

3. **Lineage in payload.** Macaroons do not natively carry hierarchical
   identity metadata (task ID, root ID, lineage chain). We would need to
   encode this as caveats, which is possible but awkward.

If Ephyr evolves to support third-party attenuation (e.g., an external
policy service adding caveats to a token), macaroons become the natural
choice. This is noted in the roadmap.

### 5.7 Why Not X.509?

X.509 certificates support hierarchical trust, capability extensions (via
OID fields), and revocation (CRL, OCSP). However:

1. **Complexity.** X.509 parsing is notoriously complex. The Go `x509`
   package is ~8,000 lines. Our JWT implementation is ~300 lines. For a
   system that must be auditable by a single engineer, this matters.

2. **Overhead.** X.509 certificates are ASN.1/DER encoded, typically 1-2KB.
   CTT-E tokens are ~500 bytes. In a system where tokens are transmitted
   with every MCP request, wire size matters.

3. **Revocation mismatch.** X.509 revocation (CRL/OCSP) is designed for
   long-lived certificates. Our tokens live for minutes. The epoch watermark
   approach (Section 7) is a better fit for short-lived, task-scoped tokens.

---

## 6. Identity Scheme

### 6.1 Task Identifiers (ULIDs)

Every task is identified by a ULID (Universally Unique Lexicographically
Sortable Identifier). ULIDs were chosen over UUIDs for three properties:

```
  01JQKX7M3NFGP4R5S6T7V8W9XY
  |---------|-----------------|
  timestamp       random
  (48 bits)      (80 bits)

  48-bit Unix ms timestamp: ~8,925 years of range
  80-bit crypto random:     ~1.2 x 10^24 values per millisecond
  Crockford Base32:         26 chars, no ambiguous characters (I/L/O/U excluded)
```

**Why ULIDs over UUIDs:**

1. **Lexicographic ordering.** ULIDs sort chronologically by string
   comparison. This means task lists, database indexes, and log entries are
   naturally time-ordered without secondary sort keys.

2. **Embedded timestamp.** `ULIDTime(id)` extracts the creation time from
   any task ID without a database lookup. This is used for debugging,
   log correlation, and revocation watermark comparisons.

3. **No external dependency.** The ULID implementation is 128 lines of Go,
   using only `crypto/rand`, `encoding/binary`, and `time`. No external
   packages.

**Implementation details:**

- Crockford Base32 encoding excludes ambiguous characters (I, L, O, U),
  eliminating transcription errors.
- The first character is bounded to `0-7` (value 0-7), preventing 48-bit
  timestamp overflow.
- Both uppercase and lowercase decoding are supported.
- Validation checks length (26 chars), character set, and timestamp overflow.

### 6.2 Identity URN Format

The `initiated_by` field in task identity uses a URN scheme to identify the
bootstrap identity that created a task:

```
ephyr:<namespace>:<type>:<value>

Examples:
  ephyr:local:uid:1000          -- Local UID (Unix process identity)
  ephyr:apikey:ak_7f3b2a       -- API key (first 6 chars of agent name)
```

**Namespaces:**

| Namespace | Description | Example |
|-----------|-------------|---------|
| `local`   | Local system identity | `ephyr:local:uid:1000` |
| `apikey`  | API key authentication | `ephyr:apikey:ak_claude` |

**Extensibility:** The URN scheme is designed for future identity sources:

```
ephyr:oidc:google:user@example.com   -- OIDC identity (future)
ephyr:spiffe:cluster-a:workload-id   -- SPIFFE identity (future)
ephyr:mtls:cn:agent-prod-01          -- mTLS client cert (future)
ephyr:task:01JQKX...:delegated       -- Parent task delegation (Phase 2b)
```

**Policy matching:** The URN format enables policy rules like "only allow
tasks initiated by API keys" or "tasks initiated by OIDC must have 2FA."
This is not yet implemented but the identity format is designed to support
it.

---

## 7. Revocation Model

### 7.1 The Problem with Traditional Revocation

Standard revocation mechanisms are designed for long-lived credentials:

| Mechanism | Design Point | Problem for Task Tokens |
|-----------|-------------|------------------------|
| CRL (Certificate Revocation List) | X.509 certs lasting months/years | List grows linearly with revocations; requires periodic distribution; stale CRL = false accepts |
| OCSP (Online Certificate Status Protocol) | Per-cert online check | Round-trip per validation; OCSP responder becomes availability dependency; stapling helps but adds complexity |
| JTI Blocklist | JWT ID deny list | Memory grows linearly with revoked tokens; requires centralized store; GC is non-trivial; no cascading |

For task-scoped tokens that live 1-30 minutes and form parent-child
hierarchies, all three approaches are poor fits:

- CRL/OCSP assume a small number of long-lived certs. We have many
  short-lived tokens.
- JTI blocklists grow with every revocation and require explicit GC.
- None of them support cascading revocation (revoking a parent should
  invalidate all children).

### 7.2 Epoch Watermark Revocation

Ephyr uses a novel revocation mechanism called **epoch watermarks**. The
core idea:

> Instead of recording *which tokens* are revoked, record *when tasks were
> revoked*. A token is invalid if any task in its lineage was revoked at or
> after the token's issuance time.

**Data structure:**

```go
type RevocationMap struct {
    watermarks map[string]time.Time  // task_id -> revoked_at timestamp
    maxTTL     time.Duration         // for GC cutoff
}
```

**Revocation:** When a task is revoked, record `task_id -> now()`:

```
Revoke("01JQKX7M3N...") -> watermarks["01JQKX7M3N..."] = 2026-03-13T14:30:00Z
```

**Validation:** Walk the token's lineage array. For each task ID in the
lineage, check if a watermark exists and whether the token's `iat` is at or
before the watermark:

```
CheckLineage(lineage=["root-task", "child-task", "self"],
             iat=2026-03-13T14:29:00Z)

  Check "root-task":  watermark exists at 14:30:00? No  -> continue
  Check "child-task": watermark exists at 14:28:00? Yes
                      iat (14:29:00) > watermark (14:28:00)? Yes -> valid
  Check "self":       no watermark -> valid
  Result: VALID
```

### 7.3 Properties

**Cascading revocation.** Revoking a parent task automatically invalidates
all children whose tokens were issued before the watermark. No explicit
child enumeration is needed:

```
Root Task (revoked at T=100)
  |
  +-- Child A (token iat=90)  -> REVOKED (90 <= 100)
  |     |
  |     +-- Grandchild (iat=95) -> REVOKED (root in lineage, 95 <= 100)
  |
  +-- Child B (token iat=110) -> VALID (110 > 100, issued after revocation)
```

This is a key property: cascading revocation is O(depth) per validation,
not O(children) per revocation. The parent does not need to know how many
children exist.

**Independent task survival.** Revoking one task does not affect unrelated
tasks, even if they belong to the same agent. This is proven by integration
test `TestTaskLifecycle`, step 7: "Second task survived first task's
revocation."

**Self-cleaning.** The GC goroutine runs every 60 seconds and removes
watermarks older than `maxTTL`. A watermark can be safely removed once
`revoked_at + maxTTL` has passed, because any token issued before the
watermark has already expired by natural TTL. This bounds memory to:

```
max_watermarks = revocations_per_hour * (maxTTL_hours + 1)
```

For a system with 100 revocations per hour and a 1-hour max TTL, the
watermark map holds at most ~200 entries.

**Constant memory per revocation.** Unlike JTI blocklists, which store one
entry per revoked *token*, watermarks store one entry per revoked *task*.
A single task may have issued many tokens (via re-authentication); all are
invalidated by a single watermark entry.

### 7.4 Watermark Overwrite Semantics

If a task is revoked twice (e.g., due to retry logic), the later watermark
overwrites the earlier one. This is correct: the later watermark is more
restrictive (it invalidates tokens issued between the two watermarks that
were previously valid). This is verified by `TestRevocationRevokeOverwritesWatermark`.

### 7.5 Complexity Analysis

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Revoke a task | O(1) | Single map write |
| Check a token | O(depth) | Walk lineage array; depth is typically 1-3 |
| GC cycle | O(n) | Iterate all watermarks; n = number of active watermarks |
| Memory | O(r) | r = number of non-GC'd revocations |

Compare with JTI blocklist:

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Revoke a token | O(1) | Single set insert |
| Check a token | O(1) | Single set lookup |
| Revoke a task (cascade) | O(children) | Must enumerate and revoke each child token |
| GC cycle | O(n) | n = number of revoked tokens (much larger than tasks) |
| Memory | O(t) | t = number of revoked tokens |

The watermark approach wins on cascade revocation (O(1) vs O(children)) and
memory (O(tasks) vs O(tokens)), at the cost of slightly higher per-check
cost (O(depth) vs O(1)). Since depth is bounded and small (typically 1-3),
this is an excellent tradeoff.

---

## 8. Capability Envelopes

### 8.1 What They Are

A capability envelope is the upper bound on what a task may do. It is a
set of five arrays:

```go
type Envelope struct {
    Targets  []string  // SSH targets: ["dockerhost", "hugoblog"]
    Roles    []string  // SSH roles: ["read", "operator"]
    Services []string  // HTTP proxy services: ["grafana", "portainer"]
    Remotes  []string  // MCP federation remotes: ["demo-tools"]
    Methods  []string  // HTTP methods: ["GET", "POST"]
}
```

The envelope is embedded in the CTT-E token payload. Every request the
task makes is checked against its envelope before execution.

### 8.2 Wildcard Resolution

**Policy wildcards are resolved at token issuance.** If an agent's RBAC
policy contains a wildcard (`"*"` for targets or services), the
`BuildEnvelopeFromPolicy` function expands the wildcard to an explicit
array of all matching resources at the time the task is created.

```
Policy:           ssh: {"*": {roles: ["read"]}}
Available targets: dockerhost, hugoblog, mandrake-rack

Resolved envelope: targets: ["dockerhost", "hugoblog", "mandrake-rack"]
                   roles: ["read"]
```

**Why resolve at issuance?** If the token carried a wildcard and a new
target was added after issuance, the token would automatically gain access
to the new target. This violates the principle of least privilege. By
resolving wildcards at issuance, the token's permissions are frozen to what
existed at creation time.

The one exception is service access: if the RBAC policy grants `"*"` for
services and the full list of services cannot be enumerated from policy
alone, the wildcard marker is preserved in the envelope. This is a
pragmatic concession documented in the code and slated for resolution when
service discovery is formalized.

### 8.3 Envelope Checks

Each envelope dimension has a corresponding check method:

```go
envelope.ContainsTarget("dockerhost")   // true if "dockerhost" or "*" in Targets
envelope.ContainsRole("operator")       // true if "operator" or "*" in Roles
envelope.ContainsService("grafana")     // true if "grafana" or "*" in Services
envelope.ContainsMethod("POST")         // true if "POST" or "*" in Methods
envelope.ContainsRemote("demo-tools")   // true if "demo-tools" or "*" in Remotes
```

These are linear scans over small arrays (typically 1-5 elements). The
runtime cost is negligible compared to the network operations they gate.

### 8.4 Subset Validation for Delegation

When a parent task delegates to a child (Phase 2b), the child's envelope
must be a subset of the parent's:

```go
func (e *Envelope) IsSubsetOf(parent *Envelope) bool {
    return isSubset(e.Targets, parent.Targets) &&
           isSubset(e.Roles, parent.Roles) &&
           isSubset(e.Services, parent.Services) &&
           isSubset(e.Remotes, parent.Remotes) &&
           isSubset(e.Methods, parent.Methods)
}
```

**Wildcard semantics in `isSubset`:**

- If the parent has `"*"`, any child value is a subset. (Parent grants
  everything; child can request anything.)
- If the child has `"*"` but the parent does not, the check fails. (Child
  requests everything; parent did not grant everything.)
- Otherwise, every element in the child must be present in the parent.

This ensures **monotonic attenuation**: capabilities can only decrease through
delegation, never increase. The proof is straightforward -- `IsSubsetOf` is
transitive, and the child envelope is validated before the child token is
signed.

### 8.5 Legacy Mode

Agents without RBAC configuration receive a legacy envelope:

```
targets:  [all defined targets]
roles:    [all defined roles]
services: ["*"]
remotes:  ["*"]
methods:  ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
```

This preserves backward compatibility while making the permissiveness
explicit and auditable. Legacy mode is flagged in the resolved permissions
(`LegacyMode: true`), enabling operators to identify and migrate agents
progressively.

---

## 9. Validation

### 9.1 The Eight-Step Chain

Every CTT-E token is validated through an eight-step chain. The validation
is performed by the `Validator.ValidateCTTE` method and is designed to
fail fast -- each step short-circuits on failure before proceeding to the
next.

```
                          CTT-E Token
                              |
                    +---------+---------+
                    |   1. Parse JWT    |
                    |   Split on "."    |
                    |   Decode base64   |
                    +---------+---------+
                              |
                    +---------+---------+
                    |   2. Extract kid  |
                    |   Look up deleg   |
                    |   cert by kid     |
                    +---------+---------+
                              |
                    +---------+---------+
                    |   3. Verify deleg |
                    |   cert signature  |
                    |   against ROOT    |
                    |   public key      |
                    +---------+---------+
                              |
                    +---------+---------+
                    |   4. Check deleg  |
                    |   cert expiry     |
                    +---------+---------+
                              |
                    +---------+---------+
                    |   5. Verify CTT-E |
                    |   signature with  |
                    |   delegated pub   |
                    |   key from cert   |
                    +---------+---------+
                              |
                    +---------+---------+
                    |   6. Check CTT-E  |
                    |   expiry          |
                    +---------+---------+
                              |
                    +---------+---------+
                    |   7. Verify aud   |
                    |   == "ephyr-     |
                    |      broker"      |
                    +---------+---------+
                              |
                    +---------+---------+
                    |   8. Walk lineage |
                    |   against epoch   |
                    |   watermark map   |
                    +---------+---------+
                              |
                          VALID / DENY
```

### 9.2 Step-by-Step Detail

**Step 1: Parse JWT structure.** Split the token on `.` into exactly three
parts. Decode each part from Base64url. Unmarshal the header as JSON.
Reject tokens with wrong part count, invalid Base64, or malformed JSON.

**Step 2: Extract delegation cert reference.** Read `kid` from the header.
Look up the corresponding `DelegationCert` in the validator's in-memory
map (a `sync.Map` for lock-free concurrent reads). Reject if `kid` is
empty or unknown.

**Step 3: Verify delegation cert.** Reconstruct the canonical delegation
payload from the cert's fields and verify the signer's signature against
the pinned root public key. This step proves that the delegation cert was
issued by the trusted signer, not forged by a compromised broker. Reject
if the signature is invalid.

**Step 4: Check delegation cert expiry.** Compare the delegation cert's
`ExpiresAt` against the current time. Reject if expired. This limits the
window during which a compromised delegation key is useful.

**Step 5: Verify CTT-E signature.** Reconstruct the signing input
(`base64url(header) + "." + base64url(payload)`) and verify the Ed25519
signature against the delegation cert's embedded public key. This step
proves that the token was signed by the holder of the delegation key.
Reject if the signature is invalid.

**Step 6: Check CTT-E expiry.** Compare the token's `exp` claim against
the current time. Reject if expired. Task tokens have a maximum TTL of
1 hour.

**Step 7: Verify audience.** Check that the `aud` claim equals
`"ephyr-broker"`. This prevents a CTT-E token from being accepted by
a different service that happens to trust the same root key. Reject if
the audience does not match.

**Step 8: Walk lineage.** For each task ID in the token's `task.lineage`
array, check the epoch watermark map. If any ancestor has a watermark
and the token's `iat` is at or before the watermark timestamp, the token
is revoked. This is an O(depth) check, where depth is typically 1-3.

### 9.3 Trust Chain Summary

The validation chain establishes a trust path from the token back to the
root CA:

```
Root CA Private Key (Tier 1)
        |
        | signs (Ed25519)
        v
Delegation Cert (binds broker public key)
        |
        | cert contains broker's public key
        v
Broker Private Key (Tier 2, ephemeral)
        |
        | signs (Ed25519 via JWT)
        v
CTT-E Token (carries task identity + envelope)
        |
        | validated against
        v
Epoch Watermark Map (revocation state)
```

Every link in this chain is verified. A valid token proves:
1. The root CA authorized the broker (delegation cert signature).
2. The broker is current (delegation cert not expired).
3. The broker signed this specific token (CTT-E signature).
4. The token is current (CTT-E not expired).
5. The token is for this system (audience check).
6. No task in the token's ancestry has been revoked (watermark walk).

---

## 10. Performance Analysis

### 10.1 Where Time Goes

The dominant cost in the system is **not** token operations -- it is API key
authentication. This is by design: bcrypt is intentionally slow to resist
brute-force attacks.

```
Request Lifecycle (cold auth):

  API Key Authentication (bcrypt)       ~216 ms   ██████████████████████
  Token Signing (Ed25519)               ~0.05 ms  |
  Task Creation (ULID + map write)      ~0.01 ms  |
  Envelope Resolution (policy eval)     ~0.01 ms  |
  Token Validation (8-step chain)       ~0.05 ms  |
  Watermark Check (lineage walk)        ~0.001 ms |
  SSH Certificate Signing               ~1 ms     |
  SSH Exec (network round-trip)         ~50-200 ms █████████████
```

The auth cache eliminates the bcrypt bottleneck for subsequent requests:

```
Request Lifecycle (warm auth):

  Auth Cache Lookup (SHA-256)           ~0.001 ms |
  Token Signing (Ed25519)              ~0.05 ms   |
  Task Creation (ULID + map write)      ~0.01 ms  |
  Envelope Resolution (policy eval)     ~0.01 ms  |
  Token Validation (8-step chain)       ~0.05 ms  |
  Watermark Check (lineage walk)        ~0.001 ms |
  SSH Certificate Signing               ~1 ms     |
  SSH Exec (network round-trip)         ~50-200 ms █████████████████████
```

### 10.2 Auth Cache Design

The auth cache avoids repeated bcrypt comparisons for the same API key:

```
                     API Key
                        |
                        v
              SHA-256(apiKey) = fingerprint
                        |
                   +----+----+
                   |  Cache?  |
                   +----+----+
                  /           \
              HIT              MISS
               |                |
     Return cached agent   bcrypt.Compare
       (< 1ms)            against all agents
                              (~216ms)
                               |
                        Cache result
                        (TTL: 60s)
```

**Key properties:**

- Cache key is `SHA-256(apiKey)`, not the raw key. The plaintext API key
  is never stored.
- Cache entries expire after 60 seconds (configurable).
- Adding or removing agents invalidates the entire cache.
- Cache is lock-free for reads (`sync.RWMutex` with read bias).
- Observable via Prometheus counters: `ephyr_auth_cache_hits_total`,
  `ephyr_auth_cache_misses_total`.

### 10.3 Measured Performance (Integration Tests)

The following numbers are from the integration test suite running against
the production Ephyr instance on LXC CT 112 (1 vCPU, 512MB RAM):

| Operation | Average Latency | Notes |
|-----------|----------------|-------|
| `task_create` | 0.83 ms | Includes auth (cached), ULID gen, policy eval, envelope resolution, token signing |
| `task_list` | 0.70 ms | Lists all tasks for the requesting agent |
| `task_info` | 0.61 ms | Single task lookup by ID |
| `task_revoke` | 0.70 ms | Sets watermark + removes from task manager |
| MCP initialize | ~2 ms | Protocol handshake |
| `list_targets` (legacy) | ~1 ms | Backward-compatible tool |
| Auth cold (bcrypt) | ~216 ms | First request with a new API key |
| Auth warm (cache) | < 1 ms | Subsequent requests within 60s |

**Observations:**

1. All task operations complete in under 1ms on average (with warm auth
   cache). This means task identity adds negligible overhead to the
   request path.

2. The bcrypt cold-start cost (~216ms) is a one-time cost per auth cache
   window. In practice, agents make many requests per minute, so the cache
   hit rate is very high.

3. Token signing is not individually measured in the integration tests
   because it is embedded in `task_create`. The unit test
   `BenchmarkSignCTTE` (not shown here) measures it at ~50us.

### 10.4 Latency Histograms

The metrics system provides lock-free latency histograms with seven buckets:

```
Bucket boundaries: <100us, <500us, <1ms, <5ms, <10ms, <50ms, >=50ms
```

Each histogram tracks:
- Per-bucket observation count (atomic int64)
- Total sum in nanoseconds (atomic int64)
- Total count (atomic int64)

Approximate percentiles (p50, p95, p99) are derived via linear
interpolation across bucket boundaries. These are exposed via the
Prometheus `/v1/metrics` endpoint:

```
ephyr_token_sign_seconds_bucket{le="0.0001"} 47
ephyr_token_sign_seconds_bucket{le="0.0005"} 52
ephyr_token_sign_seconds_bucket{le="0.001"} 52
...
ephyr_token_sign_seconds_sum 0.00234
ephyr_token_sign_seconds_count 52
```

### 10.5 Delegation Rotation Cost

Delegation rotation involves one Unix socket IPC round-trip to the signer
plus one Ed25519 key generation:

```
Rotation cost breakdown:
  Ed25519 key generation:    ~0.05 ms
  Unix socket round-trip:    ~1 ms
  Signer's Ed25519 sign:     ~0.05 ms
  Cert registration:         ~0.001 ms
  Total:                     ~1.1 ms
```

This cost is amortized over the rotation interval (default: 50 minutes).
The cost per token is therefore ~0.0004ms (1.1ms / ~3000 tokens in 50 min
at moderate load). The rotation itself is non-blocking: the new key is
prepared before the old key is retired, and the swap is protected by a
read-write mutex.

---

## 11. Integration Test Results

The integration test suite verifies the task identity system end-to-end
against the running Ephyr instance. The tests are in
`test/integration/smoke_test.go` and exercise the full MCP protocol path.

### 11.1 Test Inventory

| # | Test | What It Proves |
|---|------|----------------|
| 1 | `TestMCPInitialize` | MCP handshake works; protocol version 2025-03-26 negotiated |
| 2 | `TestToolsList` | All 4 task tools (`task_create`, `task_info`, `task_revoke`, `task_list`) are registered |
| 3 | `TestLegacyToolsStillWork` | `list_targets` (pre-v0.2 tool) continues to work alongside new task tools |
| 4 | `TestTaskLifecycle` (create) | `task_create` returns a 26-char ULID task ID, a valid JWT token (3 dot-separated segments), an expiry timestamp, and a populated capability envelope |
| 5 | `TestTaskLifecycle` (info) | `task_info` returns correct description, remaining TTL, and `is_revoked: false` for a new task |
| 6 | `TestTaskLifecycle` (list) | `task_list` includes the created task in the active task list |
| 7 | `TestTaskLifecycle` (concurrent) | A second task can be created while the first is active; concurrent tasks are independent |
| 8 | `TestTaskLifecycle` (revoke) | `task_revoke` returns the revoked task ID and "all tokens invalidated" status |
| 9 | `TestTaskLifecycle` (verify revoked) | `task_info` on a revoked task returns "not found or expired" |
| 10 | `TestTaskLifecycle` (independent survival) | Second task remains active after first task is revoked |
| 11 | `TestTaskLifecycle` (cleanup) | Second task can be independently revoked |
| 12 | `TestTaskValidation` (bad TTL) | `task_create` with TTL > 1h is rejected ("exceed") |
| 13 | `TestTaskValidation` (empty desc) | `task_create` with empty description is rejected ("required") |
| 14 | `TestTaskValidation` (unknown revoke) | `task_revoke` on a nonexistent task ID is rejected |
| 15 | `TestMetricsEndpoint` | Prometheus `/v1/metrics` returns `ephyr_tasks_created_total`, `ephyr_tokens_signed_total`, `ephyr_watermark_revocations_total` |
| 16 | `TestPerformanceBench` (create) | 10 iterations of `task_create`, avg < 5ms |
| 17 | `TestPerformanceBench` (list) | 10 iterations of `task_list`, avg < 5ms |
| 18 | `TestPerformanceBench` (info) | 10 iterations of `task_info`, avg < 5ms |
| 19 | `TestPerformanceBench` (revoke) | 10 revocations to clean up benchmark tasks |

### 11.2 Unit Test Coverage

Beyond integration tests, the task identity subsystem has comprehensive
unit test coverage:

| Package/File | Test Count | Key Areas |
|-------------|-----------|-----------|
| `internal/token/` | 56 | ULID generation, validation, uniqueness, monotonicity; Envelope contains/subset checks; Delegation cert sign/verify; CTT-E round-trip; JWT structure; Key rotation; Error cases |
| `internal/broker/task_test.go` | 17 | Task CRUD; expiry; cleanup; concurrent access; ULID uniqueness (1000 iterations); envelope preservation; sort ordering; BuildEnvelopeFromPolicy (RBAC, legacy, wildcard) |
| `internal/broker/revocation_test.go` | 16 | Basic revoke/check; exact watermark timing; lineage walk; unrelated task isolation; cascading revocation; GC (expired, recent, all-expired); concurrent access (50 goroutines); watermark overwrite; multiple ancestors |
| `internal/broker/delegation_test.go` | 16 | Defaults; custom config; start success/failure; sign data; sign before start; cert expiry; isReady; rotation (key change, prev swap, new public key); rotation failure (keeps old key); cert age; concurrent sign (100 goroutines); stop idempotent; signature copy safety |

**Total task-identity-related tests: 105 unit + 19 integration = 124.**

### 11.3 Key Invariants Proven by Tests

1. **ULID uniqueness.** 1,000 consecutive task creations produce 1,000
   unique IDs (`TestULIDUniqueness`).

2. **Cascading revocation.** Revoking a root task invalidates children at
   depths 1, 2, and 3 (`TestRevocationCascading`).

3. **Independent survival.** Revoking one task does not affect a sibling
   task by the same agent (`TestTaskLifecycle` step 10 and
   `TestRevocationLineageWalkUnrelatedTask`).

4. **Envelope monotonicity.** Child wildcard is rejected when parent has
   no wildcard (`TestEnvelope_IsSubsetOf_ChildWildcard`).

5. **Key rotation continuity.** After delegation rotation, the new cert
   ID differs from the old; the old key is preserved as prev
   (`TestDelegationRotationSwapsPrev`).

6. **Failure resilience.** When rotation fails, the broker keeps the old
   key and remains ready (`TestDelegationRotationFailureKeepsOldKey`).

7. **Concurrent safety.** 50 goroutines performing concurrent revocation
   and lineage checks complete without race conditions
   (`TestRevocationConcurrentAccess`). 100 goroutines performing
   concurrent signing complete without errors
   (`TestDelegationConcurrentSign`).

---

## 12. Comparison with Existing Approaches

### 12.1 SPIFFE/SPIRE Workload Identity

[SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for
Everyone) provides workload identity via X.509 SVIDs (SPIFFE Verifiable
Identity Documents). SPIRE is the reference implementation.

| Dimension | SPIFFE/SPIRE | Ephyr Task Identity |
|-----------|-------------|---------------------|
| Identity granularity | Workload (pod, VM, process) | Task (single agent task run) |
| Identity format | X.509 SVID or JWT SVID | CTT-E (JWT + EdDSA) |
| Trust model | Hierarchical CAs with attestation | Three-tier delegation (root -> broker -> token) |
| Revocation | CRL/OCSP, TTL-based | Epoch watermarks with lineage walk |
| Capability bounding | Not built-in (relies on external policy) | Embedded capability envelopes |
| Delegation | Nested trust domains | Monotonic envelope attenuation (Phase 2b) |
| Task hierarchy | No concept of parent-child tasks | Lineage array, cascading revocation |
| Audit correlation | By workload identity | By task ID, root ID, and lineage |
| Dependencies | SPIRE server, attestors, workload API | Single Go binary, no external deps |
| Operational complexity | Significant (node agents, attestors, federation) | Minimal (two processes, Unix socket) |

**Assessment:** SPIFFE solves a broader problem (general workload identity
across clusters) and is appropriate for Kubernetes-native environments.
Ephyr solves a narrower problem (task-scoped identity for AI agents) with
much lower operational complexity. The two are complementary: a future
Ephyr version could accept SPIFFE SVIDs as a bootstrap identity
(`ephyr:spiffe:...` URN), using SPIFFE for workload attestation and Ephyr
for task-scoped access control.

### 12.2 OAuth2 Client Credentials

OAuth2 client credentials grant is the most common pattern for service-to-
service authentication.

| Dimension | OAuth2 Client Credentials | Ephyr Task Identity |
|-----------|--------------------------|---------------------|
| Identity granularity | Client (service/application) | Task |
| Token format | JWT or opaque | CTT-E (JWT + EdDSA) |
| Scoping | OAuth scopes (string labels) | Capability envelopes (targets, roles, services, methods, remotes) |
| Revocation | Token introspection endpoint or JTI blocklist | Epoch watermarks |
| Delegation | No native support | Monotonic attenuation (Phase 2b) |
| Task hierarchy | None | Lineage array |
| Token lifetime | Minutes to hours | Minutes (max 1h) |
| Dependencies | Authorization server (Keycloak, Auth0, etc.) | Built-in to broker |

**Assessment:** OAuth2 scopes are flat string labels ("read:servers",
"write:configs"). Ephyr envelopes are multi-dimensional (target AND role
AND service AND method). The envelope model captures the natural structure of
infrastructure access more precisely than scope strings. Additionally,
OAuth2 has no concept of task lineage, cascading revocation, or monotonic
attenuation.

### 12.3 API Key Rotation

The simplest approach: issue short-lived API keys, rotate frequently, revoke
by deleting the key.

| Dimension | API Key Rotation | Ephyr Task Identity |
|-----------|-----------------|---------------------|
| Identity granularity | Key holder (agent or operator) | Task |
| Scoping | Key-level (all or nothing) | Per-task envelope |
| Revocation | Delete key (kills all tasks) | Watermark (kills one task) |
| Delegation | Not possible | Monotonic attenuation (Phase 2b) |
| Audit | By key fingerprint | By task ID and lineage |
| Rotation cost | Re-authenticate all clients | Transparent (delegation rotation) |

**Assessment:** API key rotation provides the weakest identity model. It
cannot scope permissions to a task, cannot revoke a single task without
killing the agent, and cannot delegate with attenuation. Ephyr supports
API key authentication as the *bootstrap* mechanism (how an agent proves it
is authorized to create tasks), but the API key is not the task's identity.

### 12.4 Session Tokens

Web-style session tokens (e.g., signed cookies, Redis-backed sessions).

| Dimension | Session Tokens | Ephyr Task Identity |
|-----------|---------------|---------------------|
| Identity granularity | Session (user login) | Task |
| Scoping | Session-level roles | Per-task envelope |
| Revocation | Delete from session store | Epoch watermark (no central store) |
| Delegation | Not designed for it | Monotonic attenuation (Phase 2b) |
| Hierarchy | Flat | Lineage tree |
| Stateless validation | No (requires session store lookup) | Yes (cryptographic validation only) |

**Assessment:** Session tokens require a centralized session store for
validation, which is a single point of failure. CTT-E tokens are validated
purely via cryptographic operations against pinned keys and a local
watermark map. No external store is consulted during validation.

### 12.5 Summary Matrix

```
                    API Key  OAuth2  Session  SPIFFE  Ephyr
                    -------  ------  -------  ------  ------
Task-level scope       -       -       -        -       Y
Capability envelope    -       ~       -        -       Y
Cascading revocation   -       -       -        -       Y
Targeted revocation    -       ~       Y        ~       Y
Lineage tracking       -       -       -        -       Y
Monotonic attenuation  -       -       -        ~       Y*
Stateless validation   Y       ~       -        Y       Y
Zero external deps     Y       -       -        -       Y
Audit correlation      -       ~       ~        ~       Y

Y = yes, ~ = partial, - = no, * = Phase 2b
```

---

## 13. Roadmap

### 13.1 Phase 2b: Delegation Tokens (CTT-D)

**Status:** Implemented in v0.3.0 (2026-03-13).

Phase 2b implements CTT-D (Ephyr Task Token -- Delegation), enabling
parent tasks to spawn child tasks with attenuated capabilities via the
`task_delegate` MCP tool. The broker's `SignCTTD()` issues delegation
tokens, `Validate()` verifies them, and `CreateChildTask()` enforces
envelope attenuation through `IsSubsetOf()`. Delegation depth is capped
at 5 (`DefaultMaxChildDepth` constant). Cascading revocation invalidates
entire subtrees by lineage walk. The implementation includes a
`TokensDelegated` Prometheus counter for observability, and is covered
by 13 unit tests and 7 integration tests.

**Key design decisions:**

- CTT-D tokens carry `"typ": "CTT-D"` in the header and use `ctd_` prefix
  for the JTI field.
- The child's envelope must pass `IsSubsetOf(parent.Envelope)` at issuance.
- Delegation is controlled by `CanDelegate` on the `Task` struct, and
  depth is bounded by the `DefaultMaxChildDepth = 5` constant. A parent
  with `CanDelegate: false` cannot spawn children; depth beyond 5 is
  rejected at `CreateChildTask()` time.
- Cascading revocation works unchanged: revoking the parent's task ID
  automatically invalidates all children via the lineage watermark walk.
- The child's lineage array extends the parent's:
  `[root, ..., parent, child]`.

**Example flow:**

```
Parent Task (depth=0, envelope={targets: [A,B,C]}, CanDelegate=true)
    |
    | task_delegate(envelope={targets: [A]}, description="subtask")
    |
    v
Child Task (depth=1, envelope={targets: [A]}, parent_id=parent.id)
    |
    | Cannot access B or C (envelope subset enforced)
    | Revoking parent revokes child (lineage walk)
```

### 13.2 Phase 2c: Dashboard Task Views

**Status:** Designed, not yet implemented.

The Ephyr dashboard will receive task-specific views:

- **Task Tree:** Visual hierarchy of active tasks, their lineage, and
  envelope summaries.
- **Task Timeline:** Gantt-style view of task lifetimes, overlaid with
  action events.
- **Revocation Controls:** One-click task revocation from the dashboard,
  with cascading impact preview.
- **Envelope Inspector:** Drill into a task's capability envelope and see
  which permissions are actually used vs. granted.

### 13.3 Phase 3: Federated Task Identity

**Status:** Conceptual.

When Ephyr federates with remote MCP servers, task identity should flow
across federation boundaries:

- The parent Ephyr instance issues a CTT-E with the remote server in the
  `remotes` envelope.
- The remote server validates the token's signature chain back to the
  parent's root public key (exchanged during federation setup).
- Actions on the remote server are attributed to the originating task ID.
- Revocation propagates via webhook notification.

This enables a multi-Ephyr topology where each instance manages its own
hosts but tasks can span instances.

### 13.4 Future Considerations

- **Macaroon-based tokens:** If third-party attenuation is needed (e.g.,
  an external policy service adding constraints to tokens), macaroons may
  replace or complement JWT-based CTT tokens.
- **Hardware-backed key custody:** The signer's root key could be stored
  in a TPM or HSM for hardware-level protection.
- **Token binding:** Bind tokens to a specific TLS connection or IP
  address to prevent token theft.
- **Metrics integration:** Push task metrics to Prometheus/Grafana for
  alerting on anomalous task patterns (e.g., unexpected delegation depth,
  high revocation rate).

---

## 14. Conclusion

AI agents operating infrastructure need identity systems that match the
granularity of their operations. Service-level identity -- API keys, OAuth2
client credentials, workload identity -- does not capture the concept of a
discrete task run. This gap creates security failures that grow more severe
as agents gain more autonomy: no blast radius containment, no audit
correlation, no delegation control, and no targeted revocation.

Ephyr v0.2 addresses this gap by making the task the fundamental unit of
identity. Each task receives a cryptographically signed token (CTT-E) that
carries:

- A **ULID task identifier** that is globally unique, time-sortable, and
  embeds its creation timestamp.
- A **capability envelope** that constrains what the task may do, with
  wildcards resolved to explicit arrays at issuance.
- A **lineage chain** that traces the task's ancestry from root to self,
  enabling cascading revocation without per-token blocklists.

The system is built on a **three-tier Ed25519 trust model** where the root
CA key never leaves the signer process, the broker signs tokens with a
delegated ephemeral key that rotates every 50 minutes, and agents receive
opaque tokens they cannot forge or modify.

**Epoch watermark revocation** replaces traditional CRL/OCSP/blocklist
approaches with a mechanism designed for short-lived, hierarchical tokens:
one map entry per revoked task (not per revoked token), O(depth) validation,
automatic cascading, and self-cleaning GC.

The implementation is ~3,500 lines of Go with zero external cryptographic
dependencies. It is tested by 124 tests (105 unit + 19 integration) that
verify ULID uniqueness, cascading revocation, independent task survival,
envelope monotonicity, key rotation continuity, failure resilience, and
concurrent safety. Measured performance shows all task operations complete
in under 1ms with warm auth cache.

Task-scoped identity is not a theoretical improvement. It is the difference
between "we revoked the agent's API key and killed all its tasks" and "we
revoked the misbehaving task and the other four kept running." It is the
difference between "the audit log shows the agent did something" and "the
audit log shows task 01JQKX7M, initiated by ak_claude, running
'deploy monitoring stack,' executed this specific command." It is the
difference between "the child agent inherited everything" and "the child
agent received exactly the subset of permissions needed for its subtask."

Ephyr v0.2 is the foundation. Delegation tokens (Phase 2b) will enable
parent-to-child spawning with monotonic attenuation. Federated task
identity (Phase 3) will extend task scoping across Ephyr instances.
But the core primitive -- the task as an identity unit, with a signed
token, a bounded envelope, and a revocable lineage -- is complete and
operational today.

---

## Appendix A: Token Format Reference

### A.1 CTT-E Header

```json
{
  "alg": "EdDSA",
  "typ": "CTT-E",
  "kid": "<32-char hex delegation cert ID>"
}
```

### A.2 CTT-E Payload

```json
{
  "iss": "ephyr:<broker-id>",
  "sub": "<agent-name>",
  "aud": "ephyr-broker",
  "iat": <unix-timestamp>,
  "exp": <unix-timestamp>,
  "jti": "cte_<26-char-ULID>",
  "task": {
    "id":           "<26-char-ULID>",
    "root_id":      "<26-char-ULID>",
    "parent_id":    "<26-char-ULID or empty>",
    "depth":        <int>,
    "lineage":      ["<ULID>", ...],
    "initiated_by": "ephyr:<namespace>:<type>:<value>",
    "description":  "<string>"
  },
  "envelope": {
    "targets":  ["<target-name>", ...],
    "roles":    ["<role-name>", ...],
    "services": ["<service-name>", ...],
    "remotes":  ["<remote-name>", ...],
    "methods":  ["<http-method>", ...]
  }
}
```

### A.3 CTT-D Header (Phase 2b)

```json
{
  "alg": "EdDSA",
  "typ": "CTT-D",
  "kid": "<32-char hex delegation cert ID>"
}
```

### A.4 Delegation Certificate Payload (Canonical JSON)

```json
{
  "broker_id":  "<string>",
  "cert_id":    "<32-char hex>",
  "expires_at": <unix-timestamp>,
  "issued_at":  <unix-timestamp>,
  "public_key": "<base64-encoded-ed25519-public-key>"
}
```

Note: Fields are alphabetically ordered for deterministic serialization.
The signer signs this exact JSON byte sequence.

---

## Appendix B: ULID Format Reference

```
 01JQKX7M3NFGP4R5S6T7V8W9XY
 |---------|-----------------|
  10 chars       16 chars
  Timestamp      Random

Encoding: Crockford Base32
  Alphabet: 0123456789ABCDEFGHJKMNPQRSTVWXYZ
  Excluded: I, L, O, U (ambiguous)

Timestamp: 48-bit Unix milliseconds (MSB first)
  Range: 1970-01-01 to 10889-08-02
  First char bounded to 0-7 (prevents overflow)

Random: 80-bit cryptographic random
  Source: crypto/rand
  Collision probability: < 2^-80 per millisecond
```

---

## Appendix C: Prometheus Metrics Reference

### Counters

| Metric | Description |
|--------|-------------|
| `ephyr_tasks_created_total` | Total tasks created |
| `ephyr_tokens_signed_total` | Total CTT-E tokens signed |
| `ephyr_tokens_validated_total` | Total tokens validated |
| `ephyr_tokens_rejected_total` | Total tokens rejected |
| `ephyr_watermark_revocations_total` | Total watermark revocations |
| `ephyr_delegation_rotations_total` | Total delegation cert rotations |
| `ephyr_legacy_requests_total` | Requests without CTT (legacy mode) |
| `ephyr_auth_cache_hits_total` | Auth cache hits (bcrypt bypassed) |
| `ephyr_auth_cache_misses_total` | Auth cache misses (bcrypt required) |

### Gauges

| Metric | Description |
|--------|-------------|
| `ephyr_tasks_active` | Currently active tasks |
| `ephyr_active_watermarks` | Active revocation watermarks |
| `ephyr_delegation_cert_age_seconds` | Age of current delegation cert |
| `ephyr_delegation_certs_held` | Delegation certs in memory |

### Histograms

| Metric | Description |
|--------|-------------|
| `ephyr_token_sign_seconds` | Token signing latency |
| `ephyr_token_validate_seconds` | Token validation latency |
| `ephyr_watermark_check_seconds` | Watermark check latency |
| `ephyr_envelope_check_seconds` | Envelope check latency |
| `ephyr_policy_eval_seconds` | Policy evaluation latency |
| `ephyr_ssh_cert_seconds` | SSH certificate signing latency |
| `ephyr_delegation_ipc_seconds` | Delegation IPC latency |
| `ephyr_exec_e2e_seconds` | End-to-end exec latency |

---

*This document describes Ephyr v0.2.0-alpha as implemented on 2026-03-13.
Source code: `/opt/ephyr/` on LXC CT 112 (192.168.100.75).*
