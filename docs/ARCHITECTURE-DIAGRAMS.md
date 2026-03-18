# Ephyr Authorization Framework

## Full Request Lifecycle

```mermaid
graph TD
    subgraph Agent["Agent Runtime"]
        A1[MCP Client]
    end

    subgraph Auth["Authentication Layer"]
        direction TB
        B1{"Bearer token<br/>detection"}
        B2["mac_ prefix<br/>Macaroon path"]
        B3["3 dots<br/>JWT path (legacy)"]
        B4["Other<br/>API key path"]
    end

    subgraph MacVerify["Macaroon Verification"]
        direction TB
        C1["HMAC chain<br/>verify signature"]
        C2["Reduce caveats<br/>set intersection<br/>minimum, AND"]
        C3["Resolve task<br/>SHA-256 sig lookup"]
        C4["Check watermark<br/>epoch revocation"]
        C5["Bind presenter<br/>agent identity"]
    end

    subgraph PoP["Proof-of-Possession"]
        direction TB
        D0{"HolderBound?"}
        D1["Verify Ed25519<br/>signature"]
        D2["Check body_hash<br/>request integrity"]
        D3["Check mac_digest<br/>token binding"]
        D4["Check nonce<br/>replay prevention"]
        D5["Check timestamp<br/>clock skew window"]
    end

    subgraph Policy["Policy Enforcement"]
        direction TB
        E1["RBAC evaluation<br/>agent permissions"]
        E2["Envelope check<br/>targets, roles,<br/>services, methods"]
        E3["Command filter<br/>deny/allow patterns"]
        E4{"Auto-revoke<br/>on deny?"}
    end

    subgraph Proxy["Proxy Paths"]
        direction TB
        F1["SSH exec<br/>ephemeral cert"]
        F2["HTTP proxy<br/>credential injection"]
        F3["MCP federation<br/>tool proxying"]
    end

    subgraph Signer["Signer (isolated)"]
        G1["Ed25519 CA key<br/>signs certificate<br/>Unix socket only"]
    end

    subgraph Audit["Audit"]
        H1["JSON-line log<br/>hash-chained<br/>SIEM-ready"]
    end

    A1 -->|"Bearer: mac_..."| B1
    B1 --> B2
    B1 --> B3
    B1 --> B4

    B2 --> C1
    C1 --> C2
    C2 --> C3
    C3 --> C4
    C4 --> C5

    C5 --> D0
    D0 -->|"Yes"| D1
    D0 -->|"No (bearer mode)"| E1
    D1 --> D2
    D2 --> D3
    D3 --> D4
    D4 --> D5
    D5 --> E1

    B3 --> E1
    B4 --> E1

    E1 --> E2
    E2 --> E3
    E3 -->|"Denied"| E4
    E3 -->|"Allowed"| F1
    E3 -->|"Allowed"| F2
    E3 -->|"Allowed"| F3
    E4 -->|"Yes"| H1
    E4 -->|"No"| H1

    F1 -->|"IPC"| G1
    G1 -->|"Signed cert"| F1
    F1 --> H1
    F2 --> H1
    F3 --> H1

    classDef agent fill:#7c3aed,stroke:#7c3aed,color:#fff
    classDef auth fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    classDef mac fill:#1e293b,stroke:#06b6d4,color:#e2e8f0
    classDef pop fill:#1e293b,stroke:#8b5cf6,color:#e2e8f0
    classDef policy fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    classDef proxy fill:#1e293b,stroke:#22c55e,color:#e2e8f0
    classDef signer fill:#1e293b,stroke:#ef4444,color:#e2e8f0
    classDef audit fill:#1e293b,stroke:#64748b,color:#94a3b8

    class A1 agent
    class B1,B2,B3,B4 auth
    class C1,C2,C3,C4,C5 mac
    class D0,D1,D2,D3,D4,D5 pop
    class E1,E2,E3,E4 policy
    class F1,F2,F3 proxy
    class G1 signer
    class H1 audit
```

<details>
<summary>View as text</summary>

```
Request Flow:

  Agent (MCP Client)
    |
    | Bearer: mac_<base64url>
    v
  +----------------------------------+
  | AUTHENTICATION                   |
  |  mac_ prefix --> Macaroon path   |
  |  3 dots     --> JWT (legacy)     |
  |  other      --> API key (bcrypt) |
  +----------------------------------+
    |
    v (macaroon path)
  +----------------------------------+
  | MACAROON VERIFICATION            |
  |  1. HMAC chain (signature)       |
  |  2. Reduce caveats               |
  |     - set intersection (targets) |
  |     - minimum (depth, TTL)       |
  |     - AND (can_delegate)         |
  |  3. Resolve task (sig digest)    |
  |  4. Check epoch watermark        |
  |  5. Bind presenter (agent)       |
  +----------------------------------+
    |
    v
  +----------------------------------+
  | PROOF-OF-POSSESSION (if bound)   |
  |  1. Ed25519 signature verify     |
  |  2. body_hash (request integrity)|
  |  3. mac_digest (token binding)   |
  |  4. nonce (replay prevention)    |
  |  5. timestamp (clock skew)       |
  +----------------------------------+
    |
    v
  +----------------------------------+
  | POLICY ENFORCEMENT               |
  |  1. RBAC (agent permissions)     |
  |  2. Envelope (targets, roles,    |
  |     services, methods)           |
  |  3. Command filter (deny/allow)  |
  |  4. Auto-revoke on deny?         |
  +----------------------------------+
    |
    +--------+--------+--------+
    v        v        v        v
  SSH      HTTP     MCP     DENIED
  exec     proxy    federation
    |        |        |
    v        |        |
  Signer     |        |
  (CA key)   |        |
    |        |        |
    v        v        v
  +----------------------------------+
  | AUDIT LOG                        |
  |  JSON-line, hash-chained,        |
  |  per-event, SIEM-ready           |
  +----------------------------------+
```

</details>

## Delegation Attenuation

```mermaid
graph TD
    subgraph Root["Root Task (depth 0)"]
        R1["Targets: A, B, C<br/>Roles: read, operator, admin<br/>Services: all<br/>Can delegate: true<br/>Depth: 5"]
    end

    subgraph Child1["Child Task (depth 1)"]
        C1a["Targets: A, B<br/>Roles: read, operator<br/>Services: grafana<br/>Can delegate: true<br/>Depth: 4"]
    end

    subgraph Child2["Child Task (depth 1)"]
        C1b["Targets: C<br/>Roles: read<br/>Services: none<br/>Can delegate: false<br/>Depth: 0"]
    end

    subgraph Grand["Grandchild (depth 2)"]
        G1["Targets: A<br/>Roles: read<br/>Services: grafana (GET)<br/>Can delegate: false<br/>Depth: 3"]
    end

    Root -->|"delegate<br/>intersection narrows"| Child1
    Root -->|"delegate<br/>intersection narrows"| Child2
    Child1 -->|"delegate<br/>intersection narrows"| Grand

    Root -.->|"revoke root"| Kill["Epoch watermark<br/>cascade: all 3<br/>children killed"]

    classDef root fill:#22c55e,stroke:#22c55e,color:#fff
    classDef child fill:#3b82f6,stroke:#3b82f6,color:#fff
    classDef grand fill:#8b5cf6,stroke:#8b5cf6,color:#fff
    classDef kill fill:#ef4444,stroke:#ef4444,color:#fff

    class R1 root
    class C1a,C1b child
    class G1 grand
    class Kill kill
```

<details>
<summary>View as text</summary>

```
Delegation Tree (envelope shrinks at each level):

  Root Task (depth 0)
  Targets: [A, B, C]  Roles: [read, op, admin]  Services: [*]  Delegate: yes
    |
    +-- Child 1 (depth 1)                        HMAC caveat appended
    |   Targets: [A, B]  Roles: [read, op]       intersection([A,B,C], [A,B]) = [A,B]
    |   Services: [grafana]  Delegate: yes
    |     |
    |     +-- Grandchild (depth 2)                HMAC caveat appended
    |         Targets: [A]  Roles: [read]         intersection([A,B], [A]) = [A]
    |         Services: [grafana, GET]             AND(true, false) = false
    |         Delegate: no
    |
    +-- Child 2 (depth 1)                         HMAC caveat appended
        Targets: [C]  Roles: [read]               intersection([A,B,C], [C]) = [C]
        Services: []  Delegate: no

  Revoke root --> epoch watermark --> all 3 children killed instantly
```

</details>

## Ephyr: Holder Binding (Two-Phase Key Exchange)

```mermaid
sequenceDiagram
    title Ephyr: Holder Binding (Two-Phase Key Exchange)

    participant P as Parent Agent
    participant B as Broker
    participant S as Signer (CA)
    participant C as Child Agent

    rect rgb(30, 41, 59)
    Note over P,B: Phase 1: Delegation
    P->>B: task_delegate(parent_token, child_envelope)
    B->>B: Verify parent macaroon (HMAC chain)
    B->>B: Reduce caveats + validate subset
    B->>B: Mint child macaroon (append narrowing caveats)
    B->>B: Set HolderBound=false, BindDeadline=30s
    B-->>P: Child macaroon (unbound, unusable until bound)
    end

    P->>C: Pass macaroon (out of band)

    rect rgb(30, 41, 59)
    Note over C,B: Phase 2: Key Binding
    C->>C: Generate ephemeral Ed25519 keypair
    C->>B: task_bind(macaroon, public_key)
    B->>B: Verify macaroon (only task_bind allowed for unbound tokens)
    B->>B: Check BindDeadline not expired
    B->>B: Store HolderPubKey, set HolderBound=true
    B-->>C: Bound confirmation
    end

    rect rgb(30, 41, 59)
    Note over C,S: Bound Request (e.g., SSH exec)
    C->>B: exec(target, role, command) + _pop{sig, body_hash, nonce, ts}
    B->>B: Verify macaroon HMAC chain
    B->>B: Reduce caveats to effective envelope
    B->>B: Verify PoP: Ed25519 sig, body_hash, mac_digest, nonce, timestamp
    B->>B: RBAC + envelope authorization
    B->>S: Sign SSH certificate (Unix socket IPC)
    S->>S: Ed25519 CA signs ephemeral cert
    S-->>B: Signed certificate (never on network)
    B->>B: SSH dial with cert to target
    B-->>C: Command output
    end

    Note over P,C: Parent's key cannot present child's token
    Note over P,C: Child's key cannot present parent's token
    Note over S,S: CA key never leaves signer process
```

<details>
<summary>View as text</summary>

```
Ephyr: Holder Binding (Two-Phase Key Exchange)

  Parent              Broker                Signer (CA)       Child
    |                   |                       |                |
    |                   |    PHASE 1: DELEGATION                 |
    |-- task_delegate ->|                       |                |
    |                   |-- verify parent mac    |                |
    |                   |-- reduce + subset     |                |
    |                   |-- mint child mac      |                |
    |                   |-- HolderBound=false   |                |
    |                   |-- BindDeadline=30s    |                |
    |<- child macaroon -|                       |                |
    |                   |                       |                |
    |-- pass token (out of band) ------------------------------>|
    |                   |                       |                |
    |                   |    PHASE 2: KEY BINDING                |
    |                   |                       |  generate key  |
    |                   |<--- task_bind(mac, pubkey) ------------|
    |                   |-- verify mac          |                |
    |                   |-- check deadline      |                |
    |                   |-- store key, bind=true|                |
    |                   |-- confirm ---------------------------->|
    |                   |                       |                |
    |                   |    BOUND REQUEST (e.g., SSH exec)      |
    |                   |<--- exec + _pop{sig, body_hash} ------|
    |                   |-- verify macaroon     |                |
    |                   |-- verify PoP (sig,    |                |
    |                   |   body, nonce, ts)    |                |
    |                   |-- RBAC + envelope     |                |
    |                   |-- sign cert --------->|                |
    |                   |                       |-- CA signs     |
    |                   |<-- signed cert -------|                |
    |                   |-- SSH dial + exec     |                |
    |                   |-- response --------------------------->|
    |                   |                       |                |
    |   Parent key != child key (independent keypairs)          |
    |   CA key never leaves signer process                      |
```

</details>
