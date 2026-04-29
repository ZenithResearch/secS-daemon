# secS-daemon

secS-daemon is a Cybernetic Synapse for agentic communication.


Most agent systems still speak through Web2 duct tape. REST endpoints. Webhooks. API keys. JSON-shaped trust. It works until agents need to coordinate like machines instead of pretending to be users clicking through apps.

secS-daemon gives agents a different primitive: prove identity, deliver encrypted intent, route by opcode, execute only what the receiving node has explicitly bound.

No landlord. No shared bearer secret. No platform permission in the middle.


Build the Egregore.


## The Shape of the System

```text
                 ┌──────────────────────────────────────────────┐
                 │                  secC                        │
                 │        JIT proving client / packet sender     │
                 └──────────────────────┬───────────────────────┘
                                        │ ZenithPacket
                                        │ bincode over TCP
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                                secS                                     │
│                 open mathematical gatekeeper · port 9000                │
│                                                                         │
│  verify proof envelope  →  enforce temporal claim  →  hand off bytes    │
│                                                                         │
│  no roles · no product policy · no hub dependency · no domain logic     │
└───────────────────────────────────────┬─────────────────────────────────┘
                                        │ same packet contract
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                                secZ                                     │
│                 configurable execution synapse · port 9001              │
│                                                                         │
│  decrypt payload  →  log telemetry  →  route opcode  →  execute binding │
│                                                                         │
│        0x10 → bash          0x20 → native Rust        0x30 → jq          │
└─────────────────────────────────────────────────────────────────────────┘
```

## secS vs secZ

These interfaces are separate on purpose.

| Interface | Port | Job | What it refuses |
| --- | ---: | --- | --- |
| `secS` | `9000` | Stable secure service interface. It handles canonical daemon traffic like `OPCODE_GENERATE = 0x01` and `OPCODE_CHAT = 0x02`. | Product policy, role logic, agent orchestration, payment logic. |
| `secZ` | `9001` | Extensible sidecar gateway. It validates the proof envelope, decrypts payload bytes when a tunnel key is configured, logs telemetry, and dispatches by `u8` opcode to a configured `MachineProgram`. | Hub dependencies, arbitrary shell access, hidden routing policy, payload parsing in the router. |

secS is the mathematical gate. secZ is the execution synapse.

## Why This Exists

Agents need owned communication rails.

The current default asks machine systems to coordinate through infrastructure built for browser users: OAuth flows, REST APIs, webhooks, shared API keys, and centralized gateways. Those primitives are useful. They are not enough for peer machine execution.

secS-daemon changes the default shape.

- **Proof replaces bearer secrets.** A packet without a valid proof envelope is rejected before it becomes useful.
- **Opcodes replace arbitrary authority.** An agent does not receive a shell. It receives a bounded intent channel.
- **Local manifests replace platform policy.** The receiving machine decides what `0x20` means.
- **stdin replaces framework lock-in.** Rust can secure the transport while Python, Bash, Node, `jq`, or a local worker handles execution.
- **SQLite telemetry replaces rented observability.** The node records opcode and payload size locally, without a SaaS dependency.
- **Peer nodes replace central gateways.** A MacBook, Raspberry Pi, GPU instance, homelab server, or cloud box can all run the same rail.

That is the cybernetic benefit: machines coordinate through a nervous system they own.

## Developer Value Proposition

### 1. Polyglot sidecar

secZ pipes decrypted payload bytes into `stdin`. That means the execution surface can be whatever your team already uses.

```text
Rust transport → Python model worker
Rust transport → Bash queue script
Rust transport → jq parser
Rust transport → local CLI
Rust transport → native Rust binding
```

The packet does not care what language receives the intent.

### 2. Zero-trust by default

API keys leak because they are portable authority. secS-daemon moves authority into the packet envelope.

The intended order is strict:

```text
proof first → decrypt second → route third → execute only if bound
```

An invalid packet never becomes an application request.

### 3. Unix philosophy for agent swarms

secZ does one thing: secure transport and handoff.

Every new capability should not have to rebuild authentication, networking, telemetry, and process handoff. Write the script. Bind the opcode. Keep the node sovereign.

### 4. Configuration as code

`server/src/bin/secz.rs::main()` is the deployment manifest.

There is no sprawling YAML policy maze. The bindings are readable in one place:

```rust
router.register(0x10, Box::new(SubprocessForwarder::new(
    "bash",
    vec!["-c", "echo 'Bash received payload:'; cat"],
)));

router.register(0x20, Box::new(LocalRustQueue));
router.register(0x30, Box::new(SubprocessForwarder::new("jq", vec!["."])));
```

The manifest is the firewall.

## Agentic Ecosystem Value

### True M2M RPC

Tool calls are language-level requests. `ZenithPacket` is machine-level intent: signed, routed, decrypted, measured, and handed to a capability that already exists on the other side.

This is a protocol upgrade from talking to executing.

### Sandboxed capability routing

Agents should not get broad machine authority.

They should get bounded intent channels.

Opcode `0x20` can mean “enqueue task” on one node and nothing on another. The receiving machine maintains sovereignty over what that opcode actually does.

### Decentralized swarm topology

secZ requires no central server and no domain dependency. Deploy it beside the thing that should receive intent.

A mobile agent can send authenticated payloads to a GPU box. A homelab node can forward a job to a local queue. A field machine can trigger a constrained worker without exposing a general API.

### Standardized agent intent

A shared opcode vocabulary lets agents learn the shape of a network without inheriting its internals.

Example direction:

| Opcode | Intent class |
| --- | --- |
| `0x10` | Knowledge/query pipe |
| `0x20` | Queue/enqueue action |
| `0x30` | Structured JSON processing |
| `0x40` | Site-specific service binding |

The standard is small on purpose. Intent should be portable. Meaning remains local.

## ZenithPacket Envelope

All client-to-daemon traffic is serialized with `bincode` as `libsec_core::ZenithPacket`:

```rust
pub struct ZenithPacket {
    pub session_id: [u8; 16],
    pub nonce: [u8; 12],
    pub opcode: u8,
    pub proof: Vec<u8>,
    pub claim_ttl: u64,
    pub encrypted_payload: Vec<u8>,
    pub mac: [u8; 16],
}
```

Standard secS opcodes:

- `0x01` / decimal `1`: `OPCODE_GENERATE`
- `0x02` / decimal `2`: `OPCODE_CHAT`

secZ manifest opcodes currently bound:

- `0x10` / decimal `16`: Bash echo pipe. Prints `Bash received payload:` then streams payload bytes through `cat`.
- `0x20` / decimal `32`: Native Rust queue stub.
- `0x30` / decimal `48`: `jq .` JSON formatter/parser.

CLI rule:

- `client hub` parses opcode as decimal `u8`.
- Use `16`, not `0x10`, when calling the client.

## secZ Execution Pipeline

Inbound TCP traffic to `0.0.0.0:9001` follows a strict linear pipeline:

1. Ingestion: read raw bytes from `tokio::net::TcpStream`.
2. Deserialization: parse bytes with `bincode` into `ZenithPacket`.
3. Authentication envelope: reject packets with empty proof or zero `claim_ttl`.
4. Decryption:
   - If `SECZ_TUNNEL_KEY_HEX` is set, decrypt `encrypted_payload` with ChaCha20Poly1305 using that 32-byte hex key.
   - If `SECZ_TUNNEL_KEY_HEX` is absent, fall back to plaintext payload mode for local development and quick starts.
   - `SECS_TUNNEL_KEY_HEX` is accepted as a fallback environment variable.
5. Telemetry intercept: insert `opcode` and `payload_size` into local SQLite table `node_telemetry`.
6. Routing: dispatch decrypted bytes to the `ConfigurableRouter` registry.
7. Execution: invoke the bound `MachineProgram`.

## Telemetry Constraint

secZ is stateless regarding domain logic, but it maintains a local audit log:

- Database file: `node_telemetry.db`
- Table: `node_telemetry`
- Fields: `id`, `timestamp`, `opcode`, `payload_size`

Critical rule:

- Do not use `sqlx::query!` or other compile-time SQL macros.
- Use runtime SQL only:

```rust
sqlx::query("INSERT INTO node_telemetry (opcode, payload_size) VALUES (?, ?)")
    .bind(opcode)
    .bind(payload_size)
    .execute(&pool)
    .await;
```

Compile-time SQLx macros require a database or offline cache at build time. secZ must compile without a pre-existing SQLite database.

## MachineProgram Extensibility Model

secZ delegates decrypted payloads using this async trait:

```rust
#[async_trait]
pub trait MachineProgram: Send + Sync {
    async fn execute(&self, payload: &[u8]);
}
```

Approved expansion paradigms:

### A. Subprocess Forwarder

Preferred for most integrations.

Use it to bind an opcode to:

- shell scripts
- Python/Ruby/Node programs
- Unix tools such as `jq`, `curl`, `grep`, `awk`
- local service CLIs

Mechanism:

- Spawn target with `tokio::process::Command`.
- Pipe decrypted payload bytes into child `stdin`.
- Inherit child stdout/stderr to the secZ terminal.

Example:

```rust
router.register(0x40, Box::new(SubprocessForwarder::new(
    "python3",
    vec!["./services/my_worker.py"],
)));
```

### B. Native Rust Binding

Use only for tight in-process work:

- memory queues
- low-latency local handoff
- local metrics aggregation
- simple byte-level state machines

Do not parse domain payloads in secZ unless the opcode is intentionally implemented as a Native Rust Binding.

## Quick Start: Hello World Opcode Pipe

Prerequisites:

- Rust toolchain
- Bash
- Optional: `jq` for opcode `48`

Run the secZ sidecar:

```bash
cargo run --bin secz
```

In another terminal, send `Hello World` through opcode `0x10` / decimal `16`:

```bash
SECS_URL="127.0.0.1:9001" cargo run --bin client -- hub 16 "Hello World"
```

Expected secZ output:

```text
secZ [Subprocess]: Invoking `bash ["-c", "echo 'Bash received payload:'; cat"]`
Bash received payload:
Hello World
```

One-command smoke test:

```bash
./examples/hello-world.sh
```

The smoke test starts secZ, sends the client packet, prints the secZ log, and stops the sidecar.

## Quick Start: JSON Through jq

Start secZ:

```bash
cargo run --bin secz
```

Send JSON through opcode `0x30` / decimal `48`:

```bash
SECS_URL="127.0.0.1:9001" cargo run --bin client -- hub 48 '{"synapse":"online","opcode":48}'
```

Expected secZ output includes formatted JSON from `jq .`.

## Bind Your Own Opcode

1. Create a service that reads bytes from stdin.

```bash
mkdir -p services
cat > services/uppercase.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
tr '[:lower:]' '[:upper:]'
EOF
chmod +x services/uppercase.sh
```

2. Register an opcode in `server/src/bin/secz.rs::main()`.

```rust
router.register(0x40, Box::new(SubprocessForwarder::new(
    "bash",
    vec!["./services/uppercase.sh"],
)));
```

3. Start secZ.

```bash
cargo run --bin secz
```

4. Send payload from secC.

```bash
SECS_URL="127.0.0.1:9001" cargo run --bin client -- hub 64 "cybernetic synapse"
```

Opcode conversion:

- `0x40` hex = `64` decimal.

## Repository Topology

```text
secS-daemon/
├── core/                  # libsec-core: packet schema, ZK proof helpers, tunnel crypto
│   └── src/
│       ├── lib.rs          # ZenithPacket, SessionHandshake, opcode constants
│       ├── zk.rs           # Ed25519 proof generation/verification helpers
│       ├── tunnel.rs       # X25519 + ChaCha20Poly1305 payload crypto
│       └── ffi.rs          # optional FFI/WASM bindings
├── client/                # secC companion client
│   └── src/main.rs         # generate/chat/hub packet sender
├── server/
│   └── src/
│       ├── main.rs         # secS daemon on 0.0.0.0:9000
│       ├── lib.rs          # shared TCP node runner and PayloadRouter trait
│       ├── session.rs      # lightweight session state for secS
│       └── bin/secz.rs     # secZ configurable sidecar gateway on 0.0.0.0:9001
├── docs/
│   └── announcement-thread.md
├── examples/
│   └── hello-world.sh      # quick-start opcode pipe demo
└── README.md
```

## Development Validation

Build/check everything:

```bash
cargo check --workspace
```

Run clippy with CI-equivalent strictness:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Run all tests:

```bash
cargo test --workspace
cargo test -p libsec-core --all-features
```

Inspect telemetry after sending packets:

```bash
sqlite3 node_telemetry.db 'select id, timestamp, opcode, payload_size from node_telemetry order by id desc limit 10;'
```

## Future-Prompt Directives

When modifying secZ:

- Do not introduce complex routing logic.
- Do not add external `hub` crate dependencies.
- Do not parse payload contents in the router.
- Do not use compile-time SQLx macros.
- To add a capability, write an external script/program and register a new `SubprocessForwarder` in `main()`.
- Keep `main()` readable as the deployment manifest.

secZ is not the hub. secZ is the Cybernetic Synapse: authenticated packet ingress, decrypted byte transport, telemetry intercept, opcode dispatch, and execution handoff.
