# secS-daemon

secS-daemon is a Cybernetic Synapse: a minimal cryptographic transport layer for moving machine intent across trust boundaries, then binding that intent to concrete execution surfaces.

The repository contains two intentionally separate interfaces:

- secS (`server/src/main.rs`, port `9000`): the stable secure service interface. It handles the canonical `OPCODE_GENERATE = 0x01` and `OPCODE_CHAT = 0x02` protocol surface used by the secS daemon.
- secZ (`server/src/bin/secz.rs`, port `9001`): the extensible sidecar gateway. It accepts the same `ZenithPacket` envelope, validates the proof envelope, decrypts payload bytes when a tunnel key is configured, and dispatches by `u8` opcode to a configured `MachineProgram`.

secS is the protocol-facing daemon. secZ is the configurable execution synapse.

## System Identity

secZ is a cryptographically hardened, zero-knowledge authenticated Machine-to-Machine transport node and execution gateway.

Design pattern:

- Pure Sidecar / Reverse-Proxy Gateway.

Core tenet:

- secZ is strictly a secure execution environment.
- secZ contains no internal domain logic.
- secZ contains no agents.
- secZ contains no external `hub` crate dependencies.

Configuration-as-code:

- `server/src/bin/secz.rs::main()` is the deployment manifest.
- The manifest binds `u8` opcodes directly to system capabilities.
- Adding a capability should be a small, auditable manifest diff.

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
├── examples/
│   └── hello-world.sh      # quick-start opcode pipe demo
└── README.md
```

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

Important CLI detail:

- The `client hub` command parses opcode as decimal `u8`.
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

Critical rule for future changes:

- Do not use `sqlx::query!` or other compile-time SQL macros.
- Use runtime SQL only:

```rust
sqlx::query("INSERT INTO node_telemetry (opcode, payload_size) VALUES (?, ?)")
    .bind(opcode)
    .bind(payload_size)
    .execute(&pool)
    .await;
```

Reason:

- Compile-time SQLx macros require a database or offline cache at build time and can panic/fail in clean environments.
- secZ must compile without a pre-existing SQLite database.

## MachineProgram Extensibility Model

secZ delegates decrypted payloads using this async trait:

```rust
#[async_trait]
pub trait MachineProgram: Send + Sync {
    async fn execute(&self, payload: &[u8]);
}
```

The manifest owns the registry:

```rust
let mut router = ConfigurableRouter::new(pool);
router.register(0x10, Box::new(SubprocessForwarder::new("bash", vec!["-c", "echo 'Bash received payload:'; cat"])));
router.register(0x20, Box::new(LocalRustQueue));
router.register(0x30, Box::new(SubprocessForwarder::new("jq", vec!["."])));
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

## Binding Your Own Opcode to a Service

1. Create a service that reads bytes from stdin.

Example:

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

## secS vs secZ

Use secS when:

- You are exercising the canonical daemon interface.
- You are working with core protocol operations like generate/chat.
- You want stable default behavior on port `9000`.

Use secZ when:

- You want to bind machine opcodes to local tools or services.
- You need M2M sidecar behavior on port `9001`.
- You want a byte-level execution gateway with no hub dependency.
- You want auditable, SQLite-backed telemetry per routed packet.

Boundary rule:

- secS defines the stable secure service surface.
- secZ extends the synapse by binding opcodes to execution targets.
- Do not merge hub-style agent/domain logic into secZ.

## Development Validation

Build/check everything:

```bash
cargo check --workspace
```

Check only secZ:

```bash
cargo check --bin secz
```

Run core crypto tests:

```bash
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
