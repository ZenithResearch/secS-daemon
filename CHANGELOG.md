# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Added

- Added exhaustive unit coverage across packet serialization, ZK proof verification, Merkle proofs, tunnel encryption/decryption, client command mapping, session state, secZ key parsing, proof gates, payload decryption, and router telemetry — hardens edge cases and security-critical behavior before expanding opcode-bound services.
- Added the secZ configurable sidecar gateway with opcode-to-`MachineProgram` routing, subprocess forwarding, native Rust binding stubs, and SQLite telemetry — establishes the extensible Cybernetic Synapse interface without coupling execution to a hub crate.
- Added secC client `hub` dispatch support with decimal opcode selection — enables operators to send arbitrary M2M payloads to secZ-bound services.
- Added a Hello World opcode-pipe quick start script — gives new users a one-command path to validate opcode `0x10`/decimal `16` subprocess forwarding.
- Added the Cybernetic Synapse README — documents the secS versus secZ boundary, packet flow, telemetry constraints, and service-binding workflow so future agents preserve the architecture.

### Changed

- Refactored the server into a reusable TCP node runner plus secS router — separates the stable secS protocol interface from the extensible secZ execution gateway.

### Fixed

- Gated optional FFI code behind the intended feature/target conditions — prevents non-FFI builds from pulling WASM-specific bindings into normal workspace checks.
