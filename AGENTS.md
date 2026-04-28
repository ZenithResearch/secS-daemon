# secS-daemon Agent Rules

These rules apply to this repository and all agent sessions within it.

---

## Project Overview

**secS-daemon** is a secure daemon system implementing encrypted communication protocols.

**Remote**: `git@github.com:ZenithResearch/secS-daemon.git`

**Core Features**:
- `libsec-core`: Cryptographic primitives (zk proofs, X25519 tunnel encryption)
- `client`: Command-line interface for sending encrypted messages
- `server`: Daemon listening on port 9000 for ZenithPacket protocol

---

## Changelog

Maintain `CHANGELOG.md` in [Keep a Changelog](https://keepachangelog.com) format.

**After each commit**, add an entry under `## [Unreleased]` using the format:

```
- <what changed> — <why it was changed / what problem it solves>
```

Categories: `### Added` · `### Changed` · `### Fixed` · `### Removed`

The *why* is required. The diff shows what changed — the changelog records the reasoning that won't survive in the code.

Skip entries for: whitespace-only commits, immediately reverted commits, lock file bumps with no behavioral intent change.

Never promote `[Unreleased]` to a version block without an explicit instruction.

If `CHANGELOG.md` does not exist yet, create it:

```markdown
# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]
```

---

## Protocol Specification

### ZenithPacket Structure

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

### Standard Opcodes (Epic 1.7)

- `OPCODE_GENERATE = 0x01`: Generate session key
- `OPCODE_CHAT = 0x02`: Send encrypted chat message

### SessionHandshake

Used for X25519 key exchange during connection establishment:

```rust
pub struct SessionHandshake {
    pub ephemeral_public_key: [u8; 32],
    pub timestamp: u64,
}
```

---

## Development Guidelines

### Testing

All cryptographic functions must include unit tests:
- `zk.rs`: Proof generation/verification cycle
- `tunnel.rs`: Diffie-Hellman key exchange + encryption/decryption cycle

Run tests with:
```bash
cargo test -p libsec-core --all-features
```

Expected: All tests pass with 0 warnings.

### API Migration Notes

This project uses **dalek 2.0** APIs:
- `x25519-dalek`: Use `PublicKey::from(&ephemeral_secret)` for public key extraction
- `ed25519-dalek`: Use `SigningKey::from_bytes(&[u8; 32])` for key generation from seed

### Build Configuration

The `uniffi` feature enables FFI bindings for WASM:
```bash
cargo test --all-features
```

The `#![cfg_attr(not(feature = "uniffi"), no_std)]` attribute allows compilation in both `no_std` and `std` contexts.

---

## Repository Structure

```
secS-daemon/
├── core/
│   ├── src/
│   │   ├── lib.rs      # Main library, packet structs, opcodes
│   │   ├── zk.rs       # Ed25519 zero-knowledge proofs
│   │   ├── tunnel.rs   # X25519 Diffie-Hellman + ChaCha20 encryption
│   │   └── ffi.rs      # WASM FFI bindings (uniffi feature)
│   └── Cargo.toml
├── client/             # CLI client for sending encrypted messages
├── server/             # Daemon server (port 9000)
├── CHANGELOG.md
└── AGENTS.md
```

---

## Git Workflow

- Main branch: `main`
- Remote organization: `ZenithResearch`
- Remote URL: `git@github.com:ZenithResearch/secS-daemon.git`
