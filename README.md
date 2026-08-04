# 🔐 Yes Another SSH Client (YASC)

YASC is a security-first, offline-capable SSH and infrastructure access platform. The project is
currently in its **0.1 local foundation** stage.

## ✨ What is being built

- 🖥️ Direct SSH from desktop and CLI without a cloud account
- 🔑 Explicit credential custody, synchronization, and usage grants
- 🧰 Application-level encrypted local vault with Argon2id unlock and authenticated envelopes
- 🧭 Connection inspection with safe, redacted diagnostics
- 🗂️ Host inventory, OpenSSH compatibility, tunnels, SFTP, and workspace restore
- 🌐 Optional private synchronization, teams, gateway access, automation, and staged RDP support

## 🧱 Repository layout

```text
apps/cli/              First-class command-line client
crates/yasc-domain/    Stable product types and validation rules
crates/yasc-ssh/       Product-facing SSH interfaces and connection plans
crates/yasc-vault/     Credential lifecycle boundary
crates/yasc-storage/   Local persistence and migration boundary
crates/yasc-platform/  Native OS integration boundary
tests/                 Cross-crate and compatibility fixtures
```

The desktop application will be introduced after the core and IPC boundary are proven. Product
documentation lives in the separate
[YASC documentation repository](https://github.com/kewldan/yasc-docs).

## 🚀 Bootstrap

Install Rust using [`rustup`](https://rustup.rs/), then run:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p yasc-cli -- inspect admin@example.com:2222
cargo run -p yasc-cli -- inspect --json 'admin@[2001:db8::10]:2222'
cargo run -p yasc-cli -- inspect --effective admin@example.com
cargo run -p yasc-cli -- connect --config ~/.ssh/config admin@example.com
cargo run -p yasc-cli -- --database ./yasc.db host add production admin@example.com \
  --tag linux --tag production --environment production
cargo run -p yasc-cli -- --database ./yasc.db host list
```

Host-key trust is stored separately from inventory metadata. Every accepted first-use key,
authenticated update, manual rotation, and revocation creates an immutable audit event:

```bash
# Use the host identifier returned by `host add` and the base64 SSH key blob.
cargo run -p yasc-cli -- --database ./yasc.db host-key check \
  <HOST_ID> ssh-ed25519 <KEY_BASE64> --ask --json
cargo run -p yasc-cli -- --database ./yasc.db host-key trust \
  <HOST_ID> ssh-ed25519 <KEY_BASE64>
cargo run -p yasc-cli -- --database ./yasc.db host-key list <HOST_ID> --events
```

`check` never changes trust state and exits unsuccessfully for unknown, changed, revoked, or
confirmation-required keys. Explicit `trust`, `rotate`, and authenticated `accept-update`
commands are the only paths that persist trust changes.

The same format, lint, and test gates run on Linux, macOS, and Windows in GitHub Actions.

Without `--database`, the CLI stores inventory in the operating system's application-data
directory. Host records contain connection metadata only; credential plaintext belongs exclusively
to the encrypted vault boundary.

## 🛡️ Security status

This repository is under active development and is not ready to protect production credentials.
Never use unfinished vault or connection code with real secrets.

## 📄 License

Licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
