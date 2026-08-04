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
apps/desktop/          Tauri 2 + React macOS desktop client
crates/yasc-domain/    Stable product types and validation rules
crates/yasc-ssh/       Product-facing SSH interfaces and connection plans
crates/yasc-vault/     Credential lifecycle boundary
crates/yasc-storage/   Local persistence and migration boundary
crates/yasc-platform/  Native OS integration boundary
tests/                 Cross-crate and compatibility fixtures
```

The macOS Desktop MVP now provides local inventory, external-agent credential registration,
explicit first-use host-key trust, a native interactive SSH terminal, and a bounded native SFTP
browser with create-only upload. Product documentation
lives in the separate
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
cargo run -p yasc-cli -- --database ./yasc.db host import-open-ssh \
  --config ~/.ssh/config --json
cargo run -p yasc-cli -- --database ./yasc.db host import-open-ssh \
  --config ~/.ssh/config --apply
```

Run the macOS Desktop MVP:

```bash
cd apps/desktop
npm ci
npm run tauri dev
```

Build a local application bundle and disk image:

```bash
cd apps/desktop
npm run tauri build
```

Desktop preview releases are produced for Apple Silicon and Intel by the `Desktop release`
workflow. Pushing a tag such as `desktop-v0.1.0` creates a draft prerelease with `.app` and `.dmg`
assets. Current preview artifacts are ad-hoc signed and are not notarized.

OpenSSH inventory import is preview-only unless `--apply` is explicit. It discovers literal aliases
and asks `ssh -G` for their exact effective target. Dynamic patterns are reported, entries using
unrepresented routing or host-identity semantics are blocked, and `Include` or `Match exec` is
rejected before OpenSSH runs. Imported hosts are committed atomically and tagged `openssh-import`;
credentials and other connection behavior are never silently copied.

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

The native handshake probe evaluates the exact server key before authentication and disconnects
without opening a session. First use remains an explicit state change:

```bash
cargo run -p yasc-cli -- --database ./yasc.db host-key probe <HOST_ID> --ask --json
cargo run -p yasc-cli -- --database ./yasc.db host-key probe <HOST_ID> --trust-first-use
```

After a host key is trusted, execute a bounded native SSH command with a key that remains in memory
only for the request:

```bash
chmod 600 ~/.ssh/id_ed25519
cargo run -p yasc-cli -- --database ./yasc.db exec <HOST_ID> \
  --identity ~/.ssh/id_ed25519 'uname -a'
```

Or initialize the encrypted vault, import a validated key with an explicit host grant, and select
the resulting credential by its identifier:

```bash
chmod 600 ./vault-password ~/.ssh/id_ed25519
cargo run -p yasc-cli -- --database ./yasc.db vault init \
  --password-file ./vault-password
cargo run -p yasc-cli -- --database ./yasc.db credential import-key "Production key" \
  --host <HOST_ID> --key-file ~/.ssh/id_ed25519 \
  --vault-password-file ./vault-password
cargo run -p yasc-cli -- --database ./yasc.db credential list
cargo run -p yasc-cli -- --database ./yasc.db exec <HOST_ID> \
  --credential <CREDENTIAL_ID> --vault-password-file ./vault-password 'uname -a'
cargo run -p yasc-cli -- --database ./yasc.db shell <HOST_ID> \
  --credential <CREDENTIAL_ID> --vault-password-file ./vault-password
```

To keep a private key inside an existing SSH agent, register its public fingerprint instead of
importing secret material. `openssh` uses `SSH_AUTH_SOCK` on Unix and the configured OpenSSH agent
pipe on Windows; `pageant` is available on Windows:

```bash
cargo run -p yasc-cli -- agent list
cargo run -p yasc-cli -- --database ./yasc.db credential import-agent \
  "Workstation agent" <SHA256_FINGERPRINT> --host <HOST_ID>
cargo run -p yasc-cli -- --database ./yasc.db exec <HOST_ID> \
  --credential <CREDENTIAL_ID> 'uname -a'
cargo run -p yasc-cli -- --database ./yasc.db shell <HOST_ID> \
  --credential <CREDENTIAL_ID>
cargo run -p yasc-cli -- --database ./yasc.db sftp list <HOST_ID> /var/log \
  --credential <CREDENTIAL_ID>
cargo run -p yasc-cli -- --database ./yasc.db sftp download <HOST_ID> \
  /var/log/app.log ./app.log --credential <CREDENTIAL_ID> --max-bytes 104857600
cargo run -p yasc-cli -- --database ./yasc.db sftp upload <HOST_ID> \
  ./release.tar /srv/releases/release.tar --credential <CREDENTIAL_ID> --max-bytes 104857600
```

The native command path requires a username in the stored target, applies strict persistent
host-key verification before authentication, rejects insecure key-file permissions on Unix, never
accepts a passphrase on the command line, enforces a timeout and bounded output, and returns a
non-successful CLI status when the remote command fails. Vault imports validate the private key
before encryption, store key passphrases as separate authenticated envelopes, and require a
host-scoped direct-SSH grant before decryption. The `exec` command is a one-shot workflow; native
interactive `shell` sessions use a confirmed PTY request, stream terminal bytes without retaining
terminal contents, propagate terminal-size changes, and restore local raw mode on every return
path. External-agent credentials persist only the selected public key, fingerprint metadata,
provider, and host grant; the agent performs every signature and the private key is never exported
to YASC. Native-keystore unlock is still in development.

Native SFTP uses the same strict host-key and host-scoped credential checks as terminal sessions.
Directory results and downloads are bounded. Upload writes a unique exclusive sibling temporary
file and publishes it with SFTP v3 rename; it never deletes or truncates an existing destination.
CLI downloads persist through a local no-clobber temporary file. Resume, checksums, conflict UX,
remote editing, cancellation, and transfer recovery remain planned queue work.

The same core format, lint, and test gates run on Linux, macOS, and Windows in GitHub Actions. A
separate macOS job tests both Desktop layers and builds the application bundle in parallel.

Without `--database`, the CLI stores inventory in the operating system's application-data
directory. Host records contain connection metadata only; credential plaintext belongs exclusively
to the encrypted vault boundary.

## 🛡️ Security status

This repository is under active development and is not ready to protect production credentials.
Never use unfinished vault or connection code with real secrets.

## 📄 License

Licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
