#![forbid(unsafe_code)]

use std::{fs, path::Path, process::Command};

use russh::keys::{
    PrivateKey,
    ssh_key::{Algorithm, LineEnding},
};

fn yasc(database: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_yasc"))
        .arg("--database")
        .arg(database)
        .args(arguments)
        .output()
        .expect("yasc must execute")
}

#[cfg(unix)]
fn yasc_with_agent(database: &Path, socket: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_yasc"))
        .arg("--database")
        .arg(database)
        .args(arguments)
        .env("SSH_AUTH_SOCK", socket)
        .output()
        .expect("yasc must execute")
}

#[cfg(unix)]
struct AgentFixture {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl AgentFixture {
    fn start(socket: &Path, private_key: PrivateKey) -> Self {
        use futures::stream;
        use russh::keys::agent::client::AgentClient;
        use tokio::net::{UnixListener, UnixStream};

        let socket = socket.to_owned();
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let listener = UnixListener::bind(&socket).unwrap();
                    let incoming = stream::unfold(listener, |listener| async move {
                        Some((listener.accept().await.map(|(stream, _)| stream), listener))
                    });
                    let server = russh::keys::agent::server::serve(Box::pin(incoming), ());
                    tokio::pin!(server);
                    let preload = async {
                        let stream = UnixStream::connect(&socket).await.unwrap();
                        let mut client = AgentClient::connect(stream);
                        client.add_identity(&private_key, &[]).await.unwrap();
                        ready_sender.send(()).unwrap();
                        futures::future::pending::<()>().await;
                    };
                    tokio::pin!(preload);
                    tokio::select! {
                        result = &mut server => result.unwrap(),
                        () = &mut preload => unreachable!(),
                        _ = shutdown_receiver => {},
                    }
                });
        });
        ready_receiver.recv().unwrap();
        Self {
            shutdown: Some(shutdown_sender),
            thread: Some(thread),
        }
    }
}

#[cfg(unix)]
impl Drop for AgentFixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn json(output: &std::process::Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout must contain JSON")
}

fn write_secret(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn create_host(database: &Path, label: &str, target: &str) -> String {
    json(&yasc(database, &["host", "add", label, target, "--json"]))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn encrypted_credential_import_lists_metadata_and_enforces_host_grant() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("yasc.db");
    let vault_password = directory.path().join("vault-password");
    let wrong_password = directory.path().join("wrong-password");
    let key_file = directory.path().join("id_ed25519");
    write_secret(&vault_password, b"correct horse battery staple\n");
    write_secret(&wrong_password, b"wrong password\n");
    let private_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let private_key = private_key.to_openssh(LineEnding::LF).unwrap();
    write_secret(&key_file, private_key.as_bytes());

    let allowed_host = create_host(&database, "Allowed", "admin@allowed.invalid");
    let denied_host = create_host(&database, "Denied", "admin@denied.invalid");
    json(&yasc(
        &database,
        &[
            "vault",
            "init",
            "--password-file",
            vault_password.to_str().unwrap(),
            "--json",
        ],
    ));

    let wrong_unlock = yasc(
        &database,
        &[
            "credential",
            "import-key",
            "Production key",
            "--host",
            &allowed_host,
            "--key-file",
            key_file.to_str().unwrap(),
            "--vault-password-file",
            wrong_password.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(!wrong_unlock.status.success());
    assert_eq!(
        json(&yasc(&database, &["credential", "list", "--json"])),
        serde_json::json!([])
    );

    let imported = json(&yasc(
        &database,
        &[
            "credential",
            "import-key",
            "Production key",
            "--host",
            &allowed_host,
            "--key-file",
            key_file.to_str().unwrap(),
            "--vault-password-file",
            vault_password.to_str().unwrap(),
            "--json",
        ],
    ));
    let credential_id = imported["id"].as_str().unwrap();
    assert_eq!(imported["provider"], "local_vault");
    assert_eq!(imported["synchronization"], "local_only");
    assert_eq!(imported["host_ids"], serde_json::json!([allowed_host]));
    assert_eq!(imported["has_private_key"], true);

    let listed = json(&yasc(&database, &["credential", "list", "--json"]));
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0], imported);
    assert!(
        !String::from_utf8_lossy(&listed.to_string().into_bytes()).contains(private_key.as_str())
    );
    let database_bytes = fs::read(&database).unwrap();
    assert!(
        !database_bytes
            .windows(private_key.len())
            .any(|window| window == private_key.as_bytes())
    );

    let unauthorized = yasc(
        &database,
        &[
            "exec",
            &denied_host,
            "--credential",
            credential_id,
            "--vault-password-file",
            vault_password.to_str().unwrap(),
            "true",
        ],
    );
    assert!(!unauthorized.status.success());
    assert!(String::from_utf8_lossy(&unauthorized.stderr).contains("does not authorize"));

    let non_terminal_shell = yasc(
        &database,
        &[
            "shell",
            &allowed_host,
            "--credential",
            credential_id,
            "--vault-password-file",
            vault_password.to_str().unwrap(),
        ],
    );
    assert!(!non_terminal_shell.status.success());
    assert!(
        String::from_utf8_lossy(&non_terminal_shell.stderr)
            .contains("requires terminal stdin and stdout")
    );
}

#[cfg(unix)]
#[test]
fn external_agent_import_persists_only_public_metadata_and_host_grant() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("yasc.db");
    let socket = directory.path().join("agent.sock");
    let private_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let encoded_private_key = private_key.to_openssh(LineEnding::LF).unwrap();
    let _agent = AgentFixture::start(&socket, private_key);
    let host_id = create_host(&database, "Agent host", "admin@agent.invalid");

    let identities = json(&yasc_with_agent(
        &database,
        &socket,
        &["agent", "list", "--json"],
    ));
    let fingerprint = identities[0]["fingerprint"].as_str().unwrap();
    let imported = json(&yasc_with_agent(
        &database,
        &socket,
        &[
            "credential",
            "import-agent",
            "Workstation agent",
            fingerprint,
            "--host",
            &host_id,
            "--json",
        ],
    ));

    assert_eq!(imported["provider"], "open_ssh_agent");
    assert_eq!(imported["custody"], "external_provider");
    assert_eq!(imported["synchronization"], "local_only");
    assert_eq!(imported["host_ids"], serde_json::json!([host_id]));
    assert_eq!(imported["has_private_key"], false);
    assert_eq!(imported["external_key"]["fingerprint"], fingerprint);
    assert_eq!(
        json(&yasc(&database, &["credential", "list", "--json"]))[0],
        imported
    );
    let database_bytes = fs::read(&database).unwrap();
    assert!(
        !database_bytes
            .windows(encoded_private_key.len())
            .any(|window| { window == encoded_private_key.as_bytes() })
    );
}
