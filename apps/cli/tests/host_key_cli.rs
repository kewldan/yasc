#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const KEY_ONE: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB";
const KEY_TWO: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC";
static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must be valid")
            .as_nanos();
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "yasc-cli-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test directory must be created");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn yasc(database: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_yasc"))
        .arg("--database")
        .arg(database)
        .args(arguments)
        .output()
        .expect("yasc must execute")
}

fn json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout must contain JSON")
}

fn create_host(database: &Path) -> String {
    json(&yasc(
        database,
        &["host", "add", "production", "admin@example.com", "--json"],
    ))["id"]
        .as_str()
        .expect("host id must be a string")
        .to_owned()
}

#[test]
fn trust_update_revoke_flow_is_fail_closed_and_audited() {
    let directory = TestDirectory::new();
    let database = directory.0.join("yasc.db");
    let host_id = create_host(&database);

    let confirmation_required = yasc(
        &database,
        &[
            "host-key",
            "check",
            &host_id,
            "ssh-ed25519",
            KEY_ONE,
            "--ask",
            "--json",
        ],
    );
    assert!(!confirmation_required.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&confirmation_required.stdout)
            .expect("confirmation decision must be JSON")["decision"],
        "confirm_first_use"
    );

    let trusted = json(&yasc(
        &database,
        &[
            "host-key",
            "trust",
            &host_id,
            "ssh-ed25519",
            KEY_ONE,
            "--json",
        ],
    ));
    let first_fingerprint = trusted["fingerprint"]
        .as_str()
        .expect("fingerprint must be a string")
        .to_owned();

    let known = yasc(
        &database,
        &[
            "host-key",
            "check",
            &host_id,
            "ssh-ed25519",
            KEY_ONE,
            "--json",
        ],
    );
    assert!(known.status.success());
    assert_eq!(json(&known)["decision"], "accept_known");

    let changed = yasc(
        &database,
        &[
            "host-key",
            "check",
            &host_id,
            "ssh-ed25519",
            KEY_TWO,
            "--json",
        ],
    );
    assert!(!changed.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&changed.stdout)
            .expect("rejection must still be JSON")["decision"],
        "reject_changed"
    );

    json(&yasc(
        &database,
        &[
            "host-key",
            "accept-update",
            &host_id,
            "ssh-ed25519",
            KEY_TWO,
            "--authenticated-by",
            &first_fingerprint,
            "--json",
        ],
    ));

    json(&yasc(
        &database,
        &["host-key", "revoke", &host_id, &first_fingerprint, "--json"],
    ));
    let revoked = yasc(
        &database,
        &[
            "host-key",
            "check",
            &host_id,
            "ssh-ed25519",
            KEY_ONE,
            "--json",
        ],
    );
    assert!(!revoked.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&revoked.stdout)
            .expect("rejection must still be JSON")["decision"],
        "reject_revoked"
    );

    let events = json(&yasc(
        &database,
        &["host-key", "list", &host_id, "--events", "--json"],
    ));
    assert_eq!(events.as_array().expect("events must be an array").len(), 3);
}

#[test]
fn manual_rotation_requires_the_expected_active_fingerprint() {
    let directory = TestDirectory::new();
    let database = directory.0.join("yasc.db");
    let host_id = create_host(&database);
    let trusted = json(&yasc(
        &database,
        &[
            "host-key",
            "trust",
            &host_id,
            "ssh-ed25519",
            KEY_ONE,
            "--json",
        ],
    ));
    let fingerprint = trusted["fingerprint"]
        .as_str()
        .expect("fingerprint must be a string");

    let stale_rotation = yasc(
        &database,
        &[
            "host-key",
            "rotate",
            &host_id,
            "ssh-ed25519",
            KEY_TWO,
            "--replace",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--json",
        ],
    );
    assert!(!stale_rotation.status.success());

    json(&yasc(
        &database,
        &[
            "host-key",
            "rotate",
            &host_id,
            "ssh-ed25519",
            KEY_TWO,
            "--replace",
            fingerprint,
            "--json",
        ],
    ));
    let records = json(&yasc(&database, &["host-key", "list", &host_id, "--json"]));
    let records = records.as_array().expect("records must be an array");
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| record["state"] == "superseded"));
    assert!(records.iter().any(|record| record["state"] == "trusted"));
}
