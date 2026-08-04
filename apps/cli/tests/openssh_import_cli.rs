#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix {
    use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

    fn yasc(database: &Path, arguments: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_yasc"))
            .arg("--database")
            .arg(database)
            .args(arguments)
            .output()
            .expect("yasc must execute")
    }

    fn json(output: &std::process::Output) -> serde_json::Value {
        assert!(
            output.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("stdout must contain JSON")
    }

    #[test]
    fn openssh_import_previews_blockers_then_persists_only_safe_hosts() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("yasc.db");
        let config = directory.path().join("config");
        let fake_ssh = directory.path().join("ssh-fixture");
        fs::write(
            &config,
            "Host production routed *.internal\n  User deploy\n",
        )
        .unwrap();
        fs::write(
            &fake_ssh,
            r#"#!/bin/sh
for last do :; done
case "$last" in
  production)
    printf '%s\n' 'user deploy' 'hostname 192.0.2.10' 'port 2200' 'canonicalizehostname false'
    ;;
  routed)
    printf '%s\n' 'user deploy' 'hostname 192.0.2.20' 'port 22' 'canonicalizehostname false' 'proxyjump bastion'
    ;;
  *)
    exit 64
    ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700)).unwrap();

        let arguments = [
            "host",
            "import-open-ssh",
            "--config",
            config.to_str().unwrap(),
            "--ssh-binary",
            fake_ssh.to_str().unwrap(),
            "--json",
        ];
        let preview = json(&yasc(&database, &arguments));
        assert_eq!(preview["applied"], false);
        assert_eq!(preview["ready"].as_array().unwrap().len(), 1);
        assert_eq!(preview["ready"][0]["label"], "production");
        assert_eq!(preview["ready"][0]["target"]["host"], "192.0.2.10");
        assert_eq!(
            preview["preview"]["candidates"][1]["blockers"],
            serde_json::json!(["proxy_jump"])
        );
        assert_eq!(
            preview["preview"]["skipped_patterns"][0],
            serde_json::json!({
                "pattern": "*.internal",
                "reason": "dynamic_pattern"
            })
        );
        assert_eq!(
            json(&yasc(&database, &["host", "list", "--json"])),
            serde_json::json!([])
        );

        let mut apply_arguments = arguments.to_vec();
        apply_arguments.push("--apply");
        let applied = json(&yasc(&database, &apply_arguments));
        assert_eq!(applied["applied"], true);
        let hosts = json(&yasc(&database, &["host", "list", "--json"]));
        assert_eq!(hosts.as_array().unwrap().len(), 1);
        assert_eq!(hosts[0]["label"], "production");
        assert_eq!(hosts[0]["tags"], serde_json::json!(["openssh-import"]));

        let repeated = json(&yasc(&database, &apply_arguments));
        assert!(repeated["ready"].as_array().unwrap().is_empty());
        assert_eq!(
            repeated["already_present_aliases"],
            serde_json::json!(["production"])
        );
        assert_eq!(json(&yasc(&database, &["host", "list", "--json"])), hosts);
    }
}
