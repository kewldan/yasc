//! Local persistence, forward-only migrations, and repository implementations.

#![forbid(unsafe_code)]

use std::{collections::BTreeSet, path::Path, str::FromStr, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use yasc_domain::{Host, HostError, HostId, SshTarget, TargetParseError};

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "local_host_inventory",
    sql: r#"
        CREATE TABLE hosts (
            id                  TEXT PRIMARY KEY NOT NULL,
            label               TEXT NOT NULL CHECK (length(trim(label)) > 0),
            hostname            TEXT NOT NULL CHECK (length(hostname) > 0),
            port                INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
            username            TEXT,
            environment         TEXT,
            revision            INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
            created_at_unix     INTEGER NOT NULL DEFAULT (unixepoch()),
            updated_at_unix     INTEGER NOT NULL DEFAULT (unixepoch()),
            deleted_at_unix     INTEGER
        );

        CREATE INDEX hosts_active_label_idx
            ON hosts(label COLLATE NOCASE)
            WHERE deleted_at_unix IS NULL;

        CREATE TABLE host_tags (
            host_id             TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            tag                 TEXT NOT NULL CHECK (length(trim(tag)) > 0),
            PRIMARY KEY (host_id, tag)
        );

        CREATE INDEX host_tags_tag_idx ON host_tags(tag, host_id);
    "#,
}];

/// SQLite-backed local state. Secret material is owned by `yasc-vault`, not this repository.
pub struct SqliteStorage {
    connection: Connection,
}

impl SqliteStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        Self::initialize(connection)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let connection = Connection::open_in_memory()?;
        Self::initialize(connection)
    }

    fn initialize(connection: Connection) -> Result<Self, StorageError> {
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.busy_timeout(Duration::from_secs(5))?;

        let mut storage = Self { connection };
        storage.migrate()?;
        Ok(storage)
    }

    fn migrate(&mut self) -> Result<(), StorageError> {
        let found = self.schema_version()?;
        if found > CURRENT_SCHEMA_VERSION {
            return Err(StorageError::NewerSchema {
                found,
                supported: CURRENT_SCHEMA_VERSION,
            });
        }

        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (\
                version INTEGER PRIMARY KEY NOT NULL, \
                name TEXT NOT NULL, \
                applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch())\
            );",
        )?;

        for migration in MIGRATIONS.iter().filter(|item| item.version > found) {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(migration.sql)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, name) VALUES (?1, ?2)",
                params![migration.version, migration.name],
            )?;
            transaction.pragma_update(None, "user_version", migration.version)?;
            transaction.commit()?;
        }

        Ok(())
    }

    pub fn schema_version(&self) -> Result<u32, StorageError> {
        self.connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(StorageError::from)
    }

    pub fn save_host(&mut self, host: &Host) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            r#"
                INSERT INTO hosts (
                    id, label, hostname, port, username, environment
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(id) DO UPDATE SET
                    label = excluded.label,
                    hostname = excluded.hostname,
                    port = excluded.port,
                    username = excluded.username,
                    environment = excluded.environment,
                    revision = hosts.revision + 1,
                    updated_at_unix = unixepoch(),
                    deleted_at_unix = NULL
            "#,
            params![
                host.id.to_string(),
                host.label,
                host.target.host(),
                host.target.port(),
                host.target.username(),
                host.environment,
            ],
        )?;
        transaction.execute(
            "DELETE FROM host_tags WHERE host_id = ?1",
            [host.id.to_string()],
        )?;
        for tag in &host.tags {
            transaction.execute(
                "INSERT INTO host_tags(host_id, tag) VALUES (?1, ?2)",
                params![host.id.to_string(), tag],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn find_host(&self, id: HostId) -> Result<Option<Host>, StorageError> {
        let stored = self
            .connection
            .query_row(
                r#"
                    SELECT id, label, hostname, port, username, environment
                    FROM hosts
                    WHERE id = ?1 AND deleted_at_unix IS NULL
                "#,
                [id.to_string()],
                StoredHost::from_row,
            )
            .optional()?;

        stored.map(|host| self.restore_host(host)).transpose()
    }

    pub fn list_hosts(&self) -> Result<Vec<Host>, StorageError> {
        let mut statement = self.connection.prepare(
            r#"
                SELECT id, label, hostname, port, username, environment
                FROM hosts
                WHERE deleted_at_unix IS NULL
                ORDER BY label COLLATE NOCASE, id
            "#,
        )?;
        let stored = statement
            .query_map([], StoredHost::from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        stored
            .into_iter()
            .map(|host| self.restore_host(host))
            .collect()
    }

    pub fn remove_host(&mut self, id: HostId) -> Result<bool, StorageError> {
        let changed = self.connection.execute(
            r#"
                UPDATE hosts
                SET deleted_at_unix = unixepoch(),
                    updated_at_unix = unixepoch(),
                    revision = revision + 1
                WHERE id = ?1 AND deleted_at_unix IS NULL
            "#,
            [id.to_string()],
        )?;
        Ok(changed == 1)
    }

    fn restore_host(&self, stored: StoredHost) -> Result<Host, StorageError> {
        let id = HostId::from_str(&stored.id)
            .map_err(|error| StorageError::CorruptData(error.to_string()))?;
        let port = u16::try_from(stored.port)
            .map_err(|error| StorageError::CorruptData(error.to_string()))?;
        let target = format_target(stored.username.as_deref(), &stored.hostname, port)
            .parse::<SshTarget>()?;
        let tags = self.load_tags(id)?;

        Host::restore(id, stored.label, target, tags, stored.environment)
            .map_err(StorageError::from)
    }

    fn load_tags(&self, id: HostId) -> Result<BTreeSet<String>, StorageError> {
        let mut statement = self
            .connection
            .prepare("SELECT tag FROM host_tags WHERE host_id = ?1 ORDER BY tag")?;
        statement
            .query_map([id.to_string()], |row| row.get(0))?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(StorageError::from)
    }
}

struct StoredHost {
    id: String,
    label: String,
    hostname: String,
    port: i64,
    username: Option<String>,
    environment: Option<String>,
}

impl StoredHost {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            label: row.get(1)?,
            hostname: row.get(2)?,
            port: row.get(3)?,
            username: row.get(4)?,
            environment: row.get(5)?,
        })
    }
}

fn format_target(username: Option<&str>, hostname: &str, port: u16) -> String {
    let username = username.map_or_else(String::new, |value| format!("{value}@"));
    let hostname = if hostname.contains(':') {
        format!("[{hostname}]")
    } else {
        hostname.to_owned()
    };
    format!("{username}{hostname}:{port}")
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database schema version {found} is newer than supported version {supported}")]
    NewerSchema { found: u32, supported: u32 },
    #[error("stored data is invalid: {0}")]
    CorruptData(String),
    #[error("stored SSH target is invalid: {0}")]
    InvalidTarget(#[from] TargetParseError),
    #[error("stored host is invalid: {0}")]
    InvalidHost(#[from] HostError),
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn host(label: &str, target: &str) -> Host {
        let mut host = Host::new(label, target.parse().unwrap()).unwrap();
        host.tags = ["linux".to_owned(), "production".to_owned()]
            .into_iter()
            .collect();
        host.environment = Some("production".to_owned());
        host
    }

    #[test]
    fn applies_migrations_once_and_reopens_database() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("yasc.db");

        assert_eq!(
            SqliteStorage::open(&path)
                .unwrap()
                .schema_version()
                .unwrap(),
            CURRENT_SCHEMA_VERSION
        );
        assert_eq!(
            SqliteStorage::open(&path)
                .unwrap()
                .schema_version()
                .unwrap(),
            CURRENT_SCHEMA_VERSION
        );
    }

    #[test]
    fn saves_lists_and_restores_ipv6_host() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let expected = host("Production", "admin@[2001:db8::10]:2222");

        storage.save_host(&expected).unwrap();

        assert_eq!(
            storage.find_host(expected.id).unwrap(),
            Some(expected.clone())
        );
        assert_eq!(storage.list_hosts().unwrap(), vec![expected]);
    }

    #[test]
    fn removal_creates_hidden_tombstone_and_save_restores_it() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let expected = host("Production", "admin@example.com");
        storage.save_host(&expected).unwrap();

        assert!(storage.remove_host(expected.id).unwrap());
        assert_eq!(storage.find_host(expected.id).unwrap(), None);
        assert!(storage.list_hosts().unwrap().is_empty());

        storage.save_host(&expected).unwrap();
        assert_eq!(storage.find_host(expected.id).unwrap(), Some(expected));
    }

    #[test]
    fn rejects_database_created_by_newer_application() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        storage
            .connection
            .pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION + 1)
            .unwrap();

        assert!(matches!(
            storage.migrate(),
            Err(StorageError::NewerSchema { .. })
        ));
    }
}
