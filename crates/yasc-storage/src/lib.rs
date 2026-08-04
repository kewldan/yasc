//! Local persistence, forward-only migrations, and repository implementations.

#![forbid(unsafe_code)]

use std::{collections::BTreeSet, path::Path, str::FromStr, time::Duration};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;
use yasc_domain::{
    Credential, CredentialGrant, CredentialId, Host, HostError, HostId, HostKeyAlgorithm,
    HostKeyError, HostKeyEvent, HostKeyEventId, HostKeyEventKind, HostKeyFingerprint,
    HostKeyHistory, HostKeyId, HostKeyMaterial, HostKeyRecord, HostKeyRecordState, HostKeySource,
    SshTarget, TargetParseError,
};
use yasc_vault::{
    SecretKind, SecretRef, StoredSecretEnvelope, StoredVaultHeader, VaultKdfParams, VaultStore,
    VaultStoreError,
};

pub const CURRENT_SCHEMA_VERSION: u32 = 5;

struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
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
    },
    Migration {
        version: 2,
        name: "encrypted_local_vault",
        sql: r#"
            CREATE TABLE vault_header (
                singleton               INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                format_version          INTEGER NOT NULL CHECK (format_version > 0),
                kdf_memory_kib          INTEGER NOT NULL CHECK (kdf_memory_kib > 0),
                kdf_iterations          INTEGER NOT NULL CHECK (kdf_iterations > 0),
                kdf_parallelism         INTEGER NOT NULL CHECK (kdf_parallelism > 0),
                salt                    BLOB NOT NULL,
                verifier_nonce          BLOB NOT NULL,
                verifier_ciphertext     BLOB NOT NULL,
                revision                INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
                created_at_unix         INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at_unix         INTEGER NOT NULL DEFAULT (unixepoch())
            );

            CREATE TABLE vault_secrets (
                id                      TEXT PRIMARY KEY NOT NULL,
                credential_id           TEXT NOT NULL,
                kind                    INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 255),
                format_version          INTEGER NOT NULL CHECK (format_version > 0),
                key_version             INTEGER NOT NULL CHECK (key_version > 0),
                nonce                   BLOB NOT NULL,
                ciphertext              BLOB NOT NULL,
                revision                INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
                created_at_unix         INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at_unix         INTEGER NOT NULL DEFAULT (unixepoch()),
                deleted_at_unix         INTEGER
            );

            CREATE INDEX vault_secrets_credential_idx
                ON vault_secrets(credential_id, kind)
                WHERE deleted_at_unix IS NULL;
        "#,
    },
    Migration {
        version: 3,
        name: "explicit_host_port",
        sql: r#"
            ALTER TABLE hosts
                ADD COLUMN port_explicit INTEGER NOT NULL DEFAULT 0
                CHECK (port_explicit IN (0, 1));
        "#,
    },
    Migration {
        version: 4,
        name: "host_key_history",
        sql: r#"
            CREATE TABLE host_keys (
                id                      TEXT PRIMARY KEY NOT NULL,
                host_id                 TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                algorithm               TEXT NOT NULL,
                key_blob                BLOB NOT NULL,
                fingerprint             TEXT NOT NULL,
                state                   TEXT NOT NULL,
                source                  TEXT NOT NULL,
                first_seen_at_unix      INTEGER NOT NULL,
                last_seen_at_unix       INTEGER NOT NULL,
                superseded_by           TEXT,
                revision                INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
                UNIQUE(host_id, fingerprint)
            );

            CREATE INDEX host_keys_active_idx
                ON host_keys(host_id, state, algorithm);

            CREATE TABLE host_key_events (
                id                      TEXT PRIMARY KEY NOT NULL,
                host_id                 TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                fingerprint             TEXT NOT NULL,
                previous_fingerprint    TEXT,
                kind                    TEXT NOT NULL,
                source                  TEXT NOT NULL,
                occurred_at_unix        INTEGER NOT NULL
            );

            CREATE INDEX host_key_events_host_time_idx
                ON host_key_events(host_id, occurred_at_unix, id);
        "#,
    },
    Migration {
        version: 5,
        name: "credential_metadata_and_grants",
        sql: r#"
            CREATE TABLE credentials (
                id                      TEXT PRIMARY KEY NOT NULL,
                payload_json            TEXT NOT NULL,
                created_at_unix         INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at_unix         INTEGER NOT NULL DEFAULT (unixepoch()),
                deleted_at_unix         INTEGER
            );

            CREATE TABLE credential_secret_refs (
                credential_id           TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
                kind                    INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 255),
                secret_id               TEXT NOT NULL REFERENCES vault_secrets(id),
                PRIMARY KEY (credential_id, kind),
                UNIQUE(secret_id)
            );

            CREATE TABLE credential_grants (
                id                      TEXT PRIMARY KEY NOT NULL,
                credential_id           TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
                payload_json            TEXT NOT NULL
            );

            CREATE INDEX credential_grants_credential_idx
                ON credential_grants(credential_id, id);
        "#,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedCredential {
    pub credential: Credential,
    pub secret_refs: Vec<SecretRef>,
    pub grants: Vec<CredentialGrant>,
}

impl PersistedCredential {
    #[must_use]
    pub fn secret(&self, kind: SecretKind) -> Option<SecretRef> {
        self.secret_refs
            .iter()
            .copied()
            .find(|reference| reference.kind == kind)
    }
}

/// SQLite-backed local state. Secret material is owned by `yasc-vault`, not this repository.
pub struct SqliteStorage {
    connection: Connection,
}

impl VaultStore for SqliteStorage {
    fn load_vault_header(&self) -> Result<Option<StoredVaultHeader>, VaultStoreError> {
        self.connection
            .query_row(
                r#"
                    SELECT format_version, kdf_memory_kib, kdf_iterations, kdf_parallelism,
                           salt, verifier_nonce, verifier_ciphertext
                    FROM vault_header
                    WHERE singleton = 1
                "#,
                [],
                |row| {
                    Ok(StoredVaultHeader {
                        format_version: row.get(0)?,
                        kdf: VaultKdfParams {
                            memory_kib: row.get(1)?,
                            iterations: row.get(2)?,
                            parallelism: row.get(3)?,
                        },
                        salt: row.get(4)?,
                        verifier_nonce: row.get(5)?,
                        verifier_ciphertext: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(|_| VaultStoreError)
    }

    fn save_vault_header(&mut self, header: &StoredVaultHeader) -> Result<(), VaultStoreError> {
        self.connection
            .execute(
                r#"
                    INSERT INTO vault_header (
                        singleton, format_version, kdf_memory_kib, kdf_iterations,
                        kdf_parallelism, salt, verifier_nonce, verifier_ciphertext
                    ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    header.format_version,
                    header.kdf.memory_kib,
                    header.kdf.iterations,
                    header.kdf.parallelism,
                    header.salt,
                    header.verifier_nonce,
                    header.verifier_ciphertext,
                ],
            )
            .map(|_| ())
            .map_err(|_| VaultStoreError)
    }

    fn load_secret_envelope(
        &self,
        id: uuid::Uuid,
    ) -> Result<Option<StoredSecretEnvelope>, VaultStoreError> {
        self.connection
            .query_row(
                r#"
                    SELECT id, credential_id, kind, format_version, key_version, nonce, ciphertext
                    FROM vault_secrets
                    WHERE id = ?1 AND deleted_at_unix IS NULL
                "#,
                [id.to_string()],
                |row| {
                    let id = row
                        .get::<_, String>(0)?
                        .parse()
                        .map_err(|error| sql_conversion_error(0, error))?;
                    let credential_id = row
                        .get::<_, String>(1)?
                        .parse::<uuid::Uuid>()
                        .map(yasc_domain::CredentialId::from_uuid)
                        .map_err(|error| sql_conversion_error(1, error))?;
                    let kind_code = row.get::<_, u8>(2)?;
                    let kind = SecretKind::from_code(kind_code).ok_or_else(|| {
                        sql_conversion_error(
                            2,
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "unknown secret kind",
                            ),
                        )
                    })?;
                    Ok(StoredSecretEnvelope {
                        id,
                        credential_id,
                        kind,
                        format_version: row.get(3)?,
                        key_version: row.get(4)?,
                        nonce: row.get(5)?,
                        ciphertext: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(|_| VaultStoreError)
    }

    fn save_secret_envelope(
        &mut self,
        envelope: &StoredSecretEnvelope,
    ) -> Result<(), VaultStoreError> {
        self.connection
            .execute(
                r#"
                    INSERT INTO vault_secrets (
                        id, credential_id, kind, format_version, key_version, nonce, ciphertext
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    envelope.id.to_string(),
                    envelope.credential_id.to_string(),
                    envelope.kind.code(),
                    envelope.format_version,
                    envelope.key_version,
                    envelope.nonce,
                    envelope.ciphertext,
                ],
            )
            .map(|_| ())
            .map_err(|_| VaultStoreError)
    }

    fn tombstone_secret(&mut self, id: uuid::Uuid) -> Result<bool, VaultStoreError> {
        self.connection
            .execute(
                r#"
                    UPDATE vault_secrets
                    SET deleted_at_unix = unixepoch(),
                        updated_at_unix = unixepoch(),
                        revision = revision + 1
                    WHERE id = ?1 AND deleted_at_unix IS NULL
                "#,
                [id.to_string()],
            )
            .map(|changed| changed == 1)
            .map_err(|_| VaultStoreError)
    }
}

fn sql_conversion_error(
    column: usize,
    error: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, Box::new(error))
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
                    id, label, hostname, port, port_explicit, username, environment
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(id) DO UPDATE SET
                    label = excluded.label,
                    hostname = excluded.hostname,
                    port = excluded.port,
                    port_explicit = excluded.port_explicit,
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
                host.target.port_is_explicit(),
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
                    SELECT id, label, hostname, port, port_explicit, username, environment
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
                SELECT id, label, hostname, port, port_explicit, username, environment
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

    pub fn save_credential(
        &mut self,
        credential: &Credential,
        secret_refs: &[SecretRef],
        grants: &[CredentialGrant],
    ) -> Result<(), StorageError> {
        let mut secret_kinds = BTreeSet::new();
        for reference in secret_refs {
            if reference.credential_id != credential.id || !secret_kinds.insert(reference.kind) {
                return Err(StorageError::InvalidCredentialBinding);
            }
            let stored = self
                .load_secret_envelope(reference.id)
                .map_err(|_| StorageError::InvalidCredentialBinding)?
                .ok_or(StorageError::InvalidCredentialBinding)?;
            if stored.credential_id != credential.id || stored.kind != reference.kind {
                return Err(StorageError::InvalidCredentialBinding);
            }
        }
        for grant in grants {
            if grant.credential_id != credential.id
                || grant.validate_against(&credential.capabilities).is_err()
            {
                return Err(StorageError::InvalidCredentialBinding);
            }
        }

        let credential_json = serde_json::to_string(credential)?;
        let grant_json = grants
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO credentials(id, payload_json) VALUES (?1, ?2)",
            params![credential.id.to_string(), credential_json],
        )?;
        for reference in secret_refs {
            transaction.execute(
                r#"
                    INSERT INTO credential_secret_refs(credential_id, kind, secret_id)
                    VALUES (?1, ?2, ?3)
                "#,
                params![
                    credential.id.to_string(),
                    reference.kind.code(),
                    reference.id.to_string(),
                ],
            )?;
        }
        for (grant, payload) in grants.iter().zip(grant_json) {
            transaction.execute(
                r#"
                    INSERT INTO credential_grants(id, credential_id, payload_json)
                    VALUES (?1, ?2, ?3)
                "#,
                params![grant.id.to_string(), credential.id.to_string(), payload],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn find_credential(
        &self,
        id: CredentialId,
    ) -> Result<Option<PersistedCredential>, StorageError> {
        let payload = self
            .connection
            .query_row(
                r#"
                    SELECT payload_json
                    FROM credentials
                    WHERE id = ?1 AND deleted_at_unix IS NULL
                "#,
                [id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let credential = serde_json::from_str::<Credential>(&payload)?;
        if credential.id != id {
            return Err(StorageError::InvalidCredentialBinding);
        }

        let mut secret_statement = self.connection.prepare(
            r#"
                SELECT kind, secret_id
                FROM credential_secret_refs
                WHERE credential_id = ?1
                ORDER BY kind
            "#,
        )?;
        let secret_refs = secret_statement
            .query_map([id.to_string()], |row| {
                let kind_code = row.get::<_, u8>(0)?;
                let kind = SecretKind::from_code(kind_code).ok_or_else(|| {
                    sql_conversion_error(
                        0,
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "unknown credential secret kind",
                        ),
                    )
                })?;
                let secret_id = row
                    .get::<_, String>(1)?
                    .parse()
                    .map_err(|error| sql_conversion_error(1, error))?;
                Ok(SecretRef {
                    id: secret_id,
                    credential_id: id,
                    kind,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut grant_statement = self.connection.prepare(
            r#"
                SELECT payload_json
                FROM credential_grants
                WHERE credential_id = ?1
                ORDER BY id
            "#,
        )?;
        let grant_payloads = grant_statement
            .query_map([id.to_string()], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let grants = grant_payloads
            .into_iter()
            .map(|payload| serde_json::from_str::<CredentialGrant>(&payload))
            .collect::<Result<Vec<_>, _>>()?;
        if grants.iter().any(|grant| {
            grant.credential_id != id || grant.validate_against(&credential.capabilities).is_err()
        }) {
            return Err(StorageError::InvalidCredentialBinding);
        }

        Ok(Some(PersistedCredential {
            credential,
            secret_refs,
            grants,
        }))
    }

    pub fn list_credentials(&self) -> Result<Vec<PersistedCredential>, StorageError> {
        let mut statement = self.connection.prepare(
            r#"
                SELECT id
                FROM credentials
                WHERE deleted_at_unix IS NULL
                ORDER BY json_extract(payload_json, '$.label') COLLATE NOCASE, id
            "#,
        )?;
        let ids = statement
            .query_map([], |row| {
                row.get::<_, String>(0)?
                    .parse()
                    .map(CredentialId::from_uuid)
                    .map_err(|error| sql_conversion_error(0, error))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        ids.into_iter()
            .map(|id| {
                self.find_credential(id)?.ok_or_else(|| {
                    StorageError::CorruptData("credential disappeared while listing".to_owned())
                })
            })
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

    pub fn load_host_key_history(&self, host_id: HostId) -> Result<HostKeyHistory, StorageError> {
        let mut statement = self.connection.prepare(
            r#"
                SELECT id, algorithm, key_blob, fingerprint, state, source,
                       first_seen_at_unix, last_seen_at_unix, superseded_by
                FROM host_keys
                WHERE host_id = ?1
                ORDER BY first_seen_at_unix, id
            "#,
        )?;
        let stored = statement
            .query_map([host_id.to_string()], StoredHostKey::from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        let records = stored
            .into_iter()
            .map(|record| restore_host_key_record(host_id, record))
            .collect::<Result<Vec<_>, _>>()?;
        HostKeyHistory::restore(host_id, records).map_err(StorageError::from)
    }

    pub fn save_host_key_change(
        &mut self,
        history: &HostKeyHistory,
        event: &HostKeyEvent,
    ) -> Result<(), StorageError> {
        if history.host_id() != event.host_id {
            return Err(StorageError::CorruptData(
                "host-key event does not match history host".to_owned(),
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_host_key_transition(&transaction, history, event)?;
        for record in history.records() {
            validate_stored_host_key_identity(&transaction, record)?;
            transaction.execute(
                r#"
                    INSERT INTO host_keys (
                        id, host_id, algorithm, key_blob, fingerprint, state, source,
                        first_seen_at_unix, last_seen_at_unix, superseded_by
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                    ON CONFLICT(id) DO UPDATE SET
                        state = excluded.state,
                        last_seen_at_unix = excluded.last_seen_at_unix,
                        superseded_by = excluded.superseded_by,
                        revision = host_keys.revision + 1
                "#,
                params![
                    record.id.to_string(),
                    record.host_id.to_string(),
                    record.material.algorithm.as_str(),
                    record.material.key_blob,
                    record.material.fingerprint.as_str(),
                    host_key_state_to_str(record.state),
                    host_key_source_to_str(record.source),
                    record.first_seen_at_unix,
                    record.last_seen_at_unix,
                    record.superseded_by.map(|id| id.to_string()),
                ],
            )?;
        }
        transaction.execute(
            r#"
                INSERT INTO host_key_events (
                    id, host_id, fingerprint, previous_fingerprint, kind, source, occurred_at_unix
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                event.id.to_string(),
                event.host_id.to_string(),
                event.fingerprint.as_str(),
                event
                    .previous_fingerprint
                    .as_ref()
                    .map(HostKeyFingerprint::as_str),
                host_key_event_kind_to_str(event.kind),
                host_key_source_to_str(event.source),
                event.occurred_at_unix,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_host_key_events(&self, host_id: HostId) -> Result<Vec<HostKeyEvent>, StorageError> {
        let mut statement = self.connection.prepare(
            r#"
                SELECT id, fingerprint, previous_fingerprint, kind, source, occurred_at_unix
                FROM host_key_events
                WHERE host_id = ?1
                ORDER BY occurred_at_unix, id
            "#,
        )?;
        let stored = statement
            .query_map([host_id.to_string()], StoredHostKeyEvent::from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        stored
            .into_iter()
            .map(|event| restore_host_key_event(host_id, event))
            .collect()
    }

    fn restore_host(&self, stored: StoredHost) -> Result<Host, StorageError> {
        let id = HostId::from_str(&stored.id)
            .map_err(|error| StorageError::CorruptData(error.to_string()))?;
        let port = u16::try_from(stored.port)
            .map_err(|error| StorageError::CorruptData(error.to_string()))?;
        let target = format_target(
            stored.username.as_deref(),
            &stored.hostname,
            port,
            stored.port_explicit,
        )
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

fn validate_host_key_transition(
    transaction: &Transaction<'_>,
    history: &HostKeyHistory,
    event: &HostKeyEvent,
) -> Result<(), StorageError> {
    let target = history
        .records()
        .iter()
        .find(|record| record.material.fingerprint == event.fingerprint)
        .ok_or_else(|| StorageError::HostKeyConflict("event key is missing from history".into()))?;
    let current_ids = transaction
        .prepare("SELECT id FROM host_keys WHERE host_id = ?1")?
        .query_map([event.host_id.to_string()], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    if current_ids.iter().any(|id| {
        !history
            .records()
            .iter()
            .any(|record| record.id.to_string() == *id)
    }) {
        return Err(StorageError::HostKeyConflict(
            "history snapshot is stale or incomplete".into(),
        ));
    }

    let target_state = stored_host_key_state(transaction, event.host_id, &event.fingerprint)?;
    match event.kind {
        HostKeyEventKind::TrustedFirstUse => {
            if !current_ids.is_empty()
                || event.previous_fingerprint.is_some()
                || target.state != HostKeyRecordState::Trusted
            {
                return Err(StorageError::HostKeyConflict(
                    "first-use trust requires an empty current history".into(),
                ));
            }
        }
        HostKeyEventKind::RotatedManual => {
            let previous = event.previous_fingerprint.as_ref().ok_or_else(|| {
                StorageError::HostKeyConflict("manual rotation is missing its previous key".into())
            })?;
            let previous_record = history
                .records()
                .iter()
                .find(|record| record.material.fingerprint == *previous)
                .ok_or_else(|| {
                    StorageError::HostKeyConflict(
                        "manual rotation previous key is missing from history".into(),
                    )
                })?;
            if target_state.is_some()
                || stored_host_key_state(transaction, event.host_id, previous)?
                    != Some("trusted".to_owned())
                || target.state != HostKeyRecordState::Trusted
                || previous_record.state != HostKeyRecordState::Superseded
                || previous_record.superseded_by != Some(target.id)
            {
                return Err(StorageError::HostKeyConflict(
                    "manual rotation no longer matches the active key".into(),
                ));
            }
        }
        HostKeyEventKind::LearnedUpdate => {
            let authenticated_by = event.previous_fingerprint.as_ref().ok_or_else(|| {
                StorageError::HostKeyConflict(
                    "UpdateHostKeys event is missing its authenticating key".into(),
                )
            })?;
            if target_state.is_some()
                || stored_host_key_state(transaction, event.host_id, authenticated_by)?
                    != Some("trusted".to_owned())
                || target.state != HostKeyRecordState::Trusted
            {
                return Err(StorageError::HostKeyConflict(
                    "UpdateHostKeys authentication is stale or invalid".into(),
                ));
            }
        }
        HostKeyEventKind::Revoked => {
            if event.previous_fingerprint.is_some()
                || target_state
                    .as_deref()
                    .is_none_or(|state| state == "revoked")
                || target.state != HostKeyRecordState::Revoked
            {
                return Err(StorageError::HostKeyConflict(
                    "revocation no longer matches a non-revoked stored key".into(),
                ));
            }
        }
    }
    Ok(())
}

fn stored_host_key_state(
    transaction: &Transaction<'_>,
    host_id: HostId,
    fingerprint: &HostKeyFingerprint,
) -> Result<Option<String>, StorageError> {
    transaction
        .query_row(
            "SELECT state FROM host_keys WHERE host_id = ?1 AND fingerprint = ?2",
            params![host_id.to_string(), fingerprint.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(StorageError::from)
}

fn validate_stored_host_key_identity(
    transaction: &Transaction<'_>,
    record: &HostKeyRecord,
) -> Result<(), StorageError> {
    let stored = transaction
        .query_row(
            r#"
                SELECT host_id, algorithm, key_blob, fingerprint, source, first_seen_at_unix
                FROM host_keys
                WHERE id = ?1
            "#,
            [record.id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    if let Some((host_id, algorithm, key_blob, fingerprint, source, first_seen_at_unix)) = stored
        && (host_id != record.host_id.to_string()
            || algorithm != record.material.algorithm.as_str()
            || key_blob != record.material.key_blob
            || fingerprint != record.material.fingerprint.as_str()
            || source != host_key_source_to_str(record.source)
            || first_seen_at_unix != record.first_seen_at_unix)
    {
        return Err(StorageError::HostKeyConflict(
            "immutable host-key identity does not match stored state".into(),
        ));
    }
    Ok(())
}

struct StoredHost {
    id: String,
    label: String,
    hostname: String,
    port: i64,
    port_explicit: bool,
    username: Option<String>,
    environment: Option<String>,
}

struct StoredHostKey {
    id: String,
    algorithm: String,
    key_blob: Vec<u8>,
    fingerprint: String,
    state: String,
    source: String,
    first_seen_at_unix: i64,
    last_seen_at_unix: i64,
    superseded_by: Option<String>,
}

impl StoredHostKey {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            algorithm: row.get(1)?,
            key_blob: row.get(2)?,
            fingerprint: row.get(3)?,
            state: row.get(4)?,
            source: row.get(5)?,
            first_seen_at_unix: row.get(6)?,
            last_seen_at_unix: row.get(7)?,
            superseded_by: row.get(8)?,
        })
    }
}

fn restore_host_key_record(
    host_id: HostId,
    stored: StoredHostKey,
) -> Result<HostKeyRecord, StorageError> {
    let id = stored
        .id
        .parse::<HostKeyId>()
        .map_err(|error| StorageError::CorruptData(error.to_string()))?;
    let algorithm = stored.algorithm.parse::<HostKeyAlgorithm>()?;
    let fingerprint = stored.fingerprint.parse::<HostKeyFingerprint>()?;
    let material = HostKeyMaterial::restore(algorithm, stored.key_blob, fingerprint)?;
    let superseded_by = stored
        .superseded_by
        .map(|value| value.parse::<HostKeyId>())
        .transpose()
        .map_err(|error| StorageError::CorruptData(error.to_string()))?;
    Ok(HostKeyRecord {
        id,
        host_id,
        material,
        state: host_key_state_from_str(&stored.state)?,
        source: host_key_source_from_str(&stored.source)?,
        first_seen_at_unix: stored.first_seen_at_unix,
        last_seen_at_unix: stored.last_seen_at_unix,
        superseded_by,
    })
}

struct StoredHostKeyEvent {
    id: String,
    fingerprint: String,
    previous_fingerprint: Option<String>,
    kind: String,
    source: String,
    occurred_at_unix: i64,
}

impl StoredHostKeyEvent {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            fingerprint: row.get(1)?,
            previous_fingerprint: row.get(2)?,
            kind: row.get(3)?,
            source: row.get(4)?,
            occurred_at_unix: row.get(5)?,
        })
    }
}

fn restore_host_key_event(
    host_id: HostId,
    stored: StoredHostKeyEvent,
) -> Result<HostKeyEvent, StorageError> {
    Ok(HostKeyEvent {
        id: stored
            .id
            .parse::<HostKeyEventId>()
            .map_err(|error| StorageError::CorruptData(error.to_string()))?,
        host_id,
        fingerprint: stored.fingerprint.parse()?,
        previous_fingerprint: stored
            .previous_fingerprint
            .map(|value| value.parse())
            .transpose()?,
        kind: host_key_event_kind_from_str(&stored.kind)?,
        source: host_key_source_from_str(&stored.source)?,
        occurred_at_unix: stored.occurred_at_unix,
    })
}

const fn host_key_state_to_str(state: HostKeyRecordState) -> &'static str {
    match state {
        HostKeyRecordState::Trusted => "trusted",
        HostKeyRecordState::Superseded => "superseded",
        HostKeyRecordState::Revoked => "revoked",
    }
}

fn host_key_state_from_str(value: &str) -> Result<HostKeyRecordState, StorageError> {
    match value {
        "trusted" => Ok(HostKeyRecordState::Trusted),
        "superseded" => Ok(HostKeyRecordState::Superseded),
        "revoked" => Ok(HostKeyRecordState::Revoked),
        _ => Err(StorageError::CorruptData(
            "unknown host-key state".to_owned(),
        )),
    }
}

const fn host_key_source_to_str(source: HostKeySource) -> &'static str {
    match source {
        HostKeySource::Presented => "presented",
        HostKeySource::KnownHostsImport => "known_hosts_import",
        HostKeySource::DnsSshfp => "dns_sshfp",
        HostKeySource::CertificateAuthority => "certificate_authority",
        HostKeySource::UpdateHostKeys => "update_host_keys",
        HostKeySource::Manual => "manual",
    }
}

fn host_key_source_from_str(value: &str) -> Result<HostKeySource, StorageError> {
    match value {
        "presented" => Ok(HostKeySource::Presented),
        "known_hosts_import" => Ok(HostKeySource::KnownHostsImport),
        "dns_sshfp" => Ok(HostKeySource::DnsSshfp),
        "certificate_authority" => Ok(HostKeySource::CertificateAuthority),
        "update_host_keys" => Ok(HostKeySource::UpdateHostKeys),
        "manual" => Ok(HostKeySource::Manual),
        _ => Err(StorageError::CorruptData(
            "unknown host-key source".to_owned(),
        )),
    }
}

const fn host_key_event_kind_to_str(kind: HostKeyEventKind) -> &'static str {
    match kind {
        HostKeyEventKind::TrustedFirstUse => "trusted_first_use",
        HostKeyEventKind::RotatedManual => "rotated_manual",
        HostKeyEventKind::LearnedUpdate => "learned_update",
        HostKeyEventKind::Revoked => "revoked",
    }
}

fn host_key_event_kind_from_str(value: &str) -> Result<HostKeyEventKind, StorageError> {
    match value {
        "trusted_first_use" => Ok(HostKeyEventKind::TrustedFirstUse),
        "rotated_manual" => Ok(HostKeyEventKind::RotatedManual),
        "learned_update" => Ok(HostKeyEventKind::LearnedUpdate),
        "revoked" => Ok(HostKeyEventKind::Revoked),
        _ => Err(StorageError::CorruptData(
            "unknown host-key event kind".to_owned(),
        )),
    }
}

impl StoredHost {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            label: row.get(1)?,
            hostname: row.get(2)?,
            port: row.get(3)?,
            port_explicit: row.get(4)?,
            username: row.get(5)?,
            environment: row.get(6)?,
        })
    }
}

fn format_target(username: Option<&str>, hostname: &str, port: u16, port_explicit: bool) -> String {
    let username = username.map_or_else(String::new, |value| format!("{value}@"));
    let hostname = if hostname.contains(':') {
        format!("[{hostname}]")
    } else {
        hostname.to_owned()
    };
    if port_explicit {
        format!("{username}{hostname}:{port}")
    } else {
        format!("{username}{hostname}")
    }
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("stored JSON data is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database schema version {found} is newer than supported version {supported}")]
    NewerSchema { found: u32, supported: u32 },
    #[error("stored data is invalid: {0}")]
    CorruptData(String),
    #[error("stored SSH target is invalid: {0}")]
    InvalidTarget(#[from] TargetParseError),
    #[error("stored host is invalid: {0}")]
    InvalidHost(#[from] HostError),
    #[error("stored host-key data is invalid: {0}")]
    InvalidHostKey(#[from] HostKeyError),
    #[error("host-key trust changed concurrently: {0}")]
    HostKeyConflict(String),
    #[error("credential metadata, grant, and encrypted secret references do not agree")]
    InvalidCredentialBinding,
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use yasc_domain::{
        CredentialCapabilities, CredentialGrant, CredentialProviderKind, CredentialUsage, Custody,
        Synchronization,
    };
    use yasc_vault::{
        EncryptedVault, SecretBytes, SecretKind, VaultBackend, VaultError, VaultState,
    };

    use super::*;

    fn host(label: &str, target: &str) -> Host {
        let mut host = Host::new(label, target.parse().unwrap()).unwrap();
        host.tags = ["linux".to_owned(), "production".to_owned()]
            .into_iter()
            .collect();
        host.environment = Some("production".to_owned());
        host
    }

    fn key_observation(seed: u8) -> yasc_domain::HostKeyObservation {
        yasc_domain::HostKeyObservation::presented(
            HostKeyMaterial::new("ssh-ed25519".parse().unwrap(), vec![seed; 32]).unwrap(),
        )
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
    fn upgrades_version_two_hosts_without_forcing_port_override() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("version-two.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (\
                    version INTEGER PRIMARY KEY NOT NULL, \
                    name TEXT NOT NULL, \
                    applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch())\
                );",
            )
            .unwrap();
        for migration in MIGRATIONS.iter().filter(|migration| migration.version <= 2) {
            connection.execute_batch(migration.sql).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migrations(version, name) VALUES (?1, ?2)",
                    params![migration.version, migration.name],
                )
                .unwrap();
            connection
                .pragma_update(None, "user_version", migration.version)
                .unwrap();
        }
        let id = HostId::new();
        connection
            .execute(
                r#"
                    INSERT INTO hosts(id, label, hostname, port)
                    VALUES (?1, 'Legacy host', 'legacy.example.com', 22)
                "#,
                [id.to_string()],
            )
            .unwrap();
        drop(connection);

        let storage = SqliteStorage::open(&path).unwrap();
        let restored = storage.find_host(id).unwrap().unwrap();

        assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        assert_eq!(restored.target.port(), 22);
        assert!(!restored.target.port_is_explicit());
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

    #[test]
    fn encrypted_vault_persists_without_plaintext_and_reopens() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let password = b"local test password";
        let plaintext = b"never store this private value";
        let storage = SqliteStorage::open(&path).unwrap();
        let mut vault =
            EncryptedVault::create(storage, SecretBytes::new(password.to_vec())).unwrap();
        let reference = vault
            .store(
                CredentialId::new(),
                SecretKind::Password,
                SecretBytes::new(plaintext.to_vec()),
            )
            .unwrap();
        let storage = vault.into_store();
        let ciphertext: Vec<u8> = storage
            .connection
            .query_row(
                "SELECT ciphertext FROM vault_secrets WHERE id = ?1",
                [reference.id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !ciphertext
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
        drop(storage);

        let storage = SqliteStorage::open(&path).unwrap();
        let mut reopened = EncryptedVault::open(storage).unwrap();
        assert_eq!(reopened.state(), VaultState::Locked);
        assert_eq!(
            reopened
                .unlock(SecretBytes::new(b"wrong password".to_vec()))
                .unwrap_err(),
            VaultError::InvalidUnlockMaterial
        );
        reopened
            .unlock(SecretBytes::new(password.to_vec()))
            .unwrap();
        assert_eq!(reopened.read(reference).unwrap().expose_secret(), plaintext);
    }

    #[test]
    fn credential_metadata_refs_and_host_grant_roundtrip() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let host = host("Production", "admin@example.com");
        storage.save_host(&host).unwrap();
        let credential = Credential::new(
            "Production key",
            CredentialProviderKind::LocalVault,
            CredentialCapabilities::new(
                Custody::Exportable,
                Synchronization::LocalOnly,
                [CredentialUsage::DirectSsh],
            )
            .unwrap(),
        );
        let password = b"test vault password";
        let mut vault =
            EncryptedVault::create(storage, SecretBytes::new(password.to_vec())).unwrap();
        let key_ref = vault
            .store(
                credential.id,
                SecretKind::SshPrivateKey,
                SecretBytes::new(b"fixture private key".to_vec()),
            )
            .unwrap();
        let grant =
            CredentialGrant::new(credential.id, [host.id], [CredentialUsage::DirectSsh]).unwrap();
        vault
            .store_mut()
            .save_credential(&credential, &[key_ref], std::slice::from_ref(&grant))
            .unwrap();
        let storage = vault.into_store();

        let restored = storage.find_credential(credential.id).unwrap().unwrap();
        assert_eq!(restored.credential, credential);
        assert_eq!(restored.secret(SecretKind::SshPrivateKey), Some(key_ref));
        assert_eq!(restored.grants, vec![grant]);
        assert_eq!(storage.list_credentials().unwrap(), vec![restored]);
    }

    #[test]
    fn credential_rejects_foreign_secret_reference() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let mut vault =
            EncryptedVault::create(storage, SecretBytes::new(b"test vault password".to_vec()))
                .unwrap();
        let owner = CredentialId::new();
        let key_ref = vault
            .store(
                owner,
                SecretKind::SshPrivateKey,
                SecretBytes::new(b"fixture private key".to_vec()),
            )
            .unwrap();
        let credential = Credential::new(
            "Other key",
            CredentialProviderKind::LocalVault,
            CredentialCapabilities::new(
                Custody::Exportable,
                Synchronization::LocalOnly,
                [CredentialUsage::DirectSsh],
            )
            .unwrap(),
        );

        assert!(matches!(
            vault
                .store_mut()
                .save_credential(&credential, &[key_ref], &[]),
            Err(StorageError::InvalidCredentialBinding)
        ));
    }

    #[test]
    fn host_key_history_and_events_roundtrip_atomically() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let host = host("Production", "admin@example.com");
        storage.save_host(&host).unwrap();
        let mut history = HostKeyHistory::new(host.id);
        let first = key_observation(1);
        let event = history.trust_first_use(first.clone(), 10).unwrap();

        storage.save_host_key_change(&history, &event).unwrap();

        assert_eq!(storage.load_host_key_history(host.id).unwrap(), history);
        assert_eq!(
            storage.list_host_key_events(host.id).unwrap(),
            vec![event.clone()]
        );
        let revision_before: i64 = storage
            .connection
            .query_row("SELECT revision FROM host_keys", [], |row| row.get(0))
            .unwrap();
        assert!(storage.save_host_key_change(&history, &event).is_err());
        let revision_after: i64 = storage
            .connection
            .query_row("SELECT revision FROM host_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(revision_after, revision_before);
    }

    #[test]
    fn manual_host_key_rotation_preserves_superseded_history() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let host = host("Production", "admin@example.com");
        storage.save_host(&host).unwrap();
        let mut history = HostKeyHistory::new(host.id);
        let first = key_observation(1);
        let first_event = history.trust_first_use(first.clone(), 10).unwrap();
        storage
            .save_host_key_change(&history, &first_event)
            .unwrap();
        let replacement = key_observation(2);
        let rotation = history
            .trust_manual_change(replacement.clone(), &first.material.fingerprint, 20)
            .unwrap();

        storage.save_host_key_change(&history, &rotation).unwrap();
        let restored = storage.load_host_key_history(host.id).unwrap();

        assert_eq!(restored.records().len(), 2);
        assert_eq!(restored.records()[0].state, HostKeyRecordState::Superseded);
        assert!(matches!(
            restored.evaluate(&replacement, &yasc_domain::HostKeyPolicy::strict()),
            yasc_domain::HostKeyDecision::AcceptKnown { .. }
        ));
        assert_eq!(storage.list_host_key_events(host.id).unwrap().len(), 2);
    }

    #[test]
    fn stale_first_use_snapshot_cannot_create_a_second_trusted_key() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let host = host("Production", "admin@example.com");
        storage.save_host(&host).unwrap();
        let mut first_history = HostKeyHistory::new(host.id);
        let first_event = first_history
            .trust_first_use(key_observation(1), 10)
            .unwrap();
        let mut stale_history = HostKeyHistory::new(host.id);
        let stale_event = stale_history
            .trust_first_use(key_observation(2), 10)
            .unwrap();

        storage
            .save_host_key_change(&first_history, &first_event)
            .unwrap();
        assert!(matches!(
            storage.save_host_key_change(&stale_history, &stale_event),
            Err(StorageError::HostKeyConflict(_))
        ));
        assert_eq!(
            storage.load_host_key_history(host.id).unwrap(),
            first_history
        );
        assert_eq!(storage.list_host_key_events(host.id).unwrap().len(), 1);
    }

    #[test]
    fn stale_manual_rotation_cannot_replace_the_same_key_twice() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let host = host("Production", "admin@example.com");
        storage.save_host(&host).unwrap();
        let mut initial = HostKeyHistory::new(host.id);
        let first = key_observation(1);
        let first_event = initial.trust_first_use(first.clone(), 10).unwrap();
        storage
            .save_host_key_change(&initial, &first_event)
            .unwrap();
        let mut winning = storage.load_host_key_history(host.id).unwrap();
        let mut stale = winning.clone();
        let winning_event = winning
            .trust_manual_change(key_observation(2), &first.material.fingerprint, 20)
            .unwrap();
        let stale_event = stale
            .trust_manual_change(key_observation(3), &first.material.fingerprint, 20)
            .unwrap();

        storage
            .save_host_key_change(&winning, &winning_event)
            .unwrap();
        assert!(matches!(
            storage.save_host_key_change(&stale, &stale_event),
            Err(StorageError::HostKeyConflict(_))
        ));
        assert_eq!(storage.load_host_key_history(host.id).unwrap(), winning);
        assert_eq!(storage.list_host_key_events(host.id).unwrap().len(), 2);
    }

    #[test]
    fn immutable_host_key_identity_cannot_be_rewritten() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let host = host("Production", "admin@example.com");
        storage.save_host(&host).unwrap();
        let mut initial = HostKeyHistory::new(host.id);
        let first = key_observation(1);
        let first_event = initial.trust_first_use(first.clone(), 10).unwrap();
        storage
            .save_host_key_change(&initial, &first_event)
            .unwrap();
        let mut forged_records = initial.records().to_vec();
        forged_records[0].source = HostKeySource::KnownHostsImport;
        let mut forged = HostKeyHistory::restore(host.id, forged_records).unwrap();
        let event = forged.revoke(&first.material.fingerprint, 20).unwrap();

        assert!(matches!(
            storage.save_host_key_change(&forged, &event),
            Err(StorageError::HostKeyConflict(_))
        ));
        assert_eq!(storage.load_host_key_history(host.id).unwrap(), initial);
        assert_eq!(storage.list_host_key_events(host.id).unwrap().len(), 1);
    }

    #[test]
    fn corrupted_persisted_host_key_fingerprint_is_rejected() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let host = host("Production", "admin@example.com");
        storage.save_host(&host).unwrap();
        let mut history = HostKeyHistory::new(host.id);
        let event = history.trust_first_use(key_observation(1), 10).unwrap();
        storage.save_host_key_change(&history, &event).unwrap();
        let forged = HostKeyFingerprint::sha256(&[9; 32]);
        storage
            .connection
            .execute("UPDATE host_keys SET fingerprint = ?1", [forged.as_str()])
            .unwrap();

        assert!(matches!(
            storage.load_host_key_history(host.id),
            Err(StorageError::InvalidHostKey(
                HostKeyError::FingerprintMismatch
            ))
        ));
    }
}
