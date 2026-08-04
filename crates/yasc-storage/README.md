# Local storage contract

The local SQLite schema is forward-only. Every migration is applied in an immediate transaction,
recorded in `schema_migrations`, and mirrored to SQLite's `user_version`.

- A database created by a newer application is rejected.
- Deleted inventory records become tombstones rather than disappearing immediately.
- Updates increase a monotonic per-row revision.
- Foreign keys are enabled on every connection.
- Credential plaintext is never owned by this crate.

Rollback means restoring a compatible backup and application version. Down-migrations are not run
automatically because lossy schema reversal can silently destroy security metadata.

