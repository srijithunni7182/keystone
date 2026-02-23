// Keystone — SQLCipher Database Management
//
// Opens and initializes an encrypted SQLCipher database. The encryption key
// is derived from the master secret in the enclave module and is set via
// PRAGMA before any tables are accessed.

use rusqlite::Connection;

use super::StoreError;

/// Wrapper around a SQLCipher-encrypted SQLite connection.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (or create) an encrypted database at the given path.
    /// The `hex_key` must be the hex-encoded 32-byte key derived from Argon2id.
    pub fn open(path: &std::path::Path, hex_key: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;

        // Set the SQLCipher encryption key
        conn.pragma_update(None, "key", &format!("x'{}'", hex_key))?;

        // Verify the key is correct by reading the schema
        // If the key is wrong, this will fail with "file is not a database"
        conn.execute_batch("SELECT count(*) FROM sqlite_master;")
            .map_err(|_| StoreError::InvalidKey)?;

        let db = Self { conn };
        db.run_migrations()?;

        Ok(db)
    }

    /// Open an in-memory database (unencrypted, for testing only).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.run_migrations()?;
        Ok(db)
    }

    /// Get a reference to the underlying connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Run schema migrations to create or update tables.
    fn run_migrations(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS credentials (
                id                  TEXT PRIMARY KEY,
                provider            TEXT NOT NULL,
                scope_tags          TEXT NOT NULL DEFAULT '[]',
                environment         TEXT NOT NULL DEFAULT 'development',
                intent_description  TEXT NOT NULL,
                secret_value        TEXT NOT NULL,
                policy              TEXT NOT NULL DEFAULT '{}',
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credential_embeddings (
                credential_id       TEXT PRIMARY KEY,
                embedding_blob      BLOB NOT NULL,
                FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS credential_approvals (
                id                  TEXT PRIMARY KEY,
                credential_id       TEXT NOT NULL,
                actor               TEXT NOT NULL,
                status              TEXT NOT NULL DEFAULT 'pending',
                created_at          TEXT NOT NULL,
                FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id   TEXT NOT NULL,
                action          TEXT NOT NULL,
                actor           TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                details         TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_audit_credential
                ON audit_log(credential_id);

            CREATE INDEX IF NOT EXISTS idx_credentials_provider
                ON credentials(provider);
            ",
        )?;

        tracing::debug!("Database migrations completed successfully");
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory_succeeds() {
        let db = Database::open_in_memory();
        assert!(db.is_ok(), "Should be able to open an in-memory database");
    }

    #[test]
    fn test_schema_migration_creates_tables() {
        let db = Database::open_in_memory().unwrap();

        // Verify credentials table exists
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='credentials'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "credentials table should exist");

        // Verify audit_log table exists
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='audit_log'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "audit_log table should exist");
    }

    #[test]
    fn test_schema_migration_is_idempotent() {
        let db = Database::open_in_memory().unwrap();
        // Running migrations again should not error
        assert!(
            db.run_migrations().is_ok(),
            "Migrations should be idempotent"
        );
    }

    #[test]
    fn test_encrypted_db_with_correct_key() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let result = Database::open(&db_path, hex_key);
        assert!(result.is_ok(), "Should open successfully with a valid key");
    }

    #[test]
    fn test_encrypted_db_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_wrong_key.db");
        let correct_key =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let wrong_key =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        // Create the database with the correct key
        {
            let _db = Database::open(&db_path, correct_key).unwrap();
            // Insert something so the file has content
        }

        // Try to open with the wrong key — should fail
        let result = Database::open(&db_path, wrong_key);
        assert!(
            result.is_err(),
            "Opening with the wrong key must fail"
        );
    }

    #[test]
    fn test_credentials_table_has_expected_columns() {
        let db = Database::open_in_memory().unwrap();

        // Insert a test row to verify schema
        db.conn()
            .execute(
                "INSERT INTO credentials (id, provider, scope_tags, environment,
                 intent_description, secret_value, policy, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    "test-id",
                    "github",
                    "[\"repo:read\"]",
                    "dev",
                    "test intent",
                    "secret123",
                    "{}",
                    "2024-01-01T00:00:00Z",
                    "2024-01-01T00:00:00Z"
                ],
            )
            .unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT count(*) FROM credentials", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
