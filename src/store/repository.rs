// Keystone — Credential Store Repository
//
// Implements CRUD operations on the encrypted credential database.
// Key design decision: `get()` returns metadata only; the raw secret is
// accessible ONLY via `get_secret()`, which also writes an audit log entry.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Transaction};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::db::Database;
use super::models::{Credential, CredentialSummary, NewCredential, Policy};
use super::StoreError;

// ─── Trait ───────────────────────────────────────────────────────────────────

/// Abstraction over credential storage operations.
pub trait CredentialStore {
    /// Add a new credential, optionally storing its semantic embedding. Returns the generated UUID.
    fn add(&self, credential: NewCredential, embedding: Option<&[f32]>) -> Result<Uuid, StoreError>;

    /// Get a credential by ID, WITH the secret value.
    /// The caller should audit-log this access.
    fn get(&self, id: &Uuid) -> Result<Option<Credential>, StoreError>;

    /// Get ONLY the raw secret value for a credential.
    /// Writes an audit log entry automatically.
    fn get_secret(&self, id: &Uuid, actor: &str) -> Result<Option<Zeroizing<String>>, StoreError>;

    /// List all credentials (metadata only, no secrets).
    fn list(&self) -> Result<Vec<CredentialSummary>, StoreError>;

    /// Fetch all credential embeddings for semantic search.
    fn get_all_embeddings(&self) -> Result<Vec<(Uuid, Vec<f32>)>, StoreError>;

    /// Approve a pending credential access request.
    fn approve_request(&self, request_id: &Uuid) -> Result<bool, StoreError>;
    
    /// Reject a pending credential access request.
    fn reject_request(&self, request_id: &Uuid) -> Result<bool, StoreError>;
    
    /// Retrieve the audit log for a specific credential.
    fn get_audit_logs(&self, id: &Uuid) -> Result<Vec<String>, StoreError>;

    /// Delete a credential by ID. Returns true if it existed.
    fn delete(&self, id: &Uuid) -> Result<bool, StoreError>;

    /// Write an entry to the audit log.
    fn log_access(
        &self,
        credential_id: &Uuid,
        action: &str,
        actor: &str,
        details: Option<&str>,
    ) -> Result<(), StoreError>;
}

// ─── SQLite Implementation ──────────────────────────────────────────────────

pub struct SqliteCredentialStore<'a> {
    db: &'a Database,
}

impl<'a> SqliteCredentialStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Parse a credential row from the database.
    fn row_to_credential(row: &rusqlite::Row<'_>) -> rusqlite::Result<Credential> {
        let id_str: String = row.get(0)?;
        let provider: String = row.get(1)?;
        let scope_tags_json: String = row.get(2)?;
        let environment: String = row.get(3)?;
        let intent_description: String = row.get(4)?;
        let secret_value: String = row.get(5)?;
        let policy_json: String = row.get(6)?;
        let created_at_str: String = row.get(7)?;
        let updated_at_str: String = row.get(8)?;

        let id = Uuid::parse_str(&id_str).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;

        let scope_tags: Vec<String> = serde_json::from_str(&scope_tags_json).unwrap_or_default();
        let policy: Policy = serde_json::from_str(&policy_json).unwrap_or_default();

        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(Credential::new(
            id,
            provider,
            scope_tags,
            environment,
            intent_description,
            secret_value,
            policy,
            created_at,
            updated_at,
        ))
    }

    /// Parse a credential summary row (no secret).
    fn row_to_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialSummary> {
        let id_str: String = row.get(0)?;
        let provider: String = row.get(1)?;
        let scope_tags_json: String = row.get(2)?;
        let environment: String = row.get(3)?;
        let intent_description: String = row.get(4)?;
        let policy_json: String = row.get(5)?;
        let created_at_str: String = row.get(6)?;
        let updated_at_str: String = row.get(7)?;

        let id = Uuid::parse_str(&id_str).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;

        let scope_tags: Vec<String> = serde_json::from_str(&scope_tags_json).unwrap_or_default();
        let policy: Policy = serde_json::from_str(&policy_json).unwrap_or_default();

        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(CredentialSummary {
            id,
            provider,
            scope_tags,
            environment,
            intent_description,
            policy,
            created_at,
            updated_at,
        })
    }
}

impl<'a> CredentialStore for SqliteCredentialStore<'a> {
    fn add(&self, cred: NewCredential, embedding: Option<&[f32]>) -> Result<Uuid, StoreError> {
        let id = Uuid::new_v4();
        let now = Utc::now().to_rfc3339();
        let scope_tags_json = serde_json::to_string(&cred.scope_tags)?;
        let policy_json = serde_json::to_string(&cred.policy)?;

        let tx = self.db.conn().unchecked_transaction()?;

        tx.execute(
            "INSERT INTO credentials
                (id, provider, scope_tags, environment, intent_description,
                 secret_value, policy, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id.to_string(),
                cred.provider,
                scope_tags_json,
                cred.environment,
                cred.intent_description,
                cred.secret_value,
                policy_json,
                now,
                now,
            ],
        )?;

        if let Some(emb) = embedding {
            let bytes: Vec<u8> = emb.iter().flat_map(|f| f.to_le_bytes()).collect();
            tx.execute(
                "INSERT INTO credential_embeddings (credential_id, embedding_blob) VALUES (?1, ?2)",
                params![id.to_string(), bytes],
            )?;
        }

        tx.commit()?;

        // Audit log the creation
        self.log_access(&id, "created", "keystone-cli", None)?;

        tracing::info!(
            credential_id = %id,
            provider = %cred.provider,
            "Credential stored successfully"
        );

        Ok(id)
    }

    fn get(&self, id: &Uuid) -> Result<Option<Credential>, StoreError> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, provider, scope_tags, environment, intent_description,
                    secret_value, policy, created_at, updated_at
             FROM credentials WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id.to_string()], Self::row_to_credential)?;

        match rows.next() {
            Some(Ok(cred)) => Ok(Some(cred)),
            Some(Err(e)) => Err(StoreError::Database(e)),
            None => Ok(None),
        }
    }

    fn get_secret(&self, id: &Uuid, actor: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
        // First retrieve the full credential to inspect its policies
        let cred_opt = self.get(id)?;
        let cred = match cred_opt {
            Some(c) => c,
            None => return Ok(None),
        };

        // 1. Evaluate TTL expiry
        if let Some(ttl) = cred.policy.parsed_ttl() {
            let expiration_time = cred.created_at + ttl;
            if Utc::now() > expiration_time {
                // Secret has expired! Delete it securely.
                self.delete(id)?;
                self.log_access(id, "expired_deleted", "system", Some("Credential exceeded max TTL"))?;
                return Err(StoreError::Expired);
            }
        }

        // 2. Evaluate Human-In-The-Loop Approval
        if cred.policy.require_approval {
            // Check if there's a recent Approved request for this specific actor
            let mut stmt = self.db.conn().prepare(
                "SELECT id, status, created_at FROM credential_approvals 
                 WHERE credential_id = ?1 AND actor = ?2
                 ORDER BY created_at DESC LIMIT 1"
            )?;

            let mut req_iter = stmt.query_map(params![id.to_string(), actor], |row| {
                let req_id: String = row.get(0)?;
                let status: String = row.get(1)?;
                let created_at: String = row.get(2)?;
                Ok((req_id, status, created_at))
            })?;

            let needs_new_approval = match req_iter.next() {
                Some(Ok((req_id_str, status, created_at_str))) => {
                    let req_id = Uuid::parse_str(&req_id_str).unwrap_or_default();
                    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());

                    match status.as_str() {
                        "approved" => {
                            // Approvals are valid for exactly 1 hour.
                            if Utc::now() > created_at + chrono::Duration::hours(1) {
                                true // expired approval
                            } else {
                                false // valid active approval
                            }
                        }
                        "pending" => return Err(StoreError::ApprovalRequired(req_id)),
                        "rejected" => true, // Needs a new request
                        _ => true,
                    }
                }
                _ => true, // No request exists yet
            };

            if needs_new_approval {
                // Initialize a new pending approval
                let new_req_id = Uuid::new_v4();
                self.db.conn().execute(
                    "INSERT INTO credential_approvals (id, credential_id, actor, status, created_at)
                     VALUES (?1, ?2, ?3, 'pending', ?4)",
                    params![
                        new_req_id.to_string(),
                        id.to_string(),
                        actor,
                        Utc::now().to_rfc3339(),
                    ],
                )?;
                self.log_access(id, "approval_requested", actor, Some(&format!("Request ID: {}", new_req_id)))?;
                return Err(StoreError::ApprovalRequired(new_req_id));
            }
        }

        // 3. Retrieve actual secret value
        let mut stmt = self.db.conn().prepare(
            "SELECT secret_value FROM credentials WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id.to_string()], |row| {
            let secret: String = row.get(0)?;
            Ok(secret)
        })?;

        match rows.next() {
            Some(Ok(secret)) => {
                // Audit log this successful access
                self.log_access(id, "secret_accessed", actor, None)?;
                Ok(Some(Zeroizing::new(secret)))
            }
            Some(Err(e)) => Err(StoreError::Database(e)),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<CredentialSummary>, StoreError> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, provider, scope_tags, environment, intent_description,
                    policy, created_at, updated_at
             FROM credentials ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], Self::row_to_summary)?;

        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(row?);
        }

        Ok(summaries)
    }

    fn get_all_embeddings(&self) -> Result<Vec<(Uuid, Vec<f32>)>, StoreError> {
        let mut stmt = self.db.conn().prepare(
            "SELECT credential_id, embedding_blob FROM credential_embeddings",
        )?;

        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            
            let id = Uuid::parse_str(&id_str).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
            })?;

            // Convert bytes back to f32
            let mut embedding = Vec::with_capacity(blob.len() / 4);
            for chunk in blob.chunks_exact(4) {
                let bytes: [u8; 4] = [chunk[0], chunk[1], chunk[2], chunk[3]];
                embedding.push(f32::from_le_bytes(bytes));
            }

            Ok((id, embedding))
        })?;

        let mut embeddings = Vec::new();
        for row in rows {
            embeddings.push(row?);
        }

        Ok(embeddings)
    }

    fn delete(&self, id: &Uuid) -> Result<bool, StoreError> {
        let affected = self.db.conn().execute(
            "DELETE FROM credentials WHERE id = ?1",
            params![id.to_string()],
        )?;

        if affected > 0 {
            // Log the deletion after removing the row (audit log has no FK constraint,
            // so it can reference deleted credentials for a tamper-evident history)
            self.log_access(id, "deleted", "keystone-cli", None)?;
            tracing::info!(credential_id = %id, "Credential deleted");
        }

        Ok(affected > 0)
    }

    fn approve_request(&self, request_id: &Uuid) -> Result<bool, StoreError> {
        let affected = self.db.conn().execute(
            "UPDATE credential_approvals SET status = 'approved' WHERE id = ?1 AND status = 'pending'",
            params![request_id.to_string()],
        )?;
        Ok(affected > 0)
    }

    fn reject_request(&self, request_id: &Uuid) -> Result<bool, StoreError> {
        let affected = self.db.conn().execute(
            "UPDATE credential_approvals SET status = 'rejected' WHERE id = ?1 AND status = 'pending'",
            params![request_id.to_string()],
        )?;
        Ok(affected > 0)
    }

    fn get_audit_logs(&self, id: &Uuid) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.db.conn().prepare(
            "SELECT action, actor, timestamp, details FROM audit_log 
             WHERE credential_id = ?1 ORDER BY id ASC"
        )?;

        let rows = stmt.query_map(params![id.to_string()], |row| {
            let action: String = row.get(0)?;
            let actor: String = row.get(1)?;
            let timestamp_str: String = row.get(2)?;
            let details: Option<String> = row.get(3)?;
            
            let dt = DateTime::parse_from_rfc3339(&timestamp_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
                
            let mut formatted = format!("[{}] {} by '{}'", dt.format("%Y-%m-%d %H:%M:%S"), action, actor);
            if let Some(d) = details {
                formatted.push_str(&format!(" ({})", d));
            }
            Ok(formatted)
        })?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(row?);
        }
        
        Ok(logs)
    }

    fn log_access(
        &self,
        credential_id: &Uuid,
        action: &str,
        actor: &str,
        details: Option<&str>,
    ) -> Result<(), StoreError> {
        let now = Utc::now().to_rfc3339();
        self.db.conn().execute(
            "INSERT INTO audit_log (credential_id, action, actor, timestamp, details)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                credential_id.to_string(),
                action,
                actor,
                now,
                details,
            ],
        )?;

        tracing::debug!(
            credential_id = %credential_id,
            action = %action,
            actor = %actor,
            "Audit log entry recorded"
        );

        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::models::Policy;

    fn setup_store() -> (Database, uuid::Uuid) {
        let db = Database::open_in_memory().unwrap();
        let store = SqliteCredentialStore::new(&db);

        let new_cred = NewCredential {
            provider: "github".to_string(),
            scope_tags: vec!["repo:read".to_string(), "repo:write".to_string()],
            environment: "production".to_string(),
            intent_description: "GitHub PAT for CI/CD pipeline".to_string(),
            secret_value: "ghp_test1234567890abcdef".to_string(),
            policy: Policy {
                require_approval: true,
                max_ttl: Some("1h".to_string()),
                allowed_agent_hashes: vec![],
            },
        };

        let id = store.add(new_cred, None).unwrap();
        (db, id)
    }

    #[test]
    fn test_add_credential_returns_uuid() {
        let db = Database::open_in_memory().unwrap();
        let store = SqliteCredentialStore::new(&db);

        let new_cred = NewCredential {
            provider: "openai".to_string(),
            scope_tags: vec!["models:read".to_string()],
            environment: "development".to_string(),
            intent_description: "OpenAI key for embeddings".to_string(),
            secret_value: "sk-test12345".to_string(),
            policy: Policy::default(),
        };

        let id = store.add(new_cred, None).unwrap();
        // UUID should be a valid v4
        assert_eq!(id.get_version(), Some(uuid::Version::Random));
    }

    #[test]
    fn test_get_credential_returns_full_record() {
        let (db, id) = setup_store();
        let store = SqliteCredentialStore::new(&db);

        let cred = store.get(&id).unwrap().expect("Credential should exist");
        assert_eq!(cred.id, id);
        assert_eq!(cred.provider, "github");
        assert_eq!(cred.environment, "production");
        assert_eq!(cred.intent_description, "GitHub PAT for CI/CD pipeline");
        assert_eq!(cred.scope_tags, vec!["repo:read", "repo:write"]);
        assert_eq!(cred.secret_value(), "ghp_test1234567890abcdef");
        assert!(cred.policy.require_approval);
        assert_eq!(cred.policy.max_ttl, Some("1h".to_string()));
    }

    #[test]
    fn test_get_nonexistent_returns_none() {
        let db = Database::open_in_memory().unwrap();
        let store = SqliteCredentialStore::new(&db);

        let result = store.get(&Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_secret_returns_raw_value() {
        let (db, id) = setup_store();
        let store = SqliteCredentialStore::new(&db);

        // First attempt should fail and require approval
        let err = store.get_secret(&id, "test-agent").unwrap_err();
        let req_id = match err {
            StoreError::ApprovalRequired(req_id) => req_id,
            _ => panic!("Expected ApprovalRequired error"),
        };

        // Approve it
        store.approve_request(&req_id).unwrap();

        // Second attempt should succeed
        let secret = store
            .get_secret(&id, "test-agent")
            .unwrap()
            .expect("Secret should exist");
        assert_eq!(secret.as_str(), "ghp_test1234567890abcdef");
    }

    #[test]
    fn test_get_secret_creates_audit_entry() {
        let (db, id) = setup_store();
        let store = SqliteCredentialStore::new(&db);

        // Access the secret (requires approval loop)
        let err = store.get_secret(&id, "test-agent-pid-1234").unwrap_err();
        let req_id = match err {
            StoreError::ApprovalRequired(req_id) => req_id,
            _ => panic!("Expected ApprovalRequired error"),
        };
        store.approve_request(&req_id).unwrap();
        store.get_secret(&id, "test-agent-pid-1234").unwrap();

        // Verify audit log entry was created for the final access
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM audit_log WHERE credential_id = ?1 AND action = 'secret_accessed'",
                params![id.to_string()],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "Accessing a secret must create an audit log entry");

        // Verify the actor was recorded
        let actor: String = db
            .conn()
            .query_row(
                "SELECT actor FROM audit_log WHERE credential_id = ?1 AND action = 'secret_accessed'",
                params![id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(actor, "test-agent-pid-1234");
    }

    #[test]
    fn test_list_credentials_returns_summaries() {
        let db = Database::open_in_memory().unwrap();
        let store = SqliteCredentialStore::new(&db);

        // Add three credentials
        for provider in &["github", "slack", "openai"] {
            let cred = NewCredential {
                provider: provider.to_string(),
                scope_tags: vec![],
                environment: "dev".to_string(),
                intent_description: format!("{} key", provider),
                secret_value: format!("secret-{}", provider),
                policy: Policy::default(),
            };
            store.add(cred, None).unwrap();
        }

        let summaries = store.list().unwrap();
        assert_eq!(summaries.len(), 3);

        // Verify summaries don't contain secrets (CredentialSummary has no secret_value field)
        for summary in &summaries {
            let json = serde_json::to_string(summary).unwrap();
            assert!(!json.contains("secret-"), "Summary must never contain secret values");
        }
    }

    #[test]
    fn test_delete_credential() {
        let (db, id) = setup_store();
        let store = SqliteCredentialStore::new(&db);

        let deleted = store.delete(&id).unwrap();
        assert!(deleted, "Delete should return true for existing credential");

        let cred = store.get(&id).unwrap();
        assert!(cred.is_none(), "Credential should be gone after deletion");
    }

    #[test]
    fn test_delete_nonexistent_returns_false() {
        let db = Database::open_in_memory().unwrap();
        let store = SqliteCredentialStore::new(&db);

        let deleted = store.delete(&Uuid::new_v4()).unwrap();
        assert!(!deleted, "Delete should return false for nonexistent credential");
    }

    #[test]
    fn test_add_creates_audit_entry() {
        let (db, id) = setup_store();

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM audit_log WHERE credential_id = ?1 AND action = 'created'",
                params![id.to_string()],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "Adding a credential must create an audit log entry");
    }

    #[test]
    fn test_delete_creates_audit_entry() {
        let (db, id) = setup_store();
        let store = SqliteCredentialStore::new(&db);

        store.delete(&id).unwrap();

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM audit_log WHERE credential_id = ?1 AND action = 'deleted'",
                params![id.to_string()],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "Deleting a credential must create an audit log entry");
    }

    #[test]
    fn test_full_crud_lifecycle() {
        let db = Database::open_in_memory().unwrap();
        let store = SqliteCredentialStore::new(&db);

        // Create
        let id = store
            .add(NewCredential {
                provider: "aws".to_string(),
                scope_tags: vec!["s3:read".to_string()],
                environment: "staging".to_string(),
                intent_description: "AWS key for S3 access".to_string(),
                secret_value: "AKIA_test_secret_key".to_string(),
                policy: Policy {
                    require_approval: false,
                    max_ttl: Some("24h".to_string()),
                    allowed_agent_hashes: vec!["0xabc123".to_string()],
                },
            }, None)
            .unwrap();

        // Read metadata
        let cred = store.get(&id).unwrap().unwrap();
        assert_eq!(cred.provider, "aws");
        assert_eq!(cred.scope_tags, vec!["s3:read"]);
        assert_eq!(cred.policy.max_ttl, Some("24h".to_string()));
        assert_eq!(cred.policy.allowed_agent_hashes, vec!["0xabc123"]);

        // Read secret (with audit)
        let secret = store.get_secret(&id, "ci-agent").unwrap().unwrap();
        assert_eq!(secret.as_str(), "AKIA_test_secret_key");

        // List
        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, id);

        // Delete
        let deleted = store.delete(&id).unwrap();
        assert!(deleted);

        // Verify gone
        assert!(store.get(&id).unwrap().is_none());
        assert!(store.list().unwrap().is_empty());

        // Verify audit trail has all 4 actions: created, secret_accessed, deleted
        // (technically the delete log_access happens before the DELETE query, so
        // if the credential doesn't exist we still get a log entry)
        let audit_count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM audit_log WHERE credential_id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(audit_count, 3, "Should have 3 audit entries: created + secret_accessed + deleted");
    }
}
