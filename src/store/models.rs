// Keystone — Credential data models
//
// SECURITY: The `secret_value` field is intentionally private. It is never
// included in Debug output, log messages, or serialized responses.
// Access is controlled via explicit getter methods that trigger audit logging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::fmt;

/// The full credential record, stored in the database.
/// The `secret_value` field is private — access only via `secret_value()`.
pub struct Credential {
    pub id: Uuid,
    pub provider: String,
    pub scope_tags: Vec<String>,
    pub environment: String,
    pub intent_description: String,
    /// The actual API key / secret — NEVER printed, logged, or Debug-displayed
    secret_value: String,
    pub policy: Policy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Credential {
    /// Create a new Credential with all fields.
    pub fn new(
        id: Uuid,
        provider: String,
        scope_tags: Vec<String>,
        environment: String,
        intent_description: String,
        secret_value: String,
        policy: Policy,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            provider,
            scope_tags,
            environment,
            intent_description,
            secret_value,
            policy,
            created_at,
            updated_at,
        }
    }

    /// Access the raw secret value.
    /// IMPORTANT: Callers are responsible for audit-logging this access.
    /// Prefer using `CredentialStore::get_secret()` which handles logging.
    pub fn secret_value(&self) -> &str {
        &self.secret_value
    }
}

/// Custom Debug implementation that NEVER reveals the secret.
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("scope_tags", &self.scope_tags)
            .field("environment", &self.environment)
            .field("intent_description", &self.intent_description)
            .field("secret_value", &"[REDACTED]")
            .field("policy", &self.policy)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Custom Display that shows a human-readable summary without the secret.
impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}) — {}",
            self.id, self.provider, self.environment, self.intent_description
        )
    }
}

/// A lightweight view of a credential, used for listing.
/// Never contains the secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub id: Uuid,
    pub provider: String,
    pub scope_tags: Vec<String>,
    pub environment: String,
    pub intent_description: String,
    pub policy: Policy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Display for CredentialSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}) — {}",
            self.id, self.provider, self.environment, self.intent_description
        )
    }
}

/// Input struct for creating a new credential.
pub struct NewCredential {
    pub provider: String,
    pub scope_tags: Vec<String>,
    pub environment: String,
    pub intent_description: String,
    pub secret_value: String,
    pub policy: Policy,
}

/// Status of a human-in-the-loop approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

/// Represents an asynchronous request for credential access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub credential_id: Uuid,
    pub actor: String,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
}

/// Policy governing access to a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// If true, accessing the secret requires a verified human approval.
    pub require_approval: bool,
    /// Maximum time-to-live for a checked-out secret. After this, it auto-expires.
    /// E.g. "1h", "30m", "24h"
    pub max_ttl: Option<String>,
    /// List of agent hashes allowed to access this credential auto-magically.
    pub allowed_agent_hashes: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_approval: false,
            max_ttl: None,
            allowed_agent_hashes: Vec::new(),
        }
    }
}

impl Policy {
    /// Parse the `max_ttl` string into a `chrono::Duration`.
    /// Supports 's' (seconds), 'm' (minutes), 'h' (hours), 'd' (days).
    /// Returns None if no TTL is set or if parsing fails.
    pub fn parsed_ttl(&self) -> Option<chrono::Duration> {
        let ttl_str = self.max_ttl.as_ref()?;
        
        let mut num_str = String::new();
        let mut unit = ' ';
        
        for c in ttl_str.chars() {
            if c.is_ascii_digit() {
                num_str.push(c);
            } else if c.is_alphabetic() {
                unit = c;
                break;
            }
        }
        
        let amount: i64 = num_str.parse().ok()?;
        
        match unit {
            's' => Some(chrono::Duration::seconds(amount)),
            'm' => Some(chrono::Duration::minutes(amount)),
            'h' => Some(chrono::Duration::hours(amount)),
            'd' => Some(chrono::Duration::days(amount)),
            _ => None,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_debug_redacts_secret() {
        let cred = Credential::new(
            Uuid::new_v4(),
            "github".to_string(),
            vec!["repo:read".to_string()],
            "production".to_string(),
            "GitHub PAT for CI".to_string(),
            "ghp_super_secret_12345".to_string(),
            Policy::default(),
            Utc::now(),
            Utc::now(),
        );

        let debug_output = format!("{:?}", cred);
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output must contain [REDACTED]"
        );
        assert!(
            !debug_output.contains("ghp_super_secret_12345"),
            "Debug output must NEVER contain the raw secret"
        );
    }

    #[test]
    fn test_credential_display_does_not_contain_secret() {
        let cred = Credential::new(
            Uuid::new_v4(),
            "slack".to_string(),
            vec!["chat:write".to_string()],
            "development".to_string(),
            "Slack bot token".to_string(),
            "xoxb-secret-token".to_string(),
            Policy::default(),
            Utc::now(),
            Utc::now(),
        );

        let display_output = format!("{}", cred);
        assert!(
            !display_output.contains("xoxb-secret-token"),
            "Display output must NEVER contain the raw secret"
        );
        assert!(display_output.contains("slack"), "Should show provider");
        assert!(
            display_output.contains("Slack bot token"),
            "Should show intent"
        );
    }

    #[test]
    fn test_secret_value_accessor_returns_raw_secret() {
        let secret = "my-secret-key-12345";
        let cred = Credential::new(
            Uuid::new_v4(),
            "aws".to_string(),
            vec![],
            "staging".to_string(),
            "AWS access key".to_string(),
            secret.to_string(),
            Policy::default(),
            Utc::now(),
            Utc::now(),
        );

        assert_eq!(cred.secret_value(), secret);
    }

    #[test]
    fn test_credential_summary_has_no_secret_field() {
        let summary = CredentialSummary {
            id: Uuid::new_v4(),
            provider: "openai".to_string(),
            scope_tags: vec!["models:read".to_string()],
            environment: "production".to_string(),
            intent_description: "OpenAI API key for embeddings".to_string(),
            policy: Policy::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // CredentialSummary can be serialized — and must not contain any secret field
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("secret"), "Summary JSON must not contain any secret field");
    }

    #[test]
    fn test_policy_default() {
        let policy = Policy::default();
        assert!(!policy.require_approval);
        assert!(policy.max_ttl.is_none());
        assert!(policy.allowed_agent_hashes.is_empty());
    }
}
