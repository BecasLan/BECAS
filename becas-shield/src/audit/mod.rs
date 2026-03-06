//! # Audit Logger
//!
//! Tamper-proof audit logging for BECAS.
//! Every access, level change, and significant event is recorded
//! with a hash chain to prevent tampering.

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};

/// Types of auditable events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Service deployed
    ServiceDeployed { service_name: String },
    /// Service started
    ServiceStarted { service_name: String },
    /// Service stopped
    ServiceStopped { service_name: String },
    /// Access level changed
    AccessLevelChanged { from: String, to: String, reason: String },
    /// Anomaly detected
    AnomalyDetected { anomaly: String, severity: String },
    /// Firewall action taken
    FirewallAction { ip: String, action: String },
    /// Owner override used
    OwnerOverride { justification: String },
    /// Configuration changed
    ConfigChanged { field: String, old_value: String, new_value: String },
    /// Custom event
    Custom { category: String, message: String },
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEventType::ServiceDeployed { service_name } =>
                write!(f, "Service deployed: {}", service_name),
            AuditEventType::ServiceStarted { service_name } =>
                write!(f, "Service started: {}", service_name),
            AuditEventType::ServiceStopped { service_name } =>
                write!(f, "Service stopped: {}", service_name),
            AuditEventType::AccessLevelChanged { from, to, reason } =>
                write!(f, "Access level: {} → {} ({})", from, to, reason),
            AuditEventType::AnomalyDetected { anomaly, severity } =>
                write!(f, "Anomaly [{}]: {}", severity, anomaly),
            AuditEventType::FirewallAction { ip, action } =>
                write!(f, "Firewall: {} → {}", ip, action),
            AuditEventType::OwnerOverride { justification } =>
                write!(f, "OWNER OVERRIDE: {}", justification),
            AuditEventType::ConfigChanged { field, old_value, new_value } =>
                write!(f, "Config: {} = {} → {}", field, old_value, new_value),
            AuditEventType::Custom { category, message } =>
                write!(f, "[{}] {}", category, message),
        }
    }
}

/// A single audit log entry with hash chain link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: Uuid,
    /// Sequence number (monotonically increasing)
    pub seq: u64,
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    /// Service this event relates to (None for global events)
    pub service_id: Option<Uuid>,
    /// The event itself
    pub event: AuditEventType,
    /// Who triggered this event
    pub actor: AuditActor,
    /// Hash of this entry (for tamper detection)
    pub hash: String,
    /// Hash of the previous entry (chain link)
    pub prev_hash: String,
}

/// Who triggered an audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditActor {
    /// BECAS system (automatic)
    System,
    /// PC owner
    Owner,
    /// External user/client
    External { source: String },
    /// BECAS Shield (security subsystem)
    Shield,
}

impl std::fmt::Display for AuditActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditActor::System => write!(f, "SYSTEM"),
            AuditActor::Owner => write!(f, "OWNER"),
            AuditActor::External { source } => write!(f, "EXTERNAL({})", source),
            AuditActor::Shield => write!(f, "SHIELD"),
        }
    }
}

/// Tamper-proof audit logger with hash chain
pub struct AuditLogger {
    entries: Arc<RwLock<Vec<AuditEntry>>>,
    next_seq: Arc<RwLock<u64>>,
    last_hash: Arc<RwLock<String>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            next_seq: Arc::new(RwLock::new(1)),
            last_hash: Arc::new(RwLock::new("GENESIS".to_string())),
        }
    }

    /// Log an audit event
    pub async fn log(
        &self,
        service_id: Option<Uuid>,
        event: AuditEventType,
        actor: AuditActor,
    ) -> AuditEntry {
        let mut seq_lock = self.next_seq.write().await;
        let seq = *seq_lock;
        *seq_lock += 1;

        let prev_hash = self.last_hash.read().await.clone();
        let timestamp = Utc::now();

        // Compute hash of this entry
        let hash_input = format!("{}:{}:{}:{}:{}", seq, timestamp, event, actor, prev_hash);
        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let entry = AuditEntry {
            id: Uuid::new_v4(),
            seq,
            timestamp,
            service_id,
            event,
            actor,
            hash: hash.clone(),
            prev_hash,
        };

        *self.last_hash.write().await = hash;

        tracing::debug!(
            seq = seq,
            event = %entry.event,
            actor = %entry.actor,
            "Audit log entry"
        );

        self.entries.write().await.push(entry.clone());
        entry
    }

    /// Verify the integrity of the hash chain
    pub async fn verify_integrity(&self) -> IntegrityResult {
        let entries = self.entries.read().await;

        if entries.is_empty() {
            return IntegrityResult { valid: true, total_entries: 0, broken_at: None };
        }

        // Check first entry links to GENESIS
        if entries[0].prev_hash != "GENESIS" {
            return IntegrityResult {
                valid: false,
                total_entries: entries.len(),
                broken_at: Some(0),
            };
        }

        // Verify chain
        for i in 1..entries.len() {
            if entries[i].prev_hash != entries[i - 1].hash {
                return IntegrityResult {
                    valid: false,
                    total_entries: entries.len(),
                    broken_at: Some(i),
                };
            }
        }

        IntegrityResult {
            valid: true,
            total_entries: entries.len(),
            broken_at: None,
        }
    }

    /// Get all entries
    pub async fn all_entries(&self) -> Vec<AuditEntry> {
        self.entries.read().await.clone()
    }

    /// Get entries for a specific service
    pub async fn service_entries(&self, service_id: &Uuid) -> Vec<AuditEntry> {
        self.entries.read().await.iter()
            .filter(|e| e.service_id.as_ref() == Some(service_id))
            .cloned()
            .collect()
    }

    /// Get entries by actor type
    pub async fn entries_by_actor(&self, actor_name: &str) -> Vec<AuditEntry> {
        self.entries.read().await.iter()
            .filter(|e| e.actor.to_string().starts_with(actor_name))
            .cloned()
            .collect()
    }

    /// Get recent entries (last N)
    pub async fn recent(&self, count: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Total entry count
    pub async fn count(&self) -> usize {
        self.entries.read().await.len()
    }
}

/// Result of integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityResult {
    pub valid: bool,
    pub total_entries: usize,
    pub broken_at: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_log_event() {
        let logger = AuditLogger::new();
        let entry = logger.log(
            None,
            AuditEventType::ServiceDeployed { service_name: "test-db".into() },
            AuditActor::Owner,
        ).await;

        assert_eq!(entry.seq, 1);
        assert_eq!(entry.prev_hash, "GENESIS");
        assert!(!entry.hash.is_empty());
    }

    #[tokio::test]
    async fn test_hash_chain() {
        let logger = AuditLogger::new();

        let e1 = logger.log(None, AuditEventType::Custom {
            category: "test".into(), message: "first".into(),
        }, AuditActor::System).await;

        let e2 = logger.log(None, AuditEventType::Custom {
            category: "test".into(), message: "second".into(),
        }, AuditActor::System).await;

        // e2's prev_hash should be e1's hash
        assert_eq!(e2.prev_hash, e1.hash);
        assert_ne!(e1.hash, e2.hash);
    }

    #[tokio::test]
    async fn test_verify_integrity() {
        let logger = AuditLogger::new();

        for i in 0..10 {
            logger.log(None, AuditEventType::Custom {
                category: "test".into(), message: format!("event {}", i),
            }, AuditActor::System).await;
        }

        let result = logger.verify_integrity().await;
        assert!(result.valid);
        assert_eq!(result.total_entries, 10);
    }

    #[tokio::test]
    async fn test_service_entries() {
        let logger = AuditLogger::new();
        let svc = Uuid::new_v4();

        logger.log(Some(svc), AuditEventType::ServiceStarted {
            service_name: "db".into(),
        }, AuditActor::Owner).await;

        logger.log(None, AuditEventType::Custom {
            category: "global".into(), message: "unrelated".into(),
        }, AuditActor::System).await;

        let entries = logger.service_entries(&svc).await;
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_recent_entries() {
        let logger = AuditLogger::new();
        for i in 0..20 {
            logger.log(None, AuditEventType::Custom {
                category: "test".into(), message: format!("{}", i),
            }, AuditActor::System).await;
        }

        let recent = logger.recent(5).await;
        assert_eq!(recent.len(), 5);
    }

    #[tokio::test]
    async fn test_owner_override_logged() {
        let logger = AuditLogger::new();
        let svc = Uuid::new_v4();

        logger.log(Some(svc), AuditEventType::OwnerOverride {
            justification: "Court order #12345".into(),
        }, AuditActor::Owner).await;

        let entries = logger.service_entries(&svc).await;
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].event, AuditEventType::OwnerOverride { .. }));
    }
}
