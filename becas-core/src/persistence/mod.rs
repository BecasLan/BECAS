//! # Persistence Layer
//!
//! Saves and loads BECAS state to/from disk so that:
//! - Services survive PC restarts
//! - Audit logs are never lost
//! - Request queues persist across offline periods
//!
//! ## Storage Format
//! - Services: `services/` directory, one JSON file per service
//! - Audit: `audit/audit.jsonl` (append-only, one JSON entry per line)
//! - Queue: `queues/` directory, one JSON file per service queue
//!
//! All data can optionally be stored in an EncryptedVolume.

use std::path::{Path, PathBuf};

use thiserror::Error;
use uuid::Uuid;

use crate::service::Service;

#[derive(Error, Debug)]
pub enum PersistenceError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Data not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, PersistenceError>;

// ─────────────────────────────────────────────
// Service Store
// ─────────────────────────────────────────────

/// Persistent storage for service state
pub struct ServiceStore {
    dir: PathBuf,
}

impl ServiceStore {
    /// Create a new service store at the given directory
    pub fn new(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Save a service to disk
    pub fn save(&self, service: &Service) -> Result<()> {
        let path = self.dir.join(format!("{}.json", service.id));
        let json = serde_json::to_string_pretty(service)?;
        std::fs::write(&path, json)?;
        tracing::debug!(service_id = %service.id, name = %service.config.name, "Service saved to disk");
        Ok(())
    }

    /// Save all services
    pub fn save_all(&self, services: &[Service]) -> Result<()> {
        for svc in services {
            self.save(svc)?;
        }
        Ok(())
    }

    /// Load a service by ID
    pub fn load(&self, id: &Uuid) -> Result<Service> {
        let path = self.dir.join(format!("{}.json", id));
        if !path.exists() {
            return Err(PersistenceError::NotFound(id.to_string()));
        }
        let json = std::fs::read_to_string(&path)?;
        let service: Service = serde_json::from_str(&json)?;
        Ok(service)
    }

    /// Load all services from disk
    pub fn load_all(&self) -> Result<Vec<Service>> {
        let mut services = Vec::new();
        if !self.dir.exists() {
            return Ok(services);
        }
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let json = std::fs::read_to_string(&path)?;
                match serde_json::from_str::<Service>(&json) {
                    Ok(svc) => {
                        tracing::debug!(service_id = %svc.id, name = %svc.config.name, "Loaded service from disk");
                        services.push(svc);
                    }
                    Err(e) => {
                        tracing::warn!(path = ?path, error = %e, "Failed to load service file, skipping");
                    }
                }
            }
        }
        Ok(services)
    }

    /// Delete a service file
    pub fn delete(&self, id: &Uuid) -> Result<()> {
        let path = self.dir.join(format!("{}.json", id));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────
// Audit Store (append-only JSONL)
// ─────────────────────────────────────────────


/// Persistent append-only audit log
pub struct AuditStore {
    path: PathBuf,
}

/// Generic audit entry that can store any serializable audit data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredAuditEntry {
    pub id: Uuid,
    pub seq: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub service_id: Option<Uuid>,
    pub event_type: String,
    pub event_data: serde_json::Value,
    pub actor: String,
    pub hash: String,
    pub prev_hash: String,
}

impl AuditStore {
    /// Create a new audit store
    pub fn new(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self { path })
    }

    /// Compute SHA-256 hash for an audit entry (hash chain)
    /// Hash covers: seq + timestamp + event_type + event_data + actor + prev_hash
    pub fn compute_hash(entry: &StoredAuditEntry) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(entry.seq.to_le_bytes());
        hasher.update(entry.timestamp.to_rfc3339().as_bytes());
        hasher.update(entry.event_type.as_bytes());
        hasher.update(entry.event_data.to_string().as_bytes());
        hasher.update(entry.actor.as_bytes());
        hasher.update(entry.prev_hash.as_bytes());
        if let Some(sid) = &entry.service_id {
            hasher.update(sid.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Create an audit entry with proper hash chain
    /// Automatically sets seq, prev_hash, and computes hash
    pub fn create_entry(
        &self,
        event_type: &str,
        event_data: serde_json::Value,
        service_id: Option<Uuid>,
        actor: &str,
    ) -> Result<StoredAuditEntry> {
        let last = self.last_entry()?;
        let seq = last.as_ref().map(|e| e.seq + 1).unwrap_or(1);
        let prev_hash = last.map(|e| e.hash).unwrap_or_else(|| "GENESIS".into());

        let mut entry = StoredAuditEntry {
            id: Uuid::new_v4(),
            seq,
            timestamp: chrono::Utc::now(),
            service_id,
            event_type: event_type.to_string(),
            event_data,
            actor: actor.to_string(),
            hash: String::new(), // computed below
            prev_hash,
        };
        entry.hash = Self::compute_hash(&entry);
        Ok(entry)
    }

    /// Append an entry to the audit log
    pub fn append(&self, entry: &StoredAuditEntry) -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let json = serde_json::to_string(entry)?;
        writeln!(file, "{}", json)?;
        Ok(())
    }

    /// Create and append an entry in one step (convenience method)
    pub fn log(
        &self,
        event_type: &str,
        event_data: serde_json::Value,
        service_id: Option<Uuid>,
        actor: &str,
    ) -> Result<StoredAuditEntry> {
        let entry = self.create_entry(event_type, event_data, service_id, actor)?;
        self.append(&entry)?;
        Ok(entry)
    }

    /// Verify the entire hash chain integrity
    /// Returns (valid, total_entries, first_broken_seq)
    pub fn verify_chain(&self) -> Result<(bool, usize, Option<u64>)> {
        let entries = self.load_all()?;
        if entries.is_empty() {
            return Ok((true, 0, None));
        }

        for (i, entry) in entries.iter().enumerate() {
            // Verify hash
            let computed = Self::compute_hash(entry);
            if computed != entry.hash {
                return Ok((false, entries.len(), Some(entry.seq)));
            }

            // Verify prev_hash chain
            if i == 0 {
                if entry.prev_hash != "GENESIS" {
                    return Ok((false, entries.len(), Some(entry.seq)));
                }
            } else {
                if entry.prev_hash != entries[i - 1].hash {
                    return Ok((false, entries.len(), Some(entry.seq)));
                }
            }

            // Verify sequential ordering
            if entry.seq != (i as u64 + 1) {
                return Ok((false, entries.len(), Some(entry.seq)));
            }
        }

        Ok((true, entries.len(), None))
    }

    /// Load all audit entries from disk
    pub fn load_all(&self) -> Result<Vec<StoredAuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read_to_string(&self.path)?;
        let mut entries = Vec::new();
        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<StoredAuditEntry>(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    tracing::warn!(line = line_num + 1, error = %e, "Skipping corrupt audit entry");
                }
            }
        }
        Ok(entries)
    }

    /// Get the last entry (for hash chain continuation)
    pub fn last_entry(&self) -> Result<Option<StoredAuditEntry>> {
        let entries = self.load_all()?;
        Ok(entries.into_iter().last())
    }

    /// Count entries
    pub fn count(&self) -> Result<usize> {
        if !self.path.exists() {
            return Ok(0);
        }
        let content = std::fs::read_to_string(&self.path)?;
        Ok(content.lines().filter(|l| !l.trim().is_empty()).count())
    }
}

// ─────────────────────────────────────────────
// Queue Store
// ─────────────────────────────────────────────


/// Persistent storage for request queues
pub struct QueueStore {
    dir: PathBuf,
}

/// Stored queue state for a service
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredQueue {
    pub service_id: Uuid,
    pub requests: Vec<serde_json::Value>,
    pub total_enqueued: u64,
    pub total_processed: u64,
    pub total_expired: u64,
    pub total_dropped: u64,
}

impl QueueStore {
    /// Create a new queue store
    pub fn new(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Save queue state for a service
    pub fn save(&self, queue: &StoredQueue) -> Result<()> {
        let path = self.dir.join(format!("{}.json", queue.service_id));
        let json = serde_json::to_string_pretty(queue)?;
        std::fs::write(&path, json)?;
        tracing::debug!(service_id = %queue.service_id, pending = queue.requests.len(), "Queue saved to disk");
        Ok(())
    }

    /// Load queue state for a service
    pub fn load(&self, service_id: &Uuid) -> Result<Option<StoredQueue>> {
        let path = self.dir.join(format!("{}.json", service_id));
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&path)?;
        let queue: StoredQueue = serde_json::from_str(&json)?;
        Ok(Some(queue))
    }

    /// Load all queues
    pub fn load_all(&self) -> Result<Vec<StoredQueue>> {
        let mut queues = Vec::new();
        if !self.dir.exists() {
            return Ok(queues);
        }
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let json = std::fs::read_to_string(&path)?;
                match serde_json::from_str::<StoredQueue>(&json) {
                    Ok(q) => queues.push(q),
                    Err(e) => {
                        tracing::warn!(path = ?path, error = %e, "Failed to load queue file");
                    }
                }
            }
        }
        Ok(queues)
    }

    /// Delete queue file for a service
    pub fn delete(&self, service_id: &Uuid) -> Result<()> {
        let path = self.dir.join(format!("{}.json", service_id));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────
// BECAS State Manager (orchestrates all persistence)
// ─────────────────────────────────────────────

/// Manages all persistent state for the BECAS Layer
pub struct StateManager {
    pub services: ServiceStore,
    pub audit: AuditStore,
    pub queues: QueueStore,
    base_dir: PathBuf,
}

impl StateManager {
    /// Initialize the state manager at the given base directory
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self {
            services: ServiceStore::new(base_dir.join("services"))?,
            audit: AuditStore::new(base_dir.join("audit").join("audit.jsonl"))?,
            queues: QueueStore::new(base_dir.join("queues"))?,
            base_dir,
        })
    }

    /// Get base directory
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{ServiceConfig, ServiceType, ServiceStatus};
    use crate::resource::ResourceLimits;
    use chrono::Utc;

    fn make_test_service(name: &str) -> Service {
        Service {
            id: Uuid::new_v4(),
            config: ServiceConfig {
                name: name.to_string(),
                service_type: ServiceType::Database,
                command: "echo".to_string(),
                args: vec!["hello".to_string()],
                ..Default::default()
            },
            status: ServiceStatus::Deployed,
            identity_id: "test-identity".to_string(),
            sandbox_id: None,
            endpoint: None,
            deployed_at: Utc::now(),
            updated_at: Utc::now(),
            restart_count: 0,
            total_requests: 0,
            total_uptime_secs: 0,
            pid: None,
        }
    }

    // ─── ServiceStore tests ───

    #[test]
    fn test_service_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = ServiceStore::new(dir.path().join("services")).unwrap();

        let svc = make_test_service("test-db");
        let id = svc.id;

        store.save(&svc).unwrap();
        let loaded = store.load(&id).unwrap();

        assert_eq!(loaded.id, id);
        assert_eq!(loaded.config.name, "test-db");
        assert_eq!(loaded.status, ServiceStatus::Deployed);
    }

    #[test]
    fn test_service_load_all() {
        let dir = tempfile::tempdir().unwrap();
        let store = ServiceStore::new(dir.path().join("services")).unwrap();

        store.save(&make_test_service("svc-1")).unwrap();
        store.save(&make_test_service("svc-2")).unwrap();
        store.save(&make_test_service("svc-3")).unwrap();

        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_service_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = ServiceStore::new(dir.path().join("services")).unwrap();

        let svc = make_test_service("deleteme");
        let id = svc.id;
        store.save(&svc).unwrap();

        store.delete(&id).unwrap();
        assert!(store.load(&id).is_err());
    }

    #[test]
    fn test_service_load_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = ServiceStore::new(dir.path().join("services")).unwrap();
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 0);
    }

    #[test]
    fn test_service_survives_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let svc_dir = dir.path().join("services");
        let store = ServiceStore::new(svc_dir.clone()).unwrap();

        store.save(&make_test_service("good")).unwrap();
        // Write a corrupt file
        std::fs::write(svc_dir.join("bad.json"), "not valid json{{{").unwrap();

        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1); // Only the good one loaded
    }

    // ─── AuditStore tests ───

    #[test]
    fn test_audit_append_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(dir.path().join("audit.jsonl")).unwrap();

        for i in 0..5 {
            let entry = StoredAuditEntry {
                id: Uuid::new_v4(),
                seq: i + 1,
                timestamp: Utc::now(),
                service_id: None,
                event_type: "test".to_string(),
                event_data: serde_json::json!({"msg": format!("event {}", i)}),
                actor: "SYSTEM".to_string(),
                hash: format!("hash_{}", i),
                prev_hash: if i == 0 { "GENESIS".to_string() } else { format!("hash_{}", i - 1) },
            };
            store.append(&entry).unwrap();
        }

        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[4].seq, 5);
    }

    #[test]
    fn test_audit_last_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(dir.path().join("audit.jsonl")).unwrap();

        assert!(store.last_entry().unwrap().is_none());

        store.append(&StoredAuditEntry {
            id: Uuid::new_v4(), seq: 1, timestamp: Utc::now(),
            service_id: None, event_type: "test".into(),
            event_data: serde_json::json!({}), actor: "SYS".into(),
            hash: "h1".into(), prev_hash: "GENESIS".into(),
        }).unwrap();

        store.append(&StoredAuditEntry {
            id: Uuid::new_v4(), seq: 2, timestamp: Utc::now(),
            service_id: None, event_type: "test".into(),
            event_data: serde_json::json!({}), actor: "SYS".into(),
            hash: "h2".into(), prev_hash: "h1".into(),
        }).unwrap();

        let last = store.last_entry().unwrap().unwrap();
        assert_eq!(last.seq, 2);
        assert_eq!(last.hash, "h2");
    }

    #[test]
    fn test_audit_count() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(dir.path().join("audit.jsonl")).unwrap();

        assert_eq!(store.count().unwrap(), 0);

        for i in 0..3 {
            store.append(&StoredAuditEntry {
                id: Uuid::new_v4(), seq: i + 1, timestamp: Utc::now(),
                service_id: None, event_type: "test".into(),
                event_data: serde_json::json!({}), actor: "SYS".into(),
                hash: format!("h{}", i), prev_hash: "x".into(),
            }).unwrap();
        }

        assert_eq!(store.count().unwrap(), 3);
    }

    // ─── Hash Chain tests ───

    #[test]
    fn test_audit_hash_chain_create_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(dir.path().join("audit.jsonl")).unwrap();

        // Create 5 entries using the log() convenience method
        for i in 0..5 {
            store.log(
                "test_event",
                serde_json::json!({"iteration": i}),
                None,
                "TEST",
            ).unwrap();
        }

        // Verify chain integrity
        let (valid, count, broken) = store.verify_chain().unwrap();
        assert!(valid, "Hash chain should be valid");
        assert_eq!(count, 5);
        assert!(broken.is_none());

        // Verify sequential ordering
        let entries = store.load_all().unwrap();
        assert_eq!(entries[0].prev_hash, "GENESIS");
        for i in 1..entries.len() {
            assert_eq!(entries[i].prev_hash, entries[i - 1].hash,
                "Entry {} prev_hash should match entry {} hash", i, i - 1);
            assert_eq!(entries[i].seq, (i as u64) + 1);
        }

        // Verify hashes are real SHA-256 (64 hex chars)
        for entry in &entries {
            assert_eq!(entry.hash.len(), 64, "Hash should be 64 hex chars: {}", entry.hash);
            assert!(entry.hash.chars().all(|c| c.is_ascii_hexdigit()), "Hash should be hex");
        }
    }

    #[test]
    fn test_audit_hash_chain_tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(dir.path().join("audit.jsonl")).unwrap();

        // Create legitimate chain
        store.log("event_a", serde_json::json!({"data": "original"}), None, "TEST").unwrap();
        store.log("event_b", serde_json::json!({"data": "second"}), None, "TEST").unwrap();
        store.log("event_c", serde_json::json!({"data": "third"}), None, "TEST").unwrap();

        // Verify it's valid first
        let (valid, _, _) = store.verify_chain().unwrap();
        assert!(valid);

        // Tamper: modify the file directly (change event data in entry 2)
        let content = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let tampered = content.replace("\"second\"", "\"HACKED\"");
        std::fs::write(dir.path().join("audit.jsonl"), tampered).unwrap();

        // Verify should now FAIL
        let (valid, count, broken_at) = store.verify_chain().unwrap();
        assert!(!valid, "Tampered chain should be invalid");
        assert_eq!(count, 3);
        assert_eq!(broken_at, Some(2), "Should detect tampering at seq 2");
    }

    #[test]
    fn test_audit_hash_chain_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(dir.path().join("audit.jsonl")).unwrap();

        let (valid, count, broken) = store.verify_chain().unwrap();
        assert!(valid);
        assert_eq!(count, 0);
        assert!(broken.is_none());
    }

    #[test]
    fn test_audit_compute_hash_deterministic() {
        let entry = StoredAuditEntry {
            id: Uuid::nil(),
            seq: 1,
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap().with_timezone(&Utc),
            service_id: None,
            event_type: "test".into(),
            event_data: serde_json::json!({"key": "value"}),
            actor: "SYS".into(),
            hash: String::new(),
            prev_hash: "GENESIS".into(),
        };

        let hash1 = AuditStore::compute_hash(&entry);
        let hash2 = AuditStore::compute_hash(&entry);
        assert_eq!(hash1, hash2, "Same input should produce same hash");
        assert_eq!(hash1.len(), 64, "SHA-256 should be 64 hex chars");
    }

    // ─── QueueStore tests ───

    #[test]
    fn test_queue_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = QueueStore::new(dir.path().join("queues")).unwrap();

        let svc_id = Uuid::new_v4();
        let queue = StoredQueue {
            service_id: svc_id,
            requests: vec![
                serde_json::json!({"method": "GET", "path": "/api/test"}),
                serde_json::json!({"method": "POST", "path": "/api/create"}),
            ],
            total_enqueued: 100,
            total_processed: 95,
            total_expired: 3,
            total_dropped: 0,
        };

        store.save(&queue).unwrap();
        let loaded = store.load(&svc_id).unwrap().unwrap();

        assert_eq!(loaded.service_id, svc_id);
        assert_eq!(loaded.requests.len(), 2);
        assert_eq!(loaded.total_enqueued, 100);
    }

    #[test]
    fn test_queue_load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let store = QueueStore::new(dir.path().join("queues")).unwrap();

        let result = store.load(&Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_queue_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = QueueStore::new(dir.path().join("queues")).unwrap();

        let svc_id = Uuid::new_v4();
        store.save(&StoredQueue {
            service_id: svc_id, requests: vec![],
            total_enqueued: 0, total_processed: 0,
            total_expired: 0, total_dropped: 0,
        }).unwrap();

        store.delete(&svc_id).unwrap();
        assert!(store.load(&svc_id).unwrap().is_none());
    }

    // ─── StateManager tests ───

    #[test]
    fn test_state_manager_init() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateManager::new(dir.path().join("becas-state")).unwrap();

        assert!(state.base_dir().exists());
        assert!(state.base_dir().join("services").exists());
        assert!(state.base_dir().join("queues").exists());
    }

    #[test]
    fn test_full_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateManager::new(dir.path().join("becas-state")).unwrap();

        // Save services
        let svc1 = make_test_service("becasdb");
        let svc2 = make_test_service("api-server");
        state.services.save(&svc1).unwrap();
        state.services.save(&svc2).unwrap();

        // Save audit entries
        state.audit.append(&StoredAuditEntry {
            id: Uuid::new_v4(), seq: 1, timestamp: Utc::now(),
            service_id: Some(svc1.id), event_type: "ServiceDeployed".into(),
            event_data: serde_json::json!({"name": "becasdb"}),
            actor: "OWNER".into(), hash: "h1".into(), prev_hash: "GENESIS".into(),
        }).unwrap();

        // Save queue
        state.queues.save(&StoredQueue {
            service_id: svc1.id,
            requests: vec![serde_json::json!({"method": "GET", "path": "/"})],
            total_enqueued: 1, total_processed: 0,
            total_expired: 0, total_dropped: 0,
        }).unwrap();

        // Simulate restart: create new StateManager at same path
        let state2 = StateManager::new(dir.path().join("becas-state")).unwrap();

        // Verify everything loaded correctly
        let services = state2.services.load_all().unwrap();
        assert_eq!(services.len(), 2);

        let audit = state2.audit.load_all().unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].event_type, "ServiceDeployed");

        let queue = state2.queues.load(&svc1.id).unwrap().unwrap();
        assert_eq!(queue.requests.len(), 1);
    }
}
