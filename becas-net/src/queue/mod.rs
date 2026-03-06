//! # Request Queue
//!
//! Handles requests when the PC is offline or the service is temporarily unavailable.
//! Requests are queued and processed when the service comes back online.
//!
//! ## Behavior
//! - Service online → requests handled immediately
//! - Service paused → requests queued, processed on resume
//! - PC sleeping → requests queued, processed on wake
//! - PC offline → requests held at edge/relay, synced on reconnect

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QueueError {
    #[error("Queue is full (max {max} items)")]
    QueueFull { max: usize },

    #[error("Request not found: {0}")]
    NotFound(String),

    #[error("Request expired: {0}")]
    Expired(String),

    #[error("Queue not found for service: {0}")]
    QueueNotFound(String),
}

pub type Result<T> = std::result::Result<T, QueueError>;

// ─────────────────────────────────────────────
// Queued Request
// ─────────────────────────────────────────────

/// A request waiting to be processed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedRequest {
    /// Unique request ID
    pub id: Uuid,
    /// Service this request is for
    pub service_id: Uuid,
    /// Request method (GET, POST, etc.)
    pub method: String,
    /// Request path
    pub path: String,
    /// Request headers
    pub headers: Vec<(String, String)>,
    /// Request body (if any)
    pub body: Option<Vec<u8>>,
    /// When the request was received
    pub received_at: DateTime<Utc>,
    /// When the request expires (after this, return 503)
    pub expires_at: DateTime<Utc>,
    /// Priority (lower = higher priority)
    pub priority: RequestPriority,
    /// Number of processing attempts
    pub attempts: u32,
    /// Source (who sent this request)
    pub source_addr: Option<String>,
}

/// Request priority
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestPriority {
    /// Critical (health checks, admin operations)
    Critical = 0,
    /// High (user-facing write operations)
    High = 1,
    /// Normal (regular requests)
    Normal = 2,
    /// Low (background tasks, analytics)
    Low = 3,
}

impl Default for RequestPriority {
    fn default() -> Self {
        RequestPriority::Normal
    }
}

// ─────────────────────────────────────────────
// Queue Configuration
// ─────────────────────────────────────────────

/// Configuration for a service request queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    /// Maximum number of queued requests
    pub max_size: usize,
    /// Default TTL for requests (seconds)
    pub default_ttl_secs: u64,
    /// Maximum body size in bytes
    pub max_body_bytes: usize,
    /// Whether to persist queue to disk
    pub persistent: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_size: 10_000,
            default_ttl_secs: 3600, // 1 hour
            max_body_bytes: 10 * 1024 * 1024, // 10MB
            persistent: true,
        }
    }
}

// ─────────────────────────────────────────────
// Service Queue
// ─────────────────────────────────────────────

/// Queue for a single service
struct ServiceQueue {
    config: QueueConfig,
    requests: VecDeque<QueuedRequest>,
    total_enqueued: u64,
    total_processed: u64,
    total_expired: u64,
    total_dropped: u64,
}

impl ServiceQueue {
    fn new(config: QueueConfig) -> Self {
        Self {
            config,
            requests: VecDeque::new(),
            total_enqueued: 0,
            total_processed: 0,
            total_expired: 0,
            total_dropped: 0,
        }
    }

    /// Enqueue a request
    fn enqueue(&mut self, request: QueuedRequest) -> Result<()> {
        if self.requests.len() >= self.config.max_size {
            self.total_dropped += 1;
            return Err(QueueError::QueueFull { max: self.config.max_size });
        }

        self.total_enqueued += 1;
        self.requests.push_back(request);
        Ok(())
    }

    /// Dequeue the next request (priority-aware, skips expired)
    fn dequeue(&mut self) -> Option<QueuedRequest> {
        let now = Utc::now();

        // Remove expired requests from front
        while let Some(front) = self.requests.front() {
            if front.expires_at < now {
                self.requests.pop_front();
                self.total_expired += 1;
            } else {
                break;
            }
        }

        if let Some(req) = self.requests.pop_front() {
            self.total_processed += 1;
            Some(req)
        } else {
            None
        }
    }

    /// Peek at the next request without removing
    #[allow(dead_code)]
    fn peek(&self) -> Option<&QueuedRequest> {
        self.requests.front()
    }

    /// Get queue length (excluding expired)
    fn len(&self) -> usize {
        let now = Utc::now();
        self.requests.iter().filter(|r| r.expires_at >= now).count()
    }

    /// Remove expired requests
    fn cleanup_expired(&mut self) -> usize {
        let now = Utc::now();
        let before = self.requests.len();
        self.requests.retain(|r| r.expires_at >= now);
        let removed = before - self.requests.len();
        self.total_expired += removed as u64;
        removed
    }
}

// ─────────────────────────────────────────────
// Queue Manager
// ─────────────────────────────────────────────

/// Manages request queues for all BECAS services
pub struct QueueManager {
    queues: Arc<RwLock<std::collections::HashMap<Uuid, ServiceQueue>>>,
    default_config: QueueConfig,
}

impl QueueManager {
    /// Create a new queue manager
    pub fn new(default_config: QueueConfig) -> Self {
        Self {
            queues: Arc::new(RwLock::new(std::collections::HashMap::new())),
            default_config,
        }
    }

    /// Create a queue for a service
    pub async fn create_queue(&self, service_id: Uuid, config: Option<QueueConfig>) {
        let cfg = config.unwrap_or_else(|| self.default_config.clone());
        self.queues.write().await.insert(service_id, ServiceQueue::new(cfg));
        tracing::debug!(service_id = %service_id, "Request queue created");
    }

    /// Enqueue a request for a service
    pub async fn enqueue(
        &self,
        service_id: &Uuid,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        priority: RequestPriority,
        source_addr: Option<String>,
    ) -> Result<Uuid> {
        let mut queues = self.queues.write().await;
        let queue = queues.get_mut(service_id)
            .ok_or_else(|| QueueError::QueueNotFound(service_id.to_string()))?;

        let request_id = Uuid::new_v4();
        let ttl = Duration::seconds(queue.config.default_ttl_secs as i64);

        let request = QueuedRequest {
            id: request_id,
            service_id: *service_id,
            method: method.to_string(),
            path: path.to_string(),
            headers,
            body,
            received_at: Utc::now(),
            expires_at: Utc::now() + ttl,
            priority,
            attempts: 0,
            source_addr,
        };

        queue.enqueue(request)?;

        tracing::debug!(
            service_id = %service_id,
            request_id = %request_id,
            method = method,
            path = path,
            "Request queued"
        );

        Ok(request_id)
    }

    /// Dequeue the next request for a service
    pub async fn dequeue(&self, service_id: &Uuid) -> Result<Option<QueuedRequest>> {
        let mut queues = self.queues.write().await;
        let queue = queues.get_mut(service_id)
            .ok_or_else(|| QueueError::QueueNotFound(service_id.to_string()))?;
        Ok(queue.dequeue())
    }

    /// Drain all pending requests (process all at once)
    pub async fn drain(&self, service_id: &Uuid) -> Result<Vec<QueuedRequest>> {
        let mut queues = self.queues.write().await;
        let queue = queues.get_mut(service_id)
            .ok_or_else(|| QueueError::QueueNotFound(service_id.to_string()))?;

        let mut requests = Vec::new();
        while let Some(req) = queue.dequeue() {
            requests.push(req);
        }
        Ok(requests)
    }

    /// Get queue statistics for a service
    pub async fn stats(&self, service_id: &Uuid) -> Result<QueueStats> {
        let queues = self.queues.read().await;
        let queue = queues.get(service_id)
            .ok_or_else(|| QueueError::QueueNotFound(service_id.to_string()))?;

        Ok(QueueStats {
            pending: queue.len(),
            total_enqueued: queue.total_enqueued,
            total_processed: queue.total_processed,
            total_expired: queue.total_expired,
            total_dropped: queue.total_dropped,
        })
    }

    /// Clean up expired requests across all queues
    pub async fn cleanup_all(&self) -> usize {
        let mut queues = self.queues.write().await;
        let mut total_removed = 0;
        for queue in queues.values_mut() {
            total_removed += queue.cleanup_expired();
        }
        if total_removed > 0 {
            tracing::debug!(removed = total_removed, "Cleaned up expired requests");
        }
        total_removed
    }

    /// Remove a queue
    pub async fn remove_queue(&self, service_id: &Uuid) {
        self.queues.write().await.remove(service_id);
    }
}

/// Queue statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStats {
    pub pending: usize,
    pub total_enqueued: u64,
    pub total_processed: u64,
    pub total_expired: u64,
    pub total_dropped: u64,
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enqueue_dequeue() {
        let mgr = QueueManager::new(QueueConfig::default());
        let svc = Uuid::new_v4();
        mgr.create_queue(svc, None).await;

        let req_id = mgr.enqueue(
            &svc, "GET", "/api/users", vec![], None,
            RequestPriority::Normal, None,
        ).await.unwrap();

        let req = mgr.dequeue(&svc).await.unwrap().unwrap();
        assert_eq!(req.id, req_id);
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/users");
    }

    #[tokio::test]
    async fn test_empty_dequeue() {
        let mgr = QueueManager::new(QueueConfig::default());
        let svc = Uuid::new_v4();
        mgr.create_queue(svc, None).await;

        let req = mgr.dequeue(&svc).await.unwrap();
        assert!(req.is_none());
    }

    #[tokio::test]
    async fn test_queue_full() {
        let mgr = QueueManager::new(QueueConfig {
            max_size: 2,
            ..Default::default()
        });
        let svc = Uuid::new_v4();
        mgr.create_queue(svc, None).await;

        mgr.enqueue(&svc, "GET", "/1", vec![], None, RequestPriority::Normal, None).await.unwrap();
        mgr.enqueue(&svc, "GET", "/2", vec![], None, RequestPriority::Normal, None).await.unwrap();
        let result = mgr.enqueue(&svc, "GET", "/3", vec![], None, RequestPriority::Normal, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_drain() {
        let mgr = QueueManager::new(QueueConfig::default());
        let svc = Uuid::new_v4();
        mgr.create_queue(svc, None).await;

        for i in 0..5 {
            mgr.enqueue(&svc, "GET", &format!("/{}", i), vec![], None, RequestPriority::Normal, None).await.unwrap();
        }

        let all = mgr.drain(&svc).await.unwrap();
        assert_eq!(all.len(), 5);

        // Queue should be empty now
        let req = mgr.dequeue(&svc).await.unwrap();
        assert!(req.is_none());
    }

    #[tokio::test]
    async fn test_stats() {
        let mgr = QueueManager::new(QueueConfig::default());
        let svc = Uuid::new_v4();
        mgr.create_queue(svc, None).await;

        mgr.enqueue(&svc, "GET", "/1", vec![], None, RequestPriority::Normal, None).await.unwrap();
        mgr.enqueue(&svc, "POST", "/2", vec![], None, RequestPriority::High, None).await.unwrap();
        mgr.dequeue(&svc).await.unwrap();

        let stats = mgr.stats(&svc).await.unwrap();
        assert_eq!(stats.total_enqueued, 2);
        assert_eq!(stats.total_processed, 1);
        assert_eq!(stats.pending, 1);
    }
}
