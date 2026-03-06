//! BECAS WebSocket Monitoring — Real-time metrics & log streaming
//!
//! Provides WebSocket-based real-time streaming for:
//! - System metrics (CPU, RAM, services)
//! - Service logs (tail -f style)
//! - Service events (start, stop, deploy, etc.)

use serde::{Serialize, Deserialize};
use std::sync::Arc;
use std::path::PathBuf;
use std::collections::HashMap;
use tokio::sync::{broadcast, RwLock};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::fs::File;

// ─────────────────────────────────────────────
// Metrics Streaming
// ─────────────────────────────────────────────

/// Live metrics event sent via WebSocket
#[derive(Serialize, Clone, Debug)]
pub struct MetricsEvent {
    pub timestamp: String,
    pub cpu_usage: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub active_services: usize,
    pub total_requests: u64,
    pub requests_per_sec: f64,
}

/// Metrics broadcaster — collects and broadcasts metrics
pub struct MetricsBroadcaster {
    tx: broadcast::Sender<MetricsEvent>,
    _rx: broadcast::Receiver<MetricsEvent>,
}

impl MetricsBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx, _rx }
    }

    /// Subscribe to metrics events
    pub fn subscribe(&self) -> broadcast::Receiver<MetricsEvent> {
        self.tx.subscribe()
    }

    /// Broadcast a metrics event manually
    pub fn broadcast(&self, event: MetricsEvent) {
        let _ = self.tx.send(event);
    }

    /// Start collecting metrics at the given interval
    pub fn start_collecting(self: Arc<Self>, interval_ms: u64) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut sys = sysinfo::System::new_all();
            let mut prev_time = std::time::Instant::now();
            let mut request_counter: u64 = 0;

            loop {
                sys.refresh_all();
                let now = std::time::Instant::now();
                let elapsed = now.duration_since(prev_time).as_secs_f64();
                prev_time = now;

                request_counter += 1;
                let rps = if elapsed > 0.0 { 1.0 / elapsed } else { 0.0 };

                let event = MetricsEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    cpu_usage: sys.global_cpu_usage(),
                    memory_used_mb: sys.used_memory() / 1_048_576,
                    memory_total_mb: sys.total_memory() / 1_048_576,
                    active_services: 0,
                    total_requests: request_counter,
                    requests_per_sec: rps,
                };

                let _ = self.tx.send(event);
                tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
            }
        })
    }
}

// ─────────────────────────────────────────────
// Log Streaming (tail -f style)
// ─────────────────────────────────────────────

/// Log entry from a service
#[derive(Serialize, Clone, Debug)]
pub struct LogEvent {
    pub timestamp: String,
    pub service_name: String,
    pub stream: LogStream,
    pub line: String,
    pub line_number: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

/// Log broadcaster — streams logs from service sandboxes
pub struct LogBroadcaster {
    tx: broadcast::Sender<LogEvent>,
    _rx: broadcast::Receiver<LogEvent>,
    /// Active watchers: service_name -> abort handle
    watchers: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl LogBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self {
            tx,
            _rx,
            watchers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to log events
    pub fn subscribe(&self) -> broadcast::Receiver<LogEvent> {
        self.tx.subscribe()
    }

    /// Start watching logs for a service
    pub async fn watch_service(&self, service_name: String, log_dir: PathBuf) {
        // Don't watch if already watching
        if self.watchers.read().await.contains_key(&service_name) {
            return;
        }

        let tx = self.tx.clone();
        let name = service_name.clone();
        let stdout_path = log_dir.join("stdout.log");
        let stderr_path = log_dir.join("stderr.log");

        let handle = tokio::spawn(async move {
            // Watch both stdout and stderr concurrently
            let stdout_tx = tx.clone();
            let stderr_tx = tx.clone();
            let name_stdout = name.clone();
            let name_stderr = name.clone();

            let stdout_handle = tokio::spawn(async move {
                if let Err(e) = watch_file(stdout_path, name_stdout, LogStream::Stdout, stdout_tx).await {
                    tracing::debug!("Stdout watcher ended: {}", e);
                }
            });

            let stderr_handle = tokio::spawn(async move {
                if let Err(e) = watch_file(stderr_path, name_stderr, LogStream::Stderr, stderr_tx).await {
                    tracing::debug!("Stderr watcher ended: {}", e);
                }
            });

            let _ = tokio::join!(stdout_handle, stderr_handle);
        });

        self.watchers.write().await.insert(service_name, handle);
    }

    /// Stop watching logs for a service
    pub async fn unwatch_service(&self, service_name: &str) {
        if let Some(handle) = self.watchers.write().await.remove(service_name) {
            handle.abort();
        }
    }

    /// Get list of watched services
    pub async fn watched_services(&self) -> Vec<String> {
        self.watchers.read().await.keys().cloned().collect()
    }
}

/// Watch a single log file and broadcast new lines
async fn watch_file(
    path: PathBuf,
    service_name: String,
    stream: LogStream,
    tx: broadcast::Sender<LogEvent>,
) -> anyhow::Result<()> {
    // Wait for file to exist
    loop {
        if path.exists() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    let file = File::open(&path).await?;
    let mut reader = BufReader::new(file);
    let mut line_number: u64 = 0;

    // Seek to end of file (only show new lines)
    let metadata = tokio::fs::metadata(&path).await?;
    let file_size = metadata.len();
    
    // Re-open at the end
    let file = File::open(&path).await?;
    let mut reader = BufReader::new(file);
    
    // Skip to near end (last 4KB or start)
    let skip_to = if file_size > 4096 { file_size - 4096 } else { 0 };
    let mut skipped = 0u64;
    let mut line = String::new();
    
    // Skip bytes by reading
    while skipped < skip_to {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(n) => skipped += n as u64,
            Err(_) => break,
        }
    }

    // Now stream new lines
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF - wait and retry
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            Ok(_) => {
                line_number += 1;
                let event = LogEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    service_name: service_name.clone(),
                    stream: stream.clone(),
                    line: line.trim_end().to_string(),
                    line_number,
                };
                let _ = tx.send(event);
            }
            Err(e) => {
                tracing::warn!("Error reading log file: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

// ─────────────────────────────────────────────
// Service Events
// ─────────────────────────────────────────────

/// Service lifecycle event
#[derive(Serialize, Clone, Debug)]
pub struct ServiceEvent {
    pub timestamp: String,
    pub event_type: ServiceEventType,
    pub service_name: String,
    pub service_id: String,
    pub details: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ServiceEventType {
    Deployed,
    Started,
    Stopped,
    Restarted,
    Failed,
    Removed,
    HealthCheck,
    ResourceWarning,
}

/// Service event broadcaster
pub struct ServiceEventBroadcaster {
    tx: broadcast::Sender<ServiceEvent>,
    _rx: broadcast::Receiver<ServiceEvent>,
}

impl ServiceEventBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx, _rx }
    }

    /// Subscribe to service events
    pub fn subscribe(&self) -> broadcast::Receiver<ServiceEvent> {
        self.tx.subscribe()
    }

    /// Emit a service event
    pub fn emit(&self, event_type: ServiceEventType, service_name: &str, service_id: &str, details: Option<&str>) {
        let event = ServiceEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type,
            service_name: service_name.to_string(),
            service_id: service_id.to_string(),
            details: details.map(|s| s.to_string()),
        };
        let _ = self.tx.send(event);
    }
}

// ─────────────────────────────────────────────
// Unified WebSocket Hub
// ─────────────────────────────────────────────

/// Central hub for all WebSocket streams
pub struct WebSocketHub {
    pub metrics: Arc<MetricsBroadcaster>,
    pub logs: Arc<LogBroadcaster>,
    pub events: Arc<ServiceEventBroadcaster>,
}

impl WebSocketHub {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(MetricsBroadcaster::new(64)),
            logs: Arc::new(LogBroadcaster::new(256)),
            events: Arc::new(ServiceEventBroadcaster::new(64)),
        }
    }

    /// Start all background collectors
    pub fn start(&self, metrics_interval_ms: u64) -> tokio::task::JoinHandle<()> {
        let metrics = self.metrics.clone();
        metrics.start_collecting(metrics_interval_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_broadcaster() {
        let broadcaster = Arc::new(MetricsBroadcaster::new(16));
        let mut rx = broadcaster.subscribe();
        let handle = broadcaster.clone().start_collecting(100);

        let event = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            rx.recv()
        ).await;

        assert!(event.is_ok());
        let event = event.unwrap().unwrap();
        assert!(event.memory_total_mb > 0);
        handle.abort();
    }

    #[test]
    fn test_metrics_event_serialization() {
        let event = MetricsEvent {
            timestamp: "2026-02-15T00:00:00Z".to_string(),
            cpu_usage: 45.2,
            memory_used_mb: 8192,
            memory_total_mb: 16384,
            active_services: 3,
            total_requests: 1000,
            requests_per_sec: 150.5,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("45.2"));
        assert!(json.contains("8192"));
    }
}
