//! # Health Monitor
//!
//! Monitors service health, collects metrics, detects anomalies,
//! and triggers alerts. Integrates with the Access Level Controller
//! to auto-escalate when problems are detected.
//!
//! ## Features
//! - Health checking (command, HTTP, TCP)
//! - Metrics collection (CPU, RAM, requests, errors)
//! - Baseline learning (knows what "normal" looks like)
//! - Anomaly detection (triggers access level escalation)
//! - Alert system (notifications for the PC owner)

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),
}

pub type Result<T> = std::result::Result<T, MonitorError>;

// ─────────────────────────────────────────────
// Health Status
// ─────────────────────────────────────────────

/// Overall health status of a service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    /// All checks passing
    Healthy,
    /// Some checks failing or metrics elevated
    Warning { reason: String },
    /// Critical issues detected
    Critical { reason: String },
    /// Service is down / unreachable
    Down { reason: String },
    /// Not enough data yet (just started)
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "🟢 Healthy"),
            HealthStatus::Warning { reason } => write!(f, "🟡 Warning: {}", reason),
            HealthStatus::Critical { reason } => write!(f, "🔴 Critical: {}", reason),
            HealthStatus::Down { reason } => write!(f, "⚫ Down: {}", reason),
            HealthStatus::Unknown => write!(f, "⚪ Unknown"),
        }
    }
}

// ─────────────────────────────────────────────
// Metrics
// ─────────────────────────────────────────────

/// Collected metrics for a service at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub service_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub cpu_percent: f64,
    pub ram_bytes: u64,
    pub disk_bytes: u64,
    pub requests_total: u64,
    pub requests_per_min: f64,
    pub error_count: u64,
    pub error_rate_percent: f64,
    pub avg_response_ms: f64,
    pub active_connections: u32,
    pub bandwidth_bps: u64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            service_id: Uuid::nil(),
            timestamp: Utc::now(),
            cpu_percent: 0.0,
            ram_bytes: 0,
            disk_bytes: 0,
            requests_total: 0,
            requests_per_min: 0.0,
            error_count: 0,
            error_rate_percent: 0.0,
            avg_response_ms: 0.0,
            active_connections: 0,
            bandwidth_bps: 0,
        }
    }
}

// ─────────────────────────────────────────────
// Baseline (learned "normal" behavior)
// ─────────────────────────────────────────────

/// Learned baseline for a service's normal behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Average CPU usage
    pub avg_cpu: f64,
    /// Average RAM usage
    pub avg_ram_bytes: u64,
    /// Average requests per minute
    pub avg_requests_per_min: f64,
    /// Normal error rate
    pub avg_error_rate: f64,
    /// Average response time
    pub avg_response_ms: f64,
    /// Number of samples used to build baseline
    pub sample_count: u64,
    /// Last updated
    pub updated_at: DateTime<Utc>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            avg_cpu: 0.0,
            avg_ram_bytes: 0,
            avg_requests_per_min: 0.0,
            avg_error_rate: 0.0,
            avg_response_ms: 0.0,
            sample_count: 0,
            updated_at: Utc::now(),
        }
    }
}

impl Baseline {
    /// Update baseline with a new metrics sample (exponential moving average)
    pub fn update(&mut self, metrics: &Metrics) {
        self.sample_count += 1;
        let alpha = if self.sample_count < 10 {
            1.0 / self.sample_count as f64
        } else {
            0.1 // EMA smoothing factor
        };

        self.avg_cpu = self.avg_cpu * (1.0 - alpha) + metrics.cpu_percent * alpha;
        self.avg_ram_bytes = ((self.avg_ram_bytes as f64 * (1.0 - alpha))
            + (metrics.ram_bytes as f64 * alpha)) as u64;
        self.avg_requests_per_min = self.avg_requests_per_min * (1.0 - alpha)
            + metrics.requests_per_min * alpha;
        self.avg_error_rate = self.avg_error_rate * (1.0 - alpha)
            + metrics.error_rate_percent * alpha;
        self.avg_response_ms = self.avg_response_ms * (1.0 - alpha)
            + metrics.avg_response_ms * alpha;
        self.updated_at = Utc::now();
    }

    /// Check if metrics deviate significantly from baseline
    pub fn detect_anomaly(&self, metrics: &Metrics) -> Option<AnomalyType> {
        if self.sample_count < 5 {
            return None; // Not enough data for baseline
        }

        // CPU spike: 5x normal
        if self.avg_cpu > 0.0 && metrics.cpu_percent > self.avg_cpu * 5.0 {
            return Some(AnomalyType::CpuSpike {
                current: metrics.cpu_percent,
                baseline: self.avg_cpu,
            });
        }

        // Error rate spike: 10x normal or >10%
        if metrics.error_rate_percent > 10.0
            || (self.avg_error_rate > 0.0
                && metrics.error_rate_percent > self.avg_error_rate * 10.0)
        {
            return Some(AnomalyType::ErrorSpike {
                current: metrics.error_rate_percent,
                baseline: self.avg_error_rate,
            });
        }

        // Traffic spike: 10x normal (possible DDoS)
        if self.avg_requests_per_min > 0.0
            && metrics.requests_per_min > self.avg_requests_per_min * 10.0
        {
            return Some(AnomalyType::TrafficSpike {
                current: metrics.requests_per_min,
                baseline: self.avg_requests_per_min,
            });
        }

        // Response time degradation: 5x normal
        if self.avg_response_ms > 0.0
            && metrics.avg_response_ms > self.avg_response_ms * 5.0
        {
            return Some(AnomalyType::SlowResponse {
                current_ms: metrics.avg_response_ms,
                baseline_ms: self.avg_response_ms,
            });
        }

        None
    }
}

/// Type of anomaly detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    CpuSpike { current: f64, baseline: f64 },
    ErrorSpike { current: f64, baseline: f64 },
    TrafficSpike { current: f64, baseline: f64 },
    SlowResponse { current_ms: f64, baseline_ms: f64 },
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyType::CpuSpike { current, baseline } =>
                write!(f, "CPU spike: {:.1}% (normal: {:.1}%)", current, baseline),
            AnomalyType::ErrorSpike { current, baseline } =>
                write!(f, "Error spike: {:.1}% (normal: {:.1}%)", current, baseline),
            AnomalyType::TrafficSpike { current, baseline } =>
                write!(f, "Traffic spike: {:.0} req/min (normal: {:.0})", current, baseline),
            AnomalyType::SlowResponse { current_ms, baseline_ms } =>
                write!(f, "Slow response: {:.0}ms (normal: {:.0}ms)", current_ms, baseline_ms),
        }
    }
}

// ─────────────────────────────────────────────
// Alerts
// ─────────────────────────────────────────────

/// An alert generated by the monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub service_id: Uuid,
    pub service_name: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub anomaly: Option<AnomalyType>,
    pub created_at: DateTime<Utc>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "ℹ️  Info"),
            AlertSeverity::Warning => write!(f, "⚠️  Warning"),
            AlertSeverity::Critical => write!(f, "🔴 Critical"),
        }
    }
}

// ─────────────────────────────────────────────
// Health Monitor
// ─────────────────────────────────────────────

/// Per-service monitoring state
struct MonitoredService {
    name: String,
    health: HealthStatus,
    baseline: Baseline,
    metrics_history: Vec<Metrics>,
    max_history: usize,
}

/// The health monitor watches all services and detects problems
pub struct HealthMonitor {
    /// Per-service monitoring state
    services: Arc<RwLock<HashMap<Uuid, MonitoredService>>>,
    /// Active alerts
    alerts: Arc<RwLock<Vec<Alert>>>,
    /// Maximum metrics history per service
    max_history: usize,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new(max_history: usize) -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            max_history,
        }
    }

    /// Register a service for monitoring
    pub async fn register(&self, service_id: Uuid, service_name: String) {
        self.services.write().await.insert(service_id, MonitoredService {
            name: service_name,
            health: HealthStatus::Unknown,
            baseline: Baseline::default(),
            metrics_history: Vec::new(),
            max_history: self.max_history,
        });
    }

    /// Unregister a service
    pub async fn unregister(&self, service_id: &Uuid) {
        self.services.write().await.remove(service_id);
    }

    /// Record new metrics for a service
    /// Returns an alert if anomaly detected
    pub async fn record_metrics(&self, metrics: Metrics) -> Option<Alert> {
        let mut services = self.services.write().await;
        let monitored = services.get_mut(&metrics.service_id)?;

        // Check for anomalies against baseline
        let anomaly = monitored.baseline.detect_anomaly(&metrics);

        // Update baseline with new sample
        monitored.baseline.update(&metrics);

        // Store in history (ring buffer)
        if monitored.metrics_history.len() >= monitored.max_history {
            monitored.metrics_history.remove(0);
        }
        monitored.metrics_history.push(metrics.clone());

        // Update health status
        monitored.health = if let Some(ref anomaly) = anomaly {
            match anomaly {
                AnomalyType::CpuSpike { .. } | AnomalyType::SlowResponse { .. } =>
                    HealthStatus::Warning { reason: anomaly.to_string() },
                AnomalyType::ErrorSpike { .. } | AnomalyType::TrafficSpike { .. } =>
                    HealthStatus::Critical { reason: anomaly.to_string() },
            }
        } else if metrics.error_rate_percent > 5.0 {
            HealthStatus::Warning {
                reason: format!("Error rate: {:.1}%", metrics.error_rate_percent),
            }
        } else {
            HealthStatus::Healthy
        };

        // Generate alert if anomaly detected
        if let Some(anomaly) = anomaly {
            let severity = match &anomaly {
                AnomalyType::CpuSpike { .. } | AnomalyType::SlowResponse { .. } =>
                    AlertSeverity::Warning,
                AnomalyType::ErrorSpike { .. } | AnomalyType::TrafficSpike { .. } =>
                    AlertSeverity::Critical,
            };

            let alert = Alert {
                id: Uuid::new_v4(),
                service_id: metrics.service_id,
                service_name: monitored.name.clone(),
                severity,
                message: anomaly.to_string(),
                anomaly: Some(anomaly),
                created_at: Utc::now(),
                acknowledged: false,
            };

            drop(services);
            self.alerts.write().await.push(alert.clone());

            tracing::warn!(
                service = %alert.service_name,
                severity = %alert.severity,
                message = %alert.message,
                "Alert generated"
            );

            return Some(alert);
        }

        None
    }

    /// Get current health status of a service
    pub async fn health(&self, service_id: &Uuid) -> Result<HealthStatus> {
        self.services.read().await
            .get(service_id)
            .map(|s| s.health.clone())
            .ok_or_else(|| MonitorError::ServiceNotFound(service_id.to_string()))
    }

    /// Get metrics history for a service
    pub async fn metrics_history(&self, service_id: &Uuid) -> Vec<Metrics> {
        self.services.read().await
            .get(service_id)
            .map(|s| s.metrics_history.clone())
            .unwrap_or_default()
    }

    /// Get baseline for a service
    pub async fn baseline(&self, service_id: &Uuid) -> Option<Baseline> {
        self.services.read().await
            .get(service_id)
            .map(|s| s.baseline.clone())
    }

    /// Get all active (unacknowledged) alerts
    pub async fn active_alerts(&self) -> Vec<Alert> {
        self.alerts.read().await.iter()
            .filter(|a| !a.acknowledged)
            .cloned()
            .collect()
    }

    /// Get all alerts
    pub async fn all_alerts(&self) -> Vec<Alert> {
        self.alerts.read().await.clone()
    }

    /// Acknowledge an alert
    pub async fn acknowledge_alert(&self, alert_id: &Uuid) {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.iter_mut().find(|a| &a.id == alert_id) {
            alert.acknowledged = true;
        }
    }

    /// Get summary of all monitored services
    pub async fn summary(&self) -> MonitorSummary {
        let services = self.services.read().await;
        let alerts = self.alerts.read().await;

        let mut summary = MonitorSummary::default();
        summary.total_services = services.len();

        for monitored in services.values() {
            match &monitored.health {
                HealthStatus::Healthy => summary.healthy += 1,
                HealthStatus::Warning { .. } => summary.warning += 1,
                HealthStatus::Critical { .. } => summary.critical += 1,
                HealthStatus::Down { .. } => summary.down += 1,
                HealthStatus::Unknown => summary.unknown += 1,
            }
        }

        summary.active_alerts = alerts.iter().filter(|a| !a.acknowledged).count();
        summary
    }
}

/// Summary of monitoring status
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MonitorSummary {
    pub total_services: usize,
    pub healthy: usize,
    pub warning: usize,
    pub critical: usize,
    pub down: usize,
    pub unknown: usize,
    pub active_alerts: usize,
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_metrics(service_id: Uuid) -> Metrics {
        Metrics {
            service_id,
            cpu_percent: 5.0,
            ram_bytes: 512 * 1024 * 1024,
            requests_per_min: 50.0,
            error_rate_percent: 0.1,
            avg_response_ms: 20.0,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_register_service() {
        let monitor = HealthMonitor::new(100);
        let id = Uuid::new_v4();
        monitor.register(id, "test-db".into()).await;

        let health = monitor.health(&id).await.unwrap();
        assert_eq!(health, HealthStatus::Unknown);
    }

    #[tokio::test]
    async fn test_record_normal_metrics() {
        let monitor = HealthMonitor::new(100);
        let id = Uuid::new_v4();
        monitor.register(id, "test-db".into()).await;

        // Record several normal metrics to build baseline
        for _ in 0..10 {
            let alert = monitor.record_metrics(normal_metrics(id)).await;
            assert!(alert.is_none());
        }

        let health = monitor.health(&id).await.unwrap();
        assert_eq!(health, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_detect_cpu_anomaly() {
        let monitor = HealthMonitor::new(100);
        let id = Uuid::new_v4();
        monitor.register(id, "test-db".into()).await;

        // Build baseline
        for _ in 0..10 {
            monitor.record_metrics(normal_metrics(id)).await;
        }

        // CPU spike
        let spike = Metrics {
            service_id: id,
            cpu_percent: 95.0, // 19x normal
            ..normal_metrics(id)
        };
        let alert = monitor.record_metrics(spike).await;
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Warning);
    }

    #[tokio::test]
    async fn test_detect_traffic_spike() {
        let monitor = HealthMonitor::new(100);
        let id = Uuid::new_v4();
        monitor.register(id, "test-db".into()).await;

        // Build baseline
        for _ in 0..10 {
            monitor.record_metrics(normal_metrics(id)).await;
        }

        // Traffic spike (DDoS-like)
        let spike = Metrics {
            service_id: id,
            requests_per_min: 5000.0, // 100x normal
            ..normal_metrics(id)
        };
        let alert = monitor.record_metrics(spike).await;
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Critical);
    }

    #[tokio::test]
    async fn test_alerts_list() {
        let monitor = HealthMonitor::new(100);
        let id = Uuid::new_v4();
        monitor.register(id, "test-db".into()).await;

        // Build baseline then trigger anomaly
        for _ in 0..10 {
            monitor.record_metrics(normal_metrics(id)).await;
        }

        let spike = Metrics {
            service_id: id,
            error_rate_percent: 50.0,
            ..normal_metrics(id)
        };
        monitor.record_metrics(spike).await;

        let active = monitor.active_alerts().await;
        assert_eq!(active.len(), 1);
    }

    #[tokio::test]
    async fn test_acknowledge_alert() {
        let monitor = HealthMonitor::new(100);
        let id = Uuid::new_v4();
        monitor.register(id, "test-db".into()).await;

        for _ in 0..10 {
            monitor.record_metrics(normal_metrics(id)).await;
        }

        let spike = Metrics {
            service_id: id,
            cpu_percent: 90.0,
            ..normal_metrics(id)
        };
        let alert = monitor.record_metrics(spike).await.unwrap();

        monitor.acknowledge_alert(&alert.id).await;
        let active = monitor.active_alerts().await;
        assert_eq!(active.len(), 0);
    }

    #[tokio::test]
    async fn test_metrics_history() {
        let monitor = HealthMonitor::new(5); // Only keep 5
        let id = Uuid::new_v4();
        monitor.register(id, "test-db".into()).await;

        for _ in 0..10 {
            monitor.record_metrics(normal_metrics(id)).await;
        }

        let history = monitor.metrics_history(&id).await;
        assert_eq!(history.len(), 5); // Capped at max
    }

    #[tokio::test]
    async fn test_monitor_summary() {
        let monitor = HealthMonitor::new(100);

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        monitor.register(id1, "svc-1".into()).await;
        monitor.register(id2, "svc-2".into()).await;

        // Make one healthy
        for _ in 0..5 {
            monitor.record_metrics(normal_metrics(id1)).await;
        }

        let summary = monitor.summary().await;
        assert_eq!(summary.total_services, 2);
        assert_eq!(summary.healthy, 1);
        assert_eq!(summary.unknown, 1);
    }

    #[test]
    fn test_baseline_update() {
        let mut baseline = Baseline::default();
        let id = Uuid::new_v4();

        for _ in 0..10 {
            baseline.update(&Metrics {
                service_id: id,
                cpu_percent: 10.0,
                requests_per_min: 100.0,
                ..Default::default()
            });
        }

        // Should converge towards 10.0
        assert!((baseline.avg_cpu - 10.0).abs() < 1.0);
        assert_eq!(baseline.sample_count, 10);
    }
}
