//! # Anomaly Detector
//!
//! Learns normal behavior patterns and detects deviations.
//! When an anomaly is detected, it can auto-escalate the access level
//! and trigger protective measures (rate limiting, blocking, etc.)

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use becas_core::monitor::{Metrics, AnomalyType, Baseline};
use becas_core::access::{AccessLevel, AccessController};

/// Anomaly detection engine
pub struct AnomalyDetector {
    /// Per-service baselines
    baselines: Arc<RwLock<HashMap<Uuid, Baseline>>>,
    /// Access controller for auto-escalation
    access_controller: Arc<AccessController>,
    /// Detection history
    history: Arc<RwLock<Vec<DetectionEvent>>>,
    /// Configuration
    config: AnomalyConfig,
}

/// Configuration for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyConfig {
    /// Minimum samples before detection starts
    pub min_samples: u64,
    /// CPU multiplier threshold (e.g., 5.0 = 5x baseline triggers alert)
    pub cpu_threshold_multiplier: f64,
    /// Error rate threshold (absolute %)
    pub error_rate_threshold: f64,
    /// Traffic multiplier threshold
    pub traffic_threshold_multiplier: f64,
    /// Response time multiplier threshold
    pub response_threshold_multiplier: f64,
    /// Auto-escalate access level on detection
    pub auto_escalate: bool,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            min_samples: 5,
            cpu_threshold_multiplier: 5.0,
            error_rate_threshold: 10.0,
            traffic_threshold_multiplier: 10.0,
            response_threshold_multiplier: 5.0,
            auto_escalate: true,
        }
    }
}

/// A detected anomaly event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub id: Uuid,
    pub service_id: Uuid,
    pub anomaly_type: AnomalyType,
    pub severity: DetectionSeverity,
    pub detected_at: DateTime<Utc>,
    pub auto_action_taken: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AnomalyDetector {
    /// Create a new anomaly detector
    pub fn new(access_controller: Arc<AccessController>, config: AnomalyConfig) -> Self {
        Self {
            baselines: Arc::new(RwLock::new(HashMap::new())),
            access_controller,
            history: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }

    /// Register a service for monitoring
    pub async fn register_service(&self, service_id: Uuid) {
        self.baselines.write().await.insert(service_id, Baseline::default());
    }

    /// Analyze new metrics and check for anomalies
    pub async fn analyze(&self, metrics: &Metrics) -> Option<DetectionEvent> {
        let mut baselines = self.baselines.write().await;
        let baseline = baselines.get_mut(&metrics.service_id)?;

        // Check for anomaly
        let anomaly = baseline.detect_anomaly(metrics);

        // Update baseline (always, even during anomaly)
        baseline.update(metrics);

        if let Some(anomaly_type) = anomaly {
            let severity = match &anomaly_type {
                AnomalyType::SlowResponse { .. } => DetectionSeverity::Low,
                AnomalyType::CpuSpike { .. } => DetectionSeverity::Medium,
                AnomalyType::ErrorSpike { .. } => DetectionSeverity::High,
                AnomalyType::TrafficSpike { .. } => DetectionSeverity::Critical,
            };

            let mut auto_action = None;

            // Auto-escalate access level if enabled
            if self.config.auto_escalate {
                let target_level = match severity {
                    DetectionSeverity::Low | DetectionSeverity::Medium => AccessLevel::Monitor,
                    DetectionSeverity::High => AccessLevel::Diagnostic,
                    DetectionSeverity::Critical => AccessLevel::Emergency,
                };

                let reason = format!("Anomaly detected: {}", anomaly_type);
                if self.access_controller
                    .auto_escalate(&metrics.service_id, target_level, &reason)
                    .await.is_ok()
                {
                    auto_action = Some(format!("Access level escalated to {}", target_level));
                }
            }

            let event = DetectionEvent {
                id: Uuid::new_v4(),
                service_id: metrics.service_id,
                anomaly_type,
                severity,
                detected_at: Utc::now(),
                auto_action_taken: auto_action,
            };

            tracing::warn!(
                service_id = %metrics.service_id,
                anomaly = %event.anomaly_type,
                severity = ?event.severity,
                "Anomaly detected"
            );

            drop(baselines);
            self.history.write().await.push(event.clone());

            return Some(event);
        }

        None
    }

    /// Get detection history for a service
    pub async fn service_history(&self, service_id: &Uuid) -> Vec<DetectionEvent> {
        self.history.read().await.iter()
            .filter(|e| &e.service_id == service_id)
            .cloned()
            .collect()
    }

    /// Get all detection events
    pub async fn all_events(&self) -> Vec<DetectionEvent> {
        self.history.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use becas_core::monitor::Metrics;

    fn normal_metrics(id: Uuid) -> Metrics {
        Metrics {
            service_id: id,
            cpu_percent: 5.0,
            requests_per_min: 50.0,
            error_rate_percent: 0.1,
            avg_response_ms: 20.0,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_anomaly_detection() {
        let ac = Arc::new(AccessController::new(AccessLevel::Ghost));
        let detector = AnomalyDetector::new(ac.clone(), AnomalyConfig::default());

        let svc = Uuid::new_v4();
        detector.register_service(svc).await;
        ac.register_service(svc).await;

        // Build baseline
        for _ in 0..10 {
            detector.analyze(&normal_metrics(svc)).await;
        }

        // Trigger anomaly
        let spike = Metrics {
            service_id: svc,
            requests_per_min: 5000.0,
            ..normal_metrics(svc)
        };
        let event = detector.analyze(&spike).await;
        assert!(event.is_some());

        let event = event.unwrap();
        assert_eq!(event.severity, DetectionSeverity::Critical);
    }

    #[tokio::test]
    async fn test_auto_escalation() {
        let ac = Arc::new(AccessController::new(AccessLevel::Ghost));
        let detector = AnomalyDetector::new(ac.clone(), AnomalyConfig::default());

        let svc = Uuid::new_v4();
        detector.register_service(svc).await;
        ac.register_service(svc).await;

        // Build baseline
        for _ in 0..10 {
            detector.analyze(&normal_metrics(svc)).await;
        }

        // Critical anomaly should auto-escalate to Emergency
        let spike = Metrics {
            service_id: svc,
            requests_per_min: 5000.0,
            ..normal_metrics(svc)
        };
        detector.analyze(&spike).await;

        let level = ac.get_level(&svc).await.unwrap();
        assert_eq!(level, AccessLevel::Emergency);
    }
}
