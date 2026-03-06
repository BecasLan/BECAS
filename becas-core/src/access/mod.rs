//! # Access Level Controller
//!
//! 5-level graduated access control for BECAS services.
//! PC owner can see different amounts of information based on the current level.
//!
//! ## Levels
//! - **Level 0 (Ghost):** Only "N services running" — total privacy
//! - **Level 1 (Monitor):** Service names, health status, traffic volume
//! - **Level 2 (Diagnostic):** Masked logs, network details, performance metrics
//! - **Level 3 (Emergency):** Auto-triggered on anomalies, allows intervention
//! - **Level 4 (Owner Override):** Full access, audit-logged, notification sent

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AccessError {
    #[error("Insufficient access level: requires {required:?}, current {current:?}")]
    InsufficientLevel {
        required: AccessLevel,
        current: AccessLevel,
    },

    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("Owner override requires justification")]
    JustificationRequired,
}

pub type Result<T> = std::result::Result<T, AccessError>;

// ─────────────────────────────────────────────
// Access Levels
// ─────────────────────────────────────────────

/// Access level for viewing service information
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AccessLevel {
    /// Level 0: Only service count and total resource usage visible
    Ghost = 0,
    /// Level 1: Service names, health status, request rates visible
    Monitor = 1,
    /// Level 2: Masked logs, network details, performance metrics visible
    Diagnostic = 2,
    /// Level 3: Auto-triggered on anomalies, allows stop/restart
    Emergency = 3,
    /// Level 4: Full access, audit-logged, service owner notified
    OwnerOverride = 4,
}

impl std::fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessLevel::Ghost => write!(f, "Ghost (Level 0)"),
            AccessLevel::Monitor => write!(f, "Monitor (Level 1)"),
            AccessLevel::Diagnostic => write!(f, "Diagnostic (Level 2)"),
            AccessLevel::Emergency => write!(f, "Emergency (Level 3)"),
            AccessLevel::OwnerOverride => write!(f, "Owner Override (Level 4)"),
        }
    }
}

// ─────────────────────────────────────────────
// Service View (what the owner sees at each level)
// ─────────────────────────────────────────────

/// What the PC owner can see — filtered by access level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceView {
    /// Level 0+: Always visible
    pub service_count: usize,
    pub total_cpu_percent: f64,
    pub total_ram_mb: u64,

    /// Level 1+: Service details
    pub services: Option<Vec<ServiceSummary>>,

    /// Level 2+: Diagnostic info
    pub diagnostics: Option<Vec<DiagnosticEntry>>,
}

/// Service summary visible at Level 1+
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSummary {
    pub name: String,
    pub health: HealthIndicator,
    pub cpu_percent: f64,
    pub ram_mb: u64,
    pub requests_per_min: u64,
    pub error_rate_percent: f64,
    pub uptime_seconds: u64,
}

/// Health indicator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthIndicator {
    Healthy,
    Warning,
    Critical,
    Down,
}

impl std::fmt::Display for HealthIndicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthIndicator::Healthy => write!(f, "🟢 Healthy"),
            HealthIndicator::Warning => write!(f, "🟡 Warning"),
            HealthIndicator::Critical => write!(f, "🔴 Critical"),
            HealthIndicator::Down => write!(f, "⚫ Down"),
        }
    }
}

/// Diagnostic log entry visible at Level 2+ (data is masked)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    /// Message with sensitive data masked
    /// e.g., "User [***] created record [***] at 14:32"
    pub masked_message: String,
    pub source: String,
}

// ─────────────────────────────────────────────
// Audit Log
// ─────────────────────────────────────────────

/// Audit log entry — records every access level change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub service_id: Uuid,
    pub previous_level: AccessLevel,
    pub new_level: AccessLevel,
    pub reason: String,
    pub auto_triggered: bool,
}

// ─────────────────────────────────────────────
// Access Controller
// ─────────────────────────────────────────────

/// Per-service access state
#[derive(Debug)]
struct ServiceAccess {
    level: AccessLevel,
    default_level: AccessLevel,
    last_changed: DateTime<Utc>,
    audit_log: Vec<AuditEntry>,
}

/// Controls access levels for all services in the BECAS Layer
pub struct AccessController {
    /// Per-service access levels
    services: Arc<RwLock<HashMap<Uuid, ServiceAccess>>>,
    /// Global default access level for new services
    default_level: AccessLevel,
    /// Global audit log
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
}

impl AccessController {
    /// Create a new access controller with a default level
    pub fn new(default_level: AccessLevel) -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            default_level,
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a service with the default access level
    pub async fn register_service(&self, service_id: Uuid) {
        self.services.write().await.insert(service_id, ServiceAccess {
            level: self.default_level,
            default_level: self.default_level,
            last_changed: Utc::now(),
            audit_log: Vec::new(),
        });
    }

    /// Get current access level for a service
    pub async fn get_level(&self, service_id: &Uuid) -> Result<AccessLevel> {
        self.services.read().await
            .get(service_id)
            .map(|s| s.level)
            .ok_or_else(|| AccessError::ServiceNotFound(service_id.to_string()))
    }

    /// Set access level manually (with reason)
    pub async fn set_level(
        &self,
        service_id: &Uuid,
        new_level: AccessLevel,
        reason: &str,
    ) -> Result<()> {
        // Owner Override requires justification
        if new_level == AccessLevel::OwnerOverride && reason.trim().is_empty() {
            return Err(AccessError::JustificationRequired);
        }

        let mut services = self.services.write().await;
        let access = services.get_mut(service_id)
            .ok_or_else(|| AccessError::ServiceNotFound(service_id.to_string()))?;

        let previous = access.level;
        if previous == new_level {
            return Ok(());
        }

        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            service_id: *service_id,
            previous_level: previous,
            new_level,
            reason: reason.to_string(),
            auto_triggered: false,
        };

        tracing::info!(
            service = %service_id,
            from = %previous,
            to = %new_level,
            reason = reason,
            "Access level changed"
        );

        access.level = new_level;
        access.last_changed = Utc::now();
        access.audit_log.push(entry.clone());

        // Also add to global audit log
        drop(services);
        self.audit_log.write().await.push(entry);

        Ok(())
    }

    /// Escalate access level automatically (triggered by anomaly detection)
    pub async fn auto_escalate(
        &self,
        service_id: &Uuid,
        target_level: AccessLevel,
        reason: &str,
    ) -> Result<()> {
        let mut services = self.services.write().await;
        let access = services.get_mut(service_id)
            .ok_or_else(|| AccessError::ServiceNotFound(service_id.to_string()))?;

        // Only escalate UP, never auto-downgrade
        if target_level <= access.level {
            return Ok(());
        }

        // Never auto-escalate to OwnerOverride
        if target_level == AccessLevel::OwnerOverride {
            return Ok(());
        }

        let previous = access.level;

        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            service_id: *service_id,
            previous_level: previous,
            new_level: target_level,
            reason: reason.to_string(),
            auto_triggered: true,
        };

        tracing::warn!(
            service = %service_id,
            from = %previous,
            to = %target_level,
            reason = reason,
            "Access level AUTO-ESCALATED"
        );

        access.level = target_level;
        access.last_changed = Utc::now();
        access.audit_log.push(entry.clone());

        drop(services);
        self.audit_log.write().await.push(entry);

        Ok(())
    }

    /// Reset access level back to default
    pub async fn reset_level(&self, service_id: &Uuid) -> Result<()> {
        let mut services = self.services.write().await;
        let access = services.get_mut(service_id)
            .ok_or_else(|| AccessError::ServiceNotFound(service_id.to_string()))?;

        let previous = access.level;
        let default = access.default_level;

        if previous == default {
            return Ok(());
        }

        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            service_id: *service_id,
            previous_level: previous,
            new_level: default,
            reason: "Reset to default".to_string(),
            auto_triggered: false,
        };

        access.level = default;
        access.last_changed = Utc::now();
        access.audit_log.push(entry.clone());

        drop(services);
        self.audit_log.write().await.push(entry);

        Ok(())
    }

    /// Check if an operation is allowed at the current level
    pub async fn check_permission(
        &self,
        service_id: &Uuid,
        required_level: AccessLevel,
    ) -> Result<()> {
        let current = self.get_level(service_id).await?;
        if current >= required_level {
            Ok(())
        } else {
            Err(AccessError::InsufficientLevel {
                required: required_level,
                current,
            })
        }
    }

    /// Get audit log for a service
    pub async fn service_audit_log(&self, service_id: &Uuid) -> Vec<AuditEntry> {
        self.services.read().await
            .get(service_id)
            .map(|s| s.audit_log.clone())
            .unwrap_or_default()
    }

    /// Get global audit log
    pub async fn global_audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.read().await.clone()
    }

    /// Build a service view filtered by the current access level
    pub async fn build_view(
        &self,
        service_id: &Uuid,
        service_info: &ServiceSummary,
        diagnostics: &[DiagnosticEntry],
    ) -> Result<ServiceView> {
        let level = self.get_level(service_id).await?;

        let mut view = ServiceView {
            service_count: 1,
            total_cpu_percent: service_info.cpu_percent,
            total_ram_mb: service_info.ram_mb,
            services: None,
            diagnostics: None,
        };

        // Level 1+: Show service details
        if level >= AccessLevel::Monitor {
            view.services = Some(vec![service_info.clone()]);
        }

        // Level 2+: Show diagnostics (masked)
        if level >= AccessLevel::Diagnostic {
            view.diagnostics = Some(diagnostics.to_vec());
        }

        Ok(view)
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_access_level() {
        let ctrl = AccessController::new(AccessLevel::Monitor);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        assert_eq!(ctrl.get_level(&id).await.unwrap(), AccessLevel::Monitor);
    }

    #[tokio::test]
    async fn test_set_level() {
        let ctrl = AccessController::new(AccessLevel::Ghost);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        ctrl.set_level(&id, AccessLevel::Diagnostic, "Investigating issue").await.unwrap();
        assert_eq!(ctrl.get_level(&id).await.unwrap(), AccessLevel::Diagnostic);
    }

    #[tokio::test]
    async fn test_owner_override_requires_justification() {
        let ctrl = AccessController::new(AccessLevel::Ghost);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        // Empty reason should fail
        let result = ctrl.set_level(&id, AccessLevel::OwnerOverride, "").await;
        assert!(result.is_err());

        // With reason should succeed
        ctrl.set_level(&id, AccessLevel::OwnerOverride, "Court order #12345").await.unwrap();
        assert_eq!(ctrl.get_level(&id).await.unwrap(), AccessLevel::OwnerOverride);
    }

    #[tokio::test]
    async fn test_auto_escalate() {
        let ctrl = AccessController::new(AccessLevel::Ghost);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        ctrl.auto_escalate(&id, AccessLevel::Emergency, "DDoS detected").await.unwrap();
        assert_eq!(ctrl.get_level(&id).await.unwrap(), AccessLevel::Emergency);
    }

    #[tokio::test]
    async fn test_auto_escalate_never_to_owner_override() {
        let ctrl = AccessController::new(AccessLevel::Ghost);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        ctrl.auto_escalate(&id, AccessLevel::OwnerOverride, "test").await.unwrap();
        // Should NOT escalate to OwnerOverride automatically
        assert_ne!(ctrl.get_level(&id).await.unwrap(), AccessLevel::OwnerOverride);
    }

    #[tokio::test]
    async fn test_auto_escalate_only_up() {
        let ctrl = AccessController::new(AccessLevel::Diagnostic);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        // Trying to auto-escalate to a lower level should be no-op
        ctrl.auto_escalate(&id, AccessLevel::Monitor, "test").await.unwrap();
        assert_eq!(ctrl.get_level(&id).await.unwrap(), AccessLevel::Diagnostic);
    }

    #[tokio::test]
    async fn test_reset_level() {
        let ctrl = AccessController::new(AccessLevel::Monitor);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        ctrl.set_level(&id, AccessLevel::Emergency, "issue").await.unwrap();
        ctrl.reset_level(&id).await.unwrap();
        assert_eq!(ctrl.get_level(&id).await.unwrap(), AccessLevel::Monitor);
    }

    #[tokio::test]
    async fn test_check_permission() {
        let ctrl = AccessController::new(AccessLevel::Monitor);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        // Monitor can do Monitor-level ops
        assert!(ctrl.check_permission(&id, AccessLevel::Monitor).await.is_ok());
        // Monitor cannot do Diagnostic-level ops
        assert!(ctrl.check_permission(&id, AccessLevel::Diagnostic).await.is_err());
    }

    #[tokio::test]
    async fn test_audit_log() {
        let ctrl = AccessController::new(AccessLevel::Ghost);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        ctrl.set_level(&id, AccessLevel::Monitor, "routine check").await.unwrap();
        ctrl.set_level(&id, AccessLevel::Diagnostic, "investigating").await.unwrap();

        let log = ctrl.service_audit_log(&id).await;
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].previous_level, AccessLevel::Ghost);
        assert_eq!(log[0].new_level, AccessLevel::Monitor);
        assert_eq!(log[1].new_level, AccessLevel::Diagnostic);
    }

    #[tokio::test]
    async fn test_build_view_ghost() {
        let ctrl = AccessController::new(AccessLevel::Ghost);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        let info = ServiceSummary {
            name: "TestDB".into(),
            health: HealthIndicator::Healthy,
            cpu_percent: 5.0,
            ram_mb: 512,
            requests_per_min: 100,
            error_rate_percent: 0.0,
            uptime_seconds: 3600,
        };

        let view = ctrl.build_view(&id, &info, &[]).await.unwrap();
        // Ghost: no service details, no diagnostics
        assert!(view.services.is_none());
        assert!(view.diagnostics.is_none());
        assert_eq!(view.total_cpu_percent, 5.0);
    }

    #[tokio::test]
    async fn test_build_view_monitor() {
        let ctrl = AccessController::new(AccessLevel::Monitor);
        let id = Uuid::new_v4();
        ctrl.register_service(id).await;

        let info = ServiceSummary {
            name: "TestDB".into(),
            health: HealthIndicator::Healthy,
            cpu_percent: 5.0,
            ram_mb: 512,
            requests_per_min: 100,
            error_rate_percent: 0.0,
            uptime_seconds: 3600,
        };

        let view = ctrl.build_view(&id, &info, &[]).await.unwrap();
        // Monitor: service details visible, no diagnostics
        assert!(view.services.is_some());
        assert!(view.diagnostics.is_none());
    }
}
