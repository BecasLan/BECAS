//! # Resource Governor
//!
//! Adaptive resource management for BECAS services.
//! Ensures services never impact the PC owner's experience.
//!
//! ## Adaptive Throttling
//! - Owner playing a game → services drop to 3% CPU
//! - Owner sleeping → services can use up to 30% CPU
//! - Owner browsing → services use 10-15% CPU
//!
//! The governor monitors system activity and adjusts service
//! resource allocations in real-time.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("Resource limit exceeded for {resource}: {current}/{limit}")]
    LimitExceeded {
        resource: String,
        current: f64,
        limit: f64,
    },

    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("System info unavailable: {0}")]
    SystemError(String),
}

pub type Result<T> = std::result::Result<T, ResourceError>;

// ─────────────────────────────────────────────
// Resource Limits
// ─────────────────────────────────────────────

/// Resource limits for a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum CPU usage as percentage (0.0 - 100.0)
    pub max_cpu_percent: f64,
    /// Maximum RAM in bytes
    pub max_ram_bytes: u64,
    /// Maximum disk usage in bytes
    pub max_disk_bytes: u64,
    /// Maximum network bandwidth in bytes/sec
    pub max_bandwidth_bps: u64,
    /// Maximum number of open file descriptors
    pub max_open_files: u32,
    /// Maximum number of network connections
    pub max_connections: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu_percent: 15.0,
            max_ram_bytes: 2 * 1024 * 1024 * 1024, // 2GB
            max_disk_bytes: 50 * 1024 * 1024 * 1024, // 50GB
            max_bandwidth_bps: 50 * 1024 * 1024, // 50MB/s
            max_open_files: 1024,
            max_connections: 500,
        }
    }
}

// ─────────────────────────────────────────────
// Resource Usage
// ─────────────────────────────────────────────

/// Current resource usage of a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f64,
    pub ram_bytes: u64,
    pub disk_bytes: u64,
    pub bandwidth_bps: u64,
    pub open_files: u32,
    pub connections: u32,
    pub measured_at: DateTime<Utc>,
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            cpu_percent: 0.0,
            ram_bytes: 0,
            disk_bytes: 0,
            bandwidth_bps: 0,
            open_files: 0,
            connections: 0,
            measured_at: Utc::now(),
        }
    }
}

impl ResourceUsage {
    /// Check if usage exceeds limits
    pub fn exceeds(&self, limits: &ResourceLimits) -> Option<String> {
        if self.cpu_percent > limits.max_cpu_percent {
            return Some(format!("CPU: {:.1}% > {:.1}%", self.cpu_percent, limits.max_cpu_percent));
        }
        if self.ram_bytes > limits.max_ram_bytes {
            return Some(format!("RAM: {}MB > {}MB",
                self.ram_bytes / 1_048_576,
                limits.max_ram_bytes / 1_048_576
            ));
        }
        if self.disk_bytes > limits.max_disk_bytes {
            return Some(format!("Disk: {}GB > {}GB",
                self.disk_bytes / 1_073_741_824,
                limits.max_disk_bytes / 1_073_741_824
            ));
        }
        if self.bandwidth_bps > limits.max_bandwidth_bps {
            return Some(format!("Bandwidth: {}MB/s > {}MB/s",
                self.bandwidth_bps / 1_048_576,
                limits.max_bandwidth_bps / 1_048_576
            ));
        }
        None
    }
}

// ─────────────────────────────────────────────
// System Activity Level
// ─────────────────────────────────────────────

/// Detected activity level of the PC owner
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ActivityLevel {
    /// Owner is idle (no input for 10+ minutes)
    Idle,
    /// Owner is doing light work (browsing, documents)
    Light,
    /// Owner is doing moderate work (coding, compiling)
    Moderate,
    /// Owner is doing heavy work (gaming, video editing)
    Heavy,
}

impl ActivityLevel {
    /// Get the multiplier for service resource limits based on activity
    /// Lower multiplier = less resources for services
    pub fn resource_multiplier(&self) -> f64 {
        match self {
            ActivityLevel::Idle => 1.0,     // Full allocation
            ActivityLevel::Light => 0.7,    // 70% of limits
            ActivityLevel::Moderate => 0.4, // 40% of limits
            ActivityLevel::Heavy => 0.15,   // 15% of limits (minimal)
        }
    }
}

impl std::fmt::Display for ActivityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivityLevel::Idle => write!(f, "Idle"),
            ActivityLevel::Light => write!(f, "Light"),
            ActivityLevel::Moderate => write!(f, "Moderate"),
            ActivityLevel::Heavy => write!(f, "Heavy"),
        }
    }
}

// ─────────────────────────────────────────────
// Resource Governor
// ─────────────────────────────────────────────

/// Service resource tracking entry
#[derive(Debug)]
struct ServiceResource {
    limits: ResourceLimits,
    usage: ResourceUsage,
    effective_limits: ResourceLimits,
}

/// The Resource Governor monitors system activity and adjusts
/// service resource allocations adaptively.
#[allow(dead_code)]
pub struct ResourceGovernor {
    /// Per-service resource tracking
    services: Arc<RwLock<HashMap<Uuid, ServiceResource>>>,
    /// Global limits (total for all BECAS services)
    global_limits: ResourceLimits,
    /// Current detected activity level
    activity_level: Arc<RwLock<ActivityLevel>>,
    /// System info for monitoring
    system: Arc<RwLock<sysinfo::System>>,
}

impl ResourceGovernor {
    /// Create a new resource governor with global limits
    pub fn new(global_limits: ResourceLimits) -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            global_limits,
            activity_level: Arc::new(RwLock::new(ActivityLevel::Light)),
            system: Arc::new(RwLock::new(sysinfo::System::new_all())),
        }
    }

    /// Register a service with its resource limits
    pub async fn register_service(&self, service_id: Uuid, limits: ResourceLimits) {
        let effective = self.compute_effective_limits(&limits).await;
        self.services.write().await.insert(service_id, ServiceResource {
            limits,
            usage: ResourceUsage::default(),
            effective_limits: effective,
        });
        tracing::info!(service_id = %service_id, "Service registered with resource governor");
    }

    /// Unregister a service
    pub async fn unregister_service(&self, service_id: &Uuid) {
        self.services.write().await.remove(service_id);
        tracing::info!(service_id = %service_id, "Service unregistered from resource governor");
    }

    /// Update resource usage for a service
    pub async fn update_usage(&self, service_id: &Uuid, usage: ResourceUsage) -> Result<()> {
        let mut services = self.services.write().await;
        let entry = services.get_mut(service_id)
            .ok_or_else(|| ResourceError::ServiceNotFound(service_id.to_string()))?;

        // Check against effective limits
        if let Some(violation) = usage.exceeds(&entry.effective_limits) {
            tracing::warn!(
                service_id = %service_id,
                violation = %violation,
                "Resource limit exceeded"
            );
            return Err(ResourceError::LimitExceeded {
                resource: violation.clone(),
                current: 0.0,
                limit: 0.0,
            });
        }

        entry.usage = usage;
        Ok(())
    }

    /// Get current usage for a service
    pub async fn get_usage(&self, service_id: &Uuid) -> Result<ResourceUsage> {
        let services = self.services.read().await;
        services.get(service_id)
            .map(|s| s.usage.clone())
            .ok_or_else(|| ResourceError::ServiceNotFound(service_id.to_string()))
    }

    /// Get effective limits for a service (adjusted by activity level)
    pub async fn get_effective_limits(&self, service_id: &Uuid) -> Result<ResourceLimits> {
        let services = self.services.read().await;
        services.get(service_id)
            .map(|s| s.effective_limits.clone())
            .ok_or_else(|| ResourceError::ServiceNotFound(service_id.to_string()))
    }

    /// Get total resource usage across all services
    pub async fn total_usage(&self) -> ResourceUsage {
        let services = self.services.read().await;
        let mut total = ResourceUsage::default();

        for entry in services.values() {
            total.cpu_percent += entry.usage.cpu_percent;
            total.ram_bytes += entry.usage.ram_bytes;
            total.disk_bytes += entry.usage.disk_bytes;
            total.bandwidth_bps += entry.usage.bandwidth_bps;
            total.connections += entry.usage.connections;
        }

        total.measured_at = Utc::now();
        total
    }

    /// Detect current system activity level
    pub async fn detect_activity(&self) -> ActivityLevel {
        let mut sys = self.system.write().await;
        sys.refresh_all();

        let cpu_usage = sys.global_cpu_usage() as f64;

        // Heuristic-based activity detection
        let level = if cpu_usage < 5.0 {
            ActivityLevel::Idle
        } else if cpu_usage < 30.0 {
            ActivityLevel::Light
        } else if cpu_usage < 65.0 {
            ActivityLevel::Moderate
        } else {
            ActivityLevel::Heavy
        };

        let prev = *self.activity_level.read().await;
        if level != prev {
            tracing::info!(
                from = %prev,
                to = %level,
                cpu = format!("{:.1}%", cpu_usage),
                "Activity level changed"
            );
            *self.activity_level.write().await = level;

            // Recalculate all effective limits
            self.recalculate_all_limits().await;
        }

        level
    }

    /// Get current activity level
    pub async fn activity_level(&self) -> ActivityLevel {
        *self.activity_level.read().await
    }

    /// Recalculate effective limits for all services based on activity
    async fn recalculate_all_limits(&self) {
        let mut services = self.services.write().await;
        let activity = *self.activity_level.read().await;
        let multiplier = activity.resource_multiplier();

        for entry in services.values_mut() {
            entry.effective_limits = ResourceLimits {
                max_cpu_percent: entry.limits.max_cpu_percent * multiplier,
                max_ram_bytes: (entry.limits.max_ram_bytes as f64 * multiplier) as u64,
                max_disk_bytes: entry.limits.max_disk_bytes, // Disk doesn't scale with activity
                max_bandwidth_bps: (entry.limits.max_bandwidth_bps as f64 * multiplier) as u64,
                max_open_files: entry.limits.max_open_files,
                max_connections: (entry.limits.max_connections as f64 * multiplier) as u32,
            };
        }

        tracing::debug!(
            activity = %activity,
            multiplier = multiplier,
            "Recalculated effective limits for all services"
        );
    }

    /// Compute effective limits for a single service
    async fn compute_effective_limits(&self, base: &ResourceLimits) -> ResourceLimits {
        let activity = *self.activity_level.read().await;
        let m = activity.resource_multiplier();

        ResourceLimits {
            max_cpu_percent: base.max_cpu_percent * m,
            max_ram_bytes: (base.max_ram_bytes as f64 * m) as u64,
            max_disk_bytes: base.max_disk_bytes,
            max_bandwidth_bps: (base.max_bandwidth_bps as f64 * m) as u64,
            max_open_files: base.max_open_files,
            max_connections: (base.max_connections as f64 * m) as u32,
        }
    }

    /// Get system information snapshot
    pub async fn system_info(&self) -> SystemInfo {
        let sys = self.system.read().await;
        SystemInfo {
            total_memory_bytes: sys.total_memory(),
            used_memory_bytes: sys.used_memory(),
            cpu_count: sys.cpus().len() as u32,
            cpu_usage_percent: sys.global_cpu_usage() as f64,
            activity_level: *self.activity_level.read().await,
        }
    }
}

/// System information snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub total_memory_bytes: u64,
    pub used_memory_bytes: u64,
    pub cpu_count: u32,
    pub cpu_usage_percent: f64,
    pub activity_level: ActivityLevel,
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_cpu_percent, 15.0);
        assert_eq!(limits.max_ram_bytes, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_usage_within_limits() {
        let limits = ResourceLimits::default();
        let usage = ResourceUsage {
            cpu_percent: 5.0,
            ram_bytes: 512 * 1024 * 1024,
            ..Default::default()
        };
        assert!(usage.exceeds(&limits).is_none());
    }

    #[test]
    fn test_usage_exceeds_cpu() {
        let limits = ResourceLimits { max_cpu_percent: 10.0, ..Default::default() };
        let usage = ResourceUsage { cpu_percent: 15.0, ..Default::default() };
        assert!(usage.exceeds(&limits).is_some());
    }

    #[test]
    fn test_activity_multipliers() {
        assert_eq!(ActivityLevel::Idle.resource_multiplier(), 1.0);
        assert_eq!(ActivityLevel::Heavy.resource_multiplier(), 0.15);
        assert!(ActivityLevel::Light.resource_multiplier() > ActivityLevel::Heavy.resource_multiplier());
    }

    #[tokio::test]
    async fn test_governor_register_service() {
        let gov = ResourceGovernor::new(ResourceLimits::default());
        let id = Uuid::new_v4();
        gov.register_service(id, ResourceLimits::default()).await;

        let usage = gov.get_usage(&id).await.unwrap();
        assert_eq!(usage.cpu_percent, 0.0);
    }

    #[tokio::test]
    async fn test_governor_total_usage() {
        let gov = ResourceGovernor::new(ResourceLimits::default());

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        gov.register_service(id1, ResourceLimits::default()).await;
        gov.register_service(id2, ResourceLimits::default()).await;

        gov.update_usage(&id1, ResourceUsage { cpu_percent: 3.0, ram_bytes: 100, ..Default::default() }).await.unwrap();
        gov.update_usage(&id2, ResourceUsage { cpu_percent: 5.0, ram_bytes: 200, ..Default::default() }).await.unwrap();

        let total = gov.total_usage().await;
        assert_eq!(total.cpu_percent, 8.0);
        assert_eq!(total.ram_bytes, 300);
    }

    #[tokio::test]
    async fn test_governor_detect_activity() {
        let gov = ResourceGovernor::new(ResourceLimits::default());
        let level = gov.detect_activity().await;
        // Should return some valid level
        assert!(level.resource_multiplier() > 0.0);
        assert!(level.resource_multiplier() <= 1.0);
    }
}
