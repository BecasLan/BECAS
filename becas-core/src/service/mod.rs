//! # Service Manager
//!
//! Manages the lifecycle of services deployed in the BECAS Layer.
//! Services belong to the Layer — NOT to the PC. They have:
//! - **Portable Identity:** Can migrate between PCs, same address
//! - **Layer-Native Deployment:** `becas deploy` puts services in the Layer
//! - **Lifecycle Management:** deploy → start → pause → stop → migrate → remove
//!
//! ## Key Concept: Layer Ownership
//! When you deploy a service to BECAS, it becomes a Layer citizen.
//! The PC provides resources, but the service's identity, data, and
//! configuration belong to the Layer itself.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;
use std::path::Path;
use crate::sandbox::{SandboxConfig, SandboxManager, PortMapping, VolumeMount};
use crate::access::AccessLevel;
use crate::resource::{ResourceGovernor, ResourceLimits};
use crate::crypto::{CryptoEngine};
use crate::access::{AccessController};
use crate::persistence::ServiceStore;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Service not found: {0}")]
    NotFound(String),

    #[error("Service already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid service configuration: {0}")]
    InvalidConfig(String),

    #[error("Service is in wrong state for this operation: {0}")]
    InvalidState(String),

    #[error("Sandbox error: {0}")]
    Sandbox(#[from] crate::sandbox::SandboxError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ServiceError>;

// ─────────────────────────────────────────────
// Service Configuration
// ─────────────────────────────────────────────

/// Configuration for deploying a service to the BECAS Layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Human-readable service name
    pub name: String,

    /// Service type
    pub service_type: ServiceType,

    /// Command to run
    pub command: String,

    /// Command arguments
    pub args: Vec<String>,

    /// Environment variables
    pub env: HashMap<String, String>,

    /// Resource limits
    pub resource_limits: ResourceLimits,

    /// Ports to expose
    pub ports: Vec<PortMapping>,

    /// Persistent storage volumes
    pub volumes: Vec<VolumeMount>,

    /// Health check configuration
    pub health_check: Option<HealthCheckConfig>,

    /// Auto-restart on crash
    pub auto_restart: bool,

    /// Maximum restart attempts before marking as failed
    pub max_restart_attempts: u32,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            service_type: ServiceType::Generic,
            command: String::new(),
            args: Vec::new(),
            env: HashMap::new(),
            resource_limits: ResourceLimits::default(),
            ports: Vec::new(),
            volumes: Vec::new(),
            health_check: None,
            auto_restart: true,
            max_restart_attempts: 5,
        }
    }
}

/// Type of service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServiceType {
    /// Database (BecasDB, PostgreSQL, etc.)
    Database,
    /// API server (REST, GraphQL)
    Api,
    /// Web application
    Web,
    /// AI/ML model serving
    AiModel,
    /// Background worker/job processor
    Worker,
    /// Generic service
    Generic,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceType::Database => write!(f, "Database"),
            ServiceType::Api => write!(f, "API"),
            ServiceType::Web => write!(f, "Web"),
            ServiceType::AiModel => write!(f, "AI Model"),
            ServiceType::Worker => write!(f, "Worker"),
            ServiceType::Generic => write!(f, "Generic"),
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Command or HTTP endpoint to check
    pub check_type: HealthCheckType,
    /// Interval between checks in seconds
    pub interval_secs: u64,
    /// Timeout for each check in seconds
    pub timeout_secs: u64,
    /// Number of consecutive failures before marking unhealthy
    pub failure_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthCheckType {
    /// Run a command inside the sandbox, success = exit code 0
    Command(String),
    /// HTTP GET to a port, success = 2xx response
    Http { port: u16, path: String },
    /// TCP connection to a port, success = connection established
    Tcp(u16),
}

// ─────────────────────────────────────────────
// Service Status
// ─────────────────────────────────────────────

/// Current status of a service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServiceStatus {
    /// Deployed but not started
    Deployed,
    /// Starting up
    Starting,
    /// Running and healthy
    Running,
    /// Running but health checks failing
    Unhealthy,
    /// Paused (resource conservation)
    Paused,
    /// Stopping
    Stopping,
    /// Stopped
    Stopped,
    /// Failed after max restart attempts
    Failed(String),
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStatus::Deployed => write!(f, "Deployed"),
            ServiceStatus::Starting => write!(f, "Starting"),
            ServiceStatus::Running => write!(f, "Running"),
            ServiceStatus::Unhealthy => write!(f, "Unhealthy"),
            ServiceStatus::Paused => write!(f, "Paused"),
            ServiceStatus::Stopping => write!(f, "Stopping"),
            ServiceStatus::Stopped => write!(f, "Stopped"),
            ServiceStatus::Failed(reason) => write!(f, "Failed: {}", reason),
        }
    }
}

// ─────────────────────────────────────────────
// Service Instance
// ─────────────────────────────────────────────

/// A service deployed in the BECAS Layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Unique Layer-native identifier (portable across PCs)
    pub id: Uuid,

    /// Service configuration
    pub config: ServiceConfig,

    /// Current status
    pub status: ServiceStatus,

    /// Service's own cryptographic identity
    pub identity_id: String,

    /// Sandbox ID (if running)
    pub sandbox_id: Option<Uuid>,

    /// Layer endpoint address (e.g., "becasdb.becas.net")
    pub endpoint: Option<String>,

    /// Deployment time
    pub deployed_at: DateTime<Utc>,

    /// Last status change
    pub updated_at: DateTime<Utc>,

    /// Number of restart attempts
    pub restart_count: u32,

    /// Total requests served (lifetime)
    pub total_requests: u64,

    /// Total uptime in seconds (lifetime)
    pub total_uptime_secs: u64,

    /// Process ID (persisted for cross-process lifecycle management)
    pub pid: Option<u32>,
}

// ─────────────────────────────────────────────
// Service Manager
// ─────────────────────────────────────────────

/// Manages all services in the BECAS Layer
#[allow(dead_code)]
pub struct ServiceManager {
    /// All registered services
    services: Arc<RwLock<HashMap<Uuid, Service>>>,
    /// Sandbox manager for process isolation
    sandbox_manager: Arc<SandboxManager>,
    /// Resource governor for adaptive limits
    resource_governor: Arc<ResourceGovernor>,
    /// Access controller for visibility levels
    access_controller: Arc<AccessController>,
    /// Crypto engine for identities and encryption
    crypto_engine: Arc<CryptoEngine>,
    /// Base directory for service data
    base_dir: PathBuf,
    /// Persistent storage for service state
    store: Option<ServiceStore>,
}

impl ServiceManager {
    /// Create a new service manager
    pub fn new(
        base_dir: PathBuf,
        sandbox_manager: Arc<SandboxManager>,
        resource_governor: Arc<ResourceGovernor>,
        access_controller: Arc<AccessController>,
        crypto_engine: Arc<CryptoEngine>,
    ) -> Self {
        let store = ServiceStore::new(base_dir.join("services")).ok();
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            sandbox_manager,
            resource_governor,
            access_controller,
            crypto_engine,
            base_dir,
            store,
        }
    }

    /// Load previously saved services from disk
    /// Called once at startup to restore state
    pub async fn load_from_disk(&self) -> Result<usize> {
        let store = match &self.store {
            Some(s) => s,
            None => return Ok(0),
        };

        let saved = store.load_all().map_err(|e| ServiceError::Io(
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        ))?;

        let count = saved.len();
        let mut services = self.services.write().await;

        for mut svc in saved {
            // For services that were "Running" when saved, check if process is still alive
            match &svc.status {
                ServiceStatus::Running | ServiceStatus::Paused => {
                    // Check if the sandbox process is still alive
                    let still_alive = if let Some(_sandbox_id) = &svc.sandbox_id {
                        // Try to find the sandbox directory and check pid
                        let pid_alive = Self::check_process_alive(&svc);
                        if pid_alive {
                            tracing::info!(
                                service_id = %svc.id,
                                name = %svc.config.name,
                                "Service process still running, keeping status"
                            );
                        }
                        pid_alive
                    } else {
                        false
                    };

                    if !still_alive {
                        tracing::info!(
                            service_id = %svc.id,
                            name = %svc.config.name,
                            prev_status = %svc.status,
                            "Service process not found, marking as Stopped"
                        );
                        svc.status = ServiceStatus::Stopped;
                        svc.sandbox_id = None;
                    }
                }
                ServiceStatus::Starting | ServiceStatus::Stopping => {
                    // Transitional states → force to Stopped
                    svc.status = ServiceStatus::Stopped;
                    svc.sandbox_id = None;
                }
                _ => {}
            }

            // Re-register with subsystems
            self.resource_governor
                .register_service(svc.id, svc.config.resource_limits.clone())
                .await;
            self.access_controller
                .register_service(svc.id)
                .await;

            services.insert(svc.id, svc);
        }

        tracing::info!(count = count, "Loaded services from disk");
        Ok(count)
    }

    /// Persist a service to disk
    fn persist(&self, service: &Service) {
        if let Some(store) = &self.store {
            if let Err(e) = store.save(service) {
                tracing::error!(service_id = %service.id, error = %e, "Failed to persist service");
            }
        }
    }

    /// Check if a service's process is still alive using stored PID
    fn check_process_alive(service: &Service) -> bool {
        #[cfg(unix)]
        {
            if let Some(pid) = service.pid {
                use std::process::Command;
                // kill -0 checks if process exists without sending a signal
                let result = Command::new("kill")
                    .args(["-0", &pid.to_string()])
                    .output();
                if let Ok(output) = result {
                    return output.status.success();
                }
            }
            false
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Delete service from disk
    fn unpersist(&self, id: &Uuid) {
        if let Some(store) = &self.store {
            if let Err(e) = store.delete(id) {
                tracing::error!(service_id = %id, error = %e, "Failed to delete service from disk");
            }
        }
    }

    /// Deploy a new service to the BECAS Layer
    ///
    /// This creates the service's identity, encrypted volume,
    /// and registers it with all subsystems.
    pub async fn deploy(&self, config: ServiceConfig) -> Result<Uuid> {
        // Validate config
        if config.name.is_empty() {
            return Err(ServiceError::InvalidConfig("Service name is required".into()));
        }
        if config.command.is_empty() {
            return Err(ServiceError::InvalidConfig("Service command is required".into()));
        }

        // Check for duplicate names
        {
            let services = self.services.read().await;
            for svc in services.values() {
                if svc.config.name == config.name {
                    return Err(ServiceError::AlreadyExists(config.name.clone()));
                }
            }
        }

        // Generate service identity
        let identity = self.crypto_engine.generate_service_identity();
        let identity_id = identity.id.clone();

        // Create service
        let service_id = Uuid::new_v4();
        let service = Service {
            id: service_id,
            config: config.clone(),
            status: ServiceStatus::Deployed,
            identity_id,
            sandbox_id: None,
            endpoint: None,
            deployed_at: Utc::now(),
            updated_at: Utc::now(),
            restart_count: 0,
            total_requests: 0,
            total_uptime_secs: 0,
            pid: None,
        };

        // Register with resource governor
        self.resource_governor
            .register_service(service_id, config.resource_limits.clone())
            .await;

        // Register with access controller
        self.access_controller
            .register_service(service_id)
            .await;

        // Create encrypted volume for service data
        let _volume = self.crypto_engine.create_volume(&service_id)?;

        // Store service
        self.services.write().await.insert(service_id, service.clone());

        // Persist to disk
        self.persist(&service);

        tracing::info!(
            service_id = %service_id,
            name = %config.name,
            service_type = %config.service_type,
            "Service deployed to BECAS Layer"
        );

        Ok(service_id)
    }

    /// Start a deployed service
    pub async fn start(&self, service_id: &Uuid) -> Result<()> {
        let mut services = self.services.write().await;
        let service = services.get_mut(service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;

        match &service.status {
            ServiceStatus::Deployed | ServiceStatus::Stopped => {},
            ServiceStatus::Running => return Ok(()),
            other => return Err(ServiceError::InvalidState(
                format!("Cannot start service in state: {}", other)
            )),
        }

        service.status = ServiceStatus::Starting;
        service.updated_at = Utc::now();

        // Create sandbox configuration
        let sandbox_config = SandboxConfig {
            name: service.config.name.clone(),
            command: service.config.command.clone(),
            args: service.config.args.clone(),
            env: service.config.env.clone(),
            resource_limits: service.config.resource_limits.clone(),
            exposed_ports: service.config.ports.clone(),
            network_enabled: true,
            volumes: service.config.volumes.clone(),
            ..Default::default()
        };

        // Create and start sandbox
        let sandbox_id = self.sandbox_manager.create(sandbox_config).await?;
        self.sandbox_manager.start(&sandbox_id).await?;

        // Get PID from sandbox and persist it
        let sandbox = self.sandbox_manager.get(&sandbox_id).await?;
        let pid = sandbox.pid().await;

        service.sandbox_id = Some(sandbox_id);
        service.pid = pid;
        service.status = ServiceStatus::Running;
        service.updated_at = Utc::now();

        // Persist updated state
        self.persist(service);

        tracing::info!(
            service_id = %service_id,
            name = %service.config.name,
            sandbox_id = %sandbox_id,
            "Service started"
        );

        Ok(())
    }

    /// Stop a running service
    pub async fn stop(&self, service_id: &Uuid) -> Result<()> {
        let mut services = self.services.write().await;
        let service = services.get_mut(service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;

        if service.status != ServiceStatus::Running &&
           service.status != ServiceStatus::Unhealthy &&
           service.status != ServiceStatus::Paused {
            return Err(ServiceError::InvalidState(
                format!("Cannot stop service in state: {}", service.status)
            ));
        }

        service.status = ServiceStatus::Stopping;
        service.updated_at = Utc::now();

        // Try to stop via sandbox manager first
        let mut stopped_via_sandbox = false;
        if let Some(sandbox_id) = &service.sandbox_id {
            match self.sandbox_manager.stop(sandbox_id).await {
                Ok(()) => { stopped_via_sandbox = true; }
                Err(_) => {
                    // Sandbox not found in manager (e.g., loaded from disk after restart)
                    // Kill the process directly
                    tracing::debug!(service_id = %service_id, "Sandbox not in manager, killing process directly");
                }
            }
        }

        // If sandbox manager couldn't stop it, kill the process directly
        if !stopped_via_sandbox {
            Self::kill_service_process(service);
        }

        service.sandbox_id = None;
        service.pid = None;
        service.status = ServiceStatus::Stopped;
        service.updated_at = Utc::now();

        // Persist updated state
        self.persist(service);

        tracing::info!(service_id = %service_id, name = %service.config.name, "Service stopped");
        Ok(())
    }

    /// Kill a service's process directly using stored PID
    fn kill_service_process(service: &Service) {
        #[cfg(unix)]
        {
            if let Some(pid) = service.pid {
                use std::process::Command;
                let pid_str = pid.to_string();
                // SIGTERM first
                let _ = Command::new("kill").args(["-TERM", &pid_str]).output();
                // Brief wait then SIGKILL
                std::thread::sleep(std::time::Duration::from_millis(500));
                let _ = Command::new("kill").args(["-9", &pid_str]).output();
                tracing::info!(pid = pid, "Killed service process directly");
            } else {
                tracing::warn!(name = %service.config.name, "No PID stored, cannot kill process");
            }
        }
    }

    /// Get a service by ID
    pub async fn get(&self, service_id: &Uuid) -> Result<Service> {
        self.services.read().await
            .get(service_id)
            .cloned()
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))
    }

    /// List all services
    pub async fn list(&self) -> Vec<Service> {
        self.services.read().await.values().cloned().collect()
    }

    /// Get services filtered by status
    pub async fn list_by_status(&self, status: &ServiceStatus) -> Vec<Service> {
        self.services.read().await.values()
            .filter(|s| &s.status == status)
            .cloned()
            .collect()
    }

    /// Remove a service (must be stopped)
    pub async fn remove(&self, service_id: &Uuid) -> Result<()> {
        let service = self.get(service_id).await?;

        if service.status == ServiceStatus::Running || service.status == ServiceStatus::Paused {
            return Err(ServiceError::InvalidState(
                "Cannot remove a running service. Stop it first.".into()
            ));
        }

        // Unregister from subsystems
        self.resource_governor.unregister_service(service_id).await;

        // Remove sandbox if exists
        if let Some(sandbox_id) = &service.sandbox_id {
            let _ = self.sandbox_manager.remove(sandbox_id).await;
        }

        self.services.write().await.remove(service_id);

        // Remove from disk
        self.unpersist(service_id);

        tracing::info!(service_id = %service_id, name = %service.config.name, "Service removed");
        Ok(())
    }

    /// Get service count summary
    pub async fn summary(&self) -> ServiceSummary {
        let services = self.services.read().await;
        let mut summary = ServiceSummary::default();

        for svc in services.values() {
            summary.total += 1;
            match &svc.status {
                ServiceStatus::Running => summary.running += 1,
                ServiceStatus::Stopped | ServiceStatus::Deployed => summary.stopped += 1,
                ServiceStatus::Failed(_) => summary.failed += 1,
                ServiceStatus::Paused => summary.paused += 1,
                _ => {},
            }
        }

        summary
    }
}

/// Summary of service counts
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ServiceSummary {
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
    pub failed: usize,
    pub paused: usize,
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_base_dir() -> PathBuf {
        tempfile::tempdir().unwrap().into_path()
    }

    fn create_test_manager(base_dir: &Path) -> ServiceManager {
        let sandbox_mgr = Arc::new(SandboxManager::new(base_dir.join("sandboxes")));
        let resource_gov = Arc::new(ResourceGovernor::new(ResourceLimits::default()));
        let access_ctrl = Arc::new(AccessController::new(AccessLevel::Monitor));
        let crypto_eng = Arc::new(CryptoEngine::new(base_dir.join("crypto")).unwrap());

        ServiceManager::new(
            base_dir.to_path_buf(),
            sandbox_mgr,
            resource_gov,
            access_ctrl,
            crypto_eng,
        )
    }

    fn test_config() -> ServiceConfig {
        ServiceConfig {
            name: "test-db".to_string(),
            service_type: ServiceType::Database,
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_deploy_service() {
        let dir = test_base_dir();
        let mgr = create_test_manager(&dir);

        let id = mgr.deploy(test_config()).await.unwrap();
        let svc = mgr.get(&id).await.unwrap();

        assert_eq!(svc.config.name, "test-db");
        assert_eq!(svc.status, ServiceStatus::Deployed);
        assert!(!svc.identity_id.is_empty());
    }

    #[tokio::test]
    async fn test_deploy_duplicate_name() {
        let dir = test_base_dir();
        let mgr = create_test_manager(&dir);

        mgr.deploy(test_config()).await.unwrap();
        let result = mgr.deploy(test_config()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_deploy_empty_name() {
        let dir = test_base_dir();
        let mgr = create_test_manager(&dir);

        let result = mgr.deploy(ServiceConfig {
            name: "".into(),
            command: "echo".into(),
            ..Default::default()
        }).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_services() {
        let dir = test_base_dir();
        let mgr = create_test_manager(&dir);

        mgr.deploy(ServiceConfig {
            name: "svc-1".into(),
            command: "echo".into(),
            ..Default::default()
        }).await.unwrap();

        mgr.deploy(ServiceConfig {
            name: "svc-2".into(),
            command: "echo".into(),
            ..Default::default()
        }).await.unwrap();

        let list = mgr.list().await;
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn test_service_summary() {
        let dir = test_base_dir();
        let mgr = create_test_manager(&dir);

        mgr.deploy(test_config()).await.unwrap();

        let summary = mgr.summary().await;
        assert_eq!(summary.total, 1);
        assert_eq!(summary.stopped, 1); // Deployed counts as stopped
    }

    #[tokio::test]
    async fn test_start_stop_service() {
        let dir = test_base_dir();
        let mgr = create_test_manager(&dir);

        let id = mgr.deploy(ServiceConfig {
            name: "sleeper".into(),
            command: "sleep".into(),
            args: vec!["60".into()],
            ..Default::default()
        }).await.unwrap();

        // Start
        mgr.start(&id).await.unwrap();
        let svc = mgr.get(&id).await.unwrap();
        assert_eq!(svc.status, ServiceStatus::Running);
        assert!(svc.sandbox_id.is_some());

        // Stop
        mgr.stop(&id).await.unwrap();
        let svc = mgr.get(&id).await.unwrap();
        assert_eq!(svc.status, ServiceStatus::Stopped);
    }

    #[tokio::test]
    async fn test_remove_stopped_service() {
        let dir = test_base_dir();
        let mgr = create_test_manager(&dir);

        let id = mgr.deploy(test_config()).await.unwrap();
        mgr.remove(&id).await.unwrap();

        assert!(mgr.get(&id).await.is_err());
    }

    #[tokio::test]
    async fn test_service_type_display() {
        assert_eq!(ServiceType::Database.to_string(), "Database");
        assert_eq!(ServiceType::Api.to_string(), "API");
        assert_eq!(ServiceType::AiModel.to_string(), "AI Model");
    }
}
