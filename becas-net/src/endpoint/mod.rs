//! # Endpoint Manager
//!
//! Zero-configuration public endpoint system.
//! When you deploy a service, BECAS automatically gives it a public address:
//! `your-service.becas.net` — no DNS config, no port forwarding, no SSL setup.
//!
//! ## Features
//! - Automatic DNS registration (service-name.becas.net)
//! - Automatic TLS certificate (Let's Encrypt or self-signed)
//! - Persistent identity (IP changes → address stays the same)
//! - Custom domain support (CNAME to becas.net)

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EndpointError {
    #[error("Endpoint not found: {0}")]
    NotFound(String),

    #[error("Endpoint name already taken: {0}")]
    NameTaken(String),

    #[error("Invalid endpoint name: {0}")]
    InvalidName(String),

    #[error("DNS registration failed: {0}")]
    DnsError(String),

    #[error("TLS certificate error: {0}")]
    TlsError(String),
}

pub type Result<T> = std::result::Result<T, EndpointError>;

// ─────────────────────────────────────────────
// Endpoint
// ─────────────────────────────────────────────

/// A public endpoint for a BECAS service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// Unique endpoint ID
    pub id: Uuid,
    /// Service this endpoint belongs to
    pub service_id: Uuid,
    /// Subdomain name (e.g., "my-api" → "my-api.becas.net")
    pub subdomain: String,
    /// Full public URL
    pub url: String,
    /// Custom domain (optional CNAME)
    pub custom_domain: Option<String>,
    /// TLS certificate status
    pub tls_status: TlsStatus,
    /// Whether the endpoint is currently active
    pub active: bool,
    /// Tunnel ID this endpoint routes to
    pub tunnel_id: Option<Uuid>,
    /// Total requests served through this endpoint
    pub total_requests: u64,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Last accessed
    pub last_accessed: Option<DateTime<Utc>>,
}

/// TLS certificate status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TlsStatus {
    /// No certificate
    None,
    /// Self-signed (for development)
    SelfSigned,
    /// Valid certificate from CA
    Valid { expires_at: DateTime<Utc> },
    /// Certificate expired
    Expired,
    /// Provisioning in progress
    Provisioning,
}

impl std::fmt::Display for TlsStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsStatus::None => write!(f, "No TLS"),
            TlsStatus::SelfSigned => write!(f, "Self-Signed"),
            TlsStatus::Valid { expires_at } => write!(f, "Valid (expires {})", expires_at.format("%Y-%m-%d")),
            TlsStatus::Expired => write!(f, "Expired"),
            TlsStatus::Provisioning => write!(f, "Provisioning..."),
        }
    }
}

// ─────────────────────────────────────────────
// Endpoint Manager
// ─────────────────────────────────────────────

/// Manages public endpoints for all BECAS services
pub struct EndpointManager {
    /// All endpoints indexed by ID
    endpoints: Arc<RwLock<HashMap<Uuid, Endpoint>>>,
    /// Subdomain → endpoint ID mapping (for uniqueness)
    subdomain_map: Arc<RwLock<HashMap<String, Uuid>>>,
    /// Base domain (e.g., "becas.net")
    base_domain: String,
}

impl EndpointManager {
    /// Create a new endpoint manager
    pub fn new(base_domain: String) -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            subdomain_map: Arc::new(RwLock::new(HashMap::new())),
            base_domain,
        }
    }

    /// Register a new endpoint for a service
    pub async fn register(
        &self,
        service_id: Uuid,
        subdomain: &str,
    ) -> Result<Endpoint> {
        // Validate subdomain
        Self::validate_subdomain(subdomain)?;

        // Check uniqueness
        if self.subdomain_map.read().await.contains_key(subdomain) {
            return Err(EndpointError::NameTaken(subdomain.to_string()));
        }

        let endpoint_id = Uuid::new_v4();
        let url = format!("https://{}.{}", subdomain, self.base_domain);

        let endpoint = Endpoint {
            id: endpoint_id,
            service_id,
            subdomain: subdomain.to_string(),
            url: url.clone(),
            custom_domain: None,
            tls_status: TlsStatus::Provisioning,
            active: false,
            tunnel_id: None,
            total_requests: 0,
            created_at: Utc::now(),
            last_accessed: None,
        };

        self.endpoints.write().await.insert(endpoint_id, endpoint.clone());
        self.subdomain_map.write().await.insert(subdomain.to_string(), endpoint_id);

        tracing::info!(
            endpoint_id = %endpoint_id,
            url = %url,
            service_id = %service_id,
            "Endpoint registered"
        );

        Ok(endpoint)
    }

    /// Activate an endpoint (connect to a tunnel)
    pub async fn activate(&self, endpoint_id: &Uuid, tunnel_id: Uuid) -> Result<()> {
        let mut endpoints = self.endpoints.write().await;
        let ep = endpoints.get_mut(endpoint_id)
            .ok_or_else(|| EndpointError::NotFound(endpoint_id.to_string()))?;

        ep.tunnel_id = Some(tunnel_id);
        ep.active = true;
        // For now, use self-signed TLS — real implementation would use ACME/Let's Encrypt
        ep.tls_status = TlsStatus::SelfSigned;

        tracing::info!(endpoint_id = %endpoint_id, url = %ep.url, "Endpoint activated");
        Ok(())
    }

    /// Deactivate an endpoint
    pub async fn deactivate(&self, endpoint_id: &Uuid) -> Result<()> {
        let mut endpoints = self.endpoints.write().await;
        let ep = endpoints.get_mut(endpoint_id)
            .ok_or_else(|| EndpointError::NotFound(endpoint_id.to_string()))?;

        ep.active = false;
        ep.tunnel_id = None;

        tracing::info!(endpoint_id = %endpoint_id, url = %ep.url, "Endpoint deactivated");
        Ok(())
    }

    /// Set a custom domain for an endpoint
    pub async fn set_custom_domain(&self, endpoint_id: &Uuid, domain: &str) -> Result<()> {
        let mut endpoints = self.endpoints.write().await;
        let ep = endpoints.get_mut(endpoint_id)
            .ok_or_else(|| EndpointError::NotFound(endpoint_id.to_string()))?;

        ep.custom_domain = Some(domain.to_string());
        tracing::info!(endpoint_id = %endpoint_id, domain = domain, "Custom domain set");
        Ok(())
    }

    /// Get an endpoint by ID
    pub async fn get(&self, endpoint_id: &Uuid) -> Result<Endpoint> {
        self.endpoints.read().await
            .get(endpoint_id)
            .cloned()
            .ok_or_else(|| EndpointError::NotFound(endpoint_id.to_string()))
    }

    /// Get endpoint by subdomain
    pub async fn get_by_subdomain(&self, subdomain: &str) -> Result<Endpoint> {
        let id = self.subdomain_map.read().await
            .get(subdomain)
            .cloned()
            .ok_or_else(|| EndpointError::NotFound(subdomain.to_string()))?;
        self.get(&id).await
    }

    /// Get all endpoints for a service
    pub async fn service_endpoints(&self, service_id: &Uuid) -> Vec<Endpoint> {
        self.endpoints.read().await.values()
            .filter(|ep| &ep.service_id == service_id)
            .cloned()
            .collect()
    }

    /// List all endpoints
    pub async fn list(&self) -> Vec<Endpoint> {
        self.endpoints.read().await.values().cloned().collect()
    }

    /// Remove an endpoint
    pub async fn remove(&self, endpoint_id: &Uuid) -> Result<()> {
        let ep = self.endpoints.write().await.remove(endpoint_id)
            .ok_or_else(|| EndpointError::NotFound(endpoint_id.to_string()))?;
        self.subdomain_map.write().await.remove(&ep.subdomain);
        tracing::info!(endpoint_id = %endpoint_id, url = %ep.url, "Endpoint removed");
        Ok(())
    }

    // ─── Validation ───

    fn validate_subdomain(subdomain: &str) -> Result<()> {
        if subdomain.is_empty() || subdomain.len() > 63 {
            return Err(EndpointError::InvalidName(
                "Subdomain must be 1-63 characters".into()
            ));
        }
        if !subdomain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(EndpointError::InvalidName(
                "Subdomain can only contain letters, numbers, and hyphens".into()
            ));
        }
        if subdomain.starts_with('-') || subdomain.ends_with('-') {
            return Err(EndpointError::InvalidName(
                "Subdomain cannot start or end with a hyphen".into()
            ));
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_endpoint() {
        let mgr = EndpointManager::new("becas.net".into());
        let service_id = Uuid::new_v4();

        let ep = mgr.register(service_id, "my-api").await.unwrap();
        assert_eq!(ep.url, "https://my-api.becas.net");
        assert!(!ep.active);
    }

    #[tokio::test]
    async fn test_duplicate_subdomain() {
        let mgr = EndpointManager::new("becas.net".into());
        mgr.register(Uuid::new_v4(), "taken").await.unwrap();

        let result = mgr.register(Uuid::new_v4(), "taken").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_subdomain() {
        let mgr = EndpointManager::new("becas.net".into());
        assert!(mgr.register(Uuid::new_v4(), "").await.is_err());
        assert!(mgr.register(Uuid::new_v4(), "-bad").await.is_err());
        assert!(mgr.register(Uuid::new_v4(), "bad-").await.is_err());
        assert!(mgr.register(Uuid::new_v4(), "has space").await.is_err());
    }

    #[tokio::test]
    async fn test_activate_deactivate() {
        let mgr = EndpointManager::new("becas.net".into());
        let ep = mgr.register(Uuid::new_v4(), "test-svc").await.unwrap();
        let tunnel_id = Uuid::new_v4();

        mgr.activate(&ep.id, tunnel_id).await.unwrap();
        let ep = mgr.get(&ep.id).await.unwrap();
        assert!(ep.active);
        assert_eq!(ep.tunnel_id, Some(tunnel_id));

        mgr.deactivate(&ep.id).await.unwrap();
        let ep = mgr.get(&ep.id).await.unwrap();
        assert!(!ep.active);
    }

    #[tokio::test]
    async fn test_get_by_subdomain() {
        let mgr = EndpointManager::new("becas.net".into());
        mgr.register(Uuid::new_v4(), "findme").await.unwrap();

        let ep = mgr.get_by_subdomain("findme").await.unwrap();
        assert_eq!(ep.subdomain, "findme");
    }

    #[tokio::test]
    async fn test_custom_domain() {
        let mgr = EndpointManager::new("becas.net".into());
        let ep = mgr.register(Uuid::new_v4(), "myapp").await.unwrap();

        mgr.set_custom_domain(&ep.id, "api.example.com").await.unwrap();
        let ep = mgr.get(&ep.id).await.unwrap();
        assert_eq!(ep.custom_domain, Some("api.example.com".into()));
    }
}
