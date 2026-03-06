//! # BECAS Discovery Server
//!
//! Automatic relay and peer discovery for the BECAS network.
//!
//! ## Features
//! - Relay server registry (find nearest relay)
//! - Peer discovery (find other BECAS nodes)
//! - Health monitoring of relays
//! - Geographic routing (connect to nearest relay)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

// ─────────────────────────────────────────────
// Relay Registry
// ─────────────────────────────────────────────

/// Information about a relay server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub id: String,
    pub name: String,
    pub address: SocketAddr,
    pub region: String,
    pub country: String,
    pub capacity: u32,
    pub current_load: u32,
    pub latency_ms: Option<u32>,
    pub healthy: bool,
    pub last_check: DateTime<Utc>,
    pub features: Vec<RelayFeature>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RelayFeature {
    Tcp,
    Udp,
    Quic,
    Turn,
    WebSocket,
}

/// Peer node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: String,
    pub public_key: String,
    pub addresses: Vec<SocketAddr>,
    pub services: Vec<String>,
    pub last_seen: DateTime<Utc>,
    pub nat_type: String,
}

// ─────────────────────────────────────────────
// Discovery Client
// ─────────────────────────────────────────────

/// Client for discovering relays and peers
pub struct DiscoveryClient {
    /// Known discovery servers
    servers: Vec<String>,
    /// Cached relay list
    relays: Arc<RwLock<Vec<RelayInfo>>>,
    /// Cached peer list
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    /// Our node ID
    node_id: String,
    /// HTTP client
    client: reqwest::Client,
}

impl DiscoveryClient {
    /// Create with default BECAS discovery servers
    pub fn new(node_id: &str) -> Self {
        Self {
            servers: vec![
                "https://discovery.becas.dev".to_string(),
                "https://discovery-eu.becas.dev".to_string(),
                "https://discovery-us.becas.dev".to_string(),
            ],
            relays: Arc::new(RwLock::new(Vec::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            node_id: node_id.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Create with custom discovery servers
    pub fn with_servers(node_id: &str, servers: Vec<String>) -> Self {
        Self {
            servers,
            relays: Arc::new(RwLock::new(Vec::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            node_id: node_id.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Fetch list of available relays
    pub async fn fetch_relays(&self) -> Result<Vec<RelayInfo>, DiscoveryError> {
        for server in &self.servers {
            let url = format!("{}/api/v1/relays", server);
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(relays) = resp.json::<Vec<RelayInfo>>().await {
                        *self.relays.write().await = relays.clone();
                        return Ok(relays);
                    }
                }
                _ => continue,
            }
        }
        
        // Return cached if fetch failed
        let cached = self.relays.read().await.clone();
        if !cached.is_empty() {
            return Ok(cached);
        }
        
        // Return hardcoded fallback relays
        Ok(Self::fallback_relays())
    }

    /// Get best relay for our location
    pub async fn get_best_relay(&self) -> Result<RelayInfo, DiscoveryError> {
        let relays = self.fetch_relays().await?;
        
        // Filter healthy relays with capacity
        let available: Vec<_> = relays.iter()
            .filter(|r| r.healthy && r.current_load < r.capacity)
            .collect();
        
        if available.is_empty() {
            return Err(DiscoveryError::NoRelaysAvailable);
        }
        
        // Sort by latency (if known) then by load
        let mut sorted = available.clone();
        sorted.sort_by(|a, b| {
            match (a.latency_ms, b.latency_ms) {
                (Some(la), Some(lb)) => la.cmp(&lb),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.current_load.cmp(&b.current_load),
            }
        });
        
        Ok(sorted[0].clone())
    }

    /// Register our node with discovery server
    pub async fn register(&self, info: &PeerInfo) -> Result<(), DiscoveryError> {
        for server in &self.servers {
            let url = format!("{}/api/v1/peers/register", server);
            match self.client.post(&url).json(info).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(server = %server, "Registered with discovery server");
                    return Ok(());
                }
                Ok(resp) => {
                    tracing::warn!(server = %server, status = %resp.status(), 
                        "Discovery registration failed");
                }
                Err(e) => {
                    tracing::debug!(server = %server, error = %e, 
                        "Could not reach discovery server");
                }
            }
        }
        
        Err(DiscoveryError::RegistrationFailed)
    }

    /// Find a peer by node ID
    pub async fn find_peer(&self, node_id: &str) -> Result<PeerInfo, DiscoveryError> {
        // Check cache first
        if let Some(peer) = self.peers.read().await.get(node_id) {
            return Ok(peer.clone());
        }
        
        // Query discovery servers
        for server in &self.servers {
            let url = format!("{}/api/v1/peers/{}", server, node_id);
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(peer) = resp.json::<PeerInfo>().await {
                        self.peers.write().await.insert(node_id.to_string(), peer.clone());
                        return Ok(peer);
                    }
                }
                _ => continue,
            }
        }
        
        Err(DiscoveryError::PeerNotFound(node_id.to_string()))
    }

    /// Heartbeat to keep registration alive
    pub async fn heartbeat(&self) -> Result<(), DiscoveryError> {
        for server in &self.servers {
            let url = format!("{}/api/v1/peers/{}/heartbeat", server, self.node_id);
            if self.client.post(&url).send().await.is_ok() {
                return Ok(());
            }
        }
        Err(DiscoveryError::HeartbeatFailed)
    }

    /// Fallback relays when discovery is unavailable
    fn fallback_relays() -> Vec<RelayInfo> {
        vec![
            RelayInfo {
                id: "becas-relay-eu-1".into(),
                name: "BECAS EU Relay".into(),
                address: "relay-eu.becas.dev:4433".parse().unwrap_or(
                    "0.0.0.0:4433".parse().unwrap()
                ),
                region: "eu-west".into(),
                country: "DE".into(),
                capacity: 1000,
                current_load: 0,
                latency_ms: None,
                healthy: true,
                last_check: Utc::now(),
                features: vec![RelayFeature::Tcp, RelayFeature::Quic],
            },
            RelayInfo {
                id: "becas-relay-us-1".into(),
                name: "BECAS US Relay".into(),
                address: "relay-us.becas.dev:4433".parse().unwrap_or(
                    "0.0.0.0:4433".parse().unwrap()
                ),
                region: "us-east".into(),
                country: "US".into(),
                capacity: 1000,
                current_load: 0,
                latency_ms: None,
                healthy: true,
                last_check: Utc::now(),
                features: vec![RelayFeature::Tcp, RelayFeature::Quic],
            },
        ]
    }
}

// ─────────────────────────────────────────────
// Discovery Server
// ─────────────────────────────────────────────

/// Discovery server for relay and peer registration
pub struct DiscoveryServer {
    relays: Arc<RwLock<HashMap<String, RelayInfo>>>,
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    bind_addr: SocketAddr,
}

impl DiscoveryServer {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            relays: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            bind_addr,
        }
    }

    /// Register a relay server
    pub async fn register_relay(&self, info: RelayInfo) {
        tracing::info!(relay = %info.id, addr = %info.address, "Relay registered");
        self.relays.write().await.insert(info.id.clone(), info);
    }

    /// Register a peer node
    pub async fn register_peer(&self, info: PeerInfo) {
        tracing::info!(peer = %info.node_id, "Peer registered");
        self.peers.write().await.insert(info.node_id.clone(), info);
    }

    /// Get all healthy relays
    pub async fn get_relays(&self) -> Vec<RelayInfo> {
        self.relays.read().await.values()
            .filter(|r| r.healthy)
            .cloned()
            .collect()
    }

    /// Find a peer
    pub async fn get_peer(&self, node_id: &str) -> Option<PeerInfo> {
        self.peers.read().await.get(node_id).cloned()
    }

    /// Remove stale peers (not seen in 5 minutes)
    pub async fn cleanup_stale(&self) {
        let cutoff = Utc::now() - chrono::Duration::minutes(5);
        
        let mut peers = self.peers.write().await;
        peers.retain(|_, p| p.last_seen > cutoff);
        
        let mut relays = self.relays.write().await;
        relays.retain(|_, r| r.last_check > cutoff);
    }

    /// Start the discovery server
    pub async fn start(&self) -> Result<(), DiscoveryError> {
        use tokio::net::TcpListener;
        
        let listener = TcpListener::bind(self.bind_addr).await
            .map_err(|e| DiscoveryError::ServerError(e.to_string()))?;
        
        tracing::info!(addr = %self.bind_addr, "Discovery server started");
        
        // Cleanup task
        let relays = self.relays.clone();
        let peers = self.peers.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                let cutoff = Utc::now() - chrono::Duration::minutes(5);
                peers.write().await.retain(|_, p| p.last_seen > cutoff);
                relays.write().await.retain(|_, r| r.last_check > cutoff);
            }
        });
        
        // Accept connections (simplified - real impl would use HTTP)
        loop {
            let (socket, addr) = listener.accept().await
                .map_err(|e| DiscoveryError::ServerError(e.to_string()))?;
            
            tracing::debug!(client = %addr, "Discovery client connected");
            
            // Handle in background
            let relays = self.relays.clone();
            let peers = self.peers.clone();
            tokio::spawn(async move {
                let _ = handle_discovery_connection(socket, relays, peers).await;
            });
        }
    }
}

async fn handle_discovery_connection(
    mut socket: tokio::net::TcpStream,
    _relays: Arc<RwLock<HashMap<String, RelayInfo>>>,
    _peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
) -> Result<(), DiscoveryError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    let mut buf = vec![0u8; 4096];
    let n = socket.read(&mut buf).await
        .map_err(|e| DiscoveryError::ServerError(e.to_string()))?;
    
    if n == 0 {
        return Ok(());
    }
    
    // Simple protocol: JSON request/response
    // Real implementation would be proper HTTP
    let response = serde_json::json!({
        "status": "ok",
        "message": "BECAS Discovery Server"
    });
    
    socket.write_all(response.to_string().as_bytes()).await
        .map_err(|e| DiscoveryError::ServerError(e.to_string()))?;
    
    Ok(())
}

// ─────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("No relays available")]
    NoRelaysAvailable,
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("Registration failed")]
    RegistrationFailed,
    #[error("Heartbeat failed")]
    HeartbeatFailed,
    #[error("Server error: {0}")]
    ServerError(String),
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_relays() {
        let relays = DiscoveryClient::fallback_relays();
        assert!(!relays.is_empty());
        assert!(relays.iter().all(|r| r.healthy));
    }

    #[tokio::test]
    async fn test_discovery_client() {
        let client = DiscoveryClient::new("test-node");
        // Should return fallback relays
        let relays = client.fetch_relays().await.unwrap();
        assert!(!relays.is_empty());
    }

    #[tokio::test]
    async fn test_discovery_server() {
        let server = DiscoveryServer::new("127.0.0.1:0".parse().unwrap());
        
        let relay = RelayInfo {
            id: "test-relay".into(),
            name: "Test".into(),
            address: "127.0.0.1:4433".parse().unwrap(),
            region: "test".into(),
            country: "XX".into(),
            capacity: 100,
            current_load: 0,
            latency_ms: Some(10),
            healthy: true,
            last_check: Utc::now(),
            features: vec![RelayFeature::Tcp],
        };
        
        server.register_relay(relay).await;
        let relays = server.get_relays().await;
        assert_eq!(relays.len(), 1);
    }
}
