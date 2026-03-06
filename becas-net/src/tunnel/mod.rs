//! # Tunnel Manager
//!
//! Handles NAT traversal and encrypted tunnel creation.
//! Allows services in the BECAS Layer to be accessible from the internet
//! without the PC owner opening any ports or configuring anything.
//!
//! ## How It Works
//! 1. BECAS establishes a QUIC connection to a relay/signaling server
//! 2. Clients connect to the relay, which bridges to the BECAS node
//! 3. Direct peer-to-peer connections via STUN hole-punching when possible
//! 4. Falls back to relay if direct connection fails
//!
//! All traffic is encrypted end-to-end (mTLS over QUIC).
//!
//! ## Cloudflare Quick Tunnel
//! For instant public access without any configuration, BECAS integrates
//! Cloudflare's free "Quick Tunnel" feature. When a service starts,
//! a tunnel is automatically opened and a public URL is assigned.
//! See [`cloudflare`] module for details.

pub mod cloudflare;

use std::collections::HashMap;

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("Tunnel not found: {0}")]
    NotFound(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("NAT traversal failed: {0}")]
    NatTraversalFailed(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Tunnel already exists for service: {0}")]
    AlreadyExists(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TunnelError>;

// ─────────────────────────────────────────────
// Tunnel Configuration
// ─────────────────────────────────────────────

/// Configuration for creating a tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Service this tunnel belongs to
    pub service_id: Uuid,
    /// Local port to tunnel (inside sandbox)
    pub local_port: u16,
    /// Protocol
    pub protocol: TunnelProtocol,
    /// Relay server address (for NAT traversal fallback)
    pub relay_server: Option<String>,
    /// Enable direct peer-to-peer connections
    pub enable_p2p: bool,
    /// Maximum concurrent connections through tunnel
    pub max_connections: u32,
    /// Bandwidth limit in bytes/sec (0 = unlimited)
    pub bandwidth_limit_bps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TunnelProtocol {
    /// QUIC (preferred — fast, multiplexed, encrypted by default)
    Quic,
    /// TCP over TLS
    TcpTls,
    /// UDP (raw, for real-time applications)
    Udp,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            service_id: Uuid::nil(),
            local_port: 0,
            protocol: TunnelProtocol::Quic,
            relay_server: None,
            enable_p2p: true,
            max_connections: 100,
            bandwidth_limit_bps: 0,
        }
    }
}

// ─────────────────────────────────────────────
// Tunnel State
// ─────────────────────────────────────────────

/// Current state of a tunnel
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TunnelState {
    /// Created but not connected
    Created,
    /// Attempting NAT traversal
    Connecting,
    /// Connected via direct P2P
    ConnectedDirect,
    /// Connected via relay server
    ConnectedRelay,
    /// Connection lost, attempting reconnect
    Reconnecting,
    /// Closed
    Closed,
    /// Failed permanently
    Failed(String),
}

impl std::fmt::Display for TunnelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelState::Created => write!(f, "Created"),
            TunnelState::Connecting => write!(f, "Connecting"),
            TunnelState::ConnectedDirect => write!(f, "Connected (Direct P2P)"),
            TunnelState::ConnectedRelay => write!(f, "Connected (Relay)"),
            TunnelState::Reconnecting => write!(f, "Reconnecting"),
            TunnelState::Closed => write!(f, "Closed"),
            TunnelState::Failed(e) => write!(f, "Failed: {}", e),
        }
    }
}

// ─────────────────────────────────────────────
// Tunnel Instance
// ─────────────────────────────────────────────

/// A tunnel instance connecting a BECAS service to the outside world
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    /// Unique tunnel ID
    pub id: Uuid,
    /// Configuration
    pub config: TunnelConfig,
    /// Current state
    pub state: TunnelState,
    /// Public endpoint address (how clients reach this tunnel)
    pub public_addr: Option<String>,
    /// Number of active connections
    pub active_connections: u32,
    /// Total bytes transferred (in + out)
    pub bytes_transferred: u64,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last activity
    pub last_activity: DateTime<Utc>,
}

// ─────────────────────────────────────────────
// Tunnel Manager
// ─────────────────────────────────────────────

/// Manages all tunnels in the BECAS Layer
pub struct TunnelManager {
    /// Active tunnels indexed by ID
    tunnels: Arc<RwLock<HashMap<Uuid, Tunnel>>>,
    /// Service-to-tunnel mapping
    service_tunnels: Arc<RwLock<HashMap<Uuid, Vec<Uuid>>>>,
    /// Default relay server
    default_relay: Option<String>,
}

impl TunnelManager {
    /// Create a new tunnel manager
    pub fn new(default_relay: Option<String>) -> Self {
        Self {
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            service_tunnels: Arc::new(RwLock::new(HashMap::new())),
            default_relay,
        }
    }

    /// Create a new tunnel for a service
    pub async fn create(&self, mut config: TunnelConfig) -> Result<Uuid> {
        // Use default relay if none specified
        if config.relay_server.is_none() {
            config.relay_server = self.default_relay.clone();
        }

        let tunnel_id = Uuid::new_v4();
        let tunnel = Tunnel {
            id: tunnel_id,
            config: config.clone(),
            state: TunnelState::Created,
            public_addr: None,
            active_connections: 0,
            bytes_transferred: 0,
            created_at: Utc::now(),
            last_activity: Utc::now(),
        };

        self.tunnels.write().await.insert(tunnel_id, tunnel);
        self.service_tunnels.write().await
            .entry(config.service_id)
            .or_default()
            .push(tunnel_id);

        tracing::info!(
            tunnel_id = %tunnel_id,
            service_id = %config.service_id,
            port = config.local_port,
            protocol = ?config.protocol,
            "Tunnel created"
        );

        Ok(tunnel_id)
    }

    /// Open a tunnel (start accepting connections)
    pub async fn open(&self, tunnel_id: &Uuid) -> Result<String> {
        let mut tunnels = self.tunnels.write().await;
        let tunnel = tunnels.get_mut(tunnel_id)
            .ok_or_else(|| TunnelError::NotFound(tunnel_id.to_string()))?;

        tunnel.state = TunnelState::Connecting;

        // Step 1: Try STUN hole-punching for direct P2P
        if tunnel.config.enable_p2p {
            match self.attempt_stun_traversal(tunnel).await {
                Ok(addr) => {
                    tunnel.state = TunnelState::ConnectedDirect;
                    tunnel.public_addr = Some(addr.clone());
                    tracing::info!(tunnel_id = %tunnel_id, addr = %addr, "Direct P2P tunnel opened");
                    return Ok(addr);
                }
                Err(e) => {
                    tracing::debug!(tunnel_id = %tunnel_id, "P2P failed, falling back to relay: {}", e);
                }
            }
        }

        // Step 2: Fall back to relay server
        if let Some(ref relay) = tunnel.config.relay_server {
            let addr = format!("{}/tunnel/{}", relay, tunnel_id);
            tunnel.state = TunnelState::ConnectedRelay;
            tunnel.public_addr = Some(addr.clone());
            tracing::info!(tunnel_id = %tunnel_id, addr = %addr, "Relay tunnel opened");
            return Ok(addr);
        }

        tunnel.state = TunnelState::Failed("No relay server available".into());
        Err(TunnelError::NatTraversalFailed("Both P2P and relay failed".into()))
    }

    /// Close a tunnel
    pub async fn close(&self, tunnel_id: &Uuid) -> Result<()> {
        let mut tunnels = self.tunnels.write().await;
        let tunnel = tunnels.get_mut(tunnel_id)
            .ok_or_else(|| TunnelError::NotFound(tunnel_id.to_string()))?;

        tunnel.state = TunnelState::Closed;
        tunnel.public_addr = None;
        tunnel.active_connections = 0;

        tracing::info!(tunnel_id = %tunnel_id, "Tunnel closed");
        Ok(())
    }

    /// Get a tunnel by ID
    pub async fn get(&self, tunnel_id: &Uuid) -> Result<Tunnel> {
        self.tunnels.read().await
            .get(tunnel_id)
            .cloned()
            .ok_or_else(|| TunnelError::NotFound(tunnel_id.to_string()))
    }

    /// Get all tunnels for a service
    pub async fn service_tunnels(&self, service_id: &Uuid) -> Vec<Tunnel> {
        let tunnel_ids = self.service_tunnels.read().await
            .get(service_id)
            .cloned()
            .unwrap_or_default();

        let tunnels = self.tunnels.read().await;
        tunnel_ids.iter()
            .filter_map(|id| tunnels.get(id).cloned())
            .collect()
    }

    /// List all tunnels
    pub async fn list(&self) -> Vec<Tunnel> {
        self.tunnels.read().await.values().cloned().collect()
    }

    // ─── Internal ───

    /// Attempt STUN NAT traversal for direct P2P connection
    async fn attempt_stun_traversal(&self, _tunnel: &Tunnel) -> Result<String> {
        // TODO: Real STUN implementation
        // For now, this is a placeholder that simulates the attempt
        //
        // Real implementation would:
        // 1. Send STUN binding request to discover public IP:port
        // 2. Share discovered endpoint via signaling server
        // 3. Attempt hole-punching with remote peer
        // 4. If successful, return the public address

        Err(TunnelError::NatTraversalFailed(
            "STUN traversal not yet implemented — using relay".into()
        ))
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_tunnel() {
        let mgr = TunnelManager::new(Some("relay.becas.net".into()));
        let service_id = Uuid::new_v4();

        let config = TunnelConfig {
            service_id,
            local_port: 8080,
            protocol: TunnelProtocol::Quic,
            ..Default::default()
        };

        let id = mgr.create(config).await.unwrap();
        let tunnel = mgr.get(&id).await.unwrap();

        assert_eq!(tunnel.state, TunnelState::Created);
        assert_eq!(tunnel.config.local_port, 8080);
    }

    #[tokio::test]
    async fn test_open_tunnel_relay() {
        let mgr = TunnelManager::new(Some("relay.becas.net".into()));
        let service_id = Uuid::new_v4();

        let config = TunnelConfig {
            service_id,
            local_port: 5432,
            enable_p2p: false, // Force relay
            ..Default::default()
        };

        let id = mgr.create(config).await.unwrap();
        let addr = mgr.open(&id).await.unwrap();

        assert!(addr.contains("relay.becas.net"));

        let tunnel = mgr.get(&id).await.unwrap();
        assert_eq!(tunnel.state, TunnelState::ConnectedRelay);
    }

    #[tokio::test]
    async fn test_close_tunnel() {
        let mgr = TunnelManager::new(Some("relay.becas.net".into()));

        let config = TunnelConfig {
            service_id: Uuid::new_v4(),
            local_port: 8080,
            enable_p2p: false,
            ..Default::default()
        };

        let id = mgr.create(config).await.unwrap();
        mgr.open(&id).await.unwrap();
        mgr.close(&id).await.unwrap();

        let tunnel = mgr.get(&id).await.unwrap();
        assert_eq!(tunnel.state, TunnelState::Closed);
        assert!(tunnel.public_addr.is_none());
    }

    #[tokio::test]
    async fn test_service_tunnels() {
        let mgr = TunnelManager::new(None);
        let service_id = Uuid::new_v4();

        mgr.create(TunnelConfig {
            service_id, local_port: 8080, ..Default::default()
        }).await.unwrap();

        mgr.create(TunnelConfig {
            service_id, local_port: 5432, ..Default::default()
        }).await.unwrap();

        let tunnels = mgr.service_tunnels(&service_id).await;
        assert_eq!(tunnels.len(), 2);
    }
}
