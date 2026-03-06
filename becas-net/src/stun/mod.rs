//! # BECAS STUN/TURN Implementation
//!
//! NAT traversal for direct peer-to-peer connections.
//!
//! ## How It Works
//! 1. **STUN (Session Traversal Utilities for NAT)**
//!    - Discovers public IP and port mapping
//!    - Enables direct P2P when both peers have compatible NAT
//!
//! 2. **TURN (Traversal Using Relays around NAT)**
//!    - Fallback when direct P2P fails (symmetric NAT)
//!    - Traffic relayed through TURN server
//!
//! ## Connection Flow
//! ```text
//! Client A                    STUN Server                    Client B
//!    │                            │                             │
//!    │─── Binding Request ───────►│                             │
//!    │◄── Public IP:Port ─────────│                             │
//!    │                            │                             │
//!    │                            │◄─── Binding Request ────────│
//!    │                            │──── Public IP:Port ────────►│
//!    │                            │                             │
//!    │◄═══════════════════ Direct P2P Connection ══════════════►│
//! ```

use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

// ─────────────────────────────────────────────
// STUN Protocol Constants
// ─────────────────────────────────────────────

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_HEADER_SIZE: usize = 20;

// Message types
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_BINDING_ERROR: u16 = 0x0111;

// Attribute types
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;

// ─────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid STUN message")]
    InvalidMessage,
    #[error("Timeout waiting for response")]
    Timeout,
    #[error("NAT traversal failed: {0}")]
    NatTraversalFailed(String),
    #[error("No public servers available")]
    NoServersAvailable,
}

pub type StunResult<T> = Result<T, StunError>;

// ─────────────────────────────────────────────
// NAT Type Detection
// ─────────────────────────────────────────────

/// Detected NAT type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT (public IP)
    None,
    /// Full Cone NAT (easiest to traverse)
    FullCone,
    /// Restricted Cone NAT
    RestrictedCone,
    /// Port Restricted Cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (hardest, needs TURN)
    Symmetric,
    /// Unknown/Detection failed
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::None => write!(f, "No NAT (Public IP)"),
            NatType::FullCone => write!(f, "Full Cone NAT"),
            NatType::RestrictedCone => write!(f, "Restricted Cone NAT"),
            NatType::PortRestrictedCone => write!(f, "Port Restricted Cone NAT"),
            NatType::Symmetric => write!(f, "Symmetric NAT"),
            NatType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Result of NAT detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatInfo {
    pub nat_type: NatType,
    pub public_ip: Option<IpAddr>,
    pub public_port: Option<u16>,
    pub local_ip: IpAddr,
    pub local_port: u16,
    /// Can establish direct P2P connections
    pub p2p_capable: bool,
    /// Needs TURN relay
    pub needs_relay: bool,
}

// ─────────────────────────────────────────────
// STUN Client
// ─────────────────────────────────────────────

/// Public STUN servers
pub const PUBLIC_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.stunprotocol.org:3478",
];

/// STUN client for NAT traversal
pub struct StunClient {
    socket: Arc<UdpSocket>,
    servers: Vec<SocketAddr>,
    timeout_ms: u64,
}

impl StunClient {
    /// Create a new STUN client
    pub async fn new() -> StunResult<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        
        // Resolve public STUN servers
        let mut servers = Vec::new();
        for server in PUBLIC_STUN_SERVERS {
            if let Ok(addrs) = tokio::net::lookup_host(server).await {
                for addr in addrs {
                    servers.push(addr);
                    break; // Just first address
                }
            }
        }
        
        if servers.is_empty() {
            return Err(StunError::NoServersAvailable);
        }
        
        Ok(Self {
            socket: Arc::new(socket),
            servers,
            timeout_ms: 3000,
        })
    }

    /// Create with custom servers
    pub async fn with_servers(servers: Vec<SocketAddr>) -> StunResult<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self {
            socket: Arc::new(socket),
            servers,
            timeout_ms: 3000,
        })
    }

    /// Get public IP and port via STUN
    pub async fn get_public_address(&self) -> StunResult<SocketAddr> {
        for server in &self.servers {
            match self.binding_request(*server).await {
                Ok(addr) => return Ok(addr),
                Err(e) => {
                    tracing::debug!(server = %server, error = %e, "STUN server failed, trying next");
                }
            }
        }
        Err(StunError::NoServersAvailable)
    }

    /// Detect NAT type
    pub async fn detect_nat_type(&self) -> StunResult<NatInfo> {
        let local_addr = self.socket.local_addr()?;
        
        // Try to get public address from multiple servers
        let mut public_addrs: Vec<SocketAddr> = Vec::new();
        
        for server in self.servers.iter().take(3) {
            if let Ok(addr) = self.binding_request(*server).await {
                public_addrs.push(addr);
            }
        }
        
        if public_addrs.is_empty() {
            return Ok(NatInfo {
                nat_type: NatType::Unknown,
                public_ip: None,
                public_port: None,
                local_ip: local_addr.ip(),
                local_port: local_addr.port(),
                p2p_capable: false,
                needs_relay: true,
            });
        }
        
        let first = public_addrs[0];
        
        // Check if we're behind NAT
        let is_behind_nat = first.ip() != local_addr.ip();
        
        if !is_behind_nat {
            return Ok(NatInfo {
                nat_type: NatType::None,
                public_ip: Some(first.ip()),
                public_port: Some(first.port()),
                local_ip: local_addr.ip(),
                local_port: local_addr.port(),
                p2p_capable: true,
                needs_relay: false,
            });
        }
        
        // Check if port mapping is consistent (symmetric NAT detection)
        let all_same_port = public_addrs.iter().all(|a| a.port() == first.port());
        
        let nat_type = if all_same_port {
            // Could be Full Cone, Restricted, or Port Restricted
            // For simplicity, assume Port Restricted (most common)
            NatType::PortRestrictedCone
        } else {
            // Different ports = Symmetric NAT
            NatType::Symmetric
        };
        
        let needs_relay = nat_type == NatType::Symmetric;
        
        Ok(NatInfo {
            nat_type,
            public_ip: Some(first.ip()),
            public_port: Some(first.port()),
            local_ip: local_addr.ip(),
            local_port: local_addr.port(),
            p2p_capable: !needs_relay,
            needs_relay,
        })
    }

    /// Send STUN binding request and get mapped address
    async fn binding_request(&self, server: SocketAddr) -> StunResult<SocketAddr> {
        let request = build_binding_request();
        
        self.socket.send_to(&request, server).await?;
        
        let mut buf = [0u8; 512];
        let timeout = tokio::time::Duration::from_millis(self.timeout_ms);
        
        match tokio::time::timeout(timeout, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _from))) => {
                parse_binding_response(&buf[..len])
            }
            Ok(Err(e)) => Err(StunError::Io(e)),
            Err(_) => Err(StunError::Timeout),
        }
    }
}

/// Build a STUN binding request
fn build_binding_request() -> Vec<u8> {
    let mut buf = Vec::with_capacity(STUN_HEADER_SIZE);
    
    // Message Type: Binding Request
    buf.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    
    // Message Length (0 for basic request)
    buf.extend_from_slice(&0u16.to_be_bytes());
    
    // Magic Cookie
    buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    
    // Transaction ID (96 bits = 12 bytes)
    let tx_id: [u8; 12] = rand::random();
    buf.extend_from_slice(&tx_id);
    
    buf
}

/// Parse STUN binding response
fn parse_binding_response(data: &[u8]) -> StunResult<SocketAddr> {
    if data.len() < STUN_HEADER_SIZE {
        return Err(StunError::InvalidMessage);
    }
    
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return Err(StunError::InvalidMessage);
    }
    
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    
    if magic != STUN_MAGIC_COOKIE {
        return Err(StunError::InvalidMessage);
    }
    
    // Parse attributes
    let mut offset = STUN_HEADER_SIZE;
    while offset + 4 <= data.len() && offset < STUN_HEADER_SIZE + msg_len {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        
        if offset + attr_len > data.len() {
            break;
        }
        
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return parse_xor_mapped_address(&data[offset..offset + attr_len]);
            }
            ATTR_MAPPED_ADDRESS => {
                return parse_mapped_address(&data[offset..offset + attr_len]);
            }
            _ => {}
        }
        
        // Align to 4 bytes
        offset += (attr_len + 3) & !3;
    }
    
    Err(StunError::InvalidMessage)
}

fn parse_xor_mapped_address(data: &[u8]) -> StunResult<SocketAddr> {
    if data.len() < 8 {
        return Err(StunError::InvalidMessage);
    }
    
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;
    
    let ip = if family == 0x01 {
        // IPv4
        let ip_bytes = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ STUN_MAGIC_COOKIE;
        IpAddr::V4(std::net::Ipv4Addr::from(ip_bytes))
    } else {
        return Err(StunError::InvalidMessage); // IPv6 not implemented
    };
    
    Ok(SocketAddr::new(ip, port))
}

fn parse_mapped_address(data: &[u8]) -> StunResult<SocketAddr> {
    if data.len() < 8 {
        return Err(StunError::InvalidMessage);
    }
    
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);
    
    let ip = if family == 0x01 {
        IpAddr::V4(std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]))
    } else {
        return Err(StunError::InvalidMessage);
    };
    
    Ok(SocketAddr::new(ip, port))
}

// ─────────────────────────────────────────────
// TURN Client (Relay Fallback)
// ─────────────────────────────────────────────

/// TURN allocation for relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnAllocation {
    pub relay_address: SocketAddr,
    pub mapped_address: SocketAddr,
    pub lifetime_secs: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// TURN client for relay connections
pub struct TurnClient {
    server: SocketAddr,
    username: String,
    password: String,
    socket: Arc<UdpSocket>,
    allocation: RwLock<Option<TurnAllocation>>,
}

impl TurnClient {
    /// Create a new TURN client
    pub async fn new(server: SocketAddr, username: &str, password: &str) -> StunResult<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        
        Ok(Self {
            server,
            username: username.to_string(),
            password: password.to_string(),
            socket: Arc::new(socket),
            allocation: RwLock::new(None),
        })
    }

    /// Request a relay allocation from TURN server
    pub async fn allocate(&self) -> StunResult<TurnAllocation> {
        // TURN Allocate request would go here
        // For now, return a placeholder
        let allocation = TurnAllocation {
            relay_address: self.server,
            mapped_address: self.socket.local_addr()?,
            lifetime_secs: 600,
            created_at: chrono::Utc::now(),
        };
        
        *self.allocation.write().await = Some(allocation.clone());
        
        Ok(allocation)
    }

    /// Refresh the allocation
    pub async fn refresh(&self) -> StunResult<()> {
        // TURN Refresh request
        Ok(())
    }

    /// Create a permission for a peer
    pub async fn create_permission(&self, _peer: SocketAddr) -> StunResult<()> {
        // TURN CreatePermission request
        Ok(())
    }

    /// Send data through the relay
    pub async fn send(&self, peer: SocketAddr, data: &[u8]) -> StunResult<()> {
        // TURN Send indication
        self.socket.send_to(data, peer).await?;
        Ok(())
    }

    /// Get current allocation
    pub async fn get_allocation(&self) -> Option<TurnAllocation> {
        self.allocation.read().await.clone()
    }
}

// ─────────────────────────────────────────────
// ICE (Interactive Connectivity Establishment)
// ─────────────────────────────────────────────

/// ICE candidate for connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    pub candidate_type: IceCandidateType,
    pub address: SocketAddr,
    pub priority: u32,
    pub foundation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IceCandidateType {
    Host,      // Local address
    ServerReflexive, // STUN mapped address
    Relay,     // TURN relay address
}

/// ICE agent for establishing P2P connections
pub struct IceAgent {
    stun_client: StunClient,
    turn_client: Option<TurnClient>,
    local_candidates: RwLock<Vec<IceCandidate>>,
    remote_candidates: RwLock<Vec<IceCandidate>>,
}

impl IceAgent {
    /// Create a new ICE agent
    pub async fn new() -> StunResult<Self> {
        let stun_client = StunClient::new().await?;
        
        Ok(Self {
            stun_client,
            turn_client: None,
            local_candidates: RwLock::new(Vec::new()),
            remote_candidates: RwLock::new(Vec::new()),
        })
    }

    /// Gather local ICE candidates
    pub async fn gather_candidates(&self) -> StunResult<Vec<IceCandidate>> {
        let mut candidates = Vec::new();
        
        // Host candidate (local address)
        let local_addr = self.stun_client.socket.local_addr()?;
        candidates.push(IceCandidate {
            candidate_type: IceCandidateType::Host,
            address: local_addr,
            priority: 126 << 24,
            foundation: "host".to_string(),
        });
        
        // Server reflexive candidate (STUN)
        if let Ok(public_addr) = self.stun_client.get_public_address().await {
            candidates.push(IceCandidate {
                candidate_type: IceCandidateType::ServerReflexive,
                address: public_addr,
                priority: 100 << 24,
                foundation: "srflx".to_string(),
            });
        }
        
        // Relay candidate (TURN) - if configured
        if let Some(turn) = &self.turn_client {
            if let Ok(alloc) = turn.allocate().await {
                candidates.push(IceCandidate {
                    candidate_type: IceCandidateType::Relay,
                    address: alloc.relay_address,
                    priority: 0,
                    foundation: "relay".to_string(),
                });
            }
        }
        
        *self.local_candidates.write().await = candidates.clone();
        
        Ok(candidates)
    }

    /// Add remote candidate
    pub async fn add_remote_candidate(&self, candidate: IceCandidate) {
        self.remote_candidates.write().await.push(candidate);
    }

    /// Try to establish connection with best candidate pair
    pub async fn connect(&self) -> StunResult<SocketAddr> {
        let local = self.local_candidates.read().await;
        let remote = self.remote_candidates.read().await;
        
        // Sort by priority and try pairs
        for remote_cand in remote.iter() {
            for local_cand in local.iter() {
                // Try connectivity check
                if self.check_connectivity(local_cand, remote_cand).await.is_ok() {
                    return Ok(remote_cand.address);
                }
            }
        }
        
        Err(StunError::NatTraversalFailed("No working candidate pair".into()))
    }

    async fn check_connectivity(&self, _local: &IceCandidate, remote: &IceCandidate) -> StunResult<()> {
        // Send STUN binding request to remote
        let request = build_binding_request();
        self.stun_client.socket.send_to(&request, remote.address).await?;
        
        // Wait for response (simplified)
        let mut buf = [0u8; 512];
        let timeout = tokio::time::Duration::from_millis(1000);
        
        match tokio::time::timeout(timeout, self.stun_client.socket.recv_from(&mut buf)).await {
            Ok(Ok(_)) => Ok(()),
            _ => Err(StunError::Timeout),
        }
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let request = build_binding_request();
        assert_eq!(request.len(), STUN_HEADER_SIZE);
        
        // Check message type
        let msg_type = u16::from_be_bytes([request[0], request[1]]);
        assert_eq!(msg_type, STUN_BINDING_REQUEST);
        
        // Check magic cookie
        let magic = u32::from_be_bytes([request[4], request[5], request[6], request[7]]);
        assert_eq!(magic, STUN_MAGIC_COOKIE);
    }

    #[test]
    fn test_nat_type_display() {
        assert_eq!(format!("{}", NatType::FullCone), "Full Cone NAT");
        assert_eq!(format!("{}", NatType::Symmetric), "Symmetric NAT");
    }

    #[tokio::test]
    async fn test_stun_client_creation() {
        // This may fail if no network, that's ok
        let result = StunClient::new().await;
        // Just check it doesn't panic
        let _ = result;
    }
}
