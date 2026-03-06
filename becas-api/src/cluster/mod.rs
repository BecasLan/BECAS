//! BECAS Cluster — Multi-PC peer discovery & state replication
//!
//! Allows multiple BECAS nodes to form a trust network:
//! - Peer discovery via mDNS or manual registration
//! - Service state replication across nodes
//! - Failover: if PC-A goes down, PC-B can serve

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// A peer node in the BECAS cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNode {
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub status: PeerStatus,
    pub services: Vec<String>,
    pub cpu_available: f32,
    pub ram_available_mb: u64,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    pub trust_level: TrustLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeerStatus {
    Online,
    Offline,
    Syncing,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustLevel {
    /// Manually approved, full access
    Trusted,
    /// Auto-discovered, limited access
    Verified,
    /// Unknown, read-only
    Unknown,
}

/// Cluster manager — handles peer discovery and coordination
pub struct ClusterManager {
    node_id: Uuid,
    node_name: String,
    peers: Arc<RwLock<HashMap<Uuid, PeerNode>>>,
    #[allow(dead_code)]
    port: u16,
}

impl ClusterManager {
    pub fn new(node_name: &str, port: u16) -> Self {
        Self {
            node_id: Uuid::new_v4(),
            node_name: node_name.to_string(),
            peers: Arc::new(RwLock::new(HashMap::new())),
            port,
        }
    }

    /// Get our node ID
    pub fn node_id(&self) -> Uuid {
        self.node_id
    }

    /// Register a peer manually
    pub async fn add_peer(&self, address: &str, port: u16, name: &str) -> Uuid {
        let peer_id = Uuid::new_v4();
        let peer = PeerNode {
            id: peer_id,
            name: name.to_string(),
            address: address.to_string(),
            port,
            status: PeerStatus::Online,
            services: Vec::new(),
            cpu_available: 0.0,
            ram_available_mb: 0,
            last_heartbeat: chrono::Utc::now(),
            trust_level: TrustLevel::Unknown,
        };
        self.peers.write().await.insert(peer_id, peer);
        tracing::info!(peer_id = %peer_id, name = name, "Peer added to cluster");
        peer_id
    }

    /// Update peer trust level
    pub async fn set_trust(&self, peer_id: &Uuid, level: TrustLevel) -> bool {
        if let Some(peer) = self.peers.write().await.get_mut(peer_id) {
            peer.trust_level = level;
            true
        } else {
            false
        }
    }

    /// Record a heartbeat from a peer
    pub async fn heartbeat(&self, peer_id: &Uuid, cpu: f32, ram_mb: u64, services: Vec<String>) -> bool {
        if let Some(peer) = self.peers.write().await.get_mut(peer_id) {
            peer.last_heartbeat = chrono::Utc::now();
            peer.status = PeerStatus::Online;
            peer.cpu_available = cpu;
            peer.ram_available_mb = ram_mb;
            peer.services = services;
            true
        } else {
            false
        }
    }

    /// Check for stale peers and mark them offline
    pub async fn check_health(&self, timeout_secs: i64) {
        let now = chrono::Utc::now();
        let mut peers = self.peers.write().await;
        for peer in peers.values_mut() {
            let elapsed = (now - peer.last_heartbeat).num_seconds();
            if elapsed > timeout_secs && peer.status == PeerStatus::Online {
                peer.status = PeerStatus::Offline;
                tracing::warn!(peer = %peer.name, elapsed = elapsed, "Peer went offline");
            }
        }
    }

    /// List all peers
    pub async fn list_peers(&self) -> Vec<PeerNode> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Get online peers sorted by available resources
    pub async fn available_peers(&self) -> Vec<PeerNode> {
        let peers = self.peers.read().await;
        let mut available: Vec<_> = peers.values()
            .filter(|p| p.status == PeerStatus::Online && p.trust_level != TrustLevel::Unknown)
            .cloned()
            .collect();
        available.sort_by(|a, b| b.ram_available_mb.cmp(&a.ram_available_mb));
        available
    }

    /// Find the best peer to failover a service to
    pub async fn find_failover_peer(&self, service_name: &str) -> Option<PeerNode> {
        let peers = self.available_peers().await;
        // Prefer peers that already have the service replicated
        if let Some(peer) = peers.iter().find(|p| p.services.contains(&service_name.to_string())) {
            return Some(peer.clone());
        }
        // Otherwise, pick the peer with most resources
        peers.into_iter().next()
    }

    /// Get cluster summary
    pub async fn summary(&self) -> ClusterSummary {
        let peers = self.peers.read().await;
        let online = peers.values().filter(|p| p.status == PeerStatus::Online).count();
        let total_services: usize = peers.values().map(|p| p.services.len()).sum();
        let total_ram: u64 = peers.values()
            .filter(|p| p.status == PeerStatus::Online)
            .map(|p| p.ram_available_mb)
            .sum();
        ClusterSummary {
            node_id: self.node_id,
            node_name: self.node_name.clone(),
            total_peers: peers.len(),
            online_peers: online,
            total_services_across_cluster: total_services,
            total_available_ram_mb: total_ram,
        }
    }
}

#[derive(Serialize)]
pub struct ClusterSummary {
    pub node_id: Uuid,
    pub node_name: String,
    pub total_peers: usize,
    pub online_peers: usize,
    pub total_services_across_cluster: usize,
    pub total_available_ram_mb: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cluster_add_peer() {
        let cm = ClusterManager::new("my-pc", 7700);
        let id = cm.add_peer("192.168.1.100", 7700, "friend-pc").await;
        let peers = cm.list_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "friend-pc");
        assert_eq!(peers[0].trust_level, TrustLevel::Unknown);

        cm.set_trust(&id, TrustLevel::Trusted).await;
        let peers = cm.list_peers().await;
        assert_eq!(peers[0].trust_level, TrustLevel::Trusted);
    }

    #[tokio::test]
    async fn test_cluster_heartbeat() {
        let cm = ClusterManager::new("my-pc", 7700);
        let id = cm.add_peer("10.0.0.5", 7700, "server-2").await;
        cm.set_trust(&id, TrustLevel::Verified).await;

        cm.heartbeat(&id, 25.0, 4096, vec!["api".into(), "db".into()]).await;
        let peers = cm.list_peers().await;
        assert_eq!(peers[0].cpu_available, 25.0);
        assert_eq!(peers[0].ram_available_mb, 4096);
        assert_eq!(peers[0].services.len(), 2);
    }

    #[tokio::test]
    async fn test_cluster_health_check() {
        let cm = ClusterManager::new("my-pc", 7700);
        let id = cm.add_peer("10.0.0.5", 7700, "old-pc").await;

        // Manually set last heartbeat to 2 minutes ago
        {
            let mut peers = cm.peers.write().await;
            let peer = peers.get_mut(&id).unwrap();
            peer.last_heartbeat = chrono::Utc::now() - chrono::Duration::seconds(120);
        }

        cm.check_health(60).await;
        let peers = cm.list_peers().await;
        assert_eq!(peers[0].status, PeerStatus::Offline);
    }

    #[tokio::test]
    async fn test_cluster_failover() {
        let cm = ClusterManager::new("my-pc", 7700);
        let id1 = cm.add_peer("10.0.0.1", 7700, "node-1").await;
        let id2 = cm.add_peer("10.0.0.2", 7700, "node-2").await;

        cm.set_trust(&id1, TrustLevel::Trusted).await;
        cm.set_trust(&id2, TrustLevel::Trusted).await;

        cm.heartbeat(&id1, 50.0, 2048, vec!["api".into()]).await;
        cm.heartbeat(&id2, 30.0, 8192, vec!["db".into(), "api".into()]).await;

        // Failover "api" should prefer node-2 (already has it)
        let failover = cm.find_failover_peer("api").await;
        assert!(failover.is_some());

        // Failover "web" should pick node with most RAM (node-2)
        let failover = cm.find_failover_peer("web").await;
        assert!(failover.is_some());
        assert_eq!(failover.unwrap().name, "node-2");
    }

    #[tokio::test]
    async fn test_cluster_summary() {
        let cm = ClusterManager::new("my-pc", 7700);
        let id = cm.add_peer("10.0.0.1", 7700, "friend").await;
        cm.set_trust(&id, TrustLevel::Trusted).await;
        cm.heartbeat(&id, 40.0, 4096, vec!["db".into()]).await;

        let summary = cm.summary().await;
        assert_eq!(summary.total_peers, 1);
        assert_eq!(summary.online_peers, 1);
        assert_eq!(summary.total_services_across_cluster, 1);
        assert_eq!(summary.total_available_ram_mb, 4096);
    }
}
