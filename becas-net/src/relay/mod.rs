//! # BECAS Relay Server
//!
//! A lightweight relay that sits between external clients and BECAS services.
//! When direct NAT traversal fails, traffic is relayed through this server.
//! Can run on a cheap VPS ($3/mo) or on another BECAS node in the trust circle.

use std::collections::HashMap;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Relay server error types
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Service not registered: {0}")]
    ServiceNotFound(String),
    #[error("Relay capacity exceeded")]
    CapacityExceeded,
    #[error("Connection timeout")]
    Timeout,
}

type Result<T> = std::result::Result<T, RelayError>;

/// Registration of a BECAS node's service on the relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRegistration {
    /// Unique service ID
    pub service_id: Uuid,
    /// Human-readable service name
    pub service_name: String,
    /// Node identity (public key fingerprint)
    pub node_id: String,
    /// The port the service listens on locally
    pub local_port: u16,
    /// When this registration was created
    pub registered_at: chrono::DateTime<chrono::Utc>,
    /// Number of active connections
    pub active_connections: u32,
    /// Max allowed connections
    pub max_connections: u32,
}

/// Relay server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Address to listen on
    pub listen_addr: SocketAddr,
    /// Control port for registrations
    pub control_port: u16,
    /// Max total connections across all services
    pub max_total_connections: u32,
    /// Max connections per service
    pub max_per_service: u32,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:4433".parse().unwrap(),
            control_port: 4434,
            max_total_connections: 1000,
            max_per_service: 100,
            timeout_secs: 300,
        }
    }
}

/// Connected BECAS node with its back-channel
struct ConnectedNode {
    registration: ServiceRegistration,
    /// Address of the connected node
    node_addr: SocketAddr,
}

/// The relay server that brokers connections
pub struct RelayServer {
    config: RelayConfig,
    /// Registered services: subdomain/name -> node info
    services: Arc<RwLock<HashMap<String, ConnectedNode>>>,
    /// Total active connections
    active_connections: Arc<RwLock<u32>>,
}

impl RelayServer {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            services: Arc::new(RwLock::new(HashMap::new())),
            active_connections: Arc::new(RwLock::new(0)),
        }
    }

    /// Start the relay server (control plane + data plane)
    pub async fn start(&self) -> Result<()> {
        let control_listener = TcpListener::bind(
            format!("0.0.0.0:{}", self.config.control_port)
        ).await?;

        let data_listener = TcpListener::bind(&self.config.listen_addr).await?;

        tracing::info!(
            control_port = self.config.control_port,
            data_addr = %self.config.listen_addr,
            "BECAS Relay Server started"
        );

        let services = self.services.clone();
        let active = self.active_connections.clone();
        let max_total = self.config.max_total_connections;
        let max_per = self.config.max_per_service;
        let timeout = self.config.timeout_secs;

        // Spawn control plane handler
        let ctrl_services = services.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, addr)) = control_listener.accept().await {
                    let svc = ctrl_services.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_control(stream, addr, svc).await {
                            tracing::warn!(error = %e, "Control connection error");
                        }
                    });
                }
            }
        });

        // Data plane — accept client connections and relay
        loop {
            let (stream, addr) = data_listener.accept().await?;
            let svc = services.clone();
            let act = active.clone();

            // Check total capacity
            {
                let count = act.read().await;
                if *count >= max_total {
                    tracing::warn!("Relay capacity exceeded, rejecting connection");
                    continue;
                }
            }

            tokio::spawn(async move {
                *act.write().await += 1;
                if let Err(e) = handle_data_connection(stream, addr, svc, max_per, timeout).await {
                    tracing::debug!(error = %e, addr = %addr, "Data connection ended");
                }
                *act.write().await -= 1;
            });
        }
    }

    /// Register a service on the relay
    pub async fn register_service(&self, reg: ServiceRegistration, addr: SocketAddr) {
        let key = reg.service_name.clone();
        tracing::info!(name = %key, node = %reg.node_id, "Service registered on relay");
        self.services.write().await.insert(key, ConnectedNode {
            registration: reg,
            node_addr: addr,
        });
    }

    /// Get list of registered services
    pub async fn list_services(&self) -> Vec<ServiceRegistration> {
        self.services.read().await
            .values()
            .map(|n| n.registration.clone())
            .collect()
    }
}

/// Handle a control connection (service registration)
async fn handle_control(
    mut stream: TcpStream,
    addr: SocketAddr,
    services: Arc<RwLock<HashMap<String, ConnectedNode>>>,
) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 { return Ok(()); }

    // Parse registration JSON
    if let Ok(reg) = serde_json::from_slice::<ServiceRegistration>(&buf[..n]) {
        let key = reg.service_name.clone();
        tracing::info!(name = %key, node_id = %reg.node_id, addr = %addr, "Service registered");
        services.write().await.insert(key.clone(), ConnectedNode {
            registration: reg,
            node_addr: addr,
        });
        let resp = serde_json::json!({"status": "registered", "name": key});
        stream.write_all(resp.to_string().as_bytes()).await?;
    } else {
        let resp = serde_json::json!({"error": "invalid registration"});
        stream.write_all(resp.to_string().as_bytes()).await?;
    }
    Ok(())
}

/// Handle a data connection — peek at first bytes to determine target service
async fn handle_data_connection(
    mut client: TcpStream,
    addr: SocketAddr,
    services: Arc<RwLock<HashMap<String, ConnectedNode>>>,
    max_per_service: u32,
    _timeout_secs: u64,
) -> Result<()> {
    // Read initial request to determine target service
    let mut header_buf = vec![0u8; 8192];
    let n = client.read(&mut header_buf).await?;
    if n == 0 { return Ok(()); }

    // Try to extract Host header from HTTP request
    let request = String::from_utf8_lossy(&header_buf[..n]);
    let service_name = extract_service_name(&request);

    let node_addr = {
        let svcs = services.read().await;
        let node = svcs.get(&service_name)
            .ok_or_else(|| RelayError::ServiceNotFound(service_name.clone()))?;

        if node.registration.active_connections >= max_per_service {
            return Err(RelayError::CapacityExceeded);
        }
        node.node_addr
    };

    tracing::debug!(
        service = %service_name,
        client = %addr,
        target = %node_addr,
        "Relaying connection"
    );

    // Connect to the BECAS node's service
    let mut backend = TcpStream::connect(node_addr).await
        .map_err(|_| RelayError::ServiceNotFound(service_name.clone()))?;

    // Forward the initial request data
    backend.write_all(&header_buf[..n]).await?;

    // Bidirectional relay
    let (mut cr, mut cw) = client.into_split();
    let (mut br, mut bw) = backend.into_split();

    let c2b = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => { if bw.write_all(&buf[..n]).await.is_err() { break; } }
            }
        }
    });

    let b2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => { if cw.write_all(&buf[..n]).await.is_err() { break; } }
            }
        }
    });

    let _ = tokio::join!(c2b, b2c);
    Ok(())
}

/// Extract service name from HTTP Host header or first line
fn extract_service_name(request: &str) -> String {
    // Try Host header: "Host: myservice.becas.local"
    for line in request.lines() {
        if let Some(host) = line.strip_prefix("Host: ").or_else(|| line.strip_prefix("host: ")) {
            let host = host.trim();
            // Extract subdomain: "myservice.becas.local" -> "myservice"
            if let Some(name) = host.split('.').next() {
                return name.to_string();
            }
            return host.to_string();
        }
    }

    // Fallback: use "default"
    "default".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_service_name_from_host() {
        let req = "GET / HTTP/1.1\r\nHost: becasdb.becas.local\r\n\r\n";
        assert_eq!(extract_service_name(req), "becasdb");
    }

    #[test]
    fn test_extract_service_name_no_host() {
        let req = "GET / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_service_name(req), "default");
    }

    #[test]
    fn test_relay_config_default() {
        let config = RelayConfig::default();
        assert_eq!(config.control_port, 4434);
        assert_eq!(config.max_total_connections, 1000);
        assert_eq!(config.max_per_service, 100);
    }

    #[test]
    fn test_service_registration_serialize() {
        let reg = ServiceRegistration {
            service_id: Uuid::new_v4(),
            service_name: "test-api".into(),
            node_id: "abc123".into(),
            local_port: 8080,
            registered_at: chrono::Utc::now(),
            active_connections: 0,
            max_connections: 100,
        };
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: ServiceRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.service_name, "test-api");
        assert_eq!(parsed.local_port, 8080);
    }

    #[tokio::test]
    async fn test_relay_server_register() {
        let server = RelayServer::new(RelayConfig::default());
        let reg = ServiceRegistration {
            service_id: Uuid::new_v4(),
            service_name: "my-db".into(),
            node_id: "node1".into(),
            local_port: 5432,
            registered_at: chrono::Utc::now(),
            active_connections: 0,
            max_connections: 50,
        };
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        server.register_service(reg, addr).await;
        let services = server.list_services().await;
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service_name, "my-db");
    }
}
