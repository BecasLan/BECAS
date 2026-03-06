//! # BECAS Reverse Proxy
//!
//! TCP reverse proxy that sits in front of sandbox services.
//! Routes external traffic to the correct sandbox service port,
//! integrating with SecurityGateway for rate limiting and access control.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Proxy not found: {0}")]
    NotFound(String),

    #[error("Port already in use: {0}")]
    PortInUse(u16),

    #[error("Backend unreachable: {0}")]
    BackendUnreachable(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ProxyError>;

/// Configuration for a proxy route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRoute {
    /// Unique route ID
    pub id: Uuid,
    /// Service this route belongs to
    pub service_id: Uuid,
    /// Public-facing listen port
    pub listen_port: u16,
    /// Backend address (sandbox service)
    pub backend_addr: SocketAddr,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Active connection count
    pub active_connections: u32,
    /// Total bytes forwarded
    pub bytes_forwarded: u64,
    /// Total connections served
    pub total_connections: u64,
}

/// Stats for a proxy route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStats {
    pub route_id: Uuid,
    pub active_connections: u32,
    pub total_connections: u64,
    pub bytes_forwarded: u64,
}

/// Reverse proxy manager — integrates with SecurityGateway for real protection
pub struct ReverseProxy {
    /// Active routes
    routes: Arc<RwLock<HashMap<Uuid, ProxyRoute>>>,
    /// Port -> Route ID mapping
    port_map: Arc<RwLock<HashMap<u16, Uuid>>>,
    /// Active connection counters
    connection_counts: Arc<RwLock<HashMap<Uuid, u32>>>,
    /// Shutdown signals per route
    shutdown_signals: Arc<RwLock<HashMap<Uuid, tokio::sync::watch::Sender<bool>>>>,
    /// Security gateway for request filtering (rate limit, IP block, DDoS protection)
    gateway: Option<Arc<becas_core::gateway::SecurityGateway>>,
}

impl ReverseProxy {
    /// Create a new reverse proxy (no security gateway — for backward compat)
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            port_map: Arc::new(RwLock::new(HashMap::new())),
            connection_counts: Arc::new(RwLock::new(HashMap::new())),
            shutdown_signals: Arc::new(RwLock::new(HashMap::new())),
            gateway: None,
        }
    }

    /// Create a new reverse proxy WITH SecurityGateway protection
    /// All traffic passes through gateway.check_request() before reaching the app
    pub fn with_gateway(gateway: Arc<becas_core::gateway::SecurityGateway>) -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            port_map: Arc::new(RwLock::new(HashMap::new())),
            connection_counts: Arc::new(RwLock::new(HashMap::new())),
            shutdown_signals: Arc::new(RwLock::new(HashMap::new())),
            gateway: Some(gateway),
        }
    }

    /// Add a new proxy route and start listening
    pub async fn add_route(
        &self,
        service_id: Uuid,
        listen_port: u16,
        backend_addr: SocketAddr,
        max_connections: u32,
    ) -> Result<Uuid> {
        // Check port availability
        if self.port_map.read().await.contains_key(&listen_port) {
            return Err(ProxyError::PortInUse(listen_port));
        }

        let route_id = Uuid::new_v4();
        let route = ProxyRoute {
            id: route_id,
            service_id,
            listen_port,
            backend_addr,
            max_connections,
            active_connections: 0,
            bytes_forwarded: 0,
            total_connections: 0,
        };

        self.routes.write().await.insert(route_id, route);
        self.port_map.write().await.insert(listen_port, route_id);
        self.connection_counts.write().await.insert(route_id, 0);

        // Create shutdown signal
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_signals.write().await.insert(route_id, shutdown_tx);

        // Start listener task
        let routes = self.routes.clone();
        let conn_counts = self.connection_counts.clone();
        let gateway = self.gateway.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::run_listener(
                route_id,
                service_id,
                listen_port,
                backend_addr,
                max_connections,
                routes,
                conn_counts,
                shutdown_rx,
                gateway,
            ).await {
                tracing::error!(route_id = %route_id, error = %e, "Proxy listener failed");
            }
        });

        tracing::info!(
            route_id = %route_id,
            listen_port = listen_port,
            backend = %backend_addr,
            "Proxy route added"
        );

        Ok(route_id)
    }

    /// Remove a proxy route and stop listening
    pub async fn remove_route(&self, route_id: &Uuid) -> Result<()> {
        // Send shutdown signal
        if let Some(tx) = self.shutdown_signals.write().await.remove(route_id) {
            let _ = tx.send(true);
        }

        if let Some(route) = self.routes.write().await.remove(route_id) {
            self.port_map.write().await.remove(&route.listen_port);
            self.connection_counts.write().await.remove(route_id);
            tracing::info!(route_id = %route_id, port = route.listen_port, "Proxy route removed");
            Ok(())
        } else {
            Err(ProxyError::NotFound(route_id.to_string()))
        }
    }

    /// Get stats for a route
    pub async fn stats(&self, route_id: &Uuid) -> Result<ProxyStats> {
        let routes = self.routes.read().await;
        let route = routes.get(route_id)
            .ok_or_else(|| ProxyError::NotFound(route_id.to_string()))?;
        let active = self.connection_counts.read().await
            .get(route_id).copied().unwrap_or(0);

        Ok(ProxyStats {
            route_id: *route_id,
            active_connections: active,
            total_connections: route.total_connections,
            bytes_forwarded: route.bytes_forwarded,
        })
    }

    /// List all routes
    pub async fn list_routes(&self) -> Vec<ProxyRoute> {
        self.routes.read().await.values().cloned().collect()
    }

    /// Internal: run a TCP listener for a route
    /// If a SecurityGateway is provided, every connection is checked before proxying.
    async fn run_listener(
        route_id: Uuid,
        service_id: Uuid,
        listen_port: u16,
        backend_addr: SocketAddr,
        max_connections: u32,
        routes: Arc<RwLock<HashMap<Uuid, ProxyRoute>>>,
        conn_counts: Arc<RwLock<HashMap<Uuid, u32>>>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
        gateway: Option<Arc<becas_core::gateway::SecurityGateway>>,
    ) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", listen_port)).await?;
        tracing::info!(port = listen_port, secured = gateway.is_some(), "Proxy listener started");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((client_stream, client_addr)) => {
                            // ── SecurityGateway Check ──
                            // Every incoming connection is verified before reaching the app
                            if let Some(ref gw) = gateway {
                                let verdict = gw.check_request(
                                    client_addr.ip(),
                                    service_id,
                                    0, // size unknown at TCP level, checked per-request at HTTP level
                                ).await;

                                match verdict {
                                    becas_core::gateway::RequestVerdict::Allow => {
                                        gw.connection_opened(client_addr.ip()).await;
                                    }
                                    becas_core::gateway::RequestVerdict::RateLimited { retry_after_secs } => {
                                        tracing::warn!(
                                            ip = %client_addr.ip(),
                                            retry_after = retry_after_secs,
                                            "SecurityGateway: rate limited, rejecting connection"
                                        );
                                        // Send HTTP 429 if possible, then close
                                        let _ = Self::send_rejection(&client_stream,
                                            429, &format!("Rate limited. Retry after {}s", retry_after_secs)).await;
                                        drop(client_stream);
                                        continue;
                                    }
                                    becas_core::gateway::RequestVerdict::Blocked { reason } => {
                                        tracing::warn!(
                                            ip = %client_addr.ip(),
                                            reason = %reason,
                                            "SecurityGateway: blocked, rejecting connection"
                                        );
                                        let _ = Self::send_rejection(&client_stream,
                                            403, &format!("Blocked: {}", reason)).await;
                                        drop(client_stream);
                                        continue;
                                    }
                                    becas_core::gateway::RequestVerdict::TooManyConnections { max, current } => {
                                        tracing::warn!(
                                            ip = %client_addr.ip(),
                                            max = max, current = current,
                                            "SecurityGateway: too many connections"
                                        );
                                        let _ = Self::send_rejection(&client_stream,
                                            429, "Too many connections from your IP").await;
                                        drop(client_stream);
                                        continue;
                                    }
                                    becas_core::gateway::RequestVerdict::TooLarge { .. } => {
                                        drop(client_stream);
                                        continue;
                                    }
                                }
                            }

                            // Check connection limit (proxy-level)
                            let current = conn_counts.read().await
                                .get(&route_id).copied().unwrap_or(0);
                            if current >= max_connections {
                                tracing::warn!(
                                    route_id = %route_id,
                                    current = current,
                                    max = max_connections,
                                    "Connection limit reached, rejecting"
                                );
                                drop(client_stream);
                                continue;
                            }

                            // Increment connection count
                            if let Some(count) = conn_counts.write().await.get_mut(&route_id) {
                                *count += 1;
                            }

                            // Update total connections
                            if let Some(route) = routes.write().await.get_mut(&route_id) {
                                route.total_connections += 1;
                            }

                            let routes_clone = routes.clone();
                            let conn_counts_clone = conn_counts.clone();
                            let gw_clone = gateway.clone();
                            let peer_ip = client_addr.ip();

                            tokio::spawn(async move {
                                let bytes = Self::handle_connection(
                                    client_stream,
                                    client_addr,
                                    backend_addr,
                                ).await;

                                // Update bytes forwarded
                                if let Some(route) = routes_clone.write().await.get_mut(&route_id) {
                                    route.bytes_forwarded += bytes;
                                }

                                // Decrement connection count
                                if let Some(count) = conn_counts_clone.write().await.get_mut(&route_id) {
                                    *count = count.saturating_sub(1);
                                }

                                // Notify gateway of closed connection
                                if let Some(gw) = gw_clone {
                                    gw.connection_closed(peer_ip).await;
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Accept failed");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    tracing::info!(route_id = %route_id, "Proxy listener shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Send an HTTP rejection response on a raw TCP stream
    async fn send_rejection(stream: &TcpStream, status: u16, message: &str) -> std::io::Result<()> {
        let status_text = match status {
            403 => "Forbidden",
            429 => "Too Many Requests",
            _ => "Error",
        };
        let body = format!(r#"{{"error":"{}","status":{}}}"#, message, status);
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status, status_text, body.len(), body
        );
        // Use try_write on the TcpStream reference (non-async, best-effort)
        let _ = stream.try_write(response.as_bytes());
        Ok(())
    }

    /// Handle a single client connection by proxying to backend
    async fn handle_connection(
        mut client: TcpStream,
        client_addr: SocketAddr,
        backend_addr: SocketAddr,
    ) -> u64 {
        #[allow(unused_assignments)]
        let mut total_bytes: u64 = 0;

        // Connect to backend
        let mut backend = match TcpStream::connect(backend_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::debug!(
                    client = %client_addr,
                    backend = %backend_addr,
                    error = %e,
                    "Backend connection failed"
                );
                return 0;
            }
        };

        // Bidirectional copy
        let (mut client_read, mut client_write) = client.split();
        let (mut backend_read, mut backend_write) = backend.split();

        let client_to_backend = async {
            let mut buf = [0u8; 8192];
            let mut bytes: u64 = 0;
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if backend_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        bytes += n as u64;
                    }
                    Err(_) => break,
                }
            }
            bytes
        };

        let backend_to_client = async {
            let mut buf = [0u8; 8192];
            let mut bytes: u64 = 0;
            loop {
                match backend_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if client_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        bytes += n as u64;
                    }
                    Err(_) => break,
                }
            }
            bytes
        };

        let (c2b, b2c) = tokio::join!(client_to_backend, backend_to_client);
        total_bytes = c2b + b2c;

        tracing::debug!(
            client = %client_addr,
            bytes = total_bytes,
            "Connection closed"
        );

        total_bytes
    }
}

impl Default for ReverseProxy {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_route() {
        let proxy = ReverseProxy::new();
        let service_id = Uuid::new_v4();
        let backend: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let route_id = proxy.add_route(service_id, 18080, backend, 100).await.unwrap();

        let routes = proxy.list_routes().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].listen_port, 18080);

        // Cleanup
        proxy.remove_route(&route_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_duplicate_port() {
        let proxy = ReverseProxy::new();
        let backend: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let id = proxy.add_route(Uuid::new_v4(), 18081, backend, 100).await.unwrap();
        let result = proxy.add_route(Uuid::new_v4(), 18081, backend, 100).await;
        assert!(result.is_err());

        proxy.remove_route(&id).await.unwrap();
    }

    #[tokio::test]
    async fn test_proxy_with_security_gateway() {
        // Test that SecurityGateway actually blocks traffic through the proxy

        // 1. Start echo backend
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => { if stream.write_all(&buf[..n]).await.is_err() { break; } }
                                Err(_) => break,
                            }
                        }
                    });
                }
            }
        });

        // 2. Create proxy WITH SecurityGateway (rate limit = 3 req/min)
        let gateway = std::sync::Arc::new(becas_core::gateway::SecurityGateway::new(
            becas_core::gateway::GatewayConfig {
                rate_limit_per_ip: 3,
                auto_block_threshold: 10, // high so we test rate limit, not auto-block
                ..Default::default()
            }
        ));
        let proxy = ReverseProxy::with_gateway(gateway.clone());
        let route_id = proxy.add_route(Uuid::new_v4(), 18090, echo_addr, 100).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 3. First 3 connections should succeed
        for i in 0..3 {
            let mut client = TcpStream::connect("127.0.0.1:18090").await.unwrap();
            client.write_all(format!("ping{}", i).as_bytes()).await.unwrap();
            let mut buf = [0u8; 1024];
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0, "Connection {} should echo data", i);
        }

        // 4. 4th connection should be rate-limited (rejected with 429)
        let mut client = TcpStream::connect("127.0.0.1:18090").await.unwrap();
        let mut buf = [0u8; 2048];
        // The proxy should send an HTTP 429 response
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read(&mut buf)
        ).await;
        if let Ok(Ok(n)) = n {
            if n > 0 {
                let response = String::from_utf8_lossy(&buf[..n]);
                assert!(response.contains("429") || response.contains("Rate limited"),
                    "Expected 429 rate limit response, got: {}", response);
            }
        }

        // 5. Verify gateway stats show blocked requests
        let stats = gateway.stats().await;
        assert!(stats.total_allowed >= 3, "Should have at least 3 allowed: {}", stats.total_allowed);
        assert!(stats.total_rate_limited >= 1, "Should have at least 1 rate limited: {}", stats.total_rate_limited);

        // Cleanup
        proxy.remove_route(&route_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_proxy_gateway_ip_block() {
        // Test that blocked IPs are rejected

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf).await;
                        let _ = stream.write_all(b"ok").await;
                    });
                }
            }
        });

        // Create gateway with localhost blocked
        let gateway = std::sync::Arc::new(becas_core::gateway::SecurityGateway::new(
            becas_core::gateway::GatewayConfig {
                blocked_ips: vec!["127.0.0.1".parse().unwrap()],
                ..Default::default()
            }
        ));
        let proxy = ReverseProxy::with_gateway(gateway.clone());
        let route_id = proxy.add_route(Uuid::new_v4(), 18091, echo_addr, 100).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connection from localhost should be blocked
        let mut client = TcpStream::connect("127.0.0.1:18091").await.unwrap();
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read(&mut buf)
        ).await;
        if let Ok(Ok(n)) = n {
            if n > 0 {
                let response = String::from_utf8_lossy(&buf[..n]);
                assert!(response.contains("403") || response.contains("Blocked"),
                    "Expected 403 blocked response, got: {}", response);
            }
        }

        // Verify stats
        let stats = gateway.stats().await;
        assert!(stats.total_blocked >= 1, "Should have at least 1 blocked");

        proxy.remove_route(&route_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_proxy_e2e() {
        // Start a simple TCP echo server as "backend"
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
            }
        });

        // Create proxy route to echo server
        let proxy = ReverseProxy::new();
        let route_id = proxy.add_route(
            Uuid::new_v4(),
            18082,
            echo_addr,
            100,
        ).await.unwrap();

        // Give listener time to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect through proxy and verify echo
        let mut client = TcpStream::connect("127.0.0.1:18082").await.unwrap();
        client.write_all(b"Hello BECAS!").await.unwrap();

        let mut buf = [0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Hello BECAS!");

        // Check stats
        drop(client);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let stats = proxy.stats(&route_id).await.unwrap();
        assert!(stats.total_connections >= 1, "Expected at least 1 connection, got {}", stats.total_connections);

        // Cleanup
        proxy.remove_route(&route_id).await.unwrap();
    }
}
