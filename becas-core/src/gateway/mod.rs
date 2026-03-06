//! # BECAS Security Gateway
//!
//! Real-time request filtering, rate limiting, and security enforcement
//! that sits between the network layer and services.
//!
//! Every incoming request passes through this gateway before reaching
//! the sandboxed service. The gateway enforces:
//! - Rate limiting (per-IP, per-service, global)
//! - Request size limits
//! - IP allowlist/blocklist
//! - Anomaly-based auto-blocking
//! - Geographic restrictions (optional)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Gateway configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Max requests per IP per minute
    pub rate_limit_per_ip: u32,
    /// Max requests per service per minute (global)
    pub rate_limit_per_service: u32,
    /// Max request body size in bytes
    pub max_request_size: usize,
    /// Max concurrent connections per IP
    pub max_connections_per_ip: u32,
    /// Auto-block after N violations
    pub auto_block_threshold: u32,
    /// Auto-block duration in seconds
    pub auto_block_duration_secs: u64,
    /// Blocked IPs
    pub blocked_ips: Vec<IpAddr>,
    /// Allowed IPs (empty = allow all)
    pub allowed_ips: Vec<IpAddr>,
    /// Enable anomaly-based protection
    pub anomaly_protection: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_ip: 60,
            rate_limit_per_service: 1000,
            max_request_size: 10 * 1024 * 1024, // 10MB
            max_connections_per_ip: 10,
            auto_block_threshold: 5,
            auto_block_duration_secs: 300, // 5 minutes
            blocked_ips: Vec::new(),
            allowed_ips: Vec::new(),
            anomaly_protection: true,
        }
    }
}

/// Result of a gateway check
#[derive(Debug, Clone, PartialEq)]
pub enum RequestVerdict {
    /// Request is allowed
    Allow,
    /// Request is rate-limited
    RateLimited { retry_after_secs: u64 },
    /// IP is blocked
    Blocked { reason: String },
    /// Request too large
    TooLarge { max: usize, actual: usize },
    /// Too many connections
    TooManyConnections { max: u32, current: u32 },
}

/// Per-IP tracking state
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct IpState {
    /// Request timestamps in the current window
    request_times: Vec<Instant>,
    /// Number of active connections
    active_connections: u32,
    /// Number of violations (rate limit hits)
    violations: u32,
    /// When the IP was auto-blocked (if applicable)
    blocked_until: Option<Instant>,
    /// First seen
    first_seen: Instant,
    /// Total requests lifetime
    total_requests: u64,
}

impl IpState {
    fn new() -> Self {
        Self {
            request_times: Vec::new(),
            active_connections: 0,
            violations: 0,
            blocked_until: None,
            first_seen: Instant::now(),
            total_requests: 0,
        }
    }

    /// Clean up old request timestamps (older than 1 minute)
    fn cleanup_window(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(60);
        self.request_times.retain(|t| *t > cutoff);
    }

    /// Get current requests per minute
    fn requests_per_minute(&mut self) -> u32 {
        self.cleanup_window();
        self.request_times.len() as u32
    }
}

/// Per-service tracking state
#[derive(Debug, Clone)]
struct ServiceState {
    /// Request timestamps in the current window
    request_times: Vec<Instant>,
    /// Total requests lifetime
    total_requests: u64,
    /// Total blocked requests
    total_blocked: u64,
}

impl ServiceState {
    fn new() -> Self {
        Self {
            request_times: Vec::new(),
            total_requests: 0,
            total_blocked: 0,
        }
    }

    fn cleanup_window(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(60);
        self.request_times.retain(|t| *t > cutoff);
    }

    fn requests_per_minute(&mut self) -> u32 {
        self.cleanup_window();
        self.request_times.len() as u32
    }
}

/// Gateway statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayStats {
    pub total_requests: u64,
    pub total_allowed: u64,
    pub total_blocked: u64,
    pub total_rate_limited: u64,
    pub unique_ips: usize,
    pub currently_blocked_ips: usize,
    pub requests_per_minute: u32,
}

/// The Security Gateway
pub struct SecurityGateway {
    config: Arc<RwLock<GatewayConfig>>,
    ip_states: Arc<RwLock<HashMap<IpAddr, IpState>>>,
    service_states: Arc<RwLock<HashMap<Uuid, ServiceState>>>,
    stats: Arc<RwLock<GatewayStats>>,
}

impl SecurityGateway {
    /// Create a new security gateway with the given config
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            ip_states: Arc::new(RwLock::new(HashMap::new())),
            service_states: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(GatewayStats {
                total_requests: 0,
                total_allowed: 0,
                total_blocked: 0,
                total_rate_limited: 0,
                unique_ips: 0,
                currently_blocked_ips: 0,
                requests_per_minute: 0,
            })),
        }
    }

    /// Check if a request should be allowed
    pub async fn check_request(
        &self,
        ip: IpAddr,
        service_id: Uuid,
        request_size: usize,
    ) -> RequestVerdict {
        let config = self.config.read().await;

        // 1. Check static blocklist
        if config.blocked_ips.contains(&ip) {
            self.record_blocked().await;
            return RequestVerdict::Blocked {
                reason: "IP is permanently blocked".into(),
            };
        }

        // 2. Check allowlist (if non-empty, only allow listed IPs)
        if !config.allowed_ips.is_empty() && !config.allowed_ips.contains(&ip) {
            self.record_blocked().await;
            return RequestVerdict::Blocked {
                reason: "IP not in allowlist".into(),
            };
        }

        // 3. Check request size
        if request_size > config.max_request_size {
            self.record_blocked().await;
            return RequestVerdict::TooLarge {
                max: config.max_request_size,
                actual: request_size,
            };
        }

        // 4. Check IP state
        let mut ip_states = self.ip_states.write().await;
        let ip_state = ip_states.entry(ip).or_insert_with(IpState::new);

        // 4a. Check auto-block
        if let Some(blocked_until) = ip_state.blocked_until {
            if Instant::now() < blocked_until {
                self.record_blocked().await;
                let remaining = (blocked_until - Instant::now()).as_secs();
                return RequestVerdict::Blocked {
                    reason: format!("Auto-blocked for {} more seconds", remaining),
                };
            } else {
                // Unblock
                ip_state.blocked_until = None;
                ip_state.violations = 0;
            }
        }

        // 4b. Check connections limit
        if ip_state.active_connections >= config.max_connections_per_ip {
            ip_state.violations += 1;
            self.check_auto_block(ip_state, &config);
            self.record_rate_limited().await;
            return RequestVerdict::TooManyConnections {
                max: config.max_connections_per_ip,
                current: ip_state.active_connections,
            };
        }

        // 4c. Check rate limit per IP
        let rpm = ip_state.requests_per_minute();
        if rpm >= config.rate_limit_per_ip {
            ip_state.violations += 1;
            self.check_auto_block(ip_state, &config);
            self.record_rate_limited().await;
            return RequestVerdict::RateLimited {
                retry_after_secs: 60 - ip_state.request_times.first()
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(60),
            };
        }

        // 5. Check service-level rate limit
        let mut svc_states = self.service_states.write().await;
        let svc_state = svc_states.entry(service_id).or_insert_with(ServiceState::new);
        let svc_rpm = svc_state.requests_per_minute();
        if svc_rpm >= config.rate_limit_per_service {
            svc_state.total_blocked += 1;
            self.record_rate_limited().await;
            return RequestVerdict::RateLimited {
                retry_after_secs: 5,
            };
        }

        // All checks passed — record and allow
        ip_state.request_times.push(Instant::now());
        ip_state.total_requests += 1;
        svc_state.request_times.push(Instant::now());
        svc_state.total_requests += 1;

        self.record_allowed().await;

        RequestVerdict::Allow
    }

    /// Record a new connection from an IP
    pub async fn connection_opened(&self, ip: IpAddr) {
        let mut ip_states = self.ip_states.write().await;
        let state = ip_states.entry(ip).or_insert_with(IpState::new);
        state.active_connections += 1;
    }

    /// Record a closed connection from an IP
    pub async fn connection_closed(&self, ip: IpAddr) {
        let mut ip_states = self.ip_states.write().await;
        if let Some(state) = ip_states.get_mut(&ip) {
            state.active_connections = state.active_connections.saturating_sub(1);
        }
    }

    /// Manually block an IP
    pub async fn block_ip(&self, ip: IpAddr, reason: &str) {
        let mut config = self.config.write().await;
        if !config.blocked_ips.contains(&ip) {
            config.blocked_ips.push(ip);
            tracing::warn!(%ip, reason, "IP permanently blocked");
        }
    }

    /// Manually unblock an IP
    pub async fn unblock_ip(&self, ip: IpAddr) {
        let mut config = self.config.write().await;
        config.blocked_ips.retain(|blocked| *blocked != ip);
        let mut ip_states = self.ip_states.write().await;
        if let Some(state) = ip_states.get_mut(&ip) {
            state.blocked_until = None;
            state.violations = 0;
        }
        tracing::info!(%ip, "IP unblocked");
    }

    /// Add IP to allowlist
    pub async fn allow_ip(&self, ip: IpAddr) {
        let mut config = self.config.write().await;
        if !config.allowed_ips.contains(&ip) {
            config.allowed_ips.push(ip);
        }
    }

    /// Get current gateway statistics
    pub async fn stats(&self) -> GatewayStats {
        let mut stats = self.stats.write().await;
        let ip_states = self.ip_states.read().await;
        stats.unique_ips = ip_states.len();
        stats.currently_blocked_ips = ip_states.values()
            .filter(|s| s.blocked_until.map(|b| Instant::now() < b).unwrap_or(false))
            .count();
        // Count permanently blocked too
        let config = self.config.read().await;
        stats.currently_blocked_ips += config.blocked_ips.len();
        stats.clone()
    }

    /// Update gateway configuration
    pub async fn update_config(&self, new_config: GatewayConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
    }

    /// Get current config
    pub async fn config(&self) -> GatewayConfig {
        self.config.read().await.clone()
    }

    // ── Internal helpers ──

    fn check_auto_block(&self, ip_state: &mut IpState, config: &GatewayConfig) {
        if config.anomaly_protection && ip_state.violations >= config.auto_block_threshold {
            ip_state.blocked_until = Some(
                Instant::now() + Duration::from_secs(config.auto_block_duration_secs)
            );
            tracing::warn!(
                violations = ip_state.violations,
                duration_secs = config.auto_block_duration_secs,
                "IP auto-blocked due to repeated violations"
            );
        }
    }

    async fn record_allowed(&self) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.total_allowed += 1;
    }

    async fn record_blocked(&self) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.total_blocked += 1;
    }

    async fn record_rate_limited(&self) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.total_rate_limited += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
    }

    fn test_service() -> Uuid {
        Uuid::new_v4()
    }

    #[tokio::test]
    async fn test_allow_normal_request() {
        let gw = SecurityGateway::new(GatewayConfig::default());
        let verdict = gw.check_request(test_ip(), test_service(), 100).await;
        assert_eq!(verdict, RequestVerdict::Allow);
    }

    #[tokio::test]
    async fn test_block_listed_ip() {
        let config = GatewayConfig {
            blocked_ips: vec![test_ip()],
            ..Default::default()
        };
        let gw = SecurityGateway::new(config);
        let verdict = gw.check_request(test_ip(), test_service(), 100).await;
        assert!(matches!(verdict, RequestVerdict::Blocked { .. }));
    }

    #[tokio::test]
    async fn test_allowlist_enforcement() {
        let other_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let config = GatewayConfig {
            allowed_ips: vec![other_ip],
            ..Default::default()
        };
        let gw = SecurityGateway::new(config);
        // test_ip is NOT in allowlist
        let verdict = gw.check_request(test_ip(), test_service(), 100).await;
        assert!(matches!(verdict, RequestVerdict::Blocked { .. }));
        // other_ip IS in allowlist
        let verdict = gw.check_request(other_ip, test_service(), 100).await;
        assert_eq!(verdict, RequestVerdict::Allow);
    }

    #[tokio::test]
    async fn test_request_too_large() {
        let config = GatewayConfig {
            max_request_size: 1024,
            ..Default::default()
        };
        let gw = SecurityGateway::new(config);
        let verdict = gw.check_request(test_ip(), test_service(), 2048).await;
        assert!(matches!(verdict, RequestVerdict::TooLarge { max: 1024, actual: 2048 }));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = GatewayConfig {
            rate_limit_per_ip: 5,
            ..Default::default()
        };
        let gw = SecurityGateway::new(config);
        let ip = test_ip();
        let svc = test_service();

        // First 5 requests should pass
        for _ in 0..5 {
            let verdict = gw.check_request(ip, svc, 100).await;
            assert_eq!(verdict, RequestVerdict::Allow);
        }

        // 6th should be rate limited
        let verdict = gw.check_request(ip, svc, 100).await;
        assert!(matches!(verdict, RequestVerdict::RateLimited { .. }));
    }

    #[tokio::test]
    async fn test_auto_block_after_violations() {
        let config = GatewayConfig {
            rate_limit_per_ip: 1,
            auto_block_threshold: 3,
            auto_block_duration_secs: 60,
            anomaly_protection: true,
            ..Default::default()
        };
        let gw = SecurityGateway::new(config);
        let ip = test_ip();
        let svc = test_service();

        // 1st request allowed
        gw.check_request(ip, svc, 100).await;

        // Next 3 are rate-limited (violations 1, 2, 3)
        for _ in 0..3 {
            gw.check_request(ip, svc, 100).await;
        }

        // After 3+ violations, should be auto-blocked
        let verdict = gw.check_request(ip, svc, 100).await;
        assert!(matches!(verdict, RequestVerdict::Blocked { .. }));
    }

    #[tokio::test]
    async fn test_manual_block_unblock() {
        let gw = SecurityGateway::new(GatewayConfig::default());
        let ip = test_ip();
        let svc = test_service();

        // Initially allowed
        assert_eq!(gw.check_request(ip, svc, 100).await, RequestVerdict::Allow);

        // Block
        gw.block_ip(ip, "test").await;
        assert!(matches!(gw.check_request(ip, svc, 100).await, RequestVerdict::Blocked { .. }));

        // Unblock
        gw.unblock_ip(ip).await;
        assert_eq!(gw.check_request(ip, svc, 100).await, RequestVerdict::Allow);
    }

    #[tokio::test]
    async fn test_connection_tracking() {
        let config = GatewayConfig {
            max_connections_per_ip: 2,
            ..Default::default()
        };
        let gw = SecurityGateway::new(config);
        let ip = test_ip();
        let svc = test_service();

        // Open 2 connections
        gw.connection_opened(ip).await;
        gw.connection_opened(ip).await;

        // 3rd request should fail (too many connections)
        let verdict = gw.check_request(ip, svc, 100).await;
        assert!(matches!(verdict, RequestVerdict::TooManyConnections { .. }));

        // Close one
        gw.connection_closed(ip).await;

        // Now should work
        let verdict = gw.check_request(ip, svc, 100).await;
        assert_eq!(verdict, RequestVerdict::Allow);
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let gw = SecurityGateway::new(GatewayConfig::default());
        let ip = test_ip();
        let svc = test_service();

        gw.check_request(ip, svc, 100).await;
        gw.check_request(ip, svc, 200).await;

        let stats = gw.stats().await;
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.total_allowed, 2);
        assert_eq!(stats.unique_ips, 1);
    }

    #[tokio::test]
    async fn test_service_rate_limit() {
        let config = GatewayConfig {
            rate_limit_per_ip: 1000, // High IP limit
            rate_limit_per_service: 3, // Low service limit
            ..Default::default()
        };
        let gw = SecurityGateway::new(config);
        let svc = test_service();

        // Use different IPs to avoid per-IP limit
        let ips: Vec<IpAddr> = (1..=5).map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i))).collect();

        // First 3 from different IPs should pass
        for ip in &ips[..3] {
            let verdict = gw.check_request(*ip, svc, 100).await;
            assert_eq!(verdict, RequestVerdict::Allow);
        }

        // 4th request to same service should be rate limited
        let verdict = gw.check_request(ips[3], svc, 100).await;
        assert!(matches!(verdict, RequestVerdict::RateLimited { .. }));
    }

    #[tokio::test]
    async fn test_different_services_independent() {
        let config = GatewayConfig {
            rate_limit_per_ip: 1000,
            rate_limit_per_service: 2,
            ..Default::default()
        };
        let gw = SecurityGateway::new(config);
        let svc1 = Uuid::new_v4();
        let svc2 = Uuid::new_v4();
        let ip = test_ip();

        // 2 requests to svc1
        gw.check_request(ip, svc1, 100).await;
        gw.check_request(ip, svc1, 100).await;

        // svc1 is now rate limited
        let v = gw.check_request(ip, svc1, 100).await;
        assert!(matches!(v, RequestVerdict::RateLimited { .. }));

        // But svc2 should still work
        let v = gw.check_request(ip, svc2, 100).await;
        assert_eq!(v, RequestVerdict::Allow);
    }
}
