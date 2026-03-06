//! # Firewall + DDoS Protection
//!
//! Rate limiting, IP management, connection limiting, and traffic analysis.
//! Protects BECAS services from abuse without manual configuration.

use std::collections::HashMap;

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FirewallError {
    #[error("IP blocked: {0}")]
    IpBlocked(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Connection limit exceeded")]
    ConnectionLimitExceeded,

    #[error("Service not found: {0}")]
    ServiceNotFound(String),
}

pub type Result<T> = std::result::Result<T, FirewallError>;

/// Firewall action to take on a request
#[derive(Debug, Clone, PartialEq)]
pub enum FirewallAction {
    /// Allow the request
    Allow,
    /// Rate limit (throttle but don't block)
    RateLimit,
    /// Block the request
    Block { reason: String },
}

/// Firewall rules for a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRules {
    /// Maximum requests per second per IP
    pub max_rps_per_ip: u32,
    /// Maximum requests per second total
    pub max_rps_total: u32,
    /// Maximum concurrent connections per IP
    pub max_connections_per_ip: u32,
    /// Maximum concurrent connections total
    pub max_connections_total: u32,
    /// Auto-ban duration in seconds (for repeated offenders)
    pub auto_ban_duration_secs: u64,
    /// Number of violations before auto-ban
    pub violations_before_ban: u32,
    /// Manually blocked IPs
    pub blocked_ips: Vec<String>,
    /// Whitelisted IPs (never blocked)
    pub whitelisted_ips: Vec<String>,
}

impl Default for FirewallRules {
    fn default() -> Self {
        Self {
            max_rps_per_ip: 100,
            max_rps_total: 1000,
            max_connections_per_ip: 50,
            max_connections_total: 500,
            auto_ban_duration_secs: 3600,
            violations_before_ban: 10,
            blocked_ips: Vec::new(),
            whitelisted_ips: Vec::new(),
        }
    }
}

/// Per-IP tracking state
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct IpState {
    /// Timestamps of recent requests (sliding window)
    request_times: Vec<DateTime<Utc>>,
    /// Active connection count
    active_connections: u32,
    /// Violation count
    violations: u32,
    /// Ban expiry (if banned)
    banned_until: Option<DateTime<Utc>>,
    /// First seen
    first_seen: DateTime<Utc>,
}

impl IpState {
    fn new() -> Self {
        Self {
            request_times: Vec::new(),
            active_connections: 0,
            violations: 0,
            banned_until: None,
            first_seen: Utc::now(),
        }
    }

    /// Count requests in the last second
    fn rps(&self) -> u32 {
        let one_sec_ago = Utc::now() - Duration::seconds(1);
        self.request_times.iter().filter(|t| **t > one_sec_ago).count() as u32
    }

    /// Remove old request timestamps (older than 10 seconds)
    fn cleanup(&mut self) {
        let cutoff = Utc::now() - Duration::seconds(10);
        self.request_times.retain(|t| *t > cutoff);
    }
}

/// Firewall for a single service
struct ServiceFirewall {
    rules: FirewallRules,
    ip_states: HashMap<String, IpState>,
    total_connections: u32,
    total_blocked: u64,
    total_rate_limited: u64,
}

impl ServiceFirewall {
    fn new(rules: FirewallRules) -> Self {
        Self {
            rules,
            ip_states: HashMap::new(),
            total_connections: 0,
            total_blocked: 0,
            total_rate_limited: 0,
        }
    }
}

/// Manages firewalls for all BECAS services
pub struct Firewall {
    services: Arc<RwLock<HashMap<Uuid, ServiceFirewall>>>,
}

impl Firewall {
    /// Create a new firewall
    pub fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a service with firewall rules
    pub async fn register_service(&self, service_id: Uuid, rules: FirewallRules) {
        self.services.write().await.insert(service_id, ServiceFirewall::new(rules));
        tracing::info!(service_id = %service_id, "Firewall registered");
    }

    /// Check if a request should be allowed
    pub async fn check_request(&self, service_id: &Uuid, ip: &str) -> Result<FirewallAction> {
        let mut services = self.services.write().await;
        let fw = services.get_mut(service_id)
            .ok_or_else(|| FirewallError::ServiceNotFound(service_id.to_string()))?;

        // Check whitelist first
        if fw.rules.whitelisted_ips.contains(&ip.to_string()) {
            return Ok(FirewallAction::Allow);
        }

        // Check manual block list
        if fw.rules.blocked_ips.contains(&ip.to_string()) {
            fw.total_blocked += 1;
            return Ok(FirewallAction::Block { reason: "IP manually blocked".into() });
        }

        // Get or create IP state
        let state = fw.ip_states.entry(ip.to_string()).or_insert_with(IpState::new);
        state.cleanup();

        // Check if IP is auto-banned
        if let Some(banned_until) = state.banned_until {
            if Utc::now() < banned_until {
                fw.total_blocked += 1;
                return Ok(FirewallAction::Block {
                    reason: format!("Auto-banned until {}", banned_until.format("%H:%M:%S")),
                });
            } else {
                state.banned_until = None;
                state.violations = 0;
            }
        }

        // Check per-IP rate limit
        let ip_rps = state.rps();
        if ip_rps >= fw.rules.max_rps_per_ip {
            state.violations += 1;

            // Auto-ban if too many violations
            if state.violations >= fw.rules.violations_before_ban {
                let ban_duration = Duration::seconds(fw.rules.auto_ban_duration_secs as i64);
                state.banned_until = Some(Utc::now() + ban_duration);
                fw.total_blocked += 1;

                tracing::warn!(ip = ip, service_id = %service_id, "IP auto-banned for DDoS-like behavior");

                return Ok(FirewallAction::Block {
                    reason: format!("Auto-banned: {} violations", state.violations),
                });
            }

            fw.total_rate_limited += 1;
            return Ok(FirewallAction::RateLimit);
        }

        // Check connection limit per IP
        if state.active_connections >= fw.rules.max_connections_per_ip {
            return Ok(FirewallAction::Block { reason: "Connection limit per IP exceeded".into() });
        }

        // Check total connection limit
        if fw.total_connections >= fw.rules.max_connections_total {
            return Err(FirewallError::ConnectionLimitExceeded);
        }

        // Record request
        state.request_times.push(Utc::now());

        Ok(FirewallAction::Allow)
    }

    /// Record a new connection opened
    pub async fn connection_opened(&self, service_id: &Uuid, ip: &str) {
        let mut services = self.services.write().await;
        if let Some(fw) = services.get_mut(service_id) {
            fw.total_connections += 1;
            if let Some(state) = fw.ip_states.get_mut(ip) {
                state.active_connections += 1;
            }
        }
    }

    /// Record a connection closed
    pub async fn connection_closed(&self, service_id: &Uuid, ip: &str) {
        let mut services = self.services.write().await;
        if let Some(fw) = services.get_mut(service_id) {
            fw.total_connections = fw.total_connections.saturating_sub(1);
            if let Some(state) = fw.ip_states.get_mut(ip) {
                state.active_connections = state.active_connections.saturating_sub(1);
            }
        }
    }

    /// Block an IP manually
    pub async fn block_ip(&self, service_id: &Uuid, ip: &str) -> Result<()> {
        let mut services = self.services.write().await;
        let fw = services.get_mut(service_id)
            .ok_or_else(|| FirewallError::ServiceNotFound(service_id.to_string()))?;

        if !fw.rules.blocked_ips.contains(&ip.to_string()) {
            fw.rules.blocked_ips.push(ip.to_string());
            tracing::info!(ip = ip, service_id = %service_id, "IP manually blocked");
        }
        Ok(())
    }

    /// Unblock an IP
    pub async fn unblock_ip(&self, service_id: &Uuid, ip: &str) -> Result<()> {
        let mut services = self.services.write().await;
        let fw = services.get_mut(service_id)
            .ok_or_else(|| FirewallError::ServiceNotFound(service_id.to_string()))?;

        fw.rules.blocked_ips.retain(|i| i != ip);
        if let Some(state) = fw.ip_states.get_mut(ip) {
            state.banned_until = None;
            state.violations = 0;
        }
        Ok(())
    }

    /// Get firewall stats for a service
    pub async fn stats(&self, service_id: &Uuid) -> Result<FirewallStats> {
        let services = self.services.read().await;
        let fw = services.get(service_id)
            .ok_or_else(|| FirewallError::ServiceNotFound(service_id.to_string()))?;

        Ok(FirewallStats {
            active_connections: fw.total_connections,
            unique_ips: fw.ip_states.len(),
            blocked_ips: fw.rules.blocked_ips.len(),
            total_blocked: fw.total_blocked,
            total_rate_limited: fw.total_rate_limited,
            auto_banned: fw.ip_states.values().filter(|s| s.banned_until.is_some()).count(),
        })
    }
}

/// Firewall statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStats {
    pub active_connections: u32,
    pub unique_ips: usize,
    pub blocked_ips: usize,
    pub total_blocked: u64,
    pub total_rate_limited: u64,
    pub auto_banned: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_allow_normal_request() {
        let fw = Firewall::new();
        let svc = Uuid::new_v4();
        fw.register_service(svc, FirewallRules::default()).await;

        let action = fw.check_request(&svc, "1.2.3.4").await.unwrap();
        assert_eq!(action, FirewallAction::Allow);
    }

    #[tokio::test]
    async fn test_block_manual_ip() {
        let fw = Firewall::new();
        let svc = Uuid::new_v4();
        fw.register_service(svc, FirewallRules::default()).await;
        fw.block_ip(&svc, "evil.ip").await.unwrap();

        let action = fw.check_request(&svc, "evil.ip").await.unwrap();
        assert!(matches!(action, FirewallAction::Block { .. }));
    }

    #[tokio::test]
    async fn test_whitelist_always_allowed() {
        let fw = Firewall::new();
        let svc = Uuid::new_v4();
        let mut rules = FirewallRules::default();
        rules.whitelisted_ips.push("trusted.ip".into());
        rules.blocked_ips.push("trusted.ip".into()); // Even if also blocked
        fw.register_service(svc, rules).await;

        let action = fw.check_request(&svc, "trusted.ip").await.unwrap();
        assert_eq!(action, FirewallAction::Allow);
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let fw = Firewall::new();
        let svc = Uuid::new_v4();
        fw.register_service(svc, FirewallRules {
            max_rps_per_ip: 3,
            violations_before_ban: 100,
            ..Default::default()
        }).await;

        // First 3 should pass
        for _ in 0..3 {
            let action = fw.check_request(&svc, "1.2.3.4").await.unwrap();
            assert_eq!(action, FirewallAction::Allow);
        }

        // 4th should be rate limited
        let action = fw.check_request(&svc, "1.2.3.4").await.unwrap();
        assert_eq!(action, FirewallAction::RateLimit);
    }

    #[tokio::test]
    async fn test_unblock_ip() {
        let fw = Firewall::new();
        let svc = Uuid::new_v4();
        fw.register_service(svc, FirewallRules::default()).await;
        fw.block_ip(&svc, "1.2.3.4").await.unwrap();
        fw.unblock_ip(&svc, "1.2.3.4").await.unwrap();

        let action = fw.check_request(&svc, "1.2.3.4").await.unwrap();
        assert_eq!(action, FirewallAction::Allow);
    }

    #[tokio::test]
    async fn test_stats() {
        let fw = Firewall::new();
        let svc = Uuid::new_v4();
        fw.register_service(svc, FirewallRules::default()).await;

        fw.check_request(&svc, "1.1.1.1").await.unwrap();
        fw.check_request(&svc, "2.2.2.2").await.unwrap();
        fw.block_ip(&svc, "3.3.3.3").await.unwrap();

        let stats = fw.stats(&svc).await.unwrap();
        assert_eq!(stats.unique_ips, 2);
        assert_eq!(stats.blocked_ips, 1);
    }
}
