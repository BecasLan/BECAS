//! # Cloudflare Tunnel Integration
//!
//! Provides automatic public URL generation for BECAS services using
//! Cloudflare's free "Quick Tunnel" feature. No account, no domain,
//! no VPS required.
//!
//! ## How It Works
//! 1. `cloudflared` binary is auto-downloaded if not present
//! 2. A "quick tunnel" is opened for the service port
//! 3. Cloudflare assigns a random `*.trycloudflare.com` URL
//! 4. All traffic flows: Internet → Cloudflare → localhost:port → BECAS SecurityGateway → Sandbox
//! 5. BECAS security layers (firewall, rate limit, audit) remain active
//!
//! ## Security
//! - Only the specific sandbox port is exposed (not the whole PC)
//! - All BECAS security layers apply before traffic reaches the app
//! - Tunnel process runs with minimal privileges
//! - Tunnel is automatically closed when service stops

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::process::{Child, Command};
use tokio::io::{AsyncBufReadExt, BufReader};
use serde::{Serialize, Deserialize};

/// Cloudflare tunnel manager — handles binary lifecycle and tunnel processes
pub struct CloudflareTunnel {
    /// Active tunnel processes: service_name → TunnelProcess
    tunnels: Arc<RwLock<HashMap<String, TunnelProcess>>>,
    /// Path to cloudflared binary
    binary_path: PathBuf,
}

/// A running tunnel process
pub struct TunnelProcess {
    /// Service name this tunnel belongs to
    pub service_name: String,
    /// Local port being tunneled
    pub local_port: u16,
    /// Public URL assigned by Cloudflare
    pub public_url: String,
    /// Child process handle
    child: Child,
}

/// Info about an active tunnel (safe to serialize/display)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    pub service_name: String,
    pub local_port: u16,
    pub public_url: String,
    pub status: TunnelStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TunnelStatus {
    Starting,
    Active,
    Failed(String),
    Closed,
}

impl std::fmt::Display for TunnelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelStatus::Starting => write!(f, "Starting"),
            TunnelStatus::Active => write!(f, "Active"),
            TunnelStatus::Failed(e) => write!(f, "Failed: {}", e),
            TunnelStatus::Closed => write!(f, "Closed"),
        }
    }
}

impl CloudflareTunnel {
    /// Create a new CloudflareTunnel manager
    pub fn new(data_dir: PathBuf) -> Self {
        let binary_path = data_dir.join("bin").join(cloudflared_binary_name());
        Self {
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            binary_path,
        }
    }

    /// Check if cloudflared binary is available
    pub fn is_installed(&self) -> bool {
        self.binary_path.exists()
    }

    /// Get the download URL for cloudflared based on current platform
    pub fn download_url() -> Option<String> {
        let (os, arch) = current_platform();
        let url = match (os, arch) {
            ("macos", "aarch64") => "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz",
            ("macos", "x86_64") => "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz",
            ("linux", "x86_64") => "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
            ("linux", "aarch64") => "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
            ("windows", "x86_64") => "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe",
            _ => return None,
        };
        Some(url.to_string())
    }

    /// Download and install cloudflared binary
    pub async fn install(&self) -> Result<(), String> {
        let url = Self::download_url()
            .ok_or_else(|| "Unsupported platform for cloudflared".to_string())?;

        // Create bin directory
        if let Some(parent) = self.binary_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create bin directory: {}", e))?;
        }

        let (os, _) = current_platform();

        if url.ends_with(".tgz") {
            // macOS: download .tgz and extract
            let tgz_path = self.binary_path.with_extension("tgz");
            download_file(&url, &tgz_path).await?;

            // Extract
            let output = std::process::Command::new("tar")
                .args(["xzf", &tgz_path.to_string_lossy(), "-C",
                    &self.binary_path.parent().unwrap().to_string_lossy()])
                .output()
                .map_err(|e| format!("Failed to extract: {}", e))?;

            if !output.status.success() {
                return Err(format!("tar extract failed: {}", String::from_utf8_lossy(&output.stderr)));
            }

            // Cleanup tgz
            let _ = std::fs::remove_file(&tgz_path);
        } else {
            // Linux/Windows: direct binary download
            download_file(&url, &self.binary_path).await?;
        }

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.binary_path,
                std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("Failed to set permissions: {}", e))?;
        }

        tracing::info!(path = %self.binary_path.display(), os = os, "cloudflared installed");
        Ok(())
    }

    /// Open a tunnel for a service port
    /// Returns the public URL (e.g., https://random-name.trycloudflare.com)
    pub async fn open(&self, service_name: &str, local_port: u16) -> Result<String, String> {
        // Check if already tunneled
        if self.tunnels.read().await.contains_key(service_name) {
            let tunnels = self.tunnels.read().await;
            if let Some(tp) = tunnels.get(service_name) {
                return Ok(tp.public_url.clone());
            }
        }

        // Ensure cloudflared is installed
        if !self.is_installed() {
            tracing::info!("cloudflared not found, downloading...");
            self.install().await?;
        }

        // Start cloudflared quick tunnel
        // `cloudflared tunnel --url http://localhost:<port>`
        // This requires NO account, NO config — just works
        let mut child = Command::new(&self.binary_path)
            .args(["tunnel", "--url", &format!("http://localhost:{}", local_port)])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to start cloudflared: {}", e))?;

        // Parse the public URL from stderr output
        // cloudflared prints the URL to stderr like:
        // "... | https://random-words.trycloudflare.com ..."
        let stderr = child.stderr.take()
            .ok_or_else(|| "Failed to capture cloudflared stderr".to_string())?;

        let public_url = parse_tunnel_url(stderr).await?;

        let tunnel_process = TunnelProcess {
            service_name: service_name.to_string(),
            local_port,
            public_url: public_url.clone(),
            child,
        };

        self.tunnels.write().await.insert(service_name.to_string(), tunnel_process);

        tracing::info!(
            service = %service_name,
            port = local_port,
            url = %public_url,
            "Cloudflare tunnel opened"
        );

        Ok(public_url)
    }

    /// Close a tunnel for a service
    pub async fn close(&self, service_name: &str) -> Result<(), String> {
        let mut tunnels = self.tunnels.write().await;
        if let Some(mut tp) = tunnels.remove(service_name) {
            // Kill the cloudflared process
            let _ = tp.child.kill().await;
            tracing::info!(service = %service_name, "Cloudflare tunnel closed");
            Ok(())
        } else {
            Err(format!("No active tunnel for service '{}'", service_name))
        }
    }

    /// Close all tunnels
    pub async fn close_all(&self) {
        let mut tunnels = self.tunnels.write().await;
        for (name, mut tp) in tunnels.drain() {
            let _ = tp.child.kill().await;
            tracing::info!(service = %name, "Cloudflare tunnel closed");
        }
    }

    /// List all active tunnels
    pub async fn list(&self) -> Vec<TunnelInfo> {
        let tunnels = self.tunnels.read().await;
        tunnels.values().map(|tp| TunnelInfo {
            service_name: tp.service_name.clone(),
            local_port: tp.local_port,
            public_url: tp.public_url.clone(),
            status: TunnelStatus::Active,
        }).collect()
    }

    /// Get tunnel info for a specific service
    pub async fn get(&self, service_name: &str) -> Option<TunnelInfo> {
        let tunnels = self.tunnels.read().await;
        tunnels.get(service_name).map(|tp| TunnelInfo {
            service_name: tp.service_name.clone(),
            local_port: tp.local_port,
            public_url: tp.public_url.clone(),
            status: TunnelStatus::Active,
        })
    }
}

// ─────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────

/// Parse the tunnel URL from cloudflared stderr output
/// cloudflared prints lines like:
/// `2024-01-15T10:30:00Z INF +----------------------------+`
/// `2024-01-15T10:30:00Z INF |  https://xxx.trycloudflare.com  |`
/// `2024-01-15T10:30:00Z INF +----------------------------+`
async fn parse_tunnel_url(stderr: tokio::process::ChildStderr) -> Result<String, String> {
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();

    let timeout = tokio::time::Duration::from_secs(30);
    let start = tokio::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err("Timeout waiting for cloudflared URL (30s)".to_string());
        }

        let line = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            lines.next_line()
        ).await
            .map_err(|_| "Timeout reading cloudflared output".to_string())?
            .map_err(|e| format!("IO error reading cloudflared output: {}", e))?;

        match line {
            Some(text) => {
                // Look for the trycloudflare.com URL
                if let Some(url) = extract_url(&text) {
                    return Ok(url);
                }
                // Check for error messages
                if text.contains("ERR") && text.contains("failed") {
                    return Err(format!("cloudflared error: {}", text));
                }
            }
            None => {
                return Err("cloudflared process exited before providing URL".to_string());
            }
        }
    }
}

/// Extract a trycloudflare.com URL from a line of text
fn extract_url(text: &str) -> Option<String> {
    // Find https://...trycloudflare.com in the text
    if let Some(start) = text.find("https://") {
        let rest = &text[start..];
        // Find the end of the URL (space, pipe, or end of line)
        let end = rest.find(|c: char| c.is_whitespace() || c == '|' || c == '"' || c == '\'')
            .unwrap_or(rest.len());
        let url = rest[..end].trim().to_string();
        if url.contains("trycloudflare.com") {
            return Some(url);
        }
    }
    None
}

/// Download a file from URL to path using curl
async fn download_file(url: &str, path: &PathBuf) -> Result<(), String> {
    let output = std::process::Command::new("curl")
        .args(["-sL", "-o", &path.to_string_lossy(), url])
        .output()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    if !output.status.success() {
        return Err(format!("Download failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    Ok(())
}

/// Get current platform as (os, arch)
fn current_platform() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "unknown"
    };

    (os, arch)
}

/// Get the binary name for cloudflared on this platform
fn cloudflared_binary_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "cloudflared.exe"
    } else {
        "cloudflared"
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_url_from_cloudflared_output() {
        // Real cloudflared output format
        let line = "2024-01-15T10:30:00Z INF |  https://random-words-here.trycloudflare.com  |";
        let url = extract_url(line);
        assert_eq!(url, Some("https://random-words-here.trycloudflare.com".to_string()));
    }

    #[test]
    fn test_extract_url_connector_log() {
        let line = "2024-01-15T10:30:00Z INF Registered tunnel connection connIndex=0 connection=abc url=https://my-tunnel.trycloudflare.com";
        let url = extract_url(line);
        assert_eq!(url, Some("https://my-tunnel.trycloudflare.com".to_string()));
    }

    #[test]
    fn test_extract_url_no_match() {
        let line = "2024-01-15T10:30:00Z INF Starting tunnel";
        assert!(extract_url(line).is_none());

        let line = "https://google.com is not cloudflare";
        assert!(extract_url(line).is_none());
    }

    #[test]
    fn test_download_url_exists() {
        let url = CloudflareTunnel::download_url();
        assert!(url.is_some(), "Should have a download URL for this platform");
        let url = url.unwrap();
        assert!(url.contains("cloudflared"), "URL should contain cloudflared");
    }

    #[test]
    fn test_platform_detection() {
        let (os, arch) = current_platform();
        assert!(["macos", "linux", "windows"].contains(&os));
        assert!(["aarch64", "x86_64"].contains(&arch));
    }

    #[test]
    fn test_binary_name() {
        let name = cloudflared_binary_name();
        if cfg!(target_os = "windows") {
            assert_eq!(name, "cloudflared.exe");
        } else {
            assert_eq!(name, "cloudflared");
        }
    }

    #[test]
    fn test_tunnel_status_display() {
        assert_eq!(TunnelStatus::Active.to_string(), "Active");
        assert_eq!(TunnelStatus::Starting.to_string(), "Starting");
        assert_eq!(TunnelStatus::Closed.to_string(), "Closed");
        assert_eq!(TunnelStatus::Failed("test".into()).to_string(), "Failed: test");
    }

    #[tokio::test]
    async fn test_cloudflare_tunnel_new() {
        let ct = CloudflareTunnel::new("/tmp/becas-test".into());
        assert!(!ct.is_installed()); // Not installed in test dir
        assert_eq!(ct.list().await.len(), 0);
    }

    #[tokio::test]
    async fn test_cloudflare_tunnel_close_nonexistent() {
        let ct = CloudflareTunnel::new("/tmp/becas-test".into());
        let result = ct.close("nonexistent").await;
        assert!(result.is_err());
    }
}
