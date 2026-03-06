//! # BECAS Plugin System
//!
//! Extensible plugin architecture for BECAS.
//! Plugins can hook into service lifecycle events and extend functionality.
//!
//! ## Plugin Types
//! - **Rust Plugins:** Compiled into BECAS (fastest, full access)
//! - **WASM Plugins:** Sandboxed, portable, safe (future)
//! - **Script Plugins:** Shell/Python scripts for simple tasks
//!
//! ## Hooks
//! - `on_service_deploy` — Before/after a service is deployed
//! - `on_service_start` — Before/after a service starts
//! - `on_service_stop` — Before/after a service stops
//! - `on_request` — Intercept incoming requests (middleware)
//! - `on_health_check` — Custom health check logic

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use async_trait::async_trait;

// ─────────────────────────────────────────────
// Plugin Trait
// ─────────────────────────────────────────────

/// Result type for plugin operations
pub type PluginResult<T> = Result<T, PluginError>;

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    NotFound(String),
    #[error("Plugin load error: {0}")]
    LoadError(String),
    #[error("Plugin execution error: {0}")]
    ExecutionError(String),
    #[error("Hook error: {0}")]
    HookError(String),
    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Context passed to plugin hooks
#[derive(Debug, Clone, Serialize)]
pub struct HookContext {
    pub service_id: Option<Uuid>,
    pub service_name: Option<String>,
    pub event_type: String,
    pub timestamp: String,
    pub data: serde_json::Value,
}

impl HookContext {
    pub fn new(event_type: &str) -> Self {
        Self {
            service_id: None,
            service_name: None,
            event_type: event_type.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data: serde_json::Value::Null,
        }
    }

    pub fn with_service(mut self, id: Uuid, name: &str) -> Self {
        self.service_id = Some(id);
        self.service_name = Some(name.to_string());
        self
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }
}

/// Result returned from a hook execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResult {
    /// Whether to continue processing (false = abort)
    pub continue_processing: bool,
    /// Optional modified data
    pub modified_data: Option<serde_json::Value>,
    /// Optional message/log
    pub message: Option<String>,
}

impl Default for HookResult {
    fn default() -> Self {
        Self {
            continue_processing: true,
            modified_data: None,
            message: None,
        }
    }
}

/// The main plugin trait - implement this to create a plugin
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Plugin name
    fn name(&self) -> &str;
    
    /// Plugin version
    fn version(&self) -> &str;
    
    /// Plugin description
    fn description(&self) -> &str;
    
    /// Which hooks this plugin wants to receive
    fn hooks(&self) -> Vec<HookType>;
    
    /// Called when the plugin is loaded
    async fn on_load(&self) -> PluginResult<()> {
        Ok(())
    }
    
    /// Called when the plugin is unloaded
    async fn on_unload(&self) -> PluginResult<()> {
        Ok(())
    }
    
    /// Called before a service is deployed
    async fn on_before_deploy(&self, _ctx: &HookContext) -> PluginResult<HookResult> {
        Ok(HookResult::default())
    }
    
    /// Called after a service is deployed
    async fn on_after_deploy(&self, _ctx: &HookContext) -> PluginResult<HookResult> {
        Ok(HookResult::default())
    }
    
    /// Called before a service starts
    async fn on_before_start(&self, _ctx: &HookContext) -> PluginResult<HookResult> {
        Ok(HookResult::default())
    }
    
    /// Called after a service starts
    async fn on_after_start(&self, _ctx: &HookContext) -> PluginResult<HookResult> {
        Ok(HookResult::default())
    }
    
    /// Called before a service stops
    async fn on_before_stop(&self, _ctx: &HookContext) -> PluginResult<HookResult> {
        Ok(HookResult::default())
    }
    
    /// Called after a service stops
    async fn on_after_stop(&self, _ctx: &HookContext) -> PluginResult<HookResult> {
        Ok(HookResult::default())
    }
    
    /// Called on incoming request (middleware)
    async fn on_request(&self, _ctx: &HookContext) -> PluginResult<HookResult> {
        Ok(HookResult::default())
    }
    
    /// Called on health check
    async fn on_health_check(&self, _ctx: &HookContext) -> PluginResult<HookResult> {
        Ok(HookResult::default())
    }
}

// ─────────────────────────────────────────────
// Hook Types
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HookType {
    BeforeDeploy,
    AfterDeploy,
    BeforeStart,
    AfterStart,
    BeforeStop,
    AfterStop,
    OnRequest,
    OnHealthCheck,
}

impl std::fmt::Display for HookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookType::BeforeDeploy => write!(f, "before_deploy"),
            HookType::AfterDeploy => write!(f, "after_deploy"),
            HookType::BeforeStart => write!(f, "before_start"),
            HookType::AfterStart => write!(f, "after_start"),
            HookType::BeforeStop => write!(f, "before_stop"),
            HookType::AfterStop => write!(f, "after_stop"),
            HookType::OnRequest => write!(f, "on_request"),
            HookType::OnHealthCheck => write!(f, "on_health_check"),
        }
    }
}

// ─────────────────────────────────────────────
// Plugin Manifest (for external plugins)
// ─────────────────────────────────────────────

/// Manifest file for plugin metadata (plugin.toml)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: Option<String>,
    pub license: Option<String>,
    pub homepage: Option<String>,
    pub hooks: Vec<String>,
    /// For script plugins
    pub script: Option<ScriptConfig>,
    /// Minimum BECAS version required
    pub min_becas_version: Option<String>,
    /// Dependencies on other plugins
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptConfig {
    /// Script interpreter (bash, python, node, etc.)
    pub interpreter: String,
    /// Path to main script file
    pub main: String,
    /// Timeout in seconds
    pub timeout_secs: u64,
}

impl PluginManifest {
    /// Load manifest from a plugin directory
    pub fn load(plugin_dir: &PathBuf) -> PluginResult<Self> {
        let manifest_path = plugin_dir.join("plugin.toml");
        if !manifest_path.exists() {
            return Err(PluginError::InvalidManifest(
                format!("plugin.toml not found in {:?}", plugin_dir)
            ));
        }
        
        let content = std::fs::read_to_string(&manifest_path)?;
        toml::from_str(&content)
            .map_err(|e| PluginError::InvalidManifest(e.to_string()))
    }
}

// ─────────────────────────────────────────────
// Plugin Manager
// ─────────────────────────────────────────────

/// Registered plugin info
struct RegisteredPlugin {
    plugin: Arc<dyn Plugin>,
    enabled: bool,
    load_order: u32,
}

/// Manages all loaded plugins
pub struct PluginManager {
    plugins: RwLock<HashMap<String, RegisteredPlugin>>,
    plugin_dir: PathBuf,
    load_counter: RwLock<u32>,
}

impl PluginManager {
    pub fn new(plugin_dir: PathBuf) -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            plugin_dir,
            load_counter: RwLock::new(0),
        }
    }

    /// Register a built-in plugin
    pub async fn register(&self, plugin: Arc<dyn Plugin>) -> PluginResult<()> {
        let name = plugin.name().to_string();
        
        // Call on_load
        plugin.on_load().await?;
        
        let mut counter = self.load_counter.write().await;
        *counter += 1;
        
        let registered = RegisteredPlugin {
            plugin,
            enabled: true,
            load_order: *counter,
        };
        
        self.plugins.write().await.insert(name.clone(), registered);
        tracing::info!(plugin = %name, "Plugin registered");
        
        Ok(())
    }

    /// Unregister a plugin
    pub async fn unregister(&self, name: &str) -> PluginResult<()> {
        let mut plugins = self.plugins.write().await;
        
        if let Some(registered) = plugins.remove(name) {
            registered.plugin.on_unload().await?;
            tracing::info!(plugin = %name, "Plugin unregistered");
        }
        
        Ok(())
    }

    /// Enable/disable a plugin
    pub async fn set_enabled(&self, name: &str, enabled: bool) -> PluginResult<()> {
        let mut plugins = self.plugins.write().await;
        
        if let Some(registered) = plugins.get_mut(name) {
            registered.enabled = enabled;
            tracing::info!(plugin = %name, enabled = %enabled, "Plugin state changed");
            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }

    /// List all registered plugins
    pub async fn list(&self) -> Vec<PluginInfo> {
        let plugins = self.plugins.read().await;
        let mut list: Vec<_> = plugins.iter().map(|(name, reg)| {
            PluginInfo {
                name: name.clone(),
                version: reg.plugin.version().to_string(),
                description: reg.plugin.description().to_string(),
                enabled: reg.enabled,
                hooks: reg.plugin.hooks(),
            }
        }).collect();
        
        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    /// Execute a hook on all enabled plugins
    pub async fn execute_hook(&self, hook_type: HookType, ctx: &HookContext) -> PluginResult<HookResult> {
        let plugins = self.plugins.read().await;
        
        // Sort by load order
        let mut enabled: Vec<_> = plugins.values()
            .filter(|p| p.enabled && p.plugin.hooks().contains(&hook_type))
            .collect();
        enabled.sort_by_key(|p| p.load_order);
        
        let mut final_result = HookResult::default();
        
        for registered in enabled {
            let result = match hook_type {
                HookType::BeforeDeploy => registered.plugin.on_before_deploy(ctx).await?,
                HookType::AfterDeploy => registered.plugin.on_after_deploy(ctx).await?,
                HookType::BeforeStart => registered.plugin.on_before_start(ctx).await?,
                HookType::AfterStart => registered.plugin.on_after_start(ctx).await?,
                HookType::BeforeStop => registered.plugin.on_before_stop(ctx).await?,
                HookType::AfterStop => registered.plugin.on_after_stop(ctx).await?,
                HookType::OnRequest => registered.plugin.on_request(ctx).await?,
                HookType::OnHealthCheck => registered.plugin.on_health_check(ctx).await?,
            };
            
            // If any plugin says stop, stop
            if !result.continue_processing {
                return Ok(result);
            }
            
            // Merge results
            if result.modified_data.is_some() {
                final_result.modified_data = result.modified_data;
            }
            if result.message.is_some() {
                final_result.message = result.message;
            }
        }
        
        Ok(final_result)
    }

    /// Load plugins from the plugin directory
    pub async fn load_from_directory(&self) -> PluginResult<usize> {
        if !self.plugin_dir.exists() {
            std::fs::create_dir_all(&self.plugin_dir)?;
            return Ok(0);
        }
        
        let mut loaded = 0;
        
        for entry in std::fs::read_dir(&self.plugin_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                match PluginManifest::load(&path) {
                    Ok(manifest) => {
                        tracing::info!(
                            plugin = %manifest.name,
                            version = %manifest.version,
                            "Found plugin manifest"
                        );
                        // Script plugins would be loaded here
                        // For now, just log
                        loaded += 1;
                    }
                    Err(e) => {
                        tracing::warn!(path = ?path, error = %e, "Failed to load plugin manifest");
                    }
                }
            }
        }
        
        Ok(loaded)
    }
}

/// Public plugin info
#[derive(Debug, Clone, Serialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub enabled: bool,
    pub hooks: Vec<HookType>,
}

// ─────────────────────────────────────────────
// Built-in Plugins
// ─────────────────────────────────────────────

/// Logging plugin - logs all service events
pub struct LoggingPlugin;

#[async_trait]
impl Plugin for LoggingPlugin {
    fn name(&self) -> &str { "logging" }
    fn version(&self) -> &str { "1.0.0" }
    fn description(&self) -> &str { "Logs all service lifecycle events" }
    
    fn hooks(&self) -> Vec<HookType> {
        vec![
            HookType::AfterDeploy,
            HookType::AfterStart,
            HookType::AfterStop,
        ]
    }
    
    async fn on_after_deploy(&self, ctx: &HookContext) -> PluginResult<HookResult> {
        tracing::info!(
            service = ?ctx.service_name,
            "Service deployed"
        );
        Ok(HookResult::default())
    }
    
    async fn on_after_start(&self, ctx: &HookContext) -> PluginResult<HookResult> {
        tracing::info!(
            service = ?ctx.service_name,
            "Service started"
        );
        Ok(HookResult::default())
    }
    
    async fn on_after_stop(&self, ctx: &HookContext) -> PluginResult<HookResult> {
        tracing::info!(
            service = ?ctx.service_name,
            "Service stopped"
        );
        Ok(HookResult::default())
    }
}

/// Metrics plugin - collects service metrics
pub struct MetricsPlugin {
    pub metrics_dir: PathBuf,
}

impl MetricsPlugin {
    pub fn new(metrics_dir: PathBuf) -> Self {
        Self { metrics_dir }
    }
}

#[async_trait]
impl Plugin for MetricsPlugin {
    fn name(&self) -> &str { "metrics" }
    fn version(&self) -> &str { "1.0.0" }
    fn description(&self) -> &str { "Collects and stores service metrics" }
    
    fn hooks(&self) -> Vec<HookType> {
        vec![HookType::OnHealthCheck]
    }
    
    async fn on_health_check(&self, ctx: &HookContext) -> PluginResult<HookResult> {
        // Store metrics to file
        if let Some(service_name) = &ctx.service_name {
            let metrics_file = self.metrics_dir.join(format!("{}.metrics", service_name));
            let _ = std::fs::create_dir_all(&self.metrics_dir);
            let data = serde_json::json!({
                "timestamp": ctx.timestamp,
                "service": service_name,
                "data": ctx.data,
            });
            let _ = std::fs::write(&metrics_file, data.to_string());
        }
        Ok(HookResult::default())
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_plugin_manager() {
        let mgr = PluginManager::new(PathBuf::from("/tmp/becas-plugins"));
        
        // Register logging plugin
        let plugin = Arc::new(LoggingPlugin);
        mgr.register(plugin).await.unwrap();
        
        // List plugins
        let list = mgr.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "logging");
        
        // Execute hook
        let ctx = HookContext::new("test").with_service(Uuid::new_v4(), "test-service");
        let result = mgr.execute_hook(HookType::AfterStart, &ctx).await.unwrap();
        assert!(result.continue_processing);
    }

    #[test]
    fn test_hook_context() {
        let ctx = HookContext::new("deploy")
            .with_service(Uuid::new_v4(), "my-service")
            .with_data(serde_json::json!({"port": 8080}));
        
        assert_eq!(ctx.event_type, "deploy");
        assert!(ctx.service_name.is_some());
    }
}
