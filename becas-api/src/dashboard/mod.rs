//! BECAS Dashboard API — Powered by BecasTalk
//!
//! REST endpoints for service management + real-time monitoring.

use becastalk::prelude::*;
use becas_core::persistence::ServiceStore;
use serde::Serialize;
use std::path::PathBuf;

/// Service info returned by API
#[derive(Serialize, Clone)]
pub struct ServiceInfo {
    pub id: String,
    pub name: String,
    pub status: String,
    pub service_type: String,
    pub pid: Option<u32>,
    pub uptime_secs: u64,
    pub cpu_limit: u8,
    pub ram_limit_mb: u64,
    pub ports: Vec<u16>,
}

/// System info returned by API
#[derive(Serialize)]
pub struct SystemInfo {
    pub version: String,
    pub os: String,
    pub cpu_count: usize,
    pub total_ram_mb: u64,
    pub used_ram_mb: u64,
    pub services_count: usize,
    pub running_count: usize,
}

/// Build and run the BECAS Dashboard API server
pub async fn run_dashboard(bind_addr: &str, data_dir: &str) -> anyhow::Result<()> {
    let data_path = PathBuf::from(shellexpand(data_dir));
    let services_dir = data_path.join("services");

    let dir_for_list = services_dir.clone();
    let dir_for_sys = services_dir.clone();
    let dir_for_single = services_dir.clone();

    tracing::info!("Starting BECAS Dashboard API on {}", bind_addr);

    BecasTalk::new()
        .bind(bind_addr)
        .middleware(Logger::new())
        .middleware(Cors::permissive())
        .get("/api/health", |_ctx| async {
            Response::ok().json(&serde_json::json!({
                "status": "healthy",
                "service": "becas-dashboard",
                "version": env!("CARGO_PKG_VERSION")
            }))
        })
        .get("/api/services", move |_ctx| {
            let dir = dir_for_list.clone();
            async move {
                let services = load_services(&dir);
                Response::ok().json(&serde_json::json!({
                    "success": true,
                    "count": services.len(),
                    "services": services
                }))
            }
        })
        .get("/api/services/:name", move |ctx| {
            let dir = dir_for_single.clone();
            async move {
                let name = ctx.param("name").unwrap_or("").to_string();
                let services = load_services(&dir);
                let found = services.iter().find(|s| s.name == name);
                match found {
                    Some(svc) => Response::ok().json(&serde_json::json!({
                        "success": true,
                        "service": svc
                    })),
                    None => Response::not_found("Not found").json(&serde_json::json!({
                        "success": false,
                        "error": format!("Service '{}' not found", name)
                    })),
                }
            }
        })
        .get("/api/system", move |_ctx| {
            let dir = dir_for_sys.clone();
            async move {
                let info = get_system_info(&dir);
                Response::ok().json(&serde_json::json!({
                    "success": true,
                    "system": info
                }))
            }
        })
        .get("/api/metrics", |_ctx| async {
            let mut sys = sysinfo::System::new_all();
            sys.refresh_all();
            Response::ok().json(&serde_json::json!({
                "cpu_usage": sys.global_cpu_usage(),
                "memory_used_mb": sys.used_memory() / 1_048_576,
                "memory_total_mb": sys.total_memory() / 1_048_576,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        })
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("Dashboard server error: {}", e))
}

fn load_services(services_dir: &PathBuf) -> Vec<ServiceInfo> {
    let store = match ServiceStore::new(services_dir.clone()) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let services = store.load_all().unwrap_or_default();
    services.iter().map(|svc| {
        ServiceInfo {
            id: svc.id.to_string(),
            name: svc.config.name.clone(),
            status: format!("{}", svc.status),
            service_type: format!("{}", svc.config.service_type),
            pid: svc.pid,
            uptime_secs: svc.total_uptime_secs,
            cpu_limit: svc.config.resource_limits.max_cpu_percent as u8,
            ram_limit_mb: svc.config.resource_limits.max_ram_bytes / (1024 * 1024),
            ports: svc.config.ports.iter().map(|p| p.internal).collect(),
        }
    }).collect()
}

fn get_system_info(services_dir: &PathBuf) -> SystemInfo {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    let services = load_services(services_dir);
    let running = services.iter().filter(|s| s.status == "Running").count();
    SystemInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: format!("{} {}",
            sysinfo::System::name().unwrap_or("Unknown".into()),
            sysinfo::System::os_version().unwrap_or("".into())),
        cpu_count: sys.cpus().len(),
        total_ram_mb: sys.total_memory() / 1_048_576,
        used_ram_mb: sys.used_memory() / 1_048_576,
        services_count: services.len(),
        running_count: running,
    }
}

fn shellexpand(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen("~", &home, 1);
        }
    }
    path.to_string()
}
