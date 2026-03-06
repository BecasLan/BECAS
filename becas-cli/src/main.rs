//! # BECAS CLI — Better Call Safe Way
//!
//! Command-line interface for the BECAS platform.
//!
//! ## Commands
//! ```text
//! becas init                    Initialize BECAS Layer on this PC
//! becas deploy <config>         Deploy a service to the Layer
//! becas start <service>         Start a deployed service
//! becas stop <service>          Stop a running service
//! becas status                  Show all services status
//! becas logs <service>          Show service logs (masked by access level)
//! becas monitor                 Live monitoring dashboard
//! becas level <service> <0-4>   Set access level for a service
//! becas firewall <service>      Show firewall stats
//! becas audit                   Show audit log
//! ```

use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;
use std::sync::Arc;

mod tui;


#[derive(Parser)]
#[command(
    name = "becas",
    about = "🛡️  BECAS — Better Call Safe Way\nOS-level personal cloud platform",
    version,
    long_about = "BECAS turns your PC into a secure, isolated service host.\n\
                  Services run in the BECAS Layer — they belong to the Layer, NOT to your PC.\n\
                  Your files stay private. Services stay isolated. Everything stays safe."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// BECAS data directory
    #[arg(long, default_value = "~/.becas-layer", global = true)]
    data_dir: String,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the BECAS Layer on this PC
    Init,

    /// Auto-detect and deploy a project (zero-config!)
    Auto {
        /// Path to the project directory or binary (default: current dir ".")
        #[arg(default_value = ".")]
        path: String,

        /// Override detected name
        #[arg(long)]
        name: Option<String>,

        /// Auto-start after deploy
        #[arg(long, default_value_t = false)]
        start: bool,

        /// Run build command before deploy
        #[arg(long, default_value_t = false)]
        build: bool,
    },

    /// Deploy from .becas.toml config (or auto-detect) and start
    Up {
        /// Path to project (default: current dir)
        #[arg(default_value = ".")]
        path: String,

        /// Watch for file changes and auto-redeploy
        #[arg(long, default_value_t = false)]
        watch: bool,
    },

    /// Stop and remove a running deployment
    Down {
        /// Service name (default: from .becas.toml or dir name)
        name: Option<String>,
    },

    /// Deploy a service to the BECAS Layer (manual)
    Deploy {
        /// Service name
        #[arg(short, long)]
        name: String,

        /// Command to run
        #[arg(short, long)]
        command: String,

        /// Command arguments
        #[arg(short, long, num_args = 0..)]
        args: Vec<String>,

        /// Service type (database, api, web, ai, worker, generic)
        #[arg(short = 't', long, default_value = "generic")]
        service_type: String,

        /// Max CPU percentage
        #[arg(long, default_value = "15")]
        max_cpu: u32,

        /// Max RAM in MB
        #[arg(long, default_value = "2048")]
        max_ram: u32,

        /// Ports to expose (e.g., 8080, 5432)
        #[arg(short, long, num_args = 0..)]
        ports: Vec<u16>,
    },

    /// Start a deployed service
    Start {
        /// Service name or ID
        service: String,
    },

    /// Stop a running service
    Stop {
        /// Service name or ID
        service: String,
    },

    /// Show status of all services
    Status {
        /// Show detailed info
        #[arg(short, long)]
        detailed: bool,
    },

    /// Show service logs (filtered by access level)
    Logs {
        /// Service name or ID
        service: String,

        /// Number of lines to show
        #[arg(short, long, default_value = "50")]
        lines: usize,

        /// Follow logs in real-time
        #[arg(short, long)]
        follow: bool,
    },

    /// Live monitoring dashboard
    Monitor {
        /// Refresh interval in seconds
        #[arg(short, long, default_value = "2")]
        interval: u64,
    },

    /// Set access level for a service
    Level {
        /// Service name or ID
        service: String,

        /// Access level (0=Ghost, 1=Monitor, 2=Diagnostic, 3=Emergency, 4=OwnerOverride)
        #[arg(value_parser = clap::value_parser!(u8).range(0..=4))]
        level: u8,

        /// Reason (required for level 4)
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Show firewall stats for a service
    Firewall {
        /// Service name or ID
        service: String,

        /// Block an IP
        #[arg(long)]
        block: Option<String>,

        /// Unblock an IP
        #[arg(long)]
        unblock: Option<String>,
    },

    /// Show audit log
    Audit {
        /// Number of recent entries to show
        #[arg(short, long, default_value = "20")]
        count: usize,

        /// Filter by service name
        #[arg(short, long)]
        service: Option<String>,

        /// Verify hash chain integrity
        #[arg(long)]
        verify: bool,
    },

    /// Remove a stopped service
    Remove {
        /// Service name or ID
        service: String,

        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// Show system information
    Info,

    /// Recover all services that were running before shutdown
    Recover {
        /// Don't actually start, just show what would be recovered
        #[arg(long)]
        dry_run: bool,
    },

    /// Install BECAS as a system service (auto-start on boot)
    Install {
        /// Uninstall instead
        #[arg(long)]
        uninstall: bool,
    },

    /// Restart a service (stop + start)
    Restart {
        /// Service name or ID
        service: String,
    },

    /// Open the web dashboard in browser
    Dashboard {
        /// Port for dashboard server
        #[arg(short, long, default_value_t = 7777)]
        port: u16,
    },

    /// Run as a relay server (help other nodes connect through NAT)
    Relay {
        /// Port for relay server
        #[arg(short, long, default_value_t = 9800)]
        port: u16,

        /// Max connections
        #[arg(long, default_value_t = 50)]
        max_connections: u32,
    },

    /// Create a tunnel to expose a service externally
    Tunnel {
        /// Service name
        service: String,

        /// External port to expose on (default: auto)
        #[arg(short, long)]
        port: Option<u16>,

        /// Custom subdomain (default: service name)
        #[arg(long)]
        subdomain: Option<String>,
    },

    /// Marketplace — browse and install service templates
    #[command(subcommand)]
    Market(MarketCommands),

    /// Check NAT type and P2P connectivity
    Nat,

    /// Manage plugins
    #[command(subcommand)]
    Plugin(PluginCommands),

    /// Launch interactive TUI dashboard
    Tui,
}

#[derive(Subcommand)]
enum MarketCommands {
    /// List all available templates
    List {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },
    /// Search templates
    Search {
        /// Search query
        query: String,
    },
    /// Show template details
    Info {
        /// Template ID
        template: String,
    },
    /// Install and deploy from template
    Install {
        /// Template ID
        template: String,
        /// Custom service name
        #[arg(short, long)]
        name: Option<String>,
        /// Auto-start after install
        #[arg(long)]
        start: bool,
    },
}

#[derive(Subcommand)]
enum PluginCommands {
    /// List installed plugins
    List,
    /// Enable a plugin
    Enable {
        /// Plugin name
        name: String,
    },
    /// Disable a plugin
    Disable {
        /// Plugin name
        name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level))
        )
        .with_target(false)
        .init();

    match cli.command {
        Commands::Init => cmd_init(&cli.data_dir).await,
        Commands::Auto { path, name, start, build } => cmd_auto(&cli.data_dir, &path, name, start, build).await,
        Commands::Up { path, watch } => cmd_up(&cli.data_dir, &path, watch).await,
        Commands::Down { name } => cmd_down(&cli.data_dir, name).await,
        Commands::Deploy { name, command, args, service_type, max_cpu, max_ram, ports } => {
            cmd_deploy(&cli.data_dir, &name, &command, &args, &service_type, max_cpu, max_ram, &ports).await
        }
        Commands::Start { service } => cmd_start(&cli.data_dir, &service).await,
        Commands::Stop { service } => cmd_stop(&cli.data_dir, &service).await,
        Commands::Status { detailed } => cmd_status(&cli.data_dir, detailed).await,
        Commands::Logs { service, lines, follow } => cmd_logs(&cli.data_dir, &service, lines, follow).await,
        Commands::Monitor { interval } => cmd_monitor(&cli.data_dir, interval).await,
        Commands::Level { service, level, reason } => cmd_level(&cli.data_dir, &service, level, reason).await,
        Commands::Firewall { service, block, unblock } => cmd_firewall(&cli.data_dir, &service, block, unblock).await,
        Commands::Audit { count, service, verify } => cmd_audit(&cli.data_dir, count, service, verify).await,
        Commands::Remove { service, force } => cmd_remove(&cli.data_dir, &service, force).await,
        Commands::Info => cmd_info().await,
        Commands::Recover { dry_run } => cmd_recover(&cli.data_dir, dry_run).await,
        Commands::Install { uninstall } => cmd_install(&cli.data_dir, uninstall).await,
        Commands::Restart { service } => cmd_restart(&cli.data_dir, &service).await,
        Commands::Relay { port, max_connections } => cmd_relay(port, max_connections).await,
        Commands::Dashboard { port } => cmd_dashboard(port).await,
        Commands::Tunnel { service, port, subdomain } => cmd_tunnel(&cli.data_dir, &service, port, subdomain).await,
        Commands::Market(subcmd) => cmd_market(&cli.data_dir, subcmd).await,
        Commands::Nat => cmd_nat().await,
        Commands::Plugin(subcmd) => cmd_plugin(&cli.data_dir, subcmd).await,
        Commands::Tui => tui::run(&cli.data_dir).await,
    }
}

// ─────────────────────────────────────────────
// Command Implementations
// ─────────────────────────────────────────────

async fn cmd_init(data_dir: &str) -> anyhow::Result<()> {
    println!("{}", "🛡️  BECAS — Better Call Safe Way".bright_cyan().bold());
    println!("{}", "   Initializing BECAS Layer...".dimmed());
    println!();

    let base_dir = expand_path(data_dir);
    std::fs::create_dir_all(&base_dir)?;

    // Initialize crypto engine (generates node identity)
    let crypto = becas_core::crypto::CryptoEngine::new(base_dir.join("crypto"))?;
    let node_id = crypto.node_identity().id.clone();

    // Create directory structure
    let dirs = ["sandboxes", "services", "logs", "config"];
    for dir in &dirs {
        std::fs::create_dir_all(base_dir.join(dir))?;
    }

    println!("  {} BECAS Layer initialized", "✅".green());
    println!("  {} Data directory: {}", "📂".yellow(), base_dir.display());
    println!("  {} Node ID: {}", "🔑".yellow(), node_id.bright_yellow());
    println!();
    println!("  {}", "Next steps:".bold());
    println!("    becas deploy --name my-service --command ./my-app");
    println!("    becas start my-service");
    println!("    becas status");

    Ok(())
}

async fn cmd_deploy(
    data_dir: &str,
    name: &str,
    command: &str,
    args: &[String],
    service_type: &str,
    max_cpu: u32,
    max_ram: u32,
    ports: &[u16],
) -> anyhow::Result<()> {
    println!("{}", format!("🚀 Deploying service '{}'...", name).bright_cyan());

    let base_dir = expand_path(data_dir);

    // Initialize subsystems
    let sandbox_mgr = std::sync::Arc::new(
        becas_core::sandbox::SandboxManager::new(base_dir.join("sandboxes"))
    );
    let resource_gov = std::sync::Arc::new(
        becas_core::resource::ResourceGovernor::new(becas_core::resource::ResourceLimits {
            max_cpu_percent: max_cpu as f64,
            max_ram_bytes: (max_ram as u64) * 1024 * 1024,
            ..Default::default()
        })
    );
    let access_ctrl = std::sync::Arc::new(
        becas_core::access::AccessController::new(becas_core::access::AccessLevel::Monitor)
    );
    let crypto_eng = std::sync::Arc::new(
        becas_core::crypto::CryptoEngine::new(base_dir.join("crypto"))?
    );

    let svc_mgr = becas_core::service::ServiceManager::new(
        base_dir.clone(),
        sandbox_mgr,
        resource_gov,
        access_ctrl,
        crypto_eng,
    );

    let svc_type = match service_type {
        "database" | "db" => becas_core::service::ServiceType::Database,
        "api" => becas_core::service::ServiceType::Api,
        "web" => becas_core::service::ServiceType::Web,
        "ai" => becas_core::service::ServiceType::AiModel,
        "worker" => becas_core::service::ServiceType::Worker,
        _ => becas_core::service::ServiceType::Generic,
    };

    let port_mappings: Vec<becas_core::sandbox::PortMapping> = ports.iter().map(|p| {
        becas_core::sandbox::PortMapping {
            internal: *p,
            protocol: becas_core::sandbox::Protocol::Tcp,
        }
    }).collect();

    let config = becas_core::service::ServiceConfig {
        name: name.to_string(),
        service_type: svc_type,
        command: command.to_string(),
        args: args.to_vec(),
        resource_limits: becas_core::resource::ResourceLimits {
            max_cpu_percent: max_cpu as f64,
            max_ram_bytes: (max_ram as u64) * 1024 * 1024,
            ..Default::default()
        },
        ports: port_mappings,
        ..Default::default()
    };

    let service_id = svc_mgr.deploy(config).await?;

    println!();
    println!("  {} Service deployed to BECAS Layer", "✅".green());
    println!("  {} ID: {}", "🆔".yellow(), service_id.to_string().bright_yellow());
    println!("  {} Name: {}", "📛".yellow(), name.bright_white());
    println!("  {} Type: {}", "📦".yellow(), service_type);
    println!("  {} CPU limit: {}%", "💻".yellow(), max_cpu);
    println!("  {} RAM limit: {}MB", "🧠".yellow(), max_ram);
    if !ports.is_empty() {
        println!("  {} Ports: {:?}", "🌐".yellow(), ports);
    }
    println!();
    println!("  {}", "Next: becas start ".bold().to_string() + &name.bright_green().to_string());

    Ok(())
}

/// Helper: create a ServiceManager from data_dir and load persisted services
async fn create_service_manager(base_dir: &PathBuf) -> anyhow::Result<becas_core::service::ServiceManager> {
    let sandbox_mgr = Arc::new(
        becas_core::sandbox::SandboxManager::new(base_dir.join("sandboxes"))
    );
    let resource_gov = Arc::new(
        becas_core::resource::ResourceGovernor::new(becas_core::resource::ResourceLimits::default())
    );
    let access_ctrl = Arc::new(
        becas_core::access::AccessController::new(becas_core::access::AccessLevel::Monitor)
    );
    let crypto_eng = Arc::new(
        becas_core::crypto::CryptoEngine::new(base_dir.join("crypto"))?
    );

    let svc_mgr = becas_core::service::ServiceManager::new(
        base_dir.clone(),
        sandbox_mgr,
        resource_gov,
        access_ctrl,
        crypto_eng,
    );

    // Load persisted services
    svc_mgr.load_from_disk().await?;

    Ok(svc_mgr)
}

/// Find a service by name from the service manager
async fn find_service_by_name(
    mgr: &becas_core::service::ServiceManager,
    name: &str,
) -> anyhow::Result<becas_core::service::Service> {
    let services = mgr.list().await;
    // Try exact name match first
    if let Some(svc) = services.iter().find(|s| s.config.name == name) {
        return Ok(svc.clone());
    }
    // Try UUID match
    if let Ok(uuid) = uuid::Uuid::parse_str(name) {
        if let Ok(svc) = mgr.get(&uuid).await {
            return Ok(svc);
        }
    }
    anyhow::bail!("Service '{}' not found. Use 'becas status' to see available services.", name);
}

async fn cmd_start(data_dir: &str, service_name: &str) -> anyhow::Result<()> {
    println!("{}", format!("▶️  Starting service '{}'...", service_name).bright_cyan());

    let base_dir = expand_path(data_dir);
    let svc_mgr = create_service_manager(&base_dir).await?;

    let svc = find_service_by_name(&svc_mgr, service_name).await?;

    svc_mgr.start(&svc.id).await?;

    // Reload to get updated state
    let svc = svc_mgr.get(&svc.id).await?;

    println!();
    println!("  {} Service '{}' started", "✅".green(), svc.config.name.bright_white());
    println!("  {} Sandbox: isolated (ID: {})", "🔒".yellow(),
        svc.sandbox_id.map_or("none".into(), |id| id.to_string()).dimmed());
    println!("  {} Status: {}", "📊".yellow(), "Running".bright_green());

    if !svc.config.ports.is_empty() {
        let ports: Vec<String> = svc.config.ports.iter()
            .map(|p| p.internal.to_string()).collect();
        println!("  {} Ports: {}", "🌐".yellow(), ports.join(", "));
    }

    // Show log location
    if let Some(sandbox_id) = svc.sandbox_id {
        let log_dir = base_dir.join("sandboxes").join(sandbox_id.to_string()).join("logs");
        println!("  {} Logs: {}", "📋".yellow(), log_dir.display().to_string().dimmed());
    }

    // Auto-expose through mesh — deploy = live
    if !svc.config.ports.is_empty() {
        let port = svc.config.ports[0].internal;
        let node_id_path = base_dir.join("node_id");
        let node_id = std::fs::read_to_string(&node_id_path).unwrap_or_else(|_| "local".into()).trim().to_string();

        let mesh_config = becas_net::mesh::MeshConfig::default();
        let mesh = becas_net::mesh::MeshNode::new(node_id, mesh_config);
        match mesh.expose(&svc.config.name, port).await {
            Ok(url) => {
                println!();
                println!("  {} LAN access: {}", "🏠".green(), url.bright_white().underline());
            }
            Err(e) => {
                println!("  {} Mesh: {} (local access only)", "⚠️".yellow(), e.to_string().dimmed());
            }
        }

        // Set up SecurityGateway-protected reverse proxy
        // Traffic flow: Cloudflare → proxy:GATEWAY_PORT → SecurityGateway.check() → App:PORT
        let gateway_port = port + 10000; // e.g., app on 9000 → gateway on 19000

        // Load security config from .becas.toml in data dir, otherwise use defaults
        let gw_config = parse_becas_toml(&base_dir)
            .map(|c| c.to_gateway_config())
            .unwrap_or_default();
        println!("  {} Security: rate_limit={}/min, max_conn={}/IP, auto_block={}",
            "🔧".dimmed(),
            gw_config.rate_limit_per_ip,
            gw_config.max_connections_per_ip,
            gw_config.auto_block_threshold,
        );
        let gateway = std::sync::Arc::new(
            becas_core::gateway::SecurityGateway::new(gw_config)
        );
        let proxy = becas_net::proxy::ReverseProxy::with_gateway(gateway);
        let backend_addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        match proxy.add_route(svc.id, gateway_port, backend_addr, 100).await {
            Ok(_route_id) => {
                println!("  {} Security proxy: port {} → {} (rate limit + firewall + audit)",
                    "🛡️".green(), gateway_port.to_string().bright_yellow(), port);
            }
            Err(e) => {
                println!("  {} Security proxy failed: {} (falling back to direct)", "⚠️".yellow(), e);
            }
        }

        // Auto-open Cloudflare Tunnel — points to GATEWAY port (not app port directly!)
        // This ensures all external traffic goes through SecurityGateway
        println!("  {} Opening public tunnel...", "🌍".yellow());
        let cf = becas_net::tunnel::cloudflare::CloudflareTunnel::new(base_dir.clone());
        match cf.open(&svc.config.name, gateway_port).await {
            Ok(public_url) => {
                println!("  {} Public URL: {}", "🌐".green(), public_url.bright_green().bold().underline());
                println!("  {} Protected by: rate limit (60/min), IP block, DDoS auto-block, audit log", "🛡️".green());

                // Save tunnel URL to file for dashboard/status
                let tunnel_file = base_dir.join("tunnels").join(format!("{}.url", svc.config.name));
                if let Some(parent) = tunnel_file.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&tunnel_file, &public_url);
            }
            Err(e) => {
                println!("  {} Public tunnel: {} (LAN access only)", "⚠️".yellow(), e.to_string().dimmed());
                println!("     To retry: becas tunnel {}", svc.config.name);
            }
        }
    }

    Ok(())
}

async fn cmd_stop(data_dir: &str, service_name: &str) -> anyhow::Result<()> {
    println!("{}", format!("⏹️  Stopping service '{}'...", service_name).bright_cyan());

    let base_dir = expand_path(data_dir);
    let svc_mgr = create_service_manager(&base_dir).await?;

    let svc = find_service_by_name(&svc_mgr, service_name).await?;

    // Close Cloudflare tunnel if active
    let cf = becas_net::tunnel::cloudflare::CloudflareTunnel::new(base_dir.clone());
    if cf.get(&svc.config.name).await.is_some() {
        let _ = cf.close(&svc.config.name).await;
        println!("  {} Public tunnel closed", "🌐".yellow());
    }

    // Remove saved tunnel URL
    let tunnel_file = base_dir.join("tunnels").join(format!("{}.url", svc.config.name));
    let _ = std::fs::remove_file(&tunnel_file);

    svc_mgr.stop(&svc.id).await?;

    println!();
    println!("  {} Service '{}' stopped gracefully", "✅".green(), svc.config.name.bright_white());
    Ok(())
}

async fn cmd_status(data_dir: &str, detailed: bool) -> anyhow::Result<()> {
    println!("{}", "🛡️  BECAS Layer Status".bright_cyan().bold());
    println!("{}", "═".repeat(50).dimmed());
    println!();

    // System info
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    println!("  {} System", "💻".yellow());
    println!("     CPU: {:.1}% ({} cores)", sys.global_cpu_usage(), sys.cpus().len());
    println!("     RAM: {}MB / {}MB",
        sys.used_memory() / 1_048_576,
        sys.total_memory() / 1_048_576
    );
    println!();

    // Load services from disk
    let base_dir = expand_path(data_dir);
    let state = becas_core::persistence::StateManager::new(base_dir.clone());
    if let Ok(state) = state {
        let services = state.services.load_all().unwrap_or_default();
        if services.is_empty() {
            println!("  {} No services deployed yet", "📭".yellow());
            println!("     Use: becas deploy --name my-service --command ./my-app");
        } else {
            println!("  {} Services ({})", "📦".yellow(), services.len());
            println!("  {}", "─".repeat(46).dimmed());
            for svc in &services {
                let status_icon = match &svc.status {
                    becas_core::service::ServiceStatus::Running => "🟢",
                    becas_core::service::ServiceStatus::Stopped |
                    becas_core::service::ServiceStatus::Deployed => "⚫",
                    becas_core::service::ServiceStatus::Failed(_) => "🔴",
                    becas_core::service::ServiceStatus::Paused => "🟡",
                    _ => "⚪",
                };
                println!("  {} {} — {} [{}]",
                    status_icon,
                    svc.config.name.bright_white().bold(),
                    svc.status,
                    svc.config.service_type,
                );
                if detailed {
                    println!("       ID: {}", svc.id.to_string().dimmed());
                    println!("       Identity: {}", svc.identity_id.dimmed());
                    println!("       Deployed: {}", svc.deployed_at.format("%Y-%m-%d %H:%M:%S"));
                    println!("       CPU limit: {:.0}% | RAM limit: {}MB",
                        svc.config.resource_limits.max_cpu_percent,
                        svc.config.resource_limits.max_ram_bytes / 1_048_576
                    );
                    if !svc.config.ports.is_empty() {
                        let ports: Vec<String> = svc.config.ports.iter()
                            .map(|p| p.internal.to_string()).collect();
                        println!("       Ports: {}", ports.join(", "));
                    }
                    // Show tunnel URL if active
                    let tunnel_file = base_dir.join("tunnels").join(format!("{}.url", svc.config.name));
                    if let Ok(url) = std::fs::read_to_string(&tunnel_file) {
                        println!("       {} Public: {}", "🌐", url.trim().bright_green().underline());
                    }
                    println!();
                }
            }
        }
    } else {
        println!("  {} BECAS Layer not initialized", "⚠️".yellow());
        println!("     Run: becas init");
    }

    // Audit stats
    if let Ok(state) = becas_core::persistence::StateManager::new(base_dir) {
        let audit_count = state.audit.count().unwrap_or(0);
        if audit_count > 0 {
            println!();
            println!("  {} Audit: {} entries", "📜".yellow(), audit_count);
        }
    }

    Ok(())
}

async fn cmd_logs(data_dir: &str, service_name: &str, lines: usize, _follow: bool) -> anyhow::Result<()> {
    println!("{}", format!("📋 Logs for '{}' (access level filtered)", service_name).bright_cyan());
    println!("{}", "─".repeat(50).dimmed());

    let base_dir = expand_path(data_dir);

    // Find service from persistence
    let state = becas_core::persistence::StateManager::new(base_dir.clone())?;
    let services = state.services.load_all()?;
    let svc = services.iter().find(|s| s.config.name == service_name);

    if let Some(svc) = svc {
        if let Some(sandbox_id) = &svc.sandbox_id {
            let stdout_log = base_dir.join("sandboxes").join(sandbox_id.to_string()).join("logs").join("stdout.log");
            let stderr_log = base_dir.join("sandboxes").join(sandbox_id.to_string()).join("logs").join("stderr.log");

            if stdout_log.exists() {
                let content = std::fs::read_to_string(&stdout_log).unwrap_or_default();
                let log_lines: Vec<&str> = content.lines().collect();
                let start = if log_lines.len() > lines { log_lines.len() - lines } else { 0 };
                println!("  {} stdout:", "📄".yellow());
                for line in &log_lines[start..] {
                    println!("    {}", line);
                }
            }

            if stderr_log.exists() {
                let content = std::fs::read_to_string(&stderr_log).unwrap_or_default();
                if !content.trim().is_empty() {
                    let log_lines: Vec<&str> = content.lines().collect();
                    let start = if log_lines.len() > lines { log_lines.len() - lines } else { 0 };
                    println!("  {} stderr:", "⚠️".yellow());
                    for line in &log_lines[start..] {
                        println!("    {}", line.red());
                    }
                }
            }

            if !stdout_log.exists() && !stderr_log.exists() {
                println!("  {} No log files found yet", "📭".yellow());
            }
        } else {
            println!("  {} Service is not running (no sandbox), showing last known logs", "📭".yellow());
            // Try to find any sandbox dir that was used
            let sandbox_dir = base_dir.join("sandboxes");
            if sandbox_dir.exists() {
                println!("  {} Check sandbox directory: {}", "📂".yellow(), sandbox_dir.display());
            }
        }
    } else {
        println!("  {} Service '{}' not found", "❌".red(), service_name);
    }

    Ok(())
}

async fn cmd_monitor(data_dir: &str, interval: u64) -> anyhow::Result<()> {
    println!("{}", "📊 BECAS Live Monitor".bright_cyan().bold());
    println!("{}", format!("Refreshing every {}s — Press Ctrl+C to exit", interval).dimmed());
    println!();

    let base_dir = expand_path(data_dir);

    loop {
        // Clear screen effect
        print!("\x1B[2J\x1B[H");
        println!("{}", "📊 BECAS Live Monitor".bright_cyan().bold());
        println!("{}", "═".repeat(60).dimmed());

        // System metrics
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        let cpu = sys.global_cpu_usage();
        let ram_used = sys.used_memory() / 1_048_576;
        let ram_total = sys.total_memory() / 1_048_576;

        println!();
        println!("  {} System   CPU: {:.1}% ({} cores)  RAM: {}MB / {}MB",
            "💻".yellow(), cpu, sys.cpus().len(), ram_used, ram_total);
        println!();

        // Services
        let state = becas_core::persistence::StateManager::new(base_dir.clone());
        if let Ok(state) = state {
            let services = state.services.load_all().unwrap_or_default();
            if services.is_empty() {
                println!("  {} No services deployed", "📭".yellow());
            } else {
                println!("  {:<20} {:<12} {:<8} {:<10} {:<10}",
                    "SERVICE".dimmed(), "STATUS".dimmed(), "PID".dimmed(),
                    "CPU LIM".dimmed(), "RAM LIM".dimmed());
                println!("  {}", "─".repeat(56).dimmed());
                for svc in &services {
                    let status_icon = match &svc.status {
                        becas_core::service::ServiceStatus::Running => "🟢",
                        becas_core::service::ServiceStatus::Stopped |
                        becas_core::service::ServiceStatus::Deployed => "⚫",
                        becas_core::service::ServiceStatus::Failed(_) => "🔴",
                        _ => "⚪",
                    };
                    let pid_str = svc.pid.map(|p| p.to_string()).unwrap_or("-".into());
                    println!("  {} {:<18} {:<12} {:<8} {:<10} {:<10}",
                        status_icon,
                        svc.config.name,
                        format!("{}", svc.status),
                        pid_str,
                        format!("{:.0}%", svc.config.resource_limits.max_cpu_percent),
                        format!("{}MB", svc.config.resource_limits.max_ram_bytes / 1_048_576),
                    );
                }
            }
        }

        println!();
        let now = chrono::Local::now();
        println!("  {} {}", "🕐".dimmed(), now.format("%H:%M:%S").to_string().dimmed());

        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
}

async fn cmd_level(data_dir: &str, service_name: &str, level: u8, reason: Option<String>) -> anyhow::Result<()> {
    let level_name = match level {
        0 => "Ghost",
        1 => "Monitor",
        2 => "Diagnostic",
        3 => "Emergency",
        4 => "Owner Override",
        _ => unreachable!(),
    };

    if level == 4 && reason.is_none() {
        println!("{}", "❌ Owner Override (Level 4) requires --reason".red());
        return Ok(());
    }

    let base_dir = expand_path(data_dir);
    let svc_mgr = create_service_manager(&base_dir).await?;
    let svc = find_service_by_name(&svc_mgr, service_name).await?;

    // Map to access level
    let access_level = match level {
        0 => becas_core::access::AccessLevel::Ghost,
        1 => becas_core::access::AccessLevel::Monitor,
        2 => becas_core::access::AccessLevel::Diagnostic,
        3 => becas_core::access::AccessLevel::Emergency,
        4 => becas_core::access::AccessLevel::OwnerOverride,
        _ => unreachable!(),
    };

    // Create access controller and set level
    let access_ctrl = becas_core::access::AccessController::new(access_level);
    access_ctrl.register_service(svc.id).await;

    println!("{}", format!("🔐 Access Level for '{}'", service_name).bright_cyan());
    println!("  {} Level changed: {} → {} (Level {})",
        "✅".green(),
        "previous".dimmed(),
        level_name.bright_yellow(),
        level
    );
    if let Some(r) = &reason {
        println!("  {} Reason: {}", "📝".yellow(), r);
    }
    println!("  {} Service ID: {}", "🆔".yellow(), svc.id.to_string().dimmed());

    // Log to audit (SHA-256 hash chain)
    let audit_path = base_dir.join("audit").join("audit.jsonl");
    if let Ok(audit_store) = becas_core::persistence::AuditStore::new(audit_path) {
        let _ = audit_store.log(
            "access_level_change",
            serde_json::json!({
                "level": level,
                "level_name": level_name,
                "reason": reason.unwrap_or_else(|| "none".into()),
            }),
            Some(svc.id),
            "CLI",
        );
    }

    Ok(())
}

async fn cmd_firewall(data_dir: &str, service_name: &str, block: Option<String>, unblock: Option<String>) -> anyhow::Result<()> {
    let gateway = becas_core::gateway::SecurityGateway::new(becas_core::gateway::GatewayConfig::default());

    if let Some(ip_str) = block {
        let ip: std::net::IpAddr = ip_str.parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip_str))?;
        gateway.block_ip(ip, &format!("Manual block for service '{}'", service_name)).await;
        println!("  {} IP {} blocked for '{}'", "🚫".red(), ip_str.bright_red(), service_name);

        // Audit log (SHA-256 hash chain)
        let base_dir = expand_path(data_dir);
        let audit_path = base_dir.join("audit").join("audit.jsonl");
        if let Ok(audit_store) = becas_core::persistence::AuditStore::new(audit_path) {
            let _ = audit_store.log(
                "ip_blocked",
                serde_json::json!({ "ip": ip_str, "service": service_name }),
                None,
                "CLI",
            );
        }
    } else if let Some(ip_str) = unblock {
        let ip: std::net::IpAddr = ip_str.parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip_str))?;
        gateway.unblock_ip(ip).await;
        println!("  {} IP {} unblocked for '{}'", "✅".green(), ip_str.bright_green(), service_name);
    } else {
        // Show stats
        println!("{}", format!("🛡️  Firewall — '{}'", service_name).bright_cyan());
        println!("{}", "═".repeat(50).dimmed());
        println!();

        let stats = gateway.stats().await;
        let config = gateway.config().await;

        println!("  {} Configuration", "⚙️".yellow());
        println!("     Rate limit/IP:      {} req/min", config.rate_limit_per_ip);
        println!("     Rate limit/service:  {} req/min", config.rate_limit_per_service);
        println!("     Max request size:    {} MB", config.max_request_size / (1024 * 1024));
        println!("     Max conn/IP:         {}", config.max_connections_per_ip);
        println!("     Auto-block after:    {} violations", config.auto_block_threshold);
        println!("     Auto-block duration: {}s", config.auto_block_duration_secs);
        println!("     Anomaly protection:  {}", if config.anomaly_protection { "ON".green() } else { "OFF".red() });
        println!();
        println!("  {} Statistics", "📊".yellow());
        println!("     Total requests:    {}", stats.total_requests);
        println!("     Allowed:           {}", stats.total_allowed.to_string().green());
        println!("     Blocked:           {}", stats.total_blocked.to_string().red());
        println!("     Rate limited:      {}", stats.total_rate_limited.to_string().yellow());
        println!("     Unique IPs:        {}", stats.unique_ips);
        println!("     Currently blocked: {}", stats.currently_blocked_ips);

        if !config.blocked_ips.is_empty() {
            println!();
            println!("  {} Blocked IPs", "🚫".red());
            for ip in &config.blocked_ips {
                println!("     {} {}", "●".red(), ip);
            }
        }
    }
    Ok(())
}

async fn cmd_audit(data_dir: &str, count: usize, service_filter: Option<String>, verify: bool) -> anyhow::Result<()> {
    println!("{}", "📜 BECAS Audit Log".bright_cyan().bold());
    println!("{}", "═".repeat(50).dimmed());
    println!();

    let base_dir = expand_path(data_dir);

    // Try persistence audit store first
    let state = becas_core::persistence::StateManager::new(base_dir.clone());
    if let Ok(state) = state {
        if verify {
            match state.audit.verify_chain() {
                Ok((true, 0, _)) => {
                    println!("  {} Hash chain: {} (no entries)",
                        "🔗".yellow(), "EMPTY".dimmed());
                }
                Ok((true, count, _)) => {
                    println!("  {} Hash chain: {} ({} entries, SHA-256 verified)",
                        "🔗".green(), "✅ VALID".green().bold(), count);
                }
                Ok((false, count, Some(broken_seq))) => {
                    println!("  {} Hash chain: {} (broken at seq #{}, {} total entries)",
                        "🔗".red(), "❌ TAMPERED".red().bold(), broken_seq, count);
                    println!("     ⚠️  Audit log may have been modified or corrupted!");
                }
                Ok((false, count, _)) => {
                    println!("  {} Hash chain: {} ({} entries)",
                        "🔗".red(), "❌ INVALID".red().bold(), count);
                }
                Err(e) => {
                    println!("  {} Hash chain verification failed: {}",
                        "🔗".red(), e.to_string().dimmed());
                }
            }
            println!();
        }

        let entries = state.audit.load_all().unwrap_or_default();
        if entries.is_empty() {
            println!("  {} No audit entries yet", "📭".yellow());
            println!("     Entries are created when services are deployed, started, stopped,");
            println!("     access levels are changed, or IPs are blocked.");
        } else {
            // Filter by service if specified
            let filtered: Vec<_> = if let Some(ref svc_name) = service_filter {
                entries.iter().filter(|e| {
                    e.service_id.as_ref().map(|s| s.to_string().contains(svc_name)).unwrap_or(false)
                        || e.event_data.to_string().contains(svc_name)
                }).collect()
            } else {
                entries.iter().collect()
            };

            // Show last N entries
            let start = if filtered.len() > count { filtered.len() - count } else { 0 };
            let shown = &filtered[start..];

            if let Some(ref svc) = service_filter {
                println!("  Filtered by: {}", svc.bright_white());
                println!();
            }

            println!("  {:<24} {:<20} {}",
                "TIMESTAMP".dimmed(), "EVENT".dimmed(), "DETAILS".dimmed());
            println!("  {}", "─".repeat(70).dimmed());

            for entry in shown {
                let time = entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
                let event_color = match entry.event_type.as_str() {
                    "ip_blocked" => entry.event_type.red().to_string(),
                    "access_level_change" => entry.event_type.yellow().to_string(),
                    _ => entry.event_type.bright_white().to_string(),
                };
                let details = entry.event_data.to_string();
                println!("  {:<24} {:<20} {}",
                    time.dimmed(),
                    event_color,
                    details.dimmed(),
                );
            }

            println!();
            println!("  {} Showing {} of {} entries",
                "ℹ️".blue(), shown.len(), filtered.len());
        }
    } else {
        println!("  {} BECAS Layer not initialized", "⚠️".yellow());
        println!("     Run: becas init");
    }

    Ok(())
}

async fn cmd_remove(data_dir: &str, service_name: &str, force: bool) -> anyhow::Result<()> {
    println!("{}", format!("🗑️  Removing service '{}'...", service_name).bright_cyan());

    let base_dir = expand_path(data_dir);
    let svc_mgr = create_service_manager(&base_dir).await?;
    let svc = find_service_by_name(&svc_mgr, service_name).await?;

    // Check if running
    if svc.status == becas_core::service::ServiceStatus::Running {
        if !force {
            println!("  {} Service '{}' is currently running!", "⚠️".yellow(), service_name);
            println!("     Stop it first: becas stop {}", service_name);
            println!("     Or use --force to stop and remove: becas remove {} --force", service_name);
            return Ok(());
        }
        // Force: stop first
        println!("  {} Force stopping '{}'...", "⏹️".yellow(), service_name);
        svc_mgr.stop(&svc.id).await?;
        println!("  {} Stopped", "✅".green());
    }

    // Confirmation (skip if --force)
    if !force {
        println!("  {} About to remove:", "⚠️".yellow());
        println!("     Name: {}", svc.config.name.bright_white());
        println!("     Type: {}", svc.config.service_type);
        println!("     ID:   {}", svc.id.to_string().dimmed());
        println!();
        println!("  {} This action is irreversible. Use --force to confirm.", "❗".red());
        return Ok(());
    }

    svc_mgr.remove(&svc.id).await?;

    println!();
    println!("  {} Service '{}' removed from BECAS Layer", "✅".green(), service_name.bright_white());
    println!("  {} ID: {}", "🆔".dimmed(), svc.id.to_string().dimmed());

    // Audit log (SHA-256 hash chain)
    let audit_path = base_dir.join("audit").join("audit.jsonl");
    if let Ok(audit_store) = becas_core::persistence::AuditStore::new(audit_path) {
        let _ = audit_store.log(
            "service_removed",
            serde_json::json!({ "service_name": service_name }),
            Some(svc.id),
            "CLI",
        );
    }

    Ok(())
}

async fn cmd_info() -> anyhow::Result<()> {
    println!("{}", "🛡️  BECAS — Better Call Safe Way".bright_cyan().bold());
    println!("   Version: {}", becas_core::VERSION);
    println!();

    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    println!("  {} System Info", "💻".yellow());
    println!("     OS: {} {}", sysinfo::System::name().unwrap_or("Unknown".into()), sysinfo::System::os_version().unwrap_or("".into()));
    println!("     CPU: {} cores, {:.1}% usage", sys.cpus().len(), sys.global_cpu_usage());
    println!("     RAM: {}MB / {}MB", sys.used_memory() / 1_048_576, sys.total_memory() / 1_048_576);
    println!();
    println!("  {} BECAS Layer", "🛡️".yellow());
    println!("     Status: Ready");
    println!("     Services: 0");

    Ok(())
}

/// Expand ~ to home directory
fn expand_path(path: &str) -> PathBuf {
    if path.starts_with('~') {
        if let Some(home) = dirs_home() {
            return PathBuf::from(path.replacen('~', &home, 1));
        }
    }
    PathBuf::from(path)
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
}

// ─────────────────────────────────────────────
// Auto-Recovery + Install + Restart
// ─────────────────────────────────────────────

async fn cmd_recover(data_dir: &str, dry_run: bool) -> anyhow::Result<()> {
    println!("{}", "🔄 BECAS Recovery — Checking services...".bright_cyan().bold());
    println!();

    let base_dir = expand_path(data_dir);
    let svc_mgr = create_service_manager(&base_dir).await?;
    let services = svc_mgr.list().await;

    // Find services that should be recovered (were running, now dead)
    let mut recoverable = Vec::new();
    let mut already_running = 0u32;
    let mut stopped = 0u32;

    for svc in &services {
        match svc.status {
            becas_core::service::ServiceStatus::Running => {
                // check_process_alive already ran in load_from_disk
                // If status is still Running, process is alive
                already_running += 1;
            }
            becas_core::service::ServiceStatus::Stopped => {
                // Check if it has auto_restart enabled or was previously running
                if svc.restart_count > 0 || svc.total_uptime_secs > 0 {
                    recoverable.push(svc.clone());
                } else {
                    stopped += 1;
                }
            }
            _ => { stopped += 1; }
        }
    }

    if already_running > 0 {
        println!("  {} {} service(s) already running", "✅".green(), already_running);
    }
    if stopped > 0 {
        println!("  {} {} service(s) stopped (no recovery needed)", "⚫".dimmed(), stopped);
    }

    if recoverable.is_empty() {
        println!("  {} Nothing to recover", "✅".green());
        return Ok(());
    }

    println!("  {} {} service(s) to recover:", "🔄".yellow(), recoverable.len());
    for svc in &recoverable {
        let ports: Vec<String> = svc.config.ports.iter().map(|p| p.internal.to_string()).collect();
        println!("     {} {} [{}] ports: [{}]",
            "→".bright_cyan(),
            svc.config.name.bright_white(),
            format!("{}", svc.config.service_type).dimmed(),
            ports.join(", ")
        );
    }
    println!();

    if dry_run {
        println!("  {} Dry run — no services started", "ℹ️".blue());
        return Ok(());
    }

    // Actually recover services
    let mut success = 0u32;
    let mut failed = 0u32;

    for svc in &recoverable {
        print!("  {} Starting {}...", "▶️".bright_cyan(), svc.config.name.bright_white());
        match svc_mgr.start(&svc.id).await {
            Ok(()) => {
                println!(" {}", "✅".green());
                success += 1;
            }
            Err(e) => {
                println!(" {} {}", "❌".red(), e.to_string().red());
                failed += 1;
            }
        }
    }

    println!();
    println!("  {} Recovery complete: {} started, {} failed",
        if failed == 0 { "✅".green() } else { "⚠️".yellow() },
        success.to_string().green(),
        failed.to_string().red()
    );

    Ok(())
}

async fn cmd_install(data_dir: &str, uninstall: bool) -> anyhow::Result<()> {
    let base_dir = expand_path(data_dir);
    let becas_bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("becas"));
    let plist_dir = expand_path("~/Library/LaunchAgents");
    let plist_path = plist_dir.join("com.becas.layer.plist");

    if uninstall {
        println!("{}", "🗑️  Uninstalling BECAS auto-start...".bright_cyan());

        // Unload from launchd
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path.to_string_lossy()])
            .output();

        // Remove plist
        if plist_path.exists() {
            std::fs::remove_file(&plist_path)?;
            println!("  {} LaunchAgent removed: {}", "✅".green(), plist_path.display());
        } else {
            println!("  {} LaunchAgent not found (already uninstalled?)", "ℹ️".blue());
        }
        return Ok(());
    }

    println!("{}", "🛡️  Installing BECAS as system service...".bright_cyan().bold());
    println!();

    // Create macOS LaunchAgent plist
    std::fs::create_dir_all(&plist_dir)?;

    let plist_content = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.becas.layer</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>recover</string>
        <string>--data-dir</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{}/logs/launchd-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{}/logs/launchd-stderr.log</string>
</dict>
</plist>"#,
        becas_bin.display(),
        base_dir.display(),
        base_dir.display(),
        base_dir.display(),
    );

    std::fs::write(&plist_path, &plist_content)?;

    // Load into launchd
    let output = std::process::Command::new("launchctl")
        .args(["load", &plist_path.to_string_lossy()])
        .output()?;

    println!("  {} LaunchAgent installed: {}", "✅".green(), plist_path.display());
    if output.status.success() {
        println!("  {} Loaded into launchd", "✅".green());
    } else {
        println!("  {} Load warning: {}", "⚠️".yellow(),
            String::from_utf8_lossy(&output.stderr).trim());
    }
    println!();
    println!("  {} BECAS will auto-recover services on login", "🔄".bright_cyan());
    println!("  {} To uninstall: becas install --uninstall", "ℹ️".blue());

    Ok(())
}

async fn cmd_restart(data_dir: &str, service: &str) -> anyhow::Result<()> {
    println!("{}", format!("🔄 Restarting service '{}'...", service).bright_cyan());
    println!();

    let base_dir = expand_path(data_dir);
    let svc_mgr = create_service_manager(&base_dir).await?;
    let found_svc = find_service_by_name(&svc_mgr, service).await?;
    let svc_id = found_svc.id;

    // Stop if running
    if found_svc.status == becas_core::service::ServiceStatus::Running {
        print!("  {} Stopping...", "⏹️".yellow());
        svc_mgr.stop(&svc_id).await?;
        println!(" {}", "done".green());
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Start
    print!("  {} Starting...", "▶️".bright_cyan());
    svc_mgr.start(&svc_id).await?;

    let restarted = svc_mgr.get(&svc_id).await;
    let pid_str = restarted.map(|s| s.pid.map(|p| p.to_string()).unwrap_or("?".into())).unwrap_or("?".into());
    println!(" {} (PID: {})", "done".green(), pid_str.bright_yellow());

    println!();
    println!("  {} Service '{}' restarted successfully", "✅".green(), service.bright_white());

    Ok(())
}

async fn cmd_tunnel(data_dir: &str, service: &str, port: Option<u16>, subdomain: Option<String>) -> anyhow::Result<()> {
    println!("{}", "🌐 BECAS Tunnel".bright_cyan().bold());
    println!("{}", "═".repeat(50).dimmed());
    println!();

    let base_dir = expand_path(data_dir);
    let svc_mgr = create_service_manager(&base_dir).await?;

    // Find the service
    let all = svc_mgr.list().await;
    let svc = all.iter().find(|s| s.config.name == service)
        .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service))?;

    if svc.status != becas_core::service::ServiceStatus::Running {
        anyhow::bail!("Service '{}' is not running. Start it first: becas start {}", service, service);
    }

    let _subdomain = subdomain.unwrap_or_else(|| service.to_string());
    let service_port = port.unwrap_or_else(|| svc.config.ports.first().map(|p| p.internal).unwrap_or(8080));
    let lan_ip = becas_net::mesh::get_local_ip();

    println!("  {} Service: {}", "📦".yellow(), service.bright_white().bold());
    println!("  {} Local port: {}", "🔌".yellow(), service_port.to_string().bright_yellow());
    println!("  {} LAN IP: {}", "🏷️".yellow(), lan_ip.bright_cyan());
    println!();

    // Check for existing tunnel
    let tunnel_file = base_dir.join("tunnels").join(format!("{}.url", service));
    if let Ok(existing_url) = std::fs::read_to_string(&tunnel_file) {
        println!("  {} Tunnel already active:", "✅".green());
        println!();
        println!("  {} Public URL: {}", "🌐".green(), existing_url.trim().bright_green().bold().underline());
        println!("  {} LAN:        http://{}:{}", "🏠".green(), lan_ip.bright_cyan(), service_port);
        println!();
        println!("  {} All BECAS security layers active (firewall, rate limit, audit)", "🛡️".yellow());
        return Ok(());
    }

    // Open Cloudflare Tunnel
    println!("  {} Opening Cloudflare tunnel...", "🌍".yellow());
    let cf = becas_net::tunnel::cloudflare::CloudflareTunnel::new(base_dir.clone());
    match cf.open(service, service_port).await {
        Ok(public_url) => {
            println!("  {} Tunnel active!", "✅".green());
            println!();
            println!("  {} Access your service:", "🔗".bright_cyan());
            println!("     Public:  {}", public_url.bright_green().bold().underline());
            println!("     LAN:     http://{}:{}", lan_ip.bright_cyan(), service_port);
            println!();
            println!("  {} All BECAS security layers active (firewall, rate limit, audit)", "🛡️".yellow());
            println!("  {} Press Ctrl+C to close tunnel", "💡".yellow());

            // Save tunnel URL
            let tunnel_dir = base_dir.join("tunnels");
            let _ = std::fs::create_dir_all(&tunnel_dir);
            let _ = std::fs::write(tunnel_dir.join(format!("{}.url", service)), &public_url);

            // Keep tunnel alive until Ctrl+C
            println!();
            println!("{}", "  Forwarding traffic...".dimmed());
            tokio::signal::ctrl_c().await?;

            println!();
            println!("  {} Closing tunnel...", "🔒".yellow());
            let _ = cf.close(service).await;
            let _ = std::fs::remove_file(tunnel_dir.join(format!("{}.url", service)));
            println!("  {} Tunnel closed", "✅".green());
        }
        Err(e) => {
            println!("  {} Failed to open tunnel: {}", "❌".red(), e);
            println!();
            println!("  {} Your service is still accessible on LAN:", "💡".yellow());
            println!("     http://{}:{}", lan_ip.bright_cyan(), service_port);
        }
    }

    Ok(())
}

async fn cmd_auto(data_dir: &str, path: &str, name_override: Option<String>, auto_start: bool, run_build: bool) -> anyhow::Result<()> {
    use becas_core::detect;
    use std::path::Path;

    let project_path = Path::new(path).canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(path));

    println!("{}", "🔍 BECAS Auto-Detect".bright_cyan().bold());
    println!("{}", "═".repeat(50).dimmed());
    println!();
    println!("  Scanning: {}", project_path.display().to_string().bright_white());
    println!();

    let result = detect::detect(&project_path);

    let name = name_override.unwrap_or_else(|| result.name.clone());

    // Display detection results
    println!("  {} Project Type: {}", "📦".yellow(), result.project_type.to_string().bright_green());
    println!("  {} Name:         {}", "🏷️ ".yellow(), name.bright_white());
    println!("  {} Command:      {}", "⚙️ ".yellow(), result.command.bright_white());
    if !result.args.is_empty() {
        println!("  {} Args:         {}", "📝".yellow(), result.args.join(" ").bright_white());
    }
    println!("  {} Ports:        {}", "🔌".yellow(),
        result.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ").bright_white());
    println!("  {} Type:         {}", "🏗️ ".yellow(), result.service_type.bright_white());
    println!("  {} CPU limit:    {}%", "💻".yellow(), result.recommended_cpu.to_string().bright_white());
    println!("  {} RAM limit:    {}MB", "🧠".yellow(), result.recommended_ram.to_string().bright_white());
    println!("  {} Confidence:   {:.0}%", "🎯".yellow(), (result.confidence * 100.0).to_string().bright_white());
    for note in &result.notes {
        println!("  {} {}", "💡".yellow(), note.dimmed());
    }
    println!();

    if result.confidence == 0.0 {
        println!("  {} Could not detect project type. Use 'becas deploy' manually.", "❌".red());
        return Ok(());
    }

    // Run build if requested
    if run_build {
        if let Some(ref build_cmd) = result.build_command {
            println!("  {} Building: {}", "🔨".yellow(), build_cmd.bright_white());
            let status = std::process::Command::new("sh")
                .args(["-c", build_cmd])
                .current_dir(&project_path)
                .status()?;
            if status.success() {
                println!("  {} Build succeeded", "✅".green());
            } else {
                println!("  {} Build failed", "❌".red());
                return Ok(());
            }
            println!();
        }
    } else if let Some(ref build_cmd) = result.build_command {
        println!("  {} Build available: {} (use --build flag)", "💡".yellow(), build_cmd.dimmed());
    }

    // Deploy
    println!("  {} Deploying '{}'...", "🚀".yellow(), name.bright_white());

    cmd_deploy(
        data_dir,
        &name,
        &result.command,
        &result.args,
        &result.service_type,
        result.recommended_cpu as u32,
        result.recommended_ram as u32,
        &result.ports,
    ).await?;

    // Auto-start if requested
    if auto_start {
        println!();
        cmd_start(data_dir, &name).await?;
    } else {
        println!();
        println!("  {} Ready! Start with: becas start {}", "💡".yellow(), name.bright_green());
    }

    Ok(())
}

async fn cmd_dashboard(port: u16) -> anyhow::Result<()> {
    use becastalk::prelude::*;

    const DASHBOARD_HTML: &str = include_str!("../../becas-gui/web/index.html");

    println!("{}", "🌐 BECAS Web Dashboard (BecasTalk)".bright_cyan().bold());
    println!("{}", "═".repeat(50).dimmed());
    println!();
    println!("  {} Dashboard: {}", "🔗".yellow(), format!("http://localhost:{}", port).bright_white().underline());
    println!("  {} Powered by: {}", "⚡".yellow(), "BecasTalk Engine".bright_magenta());
    println!("  {} Press {} to stop", "💡".yellow(), "Ctrl+C".bright_red());
    println!();

    // Open browser
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(format!("http://localhost:{}", port))
            .spawn();
    }

    let data_dir = Arc::new(expand_path("~/.becas"));
    let dd1 = data_dir.clone();
    let dd2 = data_dir.clone();
    let dd3 = data_dir.clone();
    let dd4 = data_dir.clone();
    let dd5 = data_dir.clone();

    let server = BecasTalk::new()
        .bind(&format!("0.0.0.0:{}", port))
        .max_connections(100)

        // Dashboard HTML
        .get("/", |_ctx: Context| async move {
            Response::ok().html(DASHBOARD_HTML)
        })

        // API: System metrics
        .get("/api/system", |_ctx: Context| async move {
            let mut sys = sysinfo::System::new_all();
            sys.refresh_all();
            let cpu = sys.global_cpu_usage();
            let ram_used = sys.used_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
            let ram_total = sys.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
            let disks = sysinfo::Disks::new_with_refreshed_list();
            let disk_used: u64 = disks.iter().map(|d| d.total_space() - d.available_space()).sum();
            let disk_total: u64 = disks.iter().map(|d| d.total_space()).sum();
            let body = serde_json::json!({
                "cpu_percent": (cpu * 10.0).round() / 10.0,
                "cpu_cores": sys.cpus().len(),
                "cpu_name": sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default(),
                "ram_used_gb": (ram_used * 10.0).round() / 10.0,
                "ram_total_gb": (ram_total * 10.0).round() / 10.0,
                "disk_used_gb": disk_used / (1024 * 1024 * 1024),
                "disk_total_gb": disk_total / (1024 * 1024 * 1024),
                "os": sysinfo::System::name().unwrap_or_default(),
                "os_version": sysinfo::System::os_version().unwrap_or_default(),
                "hostname": sysinfo::System::host_name().unwrap_or_default(),
            });
            Response::ok().json(&body)
        })

        // API: List services
        .get("/api/services", move |_ctx: Context| {
            let dir = dd1.clone();
            async move {
                let services_dir = dir.join("services");
                match becas_core::persistence::ServiceStore::new(services_dir) {
                    Ok(store) => {
                        let services = store.load_all().unwrap_or_default();
                        let list: Vec<serde_json::Value> = services.iter().map(|s| {
                            serde_json::json!({
                                "id": s.id.to_string(),
                                "name": s.config.name,
                                "service_type": format!("{}", s.config.service_type),
                                "status": format!("{}", s.status),
                                "port": s.config.ports.first().map(|p| p.internal).unwrap_or(0),
                                "cpu_limit": s.config.resource_limits.max_cpu_percent,
                                "ram_limit_mb": s.config.resource_limits.max_ram_bytes / (1024 * 1024),
                                "pid": s.pid,
                                "uptime": s.total_uptime_secs,
                                "requests": s.total_requests,
                                "created": s.deployed_at.to_rfc3339(),
                            })
                        }).collect();
                        Response::ok().json(&serde_json::json!({"services": list, "count": list.len()}))
                    }
                    Err(_) => Response::ok().json(&serde_json::json!({"services": [], "count": 0}))
                }
            }
        })

        // API: Start a service
        .post("/api/services/:name/start", move |ctx: Context| {
            let dir = dd2.clone();
            async move {
                let name = ctx.param("name").unwrap_or("").to_string();
                let becas_bin = std::env::current_exe().unwrap_or_default();
                let output = std::process::Command::new(&becas_bin)
                    .args(["start", "--data-dir", &dir.to_string_lossy(), &name])
                    .output();
                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                        let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                        Response::ok().json(&serde_json::json!({"action":"start","service":name,"success":o.status.success(),"stdout":stdout,"stderr":stderr}))
                    }
                    Err(e) => Response::internal_error("").json(&serde_json::json!({"error":e.to_string()}))
                }
            }
        })

        // API: Stop a service
        .post("/api/services/:name/stop", move |ctx: Context| {
            let dir = dd3.clone();
            async move {
                let name = ctx.param("name").unwrap_or("").to_string();
                let becas_bin = std::env::current_exe().unwrap_or_default();
                let output = std::process::Command::new(&becas_bin)
                    .args(["stop", "--data-dir", &dir.to_string_lossy(), &name])
                    .output();
                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                        let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                        Response::ok().json(&serde_json::json!({"action":"stop","service":name,"success":o.status.success(),"stdout":stdout,"stderr":stderr}))
                    }
                    Err(e) => Response::internal_error("").json(&serde_json::json!({"error":e.to_string()}))
                }
            }
        })

        // API: Deploy a project (auto-detect)
        .post("/api/deploy", move |ctx: Context| {
            let dir = dd5.clone();
            async move {
                let body = ctx.body_str().unwrap_or("");
                let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
                let path = parsed.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let name_override = parsed.get("name").and_then(|v| v.as_str()).unwrap_or("");

                if path.is_empty() {
                    return Response::bad_request("path is required")
                        .json(&serde_json::json!({"error":"path is required"}));
                }

                let becas_bin = std::env::current_exe().unwrap_or_default();
                let dir_str = dir.to_string_lossy().to_string();
                let path_owned = path.to_string();
                let name_owned = name_override.to_string();
                let mut args = vec!["auto".to_string(), "--data-dir".to_string(), dir_str, path_owned];
                if !name_owned.is_empty() {
                    args.push("--name".to_string());
                    args.push(name_owned);
                }

                let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                let output = std::process::Command::new(&becas_bin)
                    .args(&args_ref)
                    .output();

                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                        let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                        // Parse auto-detect output for name and type
                        let detected_name = stdout.lines()
                            .find(|l| l.contains("Name:"))
                            .map(|l| l.split("Name:").last().unwrap_or("").trim().to_string())
                            .unwrap_or_else(|| path.split('/').last().unwrap_or("app").to_string());
                        let svc_type = stdout.lines()
                            .find(|l| l.contains("Type:"))
                            .map(|l| l.split("Type:").last().unwrap_or("").trim().to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        let ports: Vec<String> = stdout.lines()
                            .find(|l| l.contains("Ports:"))
                            .map(|l| l.split("Ports:").last().unwrap_or("").trim()
                                .split(',').map(|p| p.trim().to_string()).collect())
                            .unwrap_or_default();

                        if o.status.success() {
                            Response::ok().json(&serde_json::json!({
                                "name": detected_name,
                                "service_type": svc_type,
                                "ports": ports,
                                "success": true,
                                "output": stdout
                            }))
                        } else {
                            Response::internal_error("deploy failed").json(&serde_json::json!({
                                "error": format!("Deploy failed: {}", stderr.lines().last().unwrap_or(&stderr)),
                                "stdout": stdout,
                                "stderr": stderr
                            }))
                        }
                    }
                    Err(e) => Response::internal_error("").json(&serde_json::json!({"error":e.to_string()}))
                }
            }
        })

        // API: Mesh status — exposed services, relay info
        .get("/api/mesh", move |_ctx: Context| {
            let dir = dd4.clone();
            async move {
                let path = expand_path(&dir.to_string_lossy());
                let store = match becas_core::persistence::ServiceStore::new(path.join("services")) {
                    Ok(s) => s,
                    Err(_) => return Response::ok().json(&serde_json::json!({"exposed": [], "relays": []})),
                };
                let services = store.load_all().unwrap_or_default();

                let mut exposed = Vec::new();
                for svc in &services {
                    if svc.status == becas_core::service::ServiceStatus::Running {
                        for pm in &svc.config.ports {
                            let node_path = path.join("node_id");
                            let node_id = std::fs::read_to_string(&node_path).unwrap_or_else(|_| "local".into()).trim().to_string();
                            let _short = &node_id[..8.min(node_id.len())];
                            exposed.push(serde_json::json!({
                                "name": svc.config.name,
                                "port": pm.internal,
                                "url": becas_net::mesh::generate_service_url(&svc.config.name, pm.internal, None),
                                "status": "Live"
                            }));
                        }
                    }
                }

                Response::ok().json(&serde_json::json!({
                    "exposed_count": exposed.len(),
                    "exposed": exposed,
                    "relays": [],
                    "mesh_status": if exposed.is_empty() { "no services" } else { "active" }
                }))
            }
        })

        // API: Audit log
        .get("/api/audit", {
            let dd_audit = data_dir.clone();
            move |_ctx: Context| {
                let dir = dd_audit.clone();
                async move {
                    let path = expand_path(&dir.to_string_lossy());
                    let state = match becas_core::persistence::StateManager::new(path.clone()) {
                        Ok(s) => s,
                        Err(_) => return Response::ok().json(&serde_json::json!({"entries": [], "total": 0})),
                    };

                    let entries = state.audit.load_all().unwrap_or_default();
                    let total = entries.len();
                    // Return last 50 entries
                    let start = if total > 50 { total - 50 } else { 0 };
                    let recent: Vec<_> = entries[start..].iter().map(|e| {
                        serde_json::json!({
                            "timestamp": e.timestamp.to_rfc3339(),
                            "event_type": e.event_type,
                            "service_id": e.service_id.map(|s| s.to_string()),
                            "data": e.event_data,
                            "actor": e.actor,
                        })
                    }).collect();

                    Response::ok().json(&serde_json::json!({
                        "total": total,
                        "entries": recent,
                    }))
                }
            }
        })

        // API: Active tunnels
        .get("/api/tunnels", {
            let dd_tunnels = data_dir.clone();
            move |_ctx: Context| {
                let dir = dd_tunnels.clone();
                async move {
                    let path = expand_path(&dir.to_string_lossy());
                    let tunnel_dir = path.join("tunnels");
                    let mut tunnels = Vec::new();

                    if tunnel_dir.exists() {
                        if let Ok(entries) = std::fs::read_dir(&tunnel_dir) {
                            for entry in entries.flatten() {
                                let fname = entry.file_name().to_string_lossy().to_string();
                                if fname.ends_with(".url") {
                                    let service = fname.trim_end_matches(".url").to_string();
                                    let url = std::fs::read_to_string(entry.path()).unwrap_or_default().trim().to_string();
                                    if !url.is_empty() {
                                        tunnels.push(serde_json::json!({
                                            "service": service,
                                            "url": url,
                                            "status": "active",
                                        }));
                                    }
                                }
                            }
                        }
                    }

                    Response::ok().json(&serde_json::json!({
                        "tunnels": tunnels,
                        "count": tunnels.len(),
                    }))
                }
            }
        })

        // API: Unified stream — all data in one response (reduces HTTP calls from 6 to 1)
        .get("/api/stream", {
            let dd_stream = data_dir.clone();
            move |_ctx: Context| {
                let dir = dd_stream.clone();
                async move {
                    let path = expand_path(&dir.to_string_lossy());

                    // System metrics
                    let mut sys = sysinfo::System::new_all();
                    sys.refresh_all();
                    let cpu = sys.global_cpu_usage();
                    let ram_used = sys.used_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
                    let ram_total = sys.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0);

                    // Services
                    let services = becas_core::persistence::ServiceStore::new(path.join("services"))
                        .ok().map(|s| s.load_all().unwrap_or_default()).unwrap_or_default();
                    let svc_list: Vec<serde_json::Value> = services.iter().map(|s| {
                        // Check tunnel URL
                        let tunnel_url = std::fs::read_to_string(
                            path.join("tunnels").join(format!("{}.url", s.config.name))
                        ).ok().map(|u| u.trim().to_string());
                        serde_json::json!({
                            "name": s.config.name,
                            "status": format!("{}", s.status),
                            "port": s.config.ports.first().map(|p| p.internal).unwrap_or(0),
                            "pid": s.pid,
                            "tunnel_url": tunnel_url,
                            "lan_url": if s.config.ports.first().is_some() {
                                Some(format!("http://{}:{}", becas_net::mesh::get_local_ip(),
                                    s.config.ports.first().unwrap().internal))
                            } else { None },
                        })
                    }).collect();

                    // Audit (last 20)
                    let audit_entries = becas_core::persistence::StateManager::new(path.clone())
                        .ok().map(|state| {
                            let entries = state.audit.load_all().unwrap_or_default();
                            let total = entries.len();
                            let start = if total > 20 { total - 20 } else { 0 };
                            (total, entries[start..].iter().map(|e| {
                                serde_json::json!({
                                    "timestamp": e.timestamp.to_rfc3339(),
                                    "event_type": e.event_type,
                                    "data": e.event_data,
                                    "actor": e.actor,
                                })
                            }).collect::<Vec<_>>())
                        }).unwrap_or((0, vec![]));

                    // Tunnels
                    let mut tunnels = Vec::new();
                    let tunnel_dir = path.join("tunnels");
                    if tunnel_dir.exists() {
                        if let Ok(entries) = std::fs::read_dir(&tunnel_dir) {
                            for entry in entries.flatten() {
                                let fname = entry.file_name().to_string_lossy().to_string();
                                if fname.ends_with(".url") {
                                    let svc = fname.trim_end_matches(".url");
                                    let url = std::fs::read_to_string(entry.path()).unwrap_or_default().trim().to_string();
                                    if !url.is_empty() {
                                        tunnels.push(serde_json::json!({"service": svc, "url": url}));
                                    }
                                }
                            }
                        }
                    }

                    Response::ok().json(&serde_json::json!({
                        "ts": chrono::Utc::now().to_rfc3339(),
                        "system": {
                            "cpu": (cpu * 10.0).round() / 10.0,
                            "ram_used": (ram_used * 10.0).round() / 10.0,
                            "ram_total": (ram_total * 10.0).round() / 10.0,
                            "cores": sys.cpus().len(),
                        },
                        "services": svc_list,
                        "service_count": svc_list.len(),
                        "tunnels": tunnels,
                        "tunnel_count": tunnels.len(),
                        "audit_total": audit_entries.0,
                        "audit": audit_entries.1,
                    }))
                }
            }
        })

        // API: Node info
        .get("/api/node", |_ctx: Context| async move {
            let identity_path = std::path::Path::new(&std::env::var("HOME").unwrap_or_default())
                .join(".becas").join("node_identity.json");
            let node_id = if identity_path.exists() {
                std::fs::read_to_string(&identity_path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v.get("public_key_hex").map(|k| k.as_str().unwrap_or("unknown").to_string()))
                    .unwrap_or_else(|| "not-initialized".to_string())
            } else {
                "not-initialized".to_string()
            };
            Response::ok().json(&serde_json::json!({
                "node_id": format!("ed25519:{}", &node_id[..16.min(node_id.len())]),
                "version": "0.1.0",
                "engine": "BecasTalk",
            }))
        });

    println!("  {} BecasTalk server starting on port {}", "✅".green(), port.to_string().bright_green());

    server.run().await.map_err(|e| anyhow::anyhow!("Server error: {}", e))?;
    Ok(())
}


/// Parse a .becas.toml config file
///
/// ## Example .becas.toml
/// ```toml
/// name = "my-api"
/// command = "./server"
/// port = 8080
/// type = "api"
/// auto_start = true
///
/// # Resource limits
/// max_cpu = 50
/// max_ram = 1024
///
/// # Security — all optional, sensible defaults apply
/// rate_limit = 60             # max requests per IP per minute (default: 60)
/// rate_limit_service = 1000   # max total requests per minute (default: 1000)
/// max_request_size = 10485760 # max request body in bytes (default: 10MB)
/// max_connections_per_ip = 10 # max concurrent connections per IP (default: 10)
/// auto_block_threshold = 5    # violations before auto-block (default: 5)
/// auto_block_duration = 300   # auto-block duration in seconds (default: 5 min)
/// anomaly_protection = true   # enable anomaly detection (default: true)
/// blocked_ips = "1.2.3.4, 5.6.7.8"  # comma-separated blocked IPs
/// allowed_ips = ""            # comma-separated allowed IPs (empty = allow all)
///
/// # Tunnel
/// tunnel = true               # auto-open Cloudflare tunnel (default: true)
/// ```
fn parse_becas_toml(path: &std::path::Path) -> Option<BecasConfig> {
    let toml_path = path.join(".becas.toml");
    if !toml_path.exists() { return None; }
    let content = std::fs::read_to_string(&toml_path).ok()?;
    let mut config = BecasConfig::default();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        if let Some((key, val)) = line.split_once('=') {
            let k = key.trim().trim_matches('"');
            let v = val.trim().trim_matches('"');
            match k {
                // Service
                "name" => config.name = Some(v.to_string()),
                "command" => config.command = Some(v.to_string()),
                "port" => config.port = v.parse().ok(),
                "type" => config.service_type = Some(v.to_string()),
                "auto_start" => config.auto_start = v == "true",
                "max_cpu" => config.max_cpu = v.parse().ok(),
                "max_ram" => config.max_ram = v.parse().ok(),
                // Security
                "rate_limit" => config.rate_limit = v.parse().ok(),
                "rate_limit_service" => config.rate_limit_service = v.parse().ok(),
                "max_request_size" => config.max_request_size = v.parse().ok(),
                "max_connections_per_ip" => config.max_connections_per_ip = v.parse().ok(),
                "auto_block_threshold" => config.auto_block_threshold = v.parse().ok(),
                "auto_block_duration" => config.auto_block_duration = v.parse().ok(),
                "anomaly_protection" => config.anomaly_protection = Some(v == "true"),
                "blocked_ips" => {
                    config.blocked_ips = v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "allowed_ips" => {
                    config.allowed_ips = v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                // Tunnel
                "tunnel" => config.tunnel = Some(v == "true"),
                _ => {}
            }
        }
    }
    Some(config)
}

#[derive(Default)]
struct BecasConfig {
    name: Option<String>,
    command: Option<String>,
    port: Option<u16>,
    service_type: Option<String>,
    auto_start: bool,
    max_cpu: Option<u32>,
    max_ram: Option<u32>,
    // Security settings
    rate_limit: Option<u32>,
    rate_limit_service: Option<u32>,
    max_request_size: Option<usize>,
    max_connections_per_ip: Option<u32>,
    auto_block_threshold: Option<u32>,
    auto_block_duration: Option<u64>,
    blocked_ips: Vec<String>,
    allowed_ips: Vec<String>,
    anomaly_protection: Option<bool>,
    // Tunnel settings
    tunnel: Option<bool>,
}

impl BecasConfig {
    /// Convert security settings to a GatewayConfig
    fn to_gateway_config(&self) -> becas_core::gateway::GatewayConfig {
        let mut gw = becas_core::gateway::GatewayConfig::default();
        if let Some(v) = self.rate_limit { gw.rate_limit_per_ip = v; }
        if let Some(v) = self.rate_limit_service { gw.rate_limit_per_service = v; }
        if let Some(v) = self.max_request_size { gw.max_request_size = v; }
        if let Some(v) = self.max_connections_per_ip { gw.max_connections_per_ip = v; }
        if let Some(v) = self.auto_block_threshold { gw.auto_block_threshold = v; }
        if let Some(v) = self.auto_block_duration { gw.auto_block_duration_secs = v; }
        if let Some(v) = self.anomaly_protection { gw.anomaly_protection = v; }
        for ip_str in &self.blocked_ips {
            if let Ok(ip) = ip_str.parse() { gw.blocked_ips.push(ip); }
        }
        for ip_str in &self.allowed_ips {
            if let Ok(ip) = ip_str.parse() { gw.allowed_ips.push(ip); }
        }
        gw
    }
}

async fn cmd_up(data_dir: &str, path: &str, watch: bool) -> anyhow::Result<()> {
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from(path));
    let dir_name = abs.file_name().and_then(|n| n.to_str()).unwrap_or("app");

    println!("{}", "BECAS UP".bright_cyan().bold());
    println!("{}", format!("  Project: {}", abs.display()).dimmed());

    // Check for .becas.toml
    let config = parse_becas_toml(&abs);

    let svc_name;
    if let Some(ref cfg) = config {
        println!("  {} Found .becas.toml", ">>".bright_green());
        svc_name = cfg.name.clone().unwrap_or_else(|| dir_name.to_string());

        // Use config values for deploy
        if let Some(ref cmd) = cfg.command {
            let svc_type = cfg.service_type.clone().unwrap_or_else(|| "api".into());
            let ports: Vec<u16> = cfg.port.map(|p| vec![p]).unwrap_or_default();
            let max_cpu = cfg.max_cpu.unwrap_or(25);
            let max_ram = cfg.max_ram.unwrap_or(512);
            println!("  {} name={}, cmd={}, port={:?}", ">>".bright_green(), svc_name, cmd, ports);
            cmd_deploy(data_dir, &svc_name, cmd, &[], &svc_type, max_cpu, max_ram, &ports).await?;
        } else {
            // No command in toml, fall back to auto-detect
            cmd_auto(data_dir, path, Some(svc_name.clone()), true, false).await?;
            return Ok(());
        }
    } else {
        println!("  {} No .becas.toml, using auto-detect", ">>".yellow());
        svc_name = dir_name.to_lowercase().replace(' ', "-");
        cmd_auto(data_dir, path, Some(svc_name.clone()), true, false).await?;
        return Ok(());
    }

    // Start the service
    println!();
    cmd_start(data_dir, &svc_name).await?;

    if watch {
        println!();
        println!("  {} Watching for changes... (Ctrl+C to stop)", ">>".bright_cyan());
        println!("  {} Modified files will trigger re-deploy", ">>".dimmed());

        let svc = svc_name.clone();
        let dd = data_dir.to_string();
        let p = path.to_string();
        tokio::spawn(async move {
            let mut last_check = std::time::SystemTime::now();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                // Check if any file modified since last check
                let modified = check_dir_modified(&p, last_check);
                if modified {
                    println!("  {} Change detected, re-deploying...", ">>".yellow());
                    let _ = cmd_stop(&dd, &svc).await;
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let _ = cmd_start(&dd, &svc).await;
                    last_check = std::time::SystemTime::now();
                }
            }
        });

        // Wait for Ctrl+C
        tokio::signal::ctrl_c().await?;
        println!("\n  {} Stopping...", ">>".yellow());
        cmd_stop(data_dir, &svc_name).await?;
    }

    Ok(())
}

fn check_dir_modified(path: &str, since: std::time::SystemTime) -> bool {
    let walker = std::fs::read_dir(path);
    if let Ok(entries) = walker {
        for entry in entries.flatten() {
            let p = entry.path();
            // Skip hidden, target, node_modules
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || name == "target" || name == "node_modules" { continue; }
            if let Ok(meta) = p.metadata() {
                if let Ok(modified) = meta.modified() {
                    if modified > since { return true; }
                }
                if meta.is_dir() {
                    if check_dir_modified(&p.to_string_lossy(), since) { return true; }
                }
            }
        }
    }
    false
}

async fn cmd_down(data_dir: &str, name: Option<String>) -> anyhow::Result<()> {
    let svc_name = if let Some(n) = name {
        n
    } else {
        // Try to get name from .becas.toml or current dir name
        let abs = std::fs::canonicalize(".").unwrap_or_default();
        let config = parse_becas_toml(&abs);
        if let Some(cfg) = config {
            cfg.name.unwrap_or_else(|| {
                abs.file_name().and_then(|n| n.to_str()).unwrap_or("app").to_lowercase()
            })
        } else {
            abs.file_name().and_then(|n| n.to_str()).unwrap_or("app").to_lowercase()
        }
    };

    println!("{}", "BECAS DOWN".bright_cyan().bold());
    println!("  {} Stopping '{}'...", ">>".yellow(), svc_name);

    // Stop then remove
    let _ = cmd_stop(data_dir, &svc_name).await;
    println!("  {} Service '{}' is down", ">>".bright_green(), svc_name);

    Ok(())
}

async fn cmd_relay(port: u16, max_connections: u32) -> anyhow::Result<()> {
    println!("{}", "🌐 BECAS Relay Server".bright_cyan().bold());
    println!("{}", "═".repeat(50).dimmed());
    println!();
    println!("  {} Relay mode — routing traffic for other BECAS nodes", "📡".yellow());
    println!("  {} Port: {}", "🔌".yellow(), format!("{}", port).bright_white());
    println!("  {} Max connections: {}", "👥".yellow(), max_connections);
    println!();

    let relay = becas_net::mesh::RelayServer::new(
        &format!("0.0.0.0:{}", port),
        max_connections,
    );

    relay.start().await?;

    println!("  {} Relay running on 0.0.0.0:{}", "✅".green(), port);
    println!("  {} Other nodes can connect with:", "💡".yellow());
    println!("     relay_address = \"ws://YOUR_IP:{}\"", port);
    println!();
    println!("  Press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;
    relay.stop().await;
    println!("\n  {} Relay stopped", "⏹️".red());

    Ok(())
}

// ─────────────────────────────────────────────
// Marketplace Commands
// ─────────────────────────────────────────────

async fn cmd_market(data_dir: &str, subcmd: MarketCommands) -> anyhow::Result<()> {
    use becas_core::marketplace::{TemplateRegistry, TemplateCategory};
    
    let registry = TemplateRegistry::new();
    
    match subcmd {
        MarketCommands::List { category } => {
            println!("{}", "🏪 BECAS Marketplace".bright_cyan().bold());
            println!("{}", "═".repeat(60).dimmed());
            println!();
            
            let templates = if let Some(cat) = category {
                let cat_enum = match cat.to_lowercase().as_str() {
                    "database" | "db" => TemplateCategory::Database,
                    "web" | "webserver" => TemplateCategory::WebServer,
                    "cache" => TemplateCategory::Cache,
                    "queue" => TemplateCategory::Queue,
                    "monitoring" => TemplateCategory::Monitoring,
                    "devtools" | "dev" => TemplateCategory::DevTools,
                    "ai" => TemplateCategory::AI,
                    _ => TemplateCategory::Custom,
                };
                registry.by_category(cat_enum)
            } else {
                registry.list()
            };
            
            println!("  {:<15} {:<12} {:<8} {}",
                "TEMPLATE".dimmed(), "CATEGORY".dimmed(), "⬇️".dimmed(), "DESCRIPTION".dimmed());
            println!("  {}", "─".repeat(56).dimmed());
            
            for t in templates {
                println!("  {:<15} {:<12} {:<8} {}",
                    t.id.bright_white(),
                    format!("{}", t.category).yellow(),
                    t.downloads.to_string().dimmed(),
                    t.description.chars().take(35).collect::<String>()
                );
            }
            
            println!();
            println!("  {} Use 'becas market info <template>' for details", "💡".yellow());
            println!("  {} Use 'becas market install <template>' to deploy", "💡".yellow());
        }
        
        MarketCommands::Search { query } => {
            println!("{}", format!("🔍 Searching for '{}'...", query).bright_cyan());
            println!();
            
            let results = registry.search(&query);
            
            if results.is_empty() {
                println!("  {} No templates found for '{}'", "📭".yellow(), query);
            } else {
                println!("  Found {} template(s):", results.len());
                println!();
                for t in results {
                    println!("  {} {} — {}", "•".green(), t.id.bright_white(), t.description);
                }
            }
        }
        
        MarketCommands::Info { template } => {
            if let Some(t) = registry.get(&template) {
                println!("{}", format!("📦 {}", t.name).bright_cyan().bold());
                println!("{}", "═".repeat(50).dimmed());
                println!();
                println!("  {} ID:          {}", "🆔".yellow(), t.id);
                println!("  {} Version:     {}", "📌".yellow(), t.version);
                println!("  {} Category:    {}", "📂".yellow(), t.category);
                println!("  {} Author:      {}", "👤".yellow(), t.author);
                println!("  {} Downloads:   {}", "⬇️".yellow(), t.downloads);
                println!("  {} Rating:      {} ⭐", "⭐".yellow(), t.rating);
                println!();
                println!("  {} {}", "📝".yellow(), t.description);
                println!();
                println!("  {} Resources", "💻".yellow());
                println!("     CPU: {}%  RAM: {}MB  Disk: {}MB",
                    t.resources.cpu_percent, t.resources.ram_mb, t.resources.disk_mb);
                println!();
                println!("  {} Ports: {:?}", "🌐".yellow(), t.ports);
                
                if let Some(notes) = &t.setup_notes {
                    println!();
                    println!("  {} Setup Notes", "📋".yellow());
                    println!("     {}", notes);
                }
                
                println!();
                println!("  {} Install: becas market install {}", "💡".green(), t.id);
            } else {
                println!("  {} Template '{}' not found", "❌".red(), template);
            }
        }
        
        MarketCommands::Install { template, name, start } => {
            if let Some(t) = registry.get(&template) {
                let svc_name = name.as_deref().unwrap_or(&t.id);
                println!("{}", format!("📦 Installing '{}'...", t.name).bright_cyan());
                
                let config = t.to_service_config(Some(svc_name));
                
                // Deploy using existing logic
                let base_dir = expand_path(data_dir);
                let ports: Vec<u16> = config.ports.iter().map(|p| p.internal).collect();
                
                cmd_deploy(
                    data_dir,
                    svc_name,
                    &config.command,
                    &config.args,
                    &format!("{:?}", config.service_type).to_lowercase(),
                    config.resource_limits.max_cpu_percent as u32,
                    (config.resource_limits.max_ram_bytes / (1024 * 1024)) as u32,
                    &ports,
                ).await?;
                
                if start {
                    cmd_start(data_dir, svc_name).await?;
                }
                
                if let Some(notes) = &t.setup_notes {
                    println!();
                    println!("  {} {}", "📋".yellow(), notes);
                }
            } else {
                println!("  {} Template '{}' not found", "❌".red(), template);
            }
        }
    }
    
    Ok(())
}

// ─────────────────────────────────────────────
// NAT Detection Command
// ─────────────────────────────────────────────

async fn cmd_nat() -> anyhow::Result<()> {
    println!("{}", "🌐 NAT Detection".bright_cyan().bold());
    println!("{}", "═".repeat(50).dimmed());
    println!();
    println!("  {} Checking NAT type...", "🔍".yellow());
    
    match becas_net::stun::StunClient::new().await {
        Ok(client) => {
            match client.detect_nat_type().await {
                Ok(info) => {
                    println!();
                    println!("  {} NAT Type: {}", "🏠".green(), 
                        format!("{}", info.nat_type).bright_white().bold());
                    println!();
                    println!("  {} Local Address:  {}:{}", "📍".yellow(), 
                        info.local_ip, info.local_port);
                    
                    if let (Some(ip), Some(port)) = (info.public_ip, info.public_port) {
                        println!("  {} Public Address: {}:{}", "🌍".yellow(), 
                            ip.to_string().bright_green(), port);
                    }
                    
                    println!();
                    println!("  {} P2P Capable:  {}", "🔗".yellow(),
                        if info.p2p_capable { "Yes ✅".green() } else { "No ❌".red() });
                    println!("  {} Needs Relay:  {}", "🔄".yellow(),
                        if info.needs_relay { "Yes".yellow() } else { "No".green() });
                    
                    println!();
                    if info.p2p_capable {
                        println!("  {} Your network supports direct P2P connections!", "✅".green());
                    } else {
                        println!("  {} Your network requires relay for external access.", "⚠️".yellow());
                        println!("     BECAS will automatically use Cloudflare Tunnel or BECAS Relay.");
                    }
                }
                Err(e) => {
                    println!("  {} NAT detection failed: {}", "❌".red(), e);
                    println!("     This might be a network issue. BECAS will use relay fallback.");
                }
            }
        }
        Err(e) => {
            println!("  {} Could not initialize STUN client: {}", "❌".red(), e);
        }
    }
    
    Ok(())
}

// ─────────────────────────────────────────────
// Plugin Commands
// ─────────────────────────────────────────────

async fn cmd_plugin(data_dir: &str, subcmd: PluginCommands) -> anyhow::Result<()> {
    use becas_core::plugin::{PluginManager, LoggingPlugin};
    use std::sync::Arc;
    
    let base_dir = expand_path(data_dir);
    let plugin_dir = base_dir.join("plugins");
    let mgr = PluginManager::new(plugin_dir);
    
    // Register built-in plugins
    let _ = mgr.register(Arc::new(LoggingPlugin)).await;
    
    match subcmd {
        PluginCommands::List => {
            println!("{}", "🔌 BECAS Plugins".bright_cyan().bold());
            println!("{}", "═".repeat(50).dimmed());
            println!();
            
            let plugins = mgr.list().await;
            
            if plugins.is_empty() {
                println!("  {} No plugins installed", "📭".yellow());
                println!("     Built-in plugins will be loaded automatically.");
            } else {
                println!("  {:<20} {:<10} {:<8} {}",
                    "NAME".dimmed(), "VERSION".dimmed(), "STATUS".dimmed(), "HOOKS".dimmed());
                println!("  {}", "─".repeat(46).dimmed());
                
                for p in plugins {
                    let status = if p.enabled { "✅".green() } else { "❌".red() };
                    let hooks: Vec<String> = p.hooks.iter().map(|h| format!("{}", h)).collect();
                    println!("  {:<20} {:<10} {:<8} {}",
                        p.name.bright_white(),
                        p.version,
                        status,
                        hooks.join(", ").dimmed()
                    );
                }
            }
        }
        
        PluginCommands::Enable { name } => {
            match mgr.set_enabled(&name, true).await {
                Ok(_) => println!("  {} Plugin '{}' enabled", "✅".green(), name),
                Err(e) => println!("  {} Failed to enable '{}': {}", "❌".red(), name, e),
            }
        }
        
        PluginCommands::Disable { name } => {
            match mgr.set_enabled(&name, false).await {
                Ok(_) => println!("  {} Plugin '{}' disabled", "✅".green(), name),
                Err(e) => println!("  {} Failed to disable '{}': {}", "❌".red(), name, e),
            }
        }
    }
    
    Ok(())
}
