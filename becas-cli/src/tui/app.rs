//! Application state for TUI

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Active screen/tab
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Services,
    Marketplace,
    Logs,
    Network,
    Help,
}

impl Screen {
    pub fn title(&self) -> &str {
        match self {
            Screen::Dashboard => "Dashboard",
            Screen::Services => "Services",
            Screen::Marketplace => "Marketplace",
            Screen::Logs => "Logs",
            Screen::Network => "Network",
            Screen::Help => "Help",
        }
    }

    pub fn all() -> Vec<Screen> {
        vec![
            Screen::Dashboard,
            Screen::Services,
            Screen::Marketplace,
            Screen::Logs,
            Screen::Network,
            Screen::Help,
        ]
    }
}

/// Service info for display
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub status: String,
    pub service_type: String,
    pub pid: Option<u32>,
    pub cpu_limit: u32,
    pub ram_limit_mb: u64,
    pub ports: Vec<u16>,
    pub uptime_secs: u64,
}

/// Template info for display
#[derive(Debug, Clone)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub downloads: u64,
    pub rating: f32,
}

/// System metrics
#[derive(Debug, Clone, Default)]
pub struct SystemMetrics {
    pub cpu_usage: f32,
    pub cpu_cores: usize,
    pub ram_used_mb: u64,
    pub ram_total_mb: u64,
    pub services_running: usize,
    pub services_total: usize,
}

/// Log entry
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub service: String,
    pub level: String,
    pub message: String,
}

/// CPU history for sparkline
pub const HISTORY_SIZE: usize = 60;

/// Main application state
pub struct App {
    /// Data directory
    pub data_dir: String,
    /// Current screen
    pub screen: Screen,
    /// Is app running
    pub running: bool,
    /// Services list
    pub services: Vec<ServiceInfo>,
    /// Selected service index
    pub selected_service: usize,
    /// Marketplace templates
    pub templates: Vec<TemplateInfo>,
    /// Selected template index
    pub selected_template: usize,
    /// System metrics
    pub metrics: SystemMetrics,
    /// Log entries
    pub logs: Vec<LogEntry>,
    /// Log scroll position
    pub log_scroll: usize,
    /// Selected log service filter
    pub log_filter: Option<String>,
    /// Show popup
    pub popup: Option<Popup>,
    /// Input mode
    pub input_mode: InputMode,
    /// Input buffer
    pub input: String,
    /// Tick counter (for animations)
    pub tick: u64,
    /// CPU usage history for sparkline
    pub cpu_history: Vec<u64>,
    /// RAM usage history for sparkline
    pub ram_history: Vec<u64>,
    /// Status message (bottom bar)
    pub status_message: Option<(String, std::time::Instant)>,
    /// NAT info cache
    pub nat_info: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Popup {
    Confirm { title: String, message: String, action: PopupAction },
    Info { title: String, message: String },
    Input { title: String, action: PopupAction },
    /// New service creation form
    NewService(NewServiceForm),
    /// Tunnel/URL info
    TunnelInfo { service: String, url: String },
}

/// Form for creating a new service
#[derive(Debug, Clone, Default)]
pub struct NewServiceForm {
    pub name: String,
    pub command: String,
    pub args: String,
    pub port: String,
    pub active_field: usize, // 0=name, 1=command, 2=args, 3=port
}

impl NewServiceForm {
    pub fn field_count() -> usize { 4 }
    
    pub fn field_name(&self, idx: usize) -> &str {
        match idx {
            0 => "Name",
            1 => "Command",
            2 => "Args",
            3 => "Port",
            _ => "",
        }
    }
    
    pub fn field_value(&self, idx: usize) -> &str {
        match idx {
            0 => &self.name,
            1 => &self.command,
            2 => &self.args,
            3 => &self.port,
            _ => "",
        }
    }
    
    pub fn field_value_mut(&mut self, idx: usize) -> &mut String {
        match idx {
            0 => &mut self.name,
            1 => &mut self.command,
            2 => &mut self.args,
            3 => &mut self.port,
            _ => &mut self.name,
        }
    }
    
    pub fn is_valid(&self) -> bool {
        !self.name.trim().is_empty() && !self.command.trim().is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum PopupAction {
    StartService(String),
    StopService(String),
    InstallTemplate(String),
    CreateService,
    OpenTunnel(String),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Search,
}

impl App {
    pub fn new(data_dir: String) -> Self {
        // Load templates from marketplace
        let templates = Self::load_templates();

        Self {
            data_dir,
            screen: Screen::Dashboard,
            running: true,
            services: Vec::new(),
            selected_service: 0,
            templates,
            selected_template: 0,
            metrics: SystemMetrics::default(),
            logs: Vec::new(),
            log_scroll: 0,
            log_filter: None,
            popup: None,
            input_mode: InputMode::Normal,
            input: String::new(),
            tick: 0,
            cpu_history: vec![0; HISTORY_SIZE],
            ram_history: vec![0; HISTORY_SIZE],
            status_message: None,
            nat_info: None,
        }
    }

    fn load_templates() -> Vec<TemplateInfo> {
        use becas_core::marketplace::TemplateRegistry;
        let registry = TemplateRegistry::new();
        registry.list().iter().map(|t| TemplateInfo {
            id: t.id.clone(),
            name: t.name.clone(),
            category: format!("{}", t.category),
            description: t.description.clone(),
            downloads: t.downloads,
            rating: t.rating,
        }).collect()
    }

    /// Load services from persistence
    pub async fn load_services(&mut self) {
        let base_dir = Self::expand_path(&self.data_dir);
        if let Ok(state) = becas_core::persistence::StateManager::new(base_dir) {
            if let Ok(services) = state.services.load_all() {
                self.services = services.iter().map(|svc| {
                    ServiceInfo {
                        name: svc.config.name.clone(),
                        status: format!("{}", svc.status),
                        service_type: format!("{}", svc.config.service_type),
                        pid: svc.pid,
                        cpu_limit: svc.config.resource_limits.max_cpu_percent as u32,
                        ram_limit_mb: svc.config.resource_limits.max_ram_bytes / (1024 * 1024),
                        ports: svc.config.ports.iter().map(|p| p.internal).collect(),
                        uptime_secs: svc.total_uptime_secs,
                    }
                }).collect();
                self.metrics.services_total = self.services.len();
                self.metrics.services_running = self.services.iter()
                    .filter(|s| s.status == "Running").count();
            }
        }
    }

    /// Load system metrics
    pub fn load_system_metrics(&mut self) {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        
        self.metrics.cpu_usage = sys.global_cpu_usage();
        self.metrics.cpu_cores = sys.cpus().len();
        self.metrics.ram_used_mb = sys.used_memory() / 1_048_576;
        self.metrics.ram_total_mb = sys.total_memory() / 1_048_576;
        
        // Update history for sparklines
        self.cpu_history.remove(0);
        self.cpu_history.push(self.metrics.cpu_usage as u64);
        
        let ram_percent = if self.metrics.ram_total_mb > 0 {
            (self.metrics.ram_used_mb * 100 / self.metrics.ram_total_mb) as u64
        } else { 0 };
        self.ram_history.remove(0);
        self.ram_history.push(ram_percent);
    }

    /// Load logs from service sandbox
    pub fn load_logs(&mut self) {
        let base_dir = Self::expand_path(&self.data_dir);
        self.logs.clear();
        
        // Load logs for all services or filtered service
        for svc in &self.services {
            // Skip if filter is set and doesn't match
            if let Some(ref filter) = self.log_filter {
                if &svc.name != filter {
                    continue;
                }
            }
            
            // Find sandbox directory
            let sandboxes_dir = base_dir.join("sandboxes");
            if !sandboxes_dir.exists() {
                continue;
            }
            
            // Look for service's sandbox by checking service files
            if let Ok(entries) = std::fs::read_dir(&sandboxes_dir) {
                for entry in entries.flatten() {
                    let sandbox_path = entry.path();
                    let stdout_log = sandbox_path.join("logs").join("stdout.log");
                    let stderr_log = sandbox_path.join("logs").join("stderr.log");
                    
                    // Read stdout
                    if stdout_log.exists() {
                        if let Ok(content) = std::fs::read_to_string(&stdout_log) {
                            for line in content.lines().rev().take(50) {
                                self.logs.push(LogEntry {
                                    timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                                    service: svc.name.clone(),
                                    level: "INFO".to_string(),
                                    message: line.to_string(),
                                });
                            }
                        }
                    }
                    
                    // Read stderr
                    if stderr_log.exists() {
                        if let Ok(content) = std::fs::read_to_string(&stderr_log) {
                            for line in content.lines().rev().take(20) {
                                if !line.trim().is_empty() {
                                    self.logs.push(LogEntry {
                                        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                                        service: svc.name.clone(),
                                        level: "ERROR".to_string(),
                                        message: line.to_string(),
                                    });
                                }
                            }
                        }
                    }
                    break; // Only first matching sandbox
                }
            }
        }
        
        // Sort by timestamp (newest first for display)
        self.logs.reverse();
    }

    /// Set status message (auto-clears after 3 seconds)
    pub fn set_status(&mut self, msg: &str) {
        self.status_message = Some((msg.to_string(), std::time::Instant::now()));
    }

    /// Clear expired status message
    pub fn clear_expired_status(&mut self) {
        if let Some((_, instant)) = &self.status_message {
            if instant.elapsed().as_secs() > 3 {
                self.status_message = None;
            }
        }
    }

    /// Handle tick event
    pub async fn on_tick(&mut self) {
        self.tick += 1;
        
        // Clear expired status messages
        self.clear_expired_status();
        
        // Refresh metrics every 2 seconds (8 ticks at 250ms)
        if self.tick % 8 == 0 {
            self.load_system_metrics();
        }
        
        // Refresh services every 5 seconds
        if self.tick % 20 == 0 {
            self.load_services().await;
        }
        
        // Refresh logs every 3 seconds when on logs screen
        if self.tick % 12 == 0 && self.screen == Screen::Logs {
            self.load_logs();
        }
    }

    /// Handle key event, returns true if should quit
    pub async fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Handle popup first
        if self.popup.is_some() {
            return self.handle_popup_key(key).await;
        }

        // Handle input mode
        if self.input_mode == InputMode::Search {
            return self.handle_search_key(key);
        }

        match key.code {
            // Quit
            KeyCode::Char('q') | KeyCode::Esc => {
                if key.modifiers.contains(KeyModifiers::CONTROL) || key.code == KeyCode::Char('q') {
                    return true;
                }
            }
            
            // Tab navigation
            KeyCode::Tab => {
                self.next_screen();
            }
            KeyCode::BackTab => {
                self.prev_screen();
            }
            
            // Number keys for quick screen switch
            KeyCode::Char('1') => self.screen = Screen::Dashboard,
            KeyCode::Char('2') => self.screen = Screen::Services,
            KeyCode::Char('3') => self.screen = Screen::Marketplace,
            KeyCode::Char('4') => self.screen = Screen::Logs,
            KeyCode::Char('5') => self.screen = Screen::Network,
            KeyCode::Char('?') => self.screen = Screen::Help,
            
            // Screen-specific keys
            _ => {
                match self.screen {
                    Screen::Dashboard => self.handle_dashboard_key(key).await,
                    Screen::Services => self.handle_services_key(key).await,
                    Screen::Marketplace => self.handle_marketplace_key(key).await,
                    Screen::Logs => self.handle_logs_key(key),
                    Screen::Network => {}
                    Screen::Help => {}
                }
            }
        }

        false
    }

    fn next_screen(&mut self) {
        let screens = Screen::all();
        let idx = screens.iter().position(|s| *s == self.screen).unwrap_or(0);
        self.screen = screens[(idx + 1) % screens.len()];
    }

    fn prev_screen(&mut self) {
        let screens = Screen::all();
        let idx = screens.iter().position(|s| *s == self.screen).unwrap_or(0);
        self.screen = screens[(idx + screens.len() - 1) % screens.len()];
    }

    async fn handle_dashboard_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('r') => {
                self.load_services().await;
                self.load_system_metrics();
            }
            _ => {}
        }
    }

    async fn handle_services_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_service > 0 {
                    self.selected_service -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_service < self.services.len().saturating_sub(1) {
                    self.selected_service += 1;
                }
            }
            KeyCode::Enter | KeyCode::Char('s') => {
                // Start/Stop service
                if let Some(svc) = self.services.get(self.selected_service) {
                    let action = if svc.status == "Running" {
                        PopupAction::StopService(svc.name.clone())
                    } else {
                        PopupAction::StartService(svc.name.clone())
                    };
                    let action_text = if svc.status == "Running" { "stop" } else { "start" };
                    self.popup = Some(Popup::Confirm {
                        title: format!("{} Service", if svc.status == "Running" { "Stop" } else { "Start" }),
                        message: format!("Do you want to {} '{}'?", action_text, svc.name),
                        action,
                    });
                }
            }
            KeyCode::Char('l') => {
                // View logs for selected service
                if let Some(svc) = self.services.get(self.selected_service) {
                    self.log_filter = Some(svc.name.clone());
                    self.screen = Screen::Logs;
                }
            }
            KeyCode::Char('n') => {
                // New service form
                self.popup = Some(Popup::NewService(NewServiceForm::default()));
            }
            KeyCode::Char('t') => {
                // Open tunnel for selected service
                if let Some(svc) = self.services.get(self.selected_service) {
                    if svc.status == "Running" && !svc.ports.is_empty() {
                        self.popup = Some(Popup::Confirm {
                            title: "🌐 Open Tunnel".to_string(),
                            message: format!("Open public tunnel for '{}'?\nThis will create a public URL.", svc.name),
                            action: PopupAction::OpenTunnel(svc.name.clone()),
                        });
                    } else {
                        self.popup = Some(Popup::Info {
                            title: "Cannot Open Tunnel".to_string(),
                            message: "Service must be running and have ports configured.".to_string(),
                        });
                    }
                }
            }
            KeyCode::Char('r') => {
                self.load_services().await;
            }
            _ => {}
        }
    }

    async fn handle_marketplace_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_template > 0 {
                    self.selected_template -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_template < self.templates.len().saturating_sub(1) {
                    self.selected_template += 1;
                }
            }
            KeyCode::Enter | KeyCode::Char('i') => {
                // Install template
                if let Some(tmpl) = self.templates.get(self.selected_template) {
                    self.popup = Some(Popup::Confirm {
                        title: "Install Template".to_string(),
                        message: format!("Install '{}' and start service?", tmpl.name),
                        action: PopupAction::InstallTemplate(tmpl.id.clone()),
                    });
                }
            }
            KeyCode::Char('/') => {
                self.input_mode = InputMode::Search;
                self.input.clear();
            }
            _ => {}
        }
    }

    fn handle_logs_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.log_scroll > 0 {
                    self.log_scroll -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.log_scroll += 1;
            }
            KeyCode::Char('c') => {
                // Clear filter
                self.log_filter = None;
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.log_scroll = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.log_scroll = self.logs.len().saturating_sub(1);
            }
            _ => {}
        }
    }

    async fn handle_popup_key(&mut self, key: KeyEvent) -> bool {
        // Handle NewService form specially
        if let Some(Popup::NewService(ref mut form)) = self.popup {
            match key.code {
                KeyCode::Esc => {
                    self.popup = None;
                }
                KeyCode::Tab | KeyCode::Down => {
                    form.active_field = (form.active_field + 1) % NewServiceForm::field_count();
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.active_field = (form.active_field + NewServiceForm::field_count() - 1) % NewServiceForm::field_count();
                }
                KeyCode::Backspace => {
                    form.field_value_mut(form.active_field).pop();
                }
                KeyCode::Char(c) => {
                    form.field_value_mut(form.active_field).push(c);
                }
                KeyCode::Enter => {
                    if form.is_valid() {
                        let form_clone = form.clone();
                        self.popup = None;
                        self.execute_action(PopupAction::CreateService).await;
                        // Store form data for create
                        self.create_service_from_form(form_clone).await;
                    }
                }
                _ => {}
            }
            return false;
        }

        // Handle TunnelInfo
        if let Some(Popup::TunnelInfo { .. }) = &self.popup {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.popup = None;
                }
                _ => {}
            }
            return false;
        }

        // Handle other popups
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') => {
                self.popup = None;
            }
            KeyCode::Enter | KeyCode::Char('y') => {
                if let Some(popup) = self.popup.take() {
                    match popup {
                        Popup::Confirm { action, .. } => {
                            self.execute_action(action).await;
                        }
                        Popup::Info { .. } => {
                            // Just close
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        false
    }

    fn handle_search_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
                self.input.clear();
            }
            KeyCode::Enter => {
                // TODO: Apply search filter
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) => {
                self.input.push(c);
            }
            _ => {}
        }
        false
    }

    async fn execute_action(&mut self, action: PopupAction) {
        match action {
            PopupAction::StartService(name) => {
                self.popup = None;
                self.set_status(&format!("Starting '{}'...", name));
                
                match self.real_start_service(&name).await {
                    Ok(_) => {
                        self.set_status(&format!("✅ Service '{}' started!", name));
                        self.load_services().await;
                    }
                    Err(e) => {
                        self.popup = Some(Popup::Info {
                            title: "❌ Start Failed".to_string(),
                            message: format!("Failed to start '{}': {}", name, e),
                        });
                    }
                }
            }
            PopupAction::StopService(name) => {
                self.popup = None;
                self.set_status(&format!("Stopping '{}'...", name));
                
                match self.real_stop_service(&name).await {
                    Ok(_) => {
                        self.set_status(&format!("✅ Service '{}' stopped!", name));
                        self.load_services().await;
                    }
                    Err(e) => {
                        self.popup = Some(Popup::Info {
                            title: "❌ Stop Failed".to_string(),
                            message: format!("Failed to stop '{}': {}", name, e),
                        });
                    }
                }
            }
            PopupAction::InstallTemplate(id) => {
                self.popup = None;
                self.set_status(&format!("Installing '{}'...", id));
                
                match self.real_install_template(&id).await {
                    Ok(service_name) => {
                        self.set_status(&format!("✅ Template '{}' installed as '{}'!", id, service_name));
                        self.load_services().await;
                        // Switch to services screen
                        self.screen = Screen::Services;
                    }
                    Err(e) => {
                        self.popup = Some(Popup::Info {
                            title: "❌ Install Failed".to_string(),
                            message: format!("Failed to install '{}': {}", id, e),
                        });
                    }
                }
            }
            PopupAction::CreateService => {
                // Handled separately in create_service_from_form
            }
            PopupAction::OpenTunnel(name) => {
                self.popup = None;
                self.set_status(&format!("Opening tunnel for '{}'...", name));
                
                match self.real_open_tunnel(&name).await {
                    Ok(url) => {
                        self.popup = Some(Popup::TunnelInfo {
                            service: name.clone(),
                            url: url.clone(),
                        });
                        self.set_status(&format!("✅ Tunnel opened: {}", url));
                    }
                    Err(e) => {
                        self.popup = Some(Popup::Info {
                            title: "❌ Tunnel Failed".to_string(),
                            message: format!("Failed to open tunnel: {}", e),
                        });
                    }
                }
            }
            PopupAction::None => {}
        }
    }

    /// Create a new service from form data
    async fn create_service_from_form(&mut self, form: NewServiceForm) {
        self.set_status(&format!("Creating service '{}'...", form.name));
        
        match self.real_create_service(&form).await {
            Ok(_) => {
                self.set_status(&format!("✅ Service '{}' created!", form.name));
                self.load_services().await;
            }
            Err(e) => {
                self.popup = Some(Popup::Info {
                    title: "❌ Create Failed".to_string(),
                    message: format!("Failed to create service: {}", e),
                });
            }
        }
    }

    /// Actually create a new service
    async fn real_create_service(&self, form: &NewServiceForm) -> anyhow::Result<()> {
        let base_dir = Self::expand_path(&self.data_dir);
        
        // Parse port
        let ports: Vec<u16> = if form.port.trim().is_empty() {
            vec![]
        } else {
            form.port.split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect()
        };
        
        // Parse args
        let args: Vec<String> = if form.args.trim().is_empty() {
            vec![]
        } else {
            form.args.split_whitespace().map(|s| s.to_string()).collect()
        };
        
        // Create service manager
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

        // Create config
        let port_mappings: Vec<becas_core::sandbox::PortMapping> = ports.iter().map(|p| {
            becas_core::sandbox::PortMapping {
                internal: *p,
                protocol: becas_core::sandbox::Protocol::Tcp,
            }
        }).collect();

        let config = becas_core::service::ServiceConfig {
            name: form.name.trim().to_string(),
            command: form.command.trim().to_string(),
            args,
            ports: port_mappings,
            ..Default::default()
        };

        // Deploy
        svc_mgr.deploy(config).await?;
        
        Ok(())
    }

    /// Open a tunnel for a service and get public URL
    async fn real_open_tunnel(&self, service_name: &str) -> anyhow::Result<String> {
        let base_dir = Self::expand_path(&self.data_dir);
        
        // Find service port
        let state = becas_core::persistence::StateManager::new(base_dir.clone())?;
        let services = state.services.load_all()?;
        let svc = services.iter()
            .find(|s| s.config.name == service_name)
            .ok_or_else(|| anyhow::anyhow!("Service not found"))?;
        
        let port = svc.config.ports.first()
            .ok_or_else(|| anyhow::anyhow!("Service has no ports"))?
            .internal;
        
        // Try Cloudflare tunnel first
        let cf = becas_net::tunnel::cloudflare::CloudflareTunnel::new(base_dir.clone());
        match cf.open(service_name, port).await {
            Ok(url) => {
                // Save tunnel URL
                let tunnel_file = base_dir.join("tunnels").join(format!("{}.url", service_name));
                if let Some(parent) = tunnel_file.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&tunnel_file, &url);
                return Ok(url);
            }
            Err(cf_err) => {
                // Fallback: generate BECAS relay URL
                let node_id = Self::get_node_id(&base_dir);
                let relay_url = format!("becas://{}.{}.relay.becas.local:{}", 
                    service_name, node_id, port);
                
                // Save relay URL
                let tunnel_file = base_dir.join("tunnels").join(format!("{}.url", service_name));
                if let Some(parent) = tunnel_file.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&tunnel_file, &relay_url);
                
                // If cloudflare failed, mention it
                tracing::warn!("Cloudflare tunnel failed: {}, using relay URL", cf_err);
                return Ok(relay_url);
            }
        }
    }

    fn get_node_id(base_dir: &PathBuf) -> String {
        let crypto_dir = base_dir.join("crypto");
        if let Ok(engine) = becas_core::crypto::CryptoEngine::new(crypto_dir) {
            engine.node_identity().id.chars().take(8).collect()
        } else {
            "local".to_string()
        }
    }

    /// Actually start a service using becas-core
    async fn real_start_service(&self, name: &str) -> anyhow::Result<()> {
        let base_dir = Self::expand_path(&self.data_dir);
        
        // Create service manager
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

        // Find service by name
        let services = svc_mgr.list().await;
        let svc = services.iter()
            .find(|s| s.config.name == name)
            .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", name))?;

        // Start it
        svc_mgr.start(&svc.id).await?;
        
        Ok(())
    }

    /// Actually stop a service using becas-core
    async fn real_stop_service(&self, name: &str) -> anyhow::Result<()> {
        let base_dir = Self::expand_path(&self.data_dir);
        
        // Create service manager
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

        // Find service by name
        let services = svc_mgr.list().await;
        let svc = services.iter()
            .find(|s| s.config.name == name)
            .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", name))?;

        // Stop it
        svc_mgr.stop(&svc.id).await?;
        
        Ok(())
    }

    /// Actually install a template using marketplace and deploy
    async fn real_install_template(&self, template_id: &str) -> anyhow::Result<String> {
        use becas_core::marketplace::TemplateRegistry;
        
        let registry = TemplateRegistry::new();
        let template = registry.get(template_id)
            .ok_or_else(|| anyhow::anyhow!("Template '{}' not found", template_id))?;
        
        let service_name = template_id.to_string();
        let config = template.to_service_config(Some(&service_name));
        
        let base_dir = Self::expand_path(&self.data_dir);
        
        // Create service manager
        let sandbox_mgr = Arc::new(
            becas_core::sandbox::SandboxManager::new(base_dir.join("sandboxes"))
        );
        let resource_gov = Arc::new(
            becas_core::resource::ResourceGovernor::new(config.resource_limits.clone())
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

        // Deploy the service
        let _service_id = svc_mgr.deploy(config).await?;
        
        Ok(service_name)
    }

    fn expand_path(path: &str) -> PathBuf {
        if path.starts_with('~') {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(path.replacen('~', &home, 1));
            }
        }
        PathBuf::from(path)
    }
}
