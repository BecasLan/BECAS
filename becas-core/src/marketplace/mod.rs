//! # BECAS Marketplace
//!
//! Pre-built service templates for quick deployment.
//! 
//! ## Usage
//! ```bash
//! becas market list              # Show available templates
//! becas market search postgres   # Search templates
//! becas market install postgres  # Deploy from template
//! ```

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::service::{ServiceConfig, ServiceType};
use crate::resource::ResourceLimits;
use crate::sandbox::PortMapping;

// ─────────────────────────────────────────────
// Template Definition
// ─────────────────────────────────────────────

/// A service template from the marketplace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    /// Unique template ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Category
    pub category: TemplateCategory,
    /// Description
    pub description: String,
    /// Version
    pub version: String,
    /// Author
    pub author: String,
    /// Tags for search
    pub tags: Vec<String>,
    /// Docker image (if applicable)
    pub docker_image: Option<String>,
    /// Command to run
    pub command: String,
    /// Default arguments
    pub args: Vec<String>,
    /// Default environment variables
    pub env: HashMap<String, String>,
    /// Default ports
    pub ports: Vec<u16>,
    /// Default resource limits
    pub resources: TemplateResources,
    /// Setup instructions
    pub setup_notes: Option<String>,
    /// Download count
    pub downloads: u64,
    /// Rating (1-5)
    pub rating: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TemplateCategory {
    Database,
    WebServer,
    Cache,
    Queue,
    Monitoring,
    DevTools,
    AI,
    Custom,
}

impl std::fmt::Display for TemplateCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateCategory::Database => write!(f, "Database"),
            TemplateCategory::WebServer => write!(f, "Web Server"),
            TemplateCategory::Cache => write!(f, "Cache"),
            TemplateCategory::Queue => write!(f, "Message Queue"),
            TemplateCategory::Monitoring => write!(f, "Monitoring"),
            TemplateCategory::DevTools => write!(f, "Dev Tools"),
            TemplateCategory::AI => write!(f, "AI/ML"),
            TemplateCategory::Custom => write!(f, "Custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateResources {
    pub cpu_percent: u32,
    pub ram_mb: u64,
    pub disk_mb: u64,
}

impl Default for TemplateResources {
    fn default() -> Self {
        Self {
            cpu_percent: 15,
            ram_mb: 512,
            disk_mb: 1024,
        }
    }
}

impl Template {
    /// Convert template to ServiceConfig
    pub fn to_service_config(&self, name_override: Option<&str>) -> ServiceConfig {
        let name = name_override.unwrap_or(&self.id).to_string();
        
        ServiceConfig {
            name,
            service_type: match self.category {
                TemplateCategory::Database => ServiceType::Database,
                TemplateCategory::WebServer => ServiceType::Web,
                TemplateCategory::AI => ServiceType::AiModel,
                _ => ServiceType::Generic,
            },
            command: self.command.clone(),
            args: self.args.clone(),
            env: self.env.clone(),
            resource_limits: ResourceLimits {
                max_cpu_percent: self.resources.cpu_percent as f64,
                max_ram_bytes: self.resources.ram_mb * 1024 * 1024,
                max_disk_bytes: self.resources.disk_mb * 1024 * 1024,
                ..Default::default()
            },
            ports: self.ports.iter().map(|p| PortMapping {
                internal: *p,
                protocol: crate::sandbox::Protocol::Tcp,
            }).collect(),
            ..Default::default()
        }
    }
}

// ─────────────────────────────────────────────
// Template Registry
// ─────────────────────────────────────────────

/// Registry of available templates
pub struct TemplateRegistry {
    templates: HashMap<String, Template>,
}

impl TemplateRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            templates: HashMap::new(),
        };
        registry.load_builtin_templates();
        registry
    }

    /// Load built-in templates
    fn load_builtin_templates(&mut self) {
        // PostgreSQL
        self.templates.insert("postgres".into(), Template {
            id: "postgres".into(),
            name: "PostgreSQL".into(),
            category: TemplateCategory::Database,
            description: "Powerful, open source object-relational database".into(),
            version: "16".into(),
            author: "BECAS Team".into(),
            tags: vec!["database".into(), "sql".into(), "relational".into()],
            docker_image: Some("postgres:16-alpine".into()),
            command: "postgres".into(),
            args: vec![],
            env: HashMap::from([
                ("POSTGRES_PASSWORD".into(), "becas_secret".into()),
                ("POSTGRES_DB".into(), "becasdb".into()),
            ]),
            ports: vec![5432],
            resources: TemplateResources {
                cpu_percent: 25,
                ram_mb: 1024,
                disk_mb: 5120,
            },
            setup_notes: Some("Default password: becas_secret. Change in production!".into()),
            downloads: 15420,
            rating: 4.8,
        });

        // Redis
        self.templates.insert("redis".into(), Template {
            id: "redis".into(),
            name: "Redis".into(),
            category: TemplateCategory::Cache,
            description: "In-memory data structure store, cache, and message broker".into(),
            version: "7".into(),
            author: "BECAS Team".into(),
            tags: vec!["cache".into(), "nosql".into(), "fast".into()],
            docker_image: Some("redis:7-alpine".into()),
            command: "redis-server".into(),
            args: vec!["--appendonly".into(), "yes".into()],
            env: HashMap::new(),
            ports: vec![6379],
            resources: TemplateResources {
                cpu_percent: 10,
                ram_mb: 256,
                disk_mb: 512,
            },
            setup_notes: None,
            downloads: 12350,
            rating: 4.9,
        });

        // Nginx
        self.templates.insert("nginx".into(), Template {
            id: "nginx".into(),
            name: "Nginx".into(),
            category: TemplateCategory::WebServer,
            description: "High-performance HTTP server and reverse proxy".into(),
            version: "1.25".into(),
            author: "BECAS Team".into(),
            tags: vec!["web".into(), "proxy".into(), "http".into()],
            docker_image: Some("nginx:alpine".into()),
            command: "nginx".into(),
            args: vec!["-g".into(), "daemon off;".into()],
            env: HashMap::new(),
            ports: vec![80, 443],
            resources: TemplateResources {
                cpu_percent: 10,
                ram_mb: 128,
                disk_mb: 256,
            },
            setup_notes: Some("Mount your config at /etc/nginx/nginx.conf".into()),
            downloads: 18900,
            rating: 4.7,
        });

        // Node.js App
        self.templates.insert("node-app".into(), Template {
            id: "node-app".into(),
            name: "Node.js App".into(),
            category: TemplateCategory::WebServer,
            description: "Node.js application template with auto-detection".into(),
            version: "20 LTS".into(),
            author: "BECAS Team".into(),
            tags: vec!["javascript".into(), "node".into(), "web".into(), "api".into()],
            docker_image: Some("node:20-alpine".into()),
            command: "node".into(),
            args: vec!["index.js".into()],
            env: HashMap::from([
                ("NODE_ENV".into(), "production".into()),
            ]),
            ports: vec![3000],
            resources: TemplateResources {
                cpu_percent: 20,
                ram_mb: 512,
                disk_mb: 1024,
            },
            setup_notes: Some("Set entry point with --args if not index.js".into()),
            downloads: 9870,
            rating: 4.5,
        });

        // Python App
        self.templates.insert("python-app".into(), Template {
            id: "python-app".into(),
            name: "Python App".into(),
            category: TemplateCategory::WebServer,
            description: "Python application template (Flask/FastAPI/Django)".into(),
            version: "3.12".into(),
            author: "BECAS Team".into(),
            tags: vec!["python".into(), "web".into(), "api".into(), "flask".into()],
            docker_image: Some("python:3.12-slim".into()),
            command: "python".into(),
            args: vec!["app.py".into()],
            env: HashMap::from([
                ("PYTHONUNBUFFERED".into(), "1".into()),
            ]),
            ports: vec![5000],
            resources: TemplateResources {
                cpu_percent: 20,
                ram_mb: 512,
                disk_mb: 1024,
            },
            setup_notes: Some("Install deps: pip install -r requirements.txt".into()),
            downloads: 8540,
            rating: 4.6,
        });

        // MongoDB
        self.templates.insert("mongodb".into(), Template {
            id: "mongodb".into(),
            name: "MongoDB".into(),
            category: TemplateCategory::Database,
            description: "Document-oriented NoSQL database".into(),
            version: "7".into(),
            author: "BECAS Team".into(),
            tags: vec!["database".into(), "nosql".into(), "document".into()],
            docker_image: Some("mongo:7".into()),
            command: "mongod".into(),
            args: vec![],
            env: HashMap::new(),
            ports: vec![27017],
            resources: TemplateResources {
                cpu_percent: 25,
                ram_mb: 1024,
                disk_mb: 5120,
            },
            setup_notes: None,
            downloads: 7650,
            rating: 4.5,
        });

        // RabbitMQ
        self.templates.insert("rabbitmq".into(), Template {
            id: "rabbitmq".into(),
            name: "RabbitMQ".into(),
            category: TemplateCategory::Queue,
            description: "Message broker with management UI".into(),
            version: "3.12".into(),
            author: "BECAS Team".into(),
            tags: vec!["queue".into(), "messaging".into(), "amqp".into()],
            docker_image: Some("rabbitmq:3.12-management-alpine".into()),
            command: "rabbitmq-server".into(),
            args: vec![],
            env: HashMap::new(),
            ports: vec![5672, 15672],
            resources: TemplateResources {
                cpu_percent: 15,
                ram_mb: 512,
                disk_mb: 1024,
            },
            setup_notes: Some("Management UI at port 15672 (guest/guest)".into()),
            downloads: 5430,
            rating: 4.4,
        });

        // Prometheus
        self.templates.insert("prometheus".into(), Template {
            id: "prometheus".into(),
            name: "Prometheus".into(),
            category: TemplateCategory::Monitoring,
            description: "Monitoring system and time series database".into(),
            version: "2.48".into(),
            author: "BECAS Team".into(),
            tags: vec!["monitoring".into(), "metrics".into(), "alerting".into()],
            docker_image: Some("prom/prometheus:latest".into()),
            command: "prometheus".into(),
            args: vec!["--config.file=/etc/prometheus/prometheus.yml".into()],
            env: HashMap::new(),
            ports: vec![9090],
            resources: TemplateResources {
                cpu_percent: 15,
                ram_mb: 512,
                disk_mb: 2048,
            },
            setup_notes: Some("Mount config at /etc/prometheus/prometheus.yml".into()),
            downloads: 4320,
            rating: 4.7,
        });

        // Grafana
        self.templates.insert("grafana".into(), Template {
            id: "grafana".into(),
            name: "Grafana".into(),
            category: TemplateCategory::Monitoring,
            description: "Analytics and monitoring dashboards".into(),
            version: "10".into(),
            author: "BECAS Team".into(),
            tags: vec!["monitoring".into(), "dashboard".into(), "visualization".into()],
            docker_image: Some("grafana/grafana:latest".into()),
            command: "grafana-server".into(),
            args: vec![],
            env: HashMap::from([
                ("GF_SECURITY_ADMIN_PASSWORD".into(), "becas_admin".into()),
            ]),
            ports: vec![3000],
            resources: TemplateResources {
                cpu_percent: 15,
                ram_mb: 256,
                disk_mb: 512,
            },
            setup_notes: Some("Default login: admin/becas_admin".into()),
            downloads: 6780,
            rating: 4.8,
        });

        // Ollama (Local AI)
        self.templates.insert("ollama".into(), Template {
            id: "ollama".into(),
            name: "Ollama".into(),
            category: TemplateCategory::AI,
            description: "Run large language models locally".into(),
            version: "latest".into(),
            author: "BECAS Team".into(),
            tags: vec!["ai".into(), "llm".into(), "local".into(), "ml".into()],
            docker_image: Some("ollama/ollama:latest".into()),
            command: "ollama".into(),
            args: vec!["serve".into()],
            env: HashMap::new(),
            ports: vec![11434],
            resources: TemplateResources {
                cpu_percent: 50,
                ram_mb: 8192,
                disk_mb: 20480,
            },
            setup_notes: Some("Pull model: ollama pull llama2".into()),
            downloads: 3210,
            rating: 4.6,
        });
    }

    /// Get a template by ID
    pub fn get(&self, id: &str) -> Option<&Template> {
        self.templates.get(id)
    }

    /// List all templates
    pub fn list(&self) -> Vec<&Template> {
        let mut list: Vec<_> = self.templates.values().collect();
        list.sort_by(|a, b| b.downloads.cmp(&a.downloads));
        list
    }

    /// Search templates by query
    pub fn search(&self, query: &str) -> Vec<&Template> {
        let query = query.to_lowercase();
        let mut results: Vec<_> = self.templates.values()
            .filter(|t| {
                t.name.to_lowercase().contains(&query)
                || t.description.to_lowercase().contains(&query)
                || t.tags.iter().any(|tag| tag.to_lowercase().contains(&query))
                || t.id.to_lowercase().contains(&query)
            })
            .collect();
        results.sort_by(|a, b| b.downloads.cmp(&a.downloads));
        results
    }

    /// List templates by category
    pub fn by_category(&self, category: TemplateCategory) -> Vec<&Template> {
        let mut results: Vec<_> = self.templates.values()
            .filter(|t| t.category == category)
            .collect();
        results.sort_by(|a, b| b.downloads.cmp(&a.downloads));
        results
    }

    /// Get all categories with counts
    pub fn categories(&self) -> Vec<(TemplateCategory, usize)> {
        let mut counts: HashMap<TemplateCategory, usize> = HashMap::new();
        for t in self.templates.values() {
            *counts.entry(t.category.clone()).or_insert(0) += 1;
        }
        let mut list: Vec<_> = counts.into_iter().collect();
        list.sort_by(|a, b| b.1.cmp(&a.1));
        list
    }

    /// Add a custom template
    pub fn add(&mut self, template: Template) {
        self.templates.insert(template.id.clone(), template);
    }
}

impl Default for TemplateRegistry {
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

    #[test]
    fn test_registry_builtin() {
        let registry = TemplateRegistry::new();
        assert!(registry.get("postgres").is_some());
        assert!(registry.get("redis").is_some());
        assert!(registry.get("nginx").is_some());
    }

    #[test]
    fn test_search() {
        let registry = TemplateRegistry::new();
        let results = registry.search("database");
        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.id == "postgres"));
    }

    #[test]
    fn test_to_service_config() {
        let registry = TemplateRegistry::new();
        let template = registry.get("redis").unwrap();
        let config = template.to_service_config(Some("my-redis"));
        assert_eq!(config.name, "my-redis");
        assert_eq!(config.ports.len(), 1);
    }

    #[test]
    fn test_categories() {
        let registry = TemplateRegistry::new();
        let cats = registry.categories();
        assert!(!cats.is_empty());
    }
}
