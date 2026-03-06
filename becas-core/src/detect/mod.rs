//! # BECAS Auto-Detect
//!
//! Automatically detects project type, command, ports, and resource needs
//! by scanning project files (Cargo.toml, package.json, Dockerfile, etc.)

use std::path::Path;
use std::fs;
use serde::{Serialize, Deserialize};

/// Detected project type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProjectType {
    Rust,
    Node,
    Python,
    Go,
    Docker,
    StaticBinary,
    ShellScript,
    Unknown,
}

impl std::fmt::Display for ProjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rust => write!(f, "Rust"),
            Self::Node => write!(f, "Node.js"),
            Self::Python => write!(f, "Python"),
            Self::Go => write!(f, "Go"),
            Self::Docker => write!(f, "Docker"),
            Self::StaticBinary => write!(f, "Binary"),
            Self::ShellScript => write!(f, "Shell"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Result of auto-detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectResult {
    pub project_type: ProjectType,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub ports: Vec<u16>,
    pub service_type: String,
    pub recommended_cpu: u8,
    pub recommended_ram: u64,
    pub env_vars: Vec<(String, String)>,
    pub build_command: Option<String>,
    pub confidence: f32,
    pub notes: Vec<String>,
}

/// Auto-detect project configuration from a directory
pub fn detect(path: &Path) -> DetectResult {
    let detectors: Vec<Box<dyn Fn(&Path) -> Option<DetectResult>>> = vec![
        Box::new(detect_rust),
        Box::new(detect_node),
        Box::new(detect_python),
        Box::new(detect_go),
        Box::new(detect_docker),
        Box::new(detect_binary),
        Box::new(detect_shell),
    ];

    for detector in &detectors {
        if let Some(result) = detector(path) {
            return result;
        }
    }

    // Fallback
    DetectResult {
        project_type: ProjectType::Unknown,
        name: dir_name(path),
        command: String::new(),
        args: vec![],
        ports: vec![8080],
        service_type: "worker".into(),
        recommended_cpu: 10,
        recommended_ram: 256,
        env_vars: vec![],
        build_command: None,
        confidence: 0.0,
        notes: vec!["Could not auto-detect project type".into()],
    }
}

fn dir_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app")
        .to_lowercase()
        .replace(' ', "-")
}

fn read_file(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn scan_ports(content: &str) -> Vec<u16> {
    let mut ports = vec![];
    let patterns = [
        r#"(?i)port[:\s=]+(\d{4,5})"#,
        r#"(?i)listen[:\s(]+(\d{4,5})"#,
        r#"(?i)bind[:\s(]+['"]?[\w.]*:(\d{4,5})"#,
        r#":(\d{4,5})\b"#,
    ];
    for pat in &patterns {
        if let Ok(re) = regex_lite::Regex::new(pat) {
            for cap in re.captures_iter(content) {
                if let Some(m) = cap.get(1) {
                    if let Ok(p) = m.as_str().parse::<u16>() {
                        if p >= 1024 && !ports.contains(&p) {
                            ports.push(p);
                        }
                    }
                }
            }
        }
    }
    if ports.is_empty() { ports.push(8080); }
    ports
}

fn detect_rust(path: &Path) -> Option<DetectResult> {
    let cargo = path.join("Cargo.toml");
    if !cargo.exists() { return None; }
    let content = read_file(&cargo);

    let name = content.lines()
        .find(|l| l.starts_with("name"))
        .and_then(|l| l.split('"').nth(1))
        .unwrap_or("app")
        .to_string();

    // Check for bin targets
    let has_server = content.contains("server") || content.contains("bin");

    // Scan src for ports (recursive — handles workspaces too)
    let mut all_src = String::new();
    fn scan_rs_files(dir: &Path, buf: &mut String) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name != "target" && name != ".git" && name != "node_modules" {
                        scan_rs_files(&p, buf);
                    }
                } else if p.extension().map(|e| e == "rs").unwrap_or(false) {
                    buf.push_str(&fs::read_to_string(&p).unwrap_or_default());
                }
            }
        }
    }
    scan_rs_files(path, &mut all_src);
    // Also scan Cargo.toml for clues
    all_src.push_str(&content);

    let ports = scan_ports(&all_src);

    let svc_type = if all_src.contains("database") || all_src.contains("storage") {
        "database"
    } else if all_src.contains("HttpServer") || all_src.contains("axum") || all_src.contains("warp") || all_src.contains("actix") {
        "api"
    } else {
        "worker"
    };

    let bin_name = if has_server { "server" } else { &name };
    let release_bin = path.join("target").join("release").join(bin_name);
    let debug_bin = path.join("target").join("debug").join(bin_name);

    let (command, build_cmd) = if release_bin.exists() {
        (release_bin.to_string_lossy().to_string(), None)
    } else if debug_bin.exists() {
        (debug_bin.to_string_lossy().to_string(), Some(format!("cargo build --release --bin {}", bin_name)))
    } else {
        (format!("cargo run --release --bin {}", bin_name), Some("cargo build --release".into()))
    };

    Some(DetectResult {
        project_type: ProjectType::Rust,
        name: name.clone(),
        command,
        args: vec![],
        ports,
        service_type: svc_type.into(),
        recommended_cpu: 25,
        recommended_ram: 512,
        env_vars: vec![],
        build_command: build_cmd,
        confidence: 0.95,
        notes: vec![format!("Rust project '{}' detected", name)],
    })
}

fn detect_node(path: &Path) -> Option<DetectResult> {
    let pkg = path.join("package.json");
    if !pkg.exists() { return None; }
    // If Cargo.toml also exists, this is a Rust project with JS tooling — skip
    if path.join("Cargo.toml").exists() { return None; }
    let content = read_file(&pkg);

    let name = content.lines()
        .find(|l| l.contains("\"name\""))
        .and_then(|l| l.split('"').nth(3))
        .unwrap_or("node-app")
        .to_string();

    // Find start script
    let start_script = content.lines()
        .find(|l| l.contains("\"start\""))
        .and_then(|l| l.split('"').nth(3))
        .unwrap_or("node index.js")
        .to_string();

    // Find main file
    let main = content.lines()
        .find(|l| l.contains("\"main\""))
        .and_then(|l| l.split('"').nth(3))
        .unwrap_or("index.js")
        .to_string();

    let main_content = read_file(&path.join(&main));
    let ports = scan_ports(&main_content);

    let svc_type = if main_content.contains("express") || main_content.contains("fastify") || main_content.contains("koa") {
        "api"
    } else if main_content.contains("next") || main_content.contains("nuxt") {
        "web"
    } else {
        "worker"
    };

    let (cmd, args) = if start_script.starts_with("node") {
        let parts: Vec<&str> = start_script.splitn(2, ' ').collect();
        ("node".into(), vec![parts.get(1).unwrap_or(&"index.js").to_string()])
    } else {
        ("npm".into(), vec!["start".into()])
    };

    Some(DetectResult {
        project_type: ProjectType::Node,
        name,
        command: cmd,
        args,
        ports,
        service_type: svc_type.into(),
        recommended_cpu: 20,
        recommended_ram: 512,
        env_vars: vec![("NODE_ENV".into(), "production".into())],
        build_command: Some("npm install".into()),
        confidence: 0.9,
        notes: vec!["Node.js project detected".into()],
    })
}

fn detect_python(path: &Path) -> Option<DetectResult> {
    let has_req = path.join("requirements.txt").exists();
    let has_pyproject = path.join("pyproject.toml").exists();
    let has_setup = path.join("setup.py").exists();
    if !has_req && !has_pyproject && !has_setup { return None; }
    // If Cargo.toml also exists, this is a Rust project with Python bindings — skip
    if path.join("Cargo.toml").exists() { return None; }
    // If package.json also exists, prefer Node
    if path.join("package.json").exists() { return None; }

    let name = dir_name(path);

    // Find main file
    let main_candidates = ["app.py", "main.py", "server.py", "manage.py", "run.py"];
    let main_file = main_candidates.iter()
        .find(|f| path.join(f).exists())
        .unwrap_or(&"app.py");

    let main_content = read_file(&path.join(main_file));
    let ports = scan_ports(&main_content);

    let svc_type = if main_content.contains("flask") || main_content.contains("Flask") {
        "api"
    } else if main_content.contains("django") || main_content.contains("Django") {
        "web"
    } else if main_content.contains("fastapi") || main_content.contains("FastAPI") {
        "api"
    } else {
        "worker"
    };

    let (cmd, args) = if main_content.contains("uvicorn") || main_content.contains("fastapi") {
        ("uvicorn".into(), vec![format!("{}:app", main_file.trim_end_matches(".py")), "--host".into(), "0.0.0.0".into(), "--port".into(), ports[0].to_string()])
    } else if main_content.contains("gunicorn") {
        ("gunicorn".into(), vec![format!("{}:app", main_file.trim_end_matches(".py")), "-b".into(), format!("0.0.0.0:{}", ports[0])])
    } else {
        ("python3".into(), vec![main_file.to_string()])
    };

    Some(DetectResult {
        project_type: ProjectType::Python,
        name,
        command: cmd,
        args,
        ports,
        service_type: svc_type.into(),
        recommended_cpu: 15,
        recommended_ram: 256,
        env_vars: vec![],
        build_command: if has_req { Some("pip install -r requirements.txt".into()) } else { None },
        confidence: 0.85,
        notes: vec![format!("Python project detected (main: {})", main_file)],
    })
}

fn detect_go(path: &Path) -> Option<DetectResult> {
    let gomod = path.join("go.mod");
    if !gomod.exists() { return None; }
    let content = read_file(&gomod);

    let name = content.lines()
        .find(|l| l.starts_with("module"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|m| m.rsplit('/').next())
        .unwrap_or("go-app")
        .to_string();

    let main_content = read_file(&path.join("main.go"));
    let ports = scan_ports(&main_content);

    let bin_path = path.join(&name);
    let command = if bin_path.exists() {
        bin_path.to_string_lossy().to_string()
    } else {
        "go".into()
    };
    let args = if bin_path.exists() { vec![] } else { vec!["run".into(), ".".into()] };

    Some(DetectResult {
        project_type: ProjectType::Go,
        name,
        command,
        args,
        ports,
        service_type: "api".into(),
        recommended_cpu: 20,
        recommended_ram: 256,
        env_vars: vec![],
        build_command: Some("go build -o app .".into()),
        confidence: 0.9,
        notes: vec!["Go project detected".into()],
    })
}

fn detect_docker(path: &Path) -> Option<DetectResult> {
    let dockerfile = path.join("Dockerfile");
    if !dockerfile.exists() { return None; }
    // Prefer native build over Docker if project files exist
    if path.join("Cargo.toml").exists() || path.join("package.json").exists()
        || path.join("go.mod").exists() || path.join("requirements.txt").exists() {
        return None;
    }
    let content = read_file(&dockerfile);

    let name = dir_name(path);
    let mut ports = vec![];

    for line in content.lines() {
        let trimmed = line.trim().to_uppercase();
        if trimmed.starts_with("EXPOSE") {
            if let Some(port_str) = trimmed.split_whitespace().nth(1) {
                let port_str = port_str.split('/').next().unwrap_or(port_str);
                if let Ok(p) = port_str.parse::<u16>() {
                    ports.push(p);
                }
            }
        }
    }
    if ports.is_empty() { ports.push(8080); }

    Some(DetectResult {
        project_type: ProjectType::Docker,
        name,
        command: "docker".into(),
        args: vec!["compose".into(), "up".into()],
        ports,
        service_type: "api".into(),
        recommended_cpu: 30,
        recommended_ram: 1024,
        env_vars: vec![],
        build_command: Some("docker compose build".into()),
        confidence: 0.8,
        notes: vec!["Dockerfile detected — consider running natively for better BECAS integration".into()],
    })
}

fn detect_binary(path: &Path) -> Option<DetectResult> {
    // Check if path itself is a binary
    if path.is_file() {
        let meta = fs::metadata(path).ok()?;
        let perms = meta.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if perms.mode() & 0o111 != 0 {
                return Some(DetectResult {
                    project_type: ProjectType::StaticBinary,
                    name: path.file_stem().and_then(|s| s.to_str()).unwrap_or("app").to_string(),
                    command: path.to_string_lossy().to_string(),
                    args: vec![],
                    ports: vec![8080],
                    service_type: "worker".into(),
                    recommended_cpu: 15,
                    recommended_ram: 256,
                    env_vars: vec![],
                    build_command: None,
                    confidence: 0.7,
                    notes: vec!["Executable binary detected".into()],
                });
            }
        }
        #[cfg(not(unix))]
        {
            let _ = perms;
        }
    }
    None
}

fn detect_shell(path: &Path) -> Option<DetectResult> {
    if path.is_file() {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "sh" || ext == "bash" {
            return Some(DetectResult {
                project_type: ProjectType::ShellScript,
                name: path.file_stem().and_then(|s| s.to_str()).unwrap_or("script").to_string(),
                command: "bash".into(),
                args: vec![path.to_string_lossy().to_string()],
                ports: vec![],
                service_type: "worker".into(),
                recommended_cpu: 5,
                recommended_ram: 128,
                env_vars: vec![],
                build_command: None,
                confidence: 0.6,
                notes: vec!["Shell script detected".into()],
            });
        }
    }
    None
}

// ===== Tests =====

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_detect_rust() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("Cargo.toml"), r#"
[package]
name = "my-api"
version = "0.1.0"
"#).unwrap();
        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src").join("main.rs"), r#"
use axum::Router;
let addr = "0.0.0.0:3000";
"#).unwrap();
        let result = detect(tmp.path());
        assert_eq!(result.project_type, ProjectType::Rust);
        assert_eq!(result.name, "my-api");
        assert!(result.ports.contains(&3000));
        assert_eq!(result.service_type, "api");
    }

    #[test]
    fn test_detect_node() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("package.json"), r#"{
  "name": "my-node-app",
  "main": "index.js",
  "scripts": { "start": "node index.js" }
}"#).unwrap();
        fs::write(tmp.path().join("index.js"), r#"
const express = require('express');
app.listen(4000);
"#).unwrap();
        let result = detect(tmp.path());
        assert_eq!(result.project_type, ProjectType::Node);
        assert!(result.ports.contains(&4000));
    }

    #[test]
    fn test_detect_python() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("requirements.txt"), "flask\n").unwrap();
        fs::write(tmp.path().join("app.py"), r#"
from flask import Flask
app = Flask(__name__)
app.run(port=5000)
"#).unwrap();
        let result = detect(tmp.path());
        assert_eq!(result.project_type, ProjectType::Python);
        assert!(result.ports.contains(&5000));
    }

    #[test]
    fn test_detect_go() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("go.mod"), "module github.com/user/my-go-svc\n").unwrap();
        fs::write(tmp.path().join("main.go"), r#"
http.ListenAndServe(":7070", nil)
"#).unwrap();
        let result = detect(tmp.path());
        assert_eq!(result.project_type, ProjectType::Go);
        assert!(result.ports.contains(&7070));
    }

    #[test]
    fn test_detect_docker() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("Dockerfile"), "FROM node:18\nEXPOSE 3000\n").unwrap();
        let result = detect(tmp.path());
        assert_eq!(result.project_type, ProjectType::Docker);
        assert!(result.ports.contains(&3000));
    }

    #[test]
    fn test_detect_unknown() {
        let tmp = TempDir::new().unwrap();
        let result = detect(tmp.path());
        assert_eq!(result.project_type, ProjectType::Unknown);
        assert_eq!(result.confidence, 0.0);
    }
}

