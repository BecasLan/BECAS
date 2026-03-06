# BECAS Documentation

> **Better Call Safe Way** — Your PC is the cloud. Zero servers. Zero cost.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [CLI Reference](#cli-reference)
4. [Configuration (.becas.toml)](#configuration)
5. [Dashboard](#dashboard)
6. [API Reference](#api-reference)
7. [Architecture](#architecture)
8. [Security Model](#security-model)
9. [Examples](#examples)

---

## Quick Start

```bash
# Initialize BECAS on your PC
becas init

# Deploy any project (auto-detect)
becas auto ./my-project --start

# Or use .becas.toml config
becas up ./my-project

# Open web dashboard
becas dashboard

# That's it. Your PC is now a server.
```

---

## Installation

### Build from source

```bash
cd BECAS
cargo build --release
# Binary: ./target/release/becas
```

### Install as system service (auto-start on boot)

```bash
becas install              # macOS LaunchAgent
becas install --uninstall  # Remove
```

---

## CLI Reference

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `becas init` | Initialize BECAS Layer, generate node identity | `becas init` |
| `becas auto <path>` | Auto-detect project type and deploy | `becas auto ./myapp --start` |
| `becas up <path>` | Deploy from .becas.toml + start (+ optional watch) | `becas up . --watch` |
| `becas down [name]` | Stop and remove a deployment | `becas down myapp` |

### Service Lifecycle

| Command | Description | Example |
|---------|-------------|---------|
| `becas deploy` | Manual deploy with full control | `becas deploy --name api --command ./server --ports 8080` |
| `becas start <name>` | Start a deployed service in sandbox | `becas start api` |
| `becas stop <name>` | Stop a running service (PID kill) | `becas stop api` |
| `becas restart <name>` | Stop + start | `becas restart api` |
| `becas remove <name>` | Remove a stopped service | `becas remove api --force` |

### Monitoring

| Command | Description | Example |
|---------|-------------|---------|
| `becas status` | Show all services and system metrics | `becas status --detailed` |
| `becas logs <name>` | Show service logs (access-level filtered) | `becas logs api --lines 100` |
| `becas monitor <name>` | Live monitoring with metrics | `becas monitor api` |
| `becas dashboard` | Open web dashboard in browser | `becas dashboard --port 8888` |

### Security

| Command | Description | Example |
|---------|-------------|---------|
| `becas level <name> <0-4>` | Set access level (0=Ghost, 4=Emergency) | `becas level api 2` |
| `becas firewall <name>` | Show firewall stats and blocked IPs | `becas firewall api` |
| `becas audit` | Show tamper-proof audit log | `becas audit` |

### Infrastructure

| Command | Description | Example |
|---------|-------------|---------|
| `becas tunnel <name>` | Expose service externally via reverse proxy | `becas tunnel api --port 18080` |
| `becas recover` | Restart services that were running before shutdown | `becas recover --dry-run` |
| `becas install` | Install as macOS LaunchAgent (boot auto-start) | `becas install` |
| `becas info` | Show system information | `becas info` |

### Global Options

```
--data-dir <path>    Data directory (default: ~/.becas-data)
-h, --help           Show help
-V, --version        Show version
```

---

## Configuration

### .becas.toml

Place a `.becas.toml` file in your project root for zero-config deployment:

```toml
# Required
name = "my-api"
command = "./target/release/server"

# Networking
port = 8080
# ports = [8080, 9090]    # Multiple ports

# Service type (database, api, web, worker)
type = "api"

# Resource limits
max_cpu = 25               # Max CPU percentage
max_ram = 1024             # Max RAM in MB

# Behavior
auto_start = true          # Start after deploy
# watch = true             # Auto-reload on file changes

# Environment variables
# [env]
# DATABASE_URL = "sqlite://data.db"
# PORT = "8080"
```

### Supported Project Types (Auto-Detect)

| Type | Detected By | Default Command |
|------|-------------|-----------------|
| **Rust** | `Cargo.toml` | `cargo run --release` or binary in `target/` |
| **Node.js** | `package.json` | `npm start` |
| **Python** | `requirements.txt`, `pyproject.toml`, `app.py` | `python3 app.py` |
| **Go** | `go.mod` | `go run .` |
| **Docker** | `Dockerfile` | `docker build && docker run` |
| **Binary** | Executable file | Direct execution |
| **Shell** | `.sh` file | `bash script.sh` |

### Port Detection

BECAS automatically scans source files for port patterns:
- `port = 8080`, `PORT: 3000`, `listen(9000)`
- `bind("0.0.0.0:5432")`, `:8080`
- Environment variables: `$PORT`, `BECAS_PORT`

---

## Dashboard

### Start Dashboard

```bash
becas dashboard                  # Default port 7777
becas dashboard --port 8888      # Custom port
```

Opens `http://localhost:7777` in your browser.

### Features

- **Overview**: Real-time CPU, RAM, Disk, Network metrics
- **Services**: List, Start, Stop, Deploy from browser
- **Deploy**: Path input + drag-and-drop support
- **Request Chart**: 24-hour request history (canvas)
- **Dark red theme**: Professional, vibrant design

### Powered by BecasTalk

Dashboard runs on BecasTalk HTTP engine — zero external dependencies.

---

## API Reference

All endpoints served by BecasTalk when `becas dashboard` is running.

### GET /api/system

Returns real-time system metrics.

```json
{
  "cpu_percent": 49.3,
  "cpu_cores": 10,
  "cpu_name": "Apple M1 Pro",
  "ram_used_mb": 21102,
  "ram_total_mb": 32768,
  "disk_used_gb": 448,
  "disk_total_gb": 460,
  "os": "macOS 26.2",
  "uptime_hours": 142
}
```

### GET /api/services

Returns all deployed services.

```json
[
  {
    "id": "9de839c6-...",
    "name": "becasdb",
    "status": "Running",
    "service_type": "Database",
    "cpu_limit": 30,
    "ram_limit_mb": 2048,
    "ports": [9000],
    "pid": 12345,
    "created": "2026-02-15T19:30:06Z"
  }
]
```

### GET /api/node

Returns node identity and engine info.

```json
{
  "node_id": "ed25519:a4b8c2...",
  "engine": "BecasTalk",
  "version": "0.1.0",
  "data_dir": "/Users/you/.becas-data"
}
```

### POST /api/deploy

Deploy a project from the dashboard.

```bash
curl -X POST http://localhost:7777/api/deploy \
  -H "Content-Type: application/json" \
  -d '{"path": "./my-project", "name": "my-app"}'
```

Response:
```json
{
  "success": true,
  "service_id": "bc6a7e58-...",
  "detected": {
    "project_type": "Rust",
    "command": "cargo run --release",
    "ports": [8080]
  }
}
```

### POST /api/services/:name/start

Start a deployed service.

### POST /api/services/:name/stop

Stop a running service.

---

## Architecture

```
BECAS/
├── becas-core/              Main engine
│   ├── sandbox/             Process isolation (env separation, PID tracking)
│   ├── resource/            Adaptive CPU/RAM/Disk governor
│   ├── crypto/              AES-256-GCM encryption, Ed25519 identity
│   ├── access/              5-level graduated access control
│   ├── service/             Service lifecycle + persistence
│   ├── monitor/             Health checks, metrics, alerts
│   ├── persistence/         JSON disk storage (services, audit, queue)
│   ├── gateway/             Rate limiting, geo-blocking, auto-ban
│   └── detect/              Auto-detect project type (7 languages)
│
├── becas-net/               Networking
│   ├── tunnel/              NAT traversal, QUIC tunnels
│   ├── endpoint/            Zero-config DNS endpoints
│   ├── queue/               Offline request queuing (TTL + priority)
│   ├── proxy/               TCP reverse proxy (bidirectional relay)
│   └── relay/               Multi-service relay server
│
├── becas-shield/            Security
│   ├── anomaly/             Baseline learning, auto-escalation
│   ├── firewall/            Rate limiting, DDoS, auto-ban
│   └── audit/               SHA-256 hash-chain tamper-proof logging
│
├── becas-api/               Dashboard API (powered by BecasTalk)
│   ├── dashboard/           REST endpoints for service management
│   ├── websocket/           Real-time metrics streaming
│   └── cluster/             Multi-PC peer discovery + failover
│
├── becas-cli/               Command-line interface (21 commands)
│
└── becas-gui/
    ├── web/index.html       Web dashboard (dark red, embedded in binary)
    └── dashboard.ao         AloneOne native GPU dashboard
```

### Crate Dependencies

```
becas-cli ─┬─ becas-core
            ├─ becas-net ──── becas-core
            ├─ becas-shield ─ becas-core
            ├─ becas-api ──┬─ becas-core
            │              ├─ becas-net
            │              └─ becas-shield
            └─ becastalk (HTTP engine)
```

---

## Security Model

### 5-Level Graduated Access Control

| Level | Name | What You See | Use Case |
|-------|------|-------------|----------|
| 0 | **Ghost** | Service count only | Normal operation |
| 1 | **Aware** | Names + status (no data) | Routine monitoring |
| 2 | **Diagnostic** | Masked logs + metrics | Troubleshooting |
| 3 | **Inspect** | Full logs + connection info | Active debugging |
| 4 | **Emergency** | Full access + data view | Critical incidents |

### Security Features

- **Sandbox Isolation**: Each service runs in isolated environment
- **Encrypted Storage**: AES-256-GCM for service data
- **Ed25519 Identity**: Unique node key pair (no central authority)
- **Rate Limiting**: Per-IP request throttling
- **Auto-Ban**: DDoS detection + automatic IP blocking
- **Geo-Blocking**: Country-based access control
- **Audit Trail**: SHA-256 hash-chain, tamper-proof logging
- **PID Management**: Direct process control via stored PIDs

---

## Examples

### Deploy BecasDB (Database)

```bash
# Auto-detect
becas auto ./becasdb --start

# With config
cd becasdb
cat .becas.toml
# name = "becasdb"
# command = "./target/debug/server"
# port = 9000
# type = "database"

becas up .
```

### Deploy a Node.js API

```bash
becas auto ./my-express-app --start
# Detected: Node.js, npm start, port 3000
```

### Deploy a Python Flask App

```bash
becas auto ./flask-app --start
# Detected: Python, python3 app.py, port 5000
```

### Multi-Service Setup

```bash
becas deploy --name db --command ./db-server --ports 5432 -t database
becas deploy --name api --command ./api-server --ports 8080 -t api
becas deploy --name web --command ./web-server --ports 3000 -t web

becas start db
becas start api
becas start web

becas status
# 🟢 db  — Running [Database]
# 🟢 api — Running [API]
# 🟢 web — Running [Web]
```

### Hot Reload (Development)

```bash
becas up ./my-project --watch
# Watching for changes... (Ctrl+C to stop)
# >> Change detected, re-deploying...
# >> Service restarted
```

### Expose Service to Internet

```bash
becas tunnel my-api --port 18080
# Tunnel active: http://localhost:18080 -> my-api (port 8080)
# External access ready
```

### Dashboard Deploy (Browser)

```bash
becas dashboard
# 1. Open http://localhost:7777
# 2. Go to Services tab
# 3. Enter path: ./my-project
# 4. Click Deploy
# 5. Click Start
```

---

## Project Metrics

| Metric | Value |
|--------|-------|
| Total Code | ~12,000+ lines Rust |
| Tests | 129 passed, 0 failed |
| CLI Commands | 21 |
| Modules | 18 |
| Crates | 5 |
| Warnings | 0 (BECAS code) |
| Supported Languages | 7 (Rust, Node, Python, Go, Docker, Binary, Shell) |

---

## License

Proprietary — Patent pending.

**BECAS — Better Call Safe Way**
*Your PC. Your cloud. Your rules.*
