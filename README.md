<div align="center">

# 🛡️ BECAS

### **B**etter **C**all **S**afe Way

**Your PC is the cloud. No servers needed.**

[![Tests](https://img.shields.io/badge/tests-129%20passing-brightgreen)]()
[![Rust](https://img.shields.io/badge/rust-2021-orange)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

*Deploy any application on your personal computer as a secure, production-ready service.*
*Zero VPS costs. Zero configuration. Zero compromise on security.*

</div>

---

## 🤔 What is BECAS?

BECAS is an **OS-level personal cloud platform** that turns your PC into a secure server. Instead of paying for VPS/cloud hosting, you run services directly on your machine — with enterprise-grade security, isolation, and monitoring.

```bash
# Deploy any app in one command
becas auto ./my-project --start

# That's it. Your PC is now serving your app.
```

### The Problem

| Traditional Way | BECAS Way |
|----------------|-----------|
| Buy a VPS ($20-100/mo) | Your own PC ($0/mo) |
| Configure servers manually | `becas auto` detects everything |
| Worry about security | 5-layer security, automatic |
| Manage Docker, nginx, SSL | Single command deployment |
| Pay for idle resources | Use your existing hardware |

### Key Innovation

> **Your PC runs the service, but the service doesn't "see" your PC.**

BECAS creates an invisible security layer between your personal files and the services you host. Services run in isolated sandboxes with graduated access control — you stay in control without micromanaging.

---

## 🚀 Quick Start

### Install

```bash
git clone https://github.com/becas-team/becas.git
cd becas
cargo build --release
```

### Deploy Your First Service

```bash
# Initialize BECAS Layer
becas init

# Auto-detect and deploy any project
becas auto ./my-web-app --start

# Check status
becas status --detailed

# Create a tunnel for external access
becas tunnel my-web-app
```

### Manual Deploy

```bash
# Deploy with full control
becas deploy --name my-api \
  --command python3 --args app.py \
  --ports 8080 \
  --max-cpu 25 --max-ram 1024 \
  -t api

# Start the service
becas start my-api

# View logs
becas logs my-api --follow

# Stop when done
becas stop my-api
```

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        YOUR PC                               │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                    BECAS LAYER                           │ │
│  │                                                         │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                │ │
│  │  │ Service A│ │ Service B│ │ Service C│  ← Sandboxed   │ │
│  │  │ (BecasDB)│ │ (API)    │ │ (Web)    │                │ │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘                │ │
│  │       │             │             │                      │ │
│  │  ┌────┴─────────────┴─────────────┴─────┐               │ │
│  │  │         Security Gateway              │               │ │
│  │  │  Rate Limiting │ DDoS │ Auth │ Audit  │               │ │
│  │  └──────────────────────────────────────-┘               │ │
│  │                                                         │ │
│  │  ┌──────────────────────────────────────-┐               │ │
│  │  │         Resource Governor              │               │ │
│  │  │  CPU │ RAM │ Disk │ Network limits     │               │ │
│  │  └──────────────────────────────────────-┘               │ │
│  │                                                         │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  📁 Your personal files — COMPLETELY ISOLATED                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 🔐 5-Level Security Model

BECAS uses a unique **Graduated Access Control** system — a world-first innovation:

| Level | Name | What You See | When |
|-------|------|-------------|------|
| **0** | 👻 Ghost | "2 services running" | Normal operation |
| **1** | 🔍 Observer | CPU/RAM/request counts | Curiosity |
| **2** | 📊 Inspector | Masked logs, error types | Debugging |
| **3** | 🔧 Operator | Full logs, restart ability | Incidents |
| **4** | 🚨 Emergency | Everything, kill switch | Emergencies |

The system **auto-escalates** when anomalies are detected. If CPU spikes, you automatically get more visibility.

---

## ✨ Features

### Core Engine
- **Sandbox Isolation** — Each service runs in its own isolated environment
- **Resource Governor** — Adaptive CPU/RAM/Disk limits (auto-throttle under load)
- **Crypto Engine** — AES-256-GCM encrypted storage, Ed25519 identities
- **PID Lifecycle** — Reliable process management with persistence

### Networking
- **Reverse Proxy** — TCP bidirectional relay with stats
- **NAT Traversal** — QUIC-based tunnels through firewalls
- **Relay Server** — Host-based routing for external access
- **Offline Queue** — Requests queued when PC is off (TTL + priority)

### Security
- **SecurityGateway** — Rate limiting, auto-block, geo-blocking
- **Anomaly Detection** — Baseline learning, deviation alerts
- **DDoS Protection** — Auto-ban after threshold
- **Audit Logger** — Tamper-proof SHA-256 hash chain

### Operations
- **Auto-Recovery** — Services restart automatically after reboot
- **Auto-Detect** — `becas auto` scans projects and configures everything
- **Dashboard API** — REST + WebSocket monitoring (powered by BecasTalk)
- **Cluster Mode** — Multi-PC peer discovery and failover

### Supported Languages
| Language | Auto-Detect | How |
|----------|-------------|-----|
| 🦀 Rust | ✅ | Finds `Cargo.toml`, locates binary |
| 🟢 Node.js | ✅ | Reads `package.json`, runs `npm start` |
| 🐍 Python | ✅ | Finds `requirements.txt` or `app.py` |
| 🐹 Go | ✅ | Finds `go.mod`, builds binary |
| 🐳 Docker | ✅ | Uses `Dockerfile` |
| 📦 Binary | ✅ | Detects ELF/Mach-O executables |
| 🐚 Shell | ✅ | Runs shell scripts |

---

## 📊 Project Stats

| Metric | Value |
|--------|-------|
| **Total Code** | ~11,000+ lines of Rust |
| **Tests** | 129 passing, 0 failures |
| **CLI Commands** | 19 |
| **Modules** | 18 across 5 crates |
| **Dependencies** | Minimal (BecasTalk for API) |

---

## 🧱 Crate Structure

```
BECAS/
├── becas-core/     — Engine: sandbox, resource, crypto, access,
│                     service, monitor, persistence, gateway, detect
├── becas-net/      — Networking: tunnel, endpoint, queue, proxy, relay
├── becas-shield/   — Security: anomaly, firewall, audit
├── becas-api/      — Dashboard: REST API, WebSocket, cluster
│                     (powered by BecasTalk — zero external deps!)
├── becas-cli/      — CLI: 19 commands for full lifecycle
└── becas-gui/      — AloneOne GUI dashboard (dashboard.ao)
```

---

## 🔬 CLI Reference

```
becas init                  Initialize BECAS Layer
becas auto <path> [--start] Auto-detect & deploy a project
becas deploy                Manual service deployment
becas start <name>          Start a service in sandbox
becas stop <name>           Stop a running service
becas restart <name>        Restart a service
becas status [--detailed]   Show all services status
becas logs <name> [--follow] View service logs
becas monitor               Live resource monitoring
becas tunnel <name>         Expose service externally
becas recover               Restart services after reboot
becas install               Install as system service
becas level <n>             Set access level (0-4)
becas firewall              Manage firewall rules
becas audit                 View audit trail
becas remove <name>         Remove a service
becas info                  Show system information
```

---

## 🌍 Real-World Example: BecasDB

```bash
# Deploy BecasDB on your PC — zero config
becas init
becas auto ./becasdb --start

# BecasDB is now serving on localhost:9000
curl http://localhost:9000/health
# → {"status": "healthy", "checks": [storage: pass, index: pass]}

# Expose to the internet
becas tunnel becasdb
# → 🌐 https://becasdb.becas.net → localhost:9000

# Your database, your PC, your rules. $0/month.
```

---

## 🔮 Roadmap

- [ ] AloneOne GUI — Native GPU-accelerated dashboard
- [ ] Mobile companion app — iOS/Android monitoring
- [ ] Plugin marketplace — Community service templates
- [ ] Multi-region cluster — Cross-internet PC federation
- [ ] Hardware wallet auth — YubiKey / Ledger integration

---

## 📜 Patent-Worthy Innovations

1. **Graduated Access Control** — 5-level adaptive visibility system
2. **Blind Hosting** — PC owner can't see service data, but can detect problems
3. **Zero-Config Service Deployment** — Auto-detect any project type
4. **OS-Level Personal Cloud** — No VPS, no Docker, no configuration
5. **Anomaly-Based Access Escalation** — Auto-promote visibility on incidents

---

## 🤝 Built With

- **Rust** — Core engine, compiler-verified safety
- **BecasTalk** — Custom HTTP/WebSocket engine (zero external deps)
- **AloneOne** — Custom UI language & GPU renderer (for GUI)

---

<div align="center">

**BECAS — Your PC is the cloud.**

*No servers. No bills. No compromises.*

Made with 🛡️ by the BECAS Team

</div>
