# BECAS — Better Call Safe Way

> Master context file for AI session continuity.

---

## Project Overview

**Path:** `BECAS/`
**Type:** OS-Level Personal Cloud Platform
**Status:** Phase 6 Complete — Mesh Network + Real CLI
**Language:** Rust
**Engine:** BecasTalk (HTTP/WS)
**GUI:** AloneOne (.ao → native ARM64) + Web Dashboard

### What Is BECAS?

BECAS turns any personal computer into a secure, zero-config server.
No VPS, no cloud bills, no Docker complexity.
One command deploys any application in an isolated sandbox.

```bash
becas init
becas auto ./my-project --start
# Done. Your PC is now a server. $0/month.
```

### Key Innovations (Patent-Worthy)

1. **Graduated Access Control** — 5-level visibility (Ghost → Emergency), world-first
2. **Blind Hosting** — PC owner cannot see service data, but can detect problems
3. **Zero-Config Auto-Detect** — Scans project, detects language/ports/type, deploys
4. **OS-Native Service Sandbox** — Process isolation without containers
5. **BecasTalk-Powered Dashboard** — No REST wrapper, direct engine communication

### Architecture

```
BECAS/
├── becas-core/src/          — Core engine (9 modules)
│   ├── sandbox/             — Process isolation, env separation, start/stop/pause
│   ├── resource/            — Adaptive CPU/RAM/Disk governor (Idle→Heavy)
│   ├── crypto/              — AES-256-GCM encrypted storage, Ed25519 identity
│   ├── access/              — 5-level graduated access control
│   ├── service/             — Service lifecycle + PID management + persistence
│   ├── monitor/             — Health checks, metrics, alerts, anomaly detection
│   ├── persistence/         — ServiceStore, AuditStore, QueueStore (JSON disk)
│   ├── gateway/             — SecurityGateway: rate limiting, geo-block, auto-ban
│   └── detect/              — Auto-detect: Rust/Node/Python/Go/Docker/Binary/Shell
│
├── becas-net/src/           — Network layer (6 modules)
│   ├── tunnel/              — NAT traversal, QUIC tunnels, STUN
│   ├── endpoint/            — Zero-config DNS endpoints
│   ├── queue/               — Offline request queuing (TTL + priority)
│   ├── proxy/               — TCP reverse proxy, bidirectional relay, stats
│   ├── relay/               — Relay server, Host-based routing, capacity control
│   └── mesh/                — Decentralized mesh network, auto-expose, relay discovery
│
├── becas-shield/src/        — Security layer (3 modules)
│   ├── anomaly/             — Baseline learning, deviation detection, auto-escalation
│   ├── firewall/            — Rate limiting, DDoS protection, IP management
│   └── audit/               — SHA-256 hash chain, tamper-proof logging
│
├── becas-api/src/           — API layer — Powered by BecasTalk (3 modules)
│   ├── dashboard/           — REST API for service management
│   ├── websocket/           — Real-time metrics streaming
│   └── cluster/             — Multi-PC peer discovery, state replication, failover
│
├── becas-cli/src/           — CLI (21 commands)
│   └── main.rs              — init, auto, up, down, deploy, start, stop, restart,
│                               recover, install, status, logs, monitor, level,
│                               firewall, audit, remove, info, tunnel, relay,
│                               dashboard
│
├── becas-gui/               — GUI layer
│   ├── dashboard.ao         — AloneOne native GUI (compiled to ARM64 binary)
│   └── web/index.html       — Web dashboard (dark red theme, SVG icons, BecasTalk API)
│
├── PATENT_DISCLOSURE.md     — Technical patent document (10 claims, 5 patent suggestions)
└── README.md                — GitHub-ready project documentation
```

### Metrics

| Metric               | Value                                      |
|----------------------|---------------------------------------------|
| Total Code           | ~13,000+ lines Rust + HTML/CSS/JS           |
| Tests                | 159 tests, 0 failures                       |
| BECAS Warnings       | 0                                           |
| CLI Commands         | 21                                          |
| Crates               | 5 (core, net, shield, api, cli)             |
| Modules              | 22 (incl. mesh + cloudflare tunnel)          |
| Supported Languages  | Rust, Node.js, Python, Go, Docker, Binary, Shell |
| Dashboard Engine     | BecasTalk (10 routes, keep-alive, 100 conn) |
| GUI Binary           | 104KB ARM64 (AloneOne compiled)             |

### Proven E2E Flows

```
1. becas init                              → Layer initialized, Ed25519 identity
2. becas auto ./becasdb --start            → Auto-detect Rust, deploy, start in sandbox
3. curl http://localhost:9000/health       → BecasDB responds from sandbox
4. becas status --detailed                 → Shows running services with PID
5. becas stop becasdb                      → PID killed, process verified dead
6. becas recover                           → Restarts previously running services
7. becas dashboard                         → BecasTalk web dashboard in browser
8. POST /api/deploy {"path":"./project"}   → Deploy from browser, zero CLI
9. becas start mydb                        → Auto-expose via mesh, real LAN URL assigned
10. becas relay                            → Start relay server for NAT traversal
11. becas monitor                          → Live CPU/RAM/status for all services
12. becas audit --verify                   → Show audit log + verify hash chain integrity
```

### Dependencies (External)

- **BecasTalk** (`../../BecasTalk`) — HTTP/WebSocket engine, used for Dashboard API
- **AloneOne** (`../../AloneOne`) — Compiler + GPU engine, used for native GUI

### Key Decisions (LOCKED)

- **No VPS required** — PC is the server
- **No Docker required** — OS-native sandbox
- **No REST middleware** — Dashboard talks directly to BecasTalk
- **PID-based lifecycle** — kill -0 for process health, SIGTERM/SIGKILL for stop
- **Persistent state** — Services survive CLI restarts (JSON on disk)
- **Zero-config deploy** — `becas auto ./path` detects everything

### What's Done (Phase 6)
- [x] Mesh network module (465 lines) — auto-expose, relay discovery, reconnect
- [x] Relay server — control + data plane, Host-based routing, bidirectional relay
- [x] Real CLI: monitor, level, firewall, audit, remove — all wired to core engines
- [x] Real URL system — LAN IP + port instead of fake becas.local domains
- [x] Dashboard mesh panel — live exposed services with real URLs
- [x] Relay E2E tests — two-node simulation through relay
- [x] Cloudflare Tunnel — auto public URL on `becas start`, zero config
- [x] Dashboard: audit log panel + tunnel panel + unified stream API (11 routes)
- [x] Security proxy: Cloudflare → SecurityGateway → App (rate limit, IP block, DDoS auto-block)
- [x] E2E security tests: proxy rate limit + IP block verified through real TCP connections
- [x] SHA-256 audit hash chain — tamper detection, chain verification, deterministic hashing
- [x] `.becas.toml` config — rate limit, block list, gateway settings from config file
- [x] 21 CLI commands, 159 tests, 0 failures

### What's Next

- [ ] WebSocket real-time streaming (metrics push instead of poll)
- [ ] Log viewer in dashboard (tail -f style)
- [ ] Plugin system (custom service types)
- [ ] Marketplace (share/discover BECAS services)
- [ ] Mobile companion app
- [ ] Real STUN/TURN for production NAT traversal
- [ ] Git repo + CI/CD
- [ ] AloneOne GUI: wire `ao run --gui` to GPU window pipeline

### Read First

Always read this file before making changes to the BECAS project.
Do NOT modify BecasTalk or AloneOne source code from within BECAS context.
