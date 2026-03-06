//! # BECAS Core — Better Call Safe Way
//!
//! OS-level personal cloud platform core engine.
//!
//! ## Architecture
//!
//! BECAS turns any personal computer into a secure, isolated service host.
//! Services run inside the BECAS Layer — they belong to the Layer, NOT to the PC.
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │  USER SPACE (Chrome, Games, Files...)    │
//! ├═════════════ ISOLATION WALL ════════════╡
//! │  🔒 BECAS LAYER                         │
//! │  ┌─────────┐ ┌─────────┐               │
//! │  │Service A│ │Service B│  ...           │
//! │  └─────────┘ └─────────┘               │
//! │  📦 Encrypted Storage                   │
//! │  🌐 Own Network Namespace               │
//! │  📊 Resource Limits (adaptive)          │
//! └─────────────────────────────────────────┘
//! ```
//!
//! ## Modules
//!
//! - [`sandbox`] — Process isolation, filesystem separation, network namespacing
//! - [`resource`] — Adaptive CPU/RAM/Disk/Bandwidth governor
//! - [`crypto`] — Encrypted storage, identity (Ed25519), key exchange (X25519)
//! - [`access`] — 5-level access control (Ghost → Owner Override)
//! - [`service`] — Service lifecycle, deployment, portable identity
//! - [`monitor`] — Health checking, metrics, alerts, anomaly triggers

pub mod sandbox;
pub mod resource;
pub mod crypto;
pub mod access;
pub mod service;
pub mod monitor;
pub mod persistence;
pub mod gateway;
pub mod detect;
pub mod plugin;
pub mod marketplace;

/// BECAS version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Re-export commonly used types
pub mod prelude {
    pub use crate::sandbox::{Sandbox, SandboxConfig};
    pub use crate::resource::{ResourceGovernor, ResourceLimits, ResourceUsage};
    pub use crate::crypto::{CryptoEngine, Identity, EncryptedVolume};
    pub use crate::access::{AccessLevel, AccessController};
    pub use crate::service::{Service, ServiceConfig, ServiceStatus, ServiceManager};
    pub use crate::monitor::{HealthMonitor, HealthStatus, Alert, Metrics};
    pub use crate::persistence::StateManager;
    pub use crate::gateway::{SecurityGateway, GatewayConfig, RequestVerdict};
}
