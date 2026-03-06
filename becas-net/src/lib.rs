//! # BECAS Net — Network Layer
//!
//! Provides networking capabilities for the BECAS Layer:
//! - **Tunnel:** NAT traversal, encrypted tunnels, QUIC transport
//! - **Endpoint:** Zero-config public endpoints (servis.becas.net)
//! - **Queue:** Offline request queuing (PC kapalıyken)
//! - **STUN/TURN:** P2P connectivity and relay fallback
//! - **Discovery:** Automatic relay and peer discovery

pub mod tunnel;
pub mod endpoint;
pub mod queue;
pub mod proxy;
pub mod relay;
pub mod mesh;
pub mod stun;
pub mod discovery;
