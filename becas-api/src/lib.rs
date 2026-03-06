//! # BECAS API — Dashboard & Monitoring
//!
//! Provides:
//! - **REST API:** Service management (deploy, start, stop, status)
//! - **WebSocket:** Real-time metrics streaming
//! - **Cluster:** Multi-PC peer discovery & state replication

pub mod dashboard;
pub mod websocket;
pub mod cluster;
