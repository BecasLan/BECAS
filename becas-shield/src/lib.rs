//! # BECAS Shield — Security Layer
//!
//! Provides security services for the BECAS Layer:
//! - **Anomaly Detection:** Baseline learning + deviation detection
//! - **Firewall:** Rate limiting, DDoS protection, IP management
//! - **Audit:** Tamper-proof access logging

pub mod anomaly;
pub mod firewall;
pub mod audit;
