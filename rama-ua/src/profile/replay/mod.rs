//! Compile selected observations into request and connection configuration.
//!
//! Selection chooses correlated variants. Replay checks provider support and
//! binds request-owned values. Fidelity limitations never block replay; each
//! deviation is traced and recorded in a preservation report.

mod h3_bootstrap;

pub mod connection;

pub mod request;
