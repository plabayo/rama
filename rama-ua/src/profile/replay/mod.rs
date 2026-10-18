//! Compile selected observations into request and connection configuration.
//!
//! Selection chooses correlated variants. Replay checks provider support and
//! binds request-owned values. Strict mode rejects fidelity limitations before
//! use; best-effort mode records each supported deviation in a preservation report.

mod h3_bootstrap;

pub mod connection;

pub mod request;
