//! Compile selected observations into request and connection configuration.
//!
//! Selection chooses correlated variants. Replay checks provider support and
//! binds request-owned values. A captured property that cannot be preserved is
//! lowered to native or caller behaviour, traced and recorded in a preservation
//! report; only malformed captures fail replay.

mod h3_bootstrap;

pub mod connection;

pub mod request;
