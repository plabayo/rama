//! Http Services provided by Rama.

pub mod client;
pub mod fs;
pub mod redirect;
pub mod web;

#[cfg(feature = "opentelemetry")]
pub mod opentelemetry;
