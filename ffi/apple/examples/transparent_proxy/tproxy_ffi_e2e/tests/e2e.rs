#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests use explicit assertions and panics for clarity"
)]

//! Apple FFI end-to-end coverage for the transparent proxy example static library.

mod cases;

pub(crate) mod shared;
