//! Rama Runtime
//!
//! This crate provides a runtime for Rama applications.
//!
//! For now only Tokio is implemented and supported.
//! There is no plan to support other runtimes.
//! If you want to use other runtimes, you can
//! provide feedback, input and motivation at
//! <https://github.com/plabayo/rama/issues/6>.

pub use rama_rt::*;

pub use rama_rt_macros::{main, test};
