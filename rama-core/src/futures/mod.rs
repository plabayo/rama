//! Re-export of the [futures](https://docs.rs/futures/latest/futures/)
//! and [asynk-strim](https://docs.rs/asynk-strim/latest/asynk_strim/) crates.
//!
//! Plus also additional utilities shipped with Rama.
//!
//! Exported for your convenience and because it is so fundamental to rama.

#[doc(inline)]
pub use ::futures::*;

#[doc(inline)]
pub use ::asynk_strim as async_stream;

mod delay;
pub use delay::DelayStream;

mod zip;
pub use zip::{TryZip, Zip, try_zip, zip};

mod graceful;
pub use graceful::GracefulStream;

#[cfg(test)]
mod tests;
