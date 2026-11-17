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

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
mod delay;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use delay::DelayStream;

#[cfg(feature = "std")]
mod drain;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use drain::try_join_with_drain;

mod zip;
pub use zip::{TryZip, Zip, try_zip, zip};

mod graceful;
pub use graceful::GracefulStream;

/// Await `future` if there is one, else stay pending forever.
///
/// Unlike [`future::OptionFuture`], which resolves to `None`, this suits a
/// `select!` branch that must never fire while its future is absent.
pub async fn maybe<F: Future>(future: Option<F>) -> F::Output {
    match future {
        Some(future) => future.await,
        None => core::future::pending().await,
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
