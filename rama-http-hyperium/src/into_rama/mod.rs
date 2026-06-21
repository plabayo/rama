//! hyperium `http` → rama-http-types conversions.

mod body;
mod leaf;
mod message;

pub use body::{RamaBody, RamaBodyError};

/// Fallibly convert a hyperium [`http`]-crate value into its rama-http-types
/// equivalent. Sealed; the implemented set is fixed by this crate.
///
/// [`http`]: https://docs.rs/http
pub trait TryIntoRamaHttp: crate::sealed::Sealed {
    /// The rama-http-types type produced.
    type Output;
    /// The conversion error.
    type Error;

    /// Convert `self` into its rama-http-types equivalent.
    fn try_into_rama_http(self) -> Result<Self::Output, Self::Error>;
}
