//! rama-http-types → hyperium `http` conversions.

mod body;
mod leaf;
mod message;

pub use body::{HyperiumBody, HyperiumBodyError};

/// Fallibly convert a rama-http-types value into its hyperium [`http`]-crate
/// equivalent. Sealed; the implemented set is fixed by this crate.
///
/// [`http`]: https://docs.rs/http
pub trait TryIntoHyperiumHttp: crate::sealed::Sealed {
    /// The hyperium `http` type produced.
    type Output;
    /// The conversion error.
    type Error;

    /// Convert `self` into its hyperium `http` equivalent.
    fn try_into_hyperium_http(self) -> Result<Self::Output, Self::Error>;
}
