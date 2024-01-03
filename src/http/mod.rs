//! Rama http modules.

pub(crate) mod body;
pub use body::{Body, BodyDataStream};

/// Type alias for [`http::Request`] whose body type
/// defaults to [`Body`], the most common body type used with rama.
pub type Request<T = Body> = http::Request<T>;

/// Type alias for [`http::Response`] whose body type
/// defaults to [`Body`], the most common body type used with rama.
pub type Response<T = Body> = http::Response<T>;
