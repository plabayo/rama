//! Codegen exports used by `tonic-build`.

pub use rama_core::Service;
pub use std::pin::Pin;
pub use std::sync::Arc;
pub use std::task::{Context, Poll};
pub type StdError = rama_core::error::BoxError;
pub use crate::codec::{CompressionEncoding, EnabledCompressionEncodings};
pub use crate::extensions::GrpcMethod;
pub use rama_core::{bytes::Bytes, futures::Stream, stream};
pub use rama_http_types as http;

// TOOD: check if we really need these boxes without async-trait etc...
pub type BoxFuture<T, E> = self::Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'static>>;
pub type BoxStream<T> =
    self::Pin<Box<dyn Stream<Item = Result<T, crate::Status>> + Send + 'static>>;
