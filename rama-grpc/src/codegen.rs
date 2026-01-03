//! Codegen exports used by `rama-grpc-build`.

pub use crate::codec::{CompressionEncoding, EnabledCompressionEncodings};
pub use crate::extensions::GrpcMethod;
pub use rama_core::Service;
pub use rama_core::{bytes::Bytes, error::BoxError, futures::Stream, stream};
pub use rama_http_types as http;
pub use rama_utils::macros::generate_set_and_with;
pub use std::pin::Pin;
pub use std::sync::Arc;
pub use std::task::{Context, Poll};

// TOOD: check if we really need these boxes without async-trait etc...
pub type BoxFuture<T, E> = self::Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'static>>;
pub type BoxStream<T> =
    self::Pin<Box<dyn Stream<Item = Result<T, crate::Status>> + Send + 'static>>;
