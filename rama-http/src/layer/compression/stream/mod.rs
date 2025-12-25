//! Streaming Compression Support in Rama.

mod body;
mod layer;
mod service;

pub use body::StreamCompressionBody;
pub use layer::StreamCompressionLayer;
pub use service::StreamCompression;

#[doc(inline)]
pub use crate::layer::util::compression::CompressionLevel;
