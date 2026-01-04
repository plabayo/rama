//! Codegen exports used by `rama-grpc-build`.
//!
//! Not meant to be used directly by the user

pub use rama_core::{
    Service, bytes::Bytes, error::BoxError, extensions::ExtensionsMut, futures::Stream,
};
pub use rama_http_types as http;
pub use rama_utils::macros::generate_set_and_with;
