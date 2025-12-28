//! Prost codec implementation for tonic.
//!
//! This module provides the [`ProstCodec`] for encoding and decoding protobuf
//! messages using the [`prost`] library.

mod codec;

pub use codec::{ProstCodec, ProstDecoder, ProstEncoder};

// Re-export prost types that users might need
pub use prost as core;
