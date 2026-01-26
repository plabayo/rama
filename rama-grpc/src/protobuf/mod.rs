//! protocol buffer (protobuf) support for `rama-grpc`
//!
//! Protocol Buffers are language-neutral, platform-neutral
//! extensible mechanisms for serializing structured data.
//!
//! ## Prost Codec
//!
//! This crate provides the [`ProstCodec`] for encoding and decoding protobuf
//! messages using the [`prost`] library, which is also re-exported here.
//!
//! ## Types
//!
//! The [`types`] submodule contains a collection of useful protobuf types
//! that can be used with the rest of `rama-grpc`.
//!
//! ## What Are Protocol Buffers?
//!
//! Protocol buffers are Google’s language-neutral, platform-neutral,
//! extensible mechanism for serializing structured data – think XML, but smaller,
//! faster, and simpler. You define how you want your data to be structured once,
//! then you can use special generated source code to easily write and read your structured data
//! to and from a variety of data streams and using a variety of languages.

mod codec;
pub use codec::{ProstCodec, ProstDecoder, ProstEncoder};

pub mod types;

pub mod prost {
    //! Re-export of [prost](https://docs.rs/prost) and
    //! [prost-types](https://docs.rs/prost-types) crates.

    pub use ::prost::*;
    pub use ::prost_types as types;
}
