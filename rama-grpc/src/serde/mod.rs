//! A [`Codec`] which (de)serializes messages using [serde].
//!
//! Where [`ProstCodec`] is limited to protobuf messages generated from a `.proto` file,
//! [`SerdeCodec`] works with any Rust type which implements [`Serialize`] and
//! [`DeserializeOwned`], serialized in the wire format of your choice.
//!
//! Together with the [`define_service!`] macro this gives you gRPC services
//! defined and served fully in Rust, without protobuf or a build script.
//!
//! What you give up is reach: a `.proto` file is a contract other languages can generate
//! code from, and nothing here replaces that.
//!
//! What you get is that your own types are the contract. There is no generated message type
//! to convert to and from, an enum whose variants carry data needs no `oneof`, and there is
//! no `protoc` or build step between you and a change to a service.
//!
//! # Formats
//!
//! JSON is provided out of the box, as `JsonFormat` behind the `json` feature. Any other
//! format is a matter of implementing [`SerdeFormat`] for it: a serialize and a deserialize
//! call, plus a `type MyCodec<T, U> = SerdeCodec<MyFormat, T, U>` alias to name the result.
//! The JSON implementation is the reference for the shape of it, MessagePack via `rmp-serde`
//! is the same two calls.
//!
//! JSON being the one that ships does not make it the one to use. It is here because you can
//! read it on the wire, which helps when debugging and in examples. It is also the slowest
//! and most verbose option.
//!
//! MessagePack gives you a binary encoding from the same types and derives: smaller and
//! faster. Rust-native formats such as postcard or bincode are smaller and faster still, but
//! only Rust can read them. The codec is a type parameter, so pick one per service.
//!
//! All of them can stay backwards compatible, through optional fields, defaults and ignored
//! unknown fields. Unlike protobuf, nothing enforces that for you.
//!
//! Note that [`SerdeCodec`] is generic over the message types as well as the format, so
//! naming it in a service definition means naming all three: `SerdeCodec<JsonFormat, _, _>`,
//! where the `_` are the message types to infer. An alias such as `JsonCodec` avoids that.
//!
//! # Interoperability
//!
//! gRPC has no content type negotiation: both ends of a route have to be generated
//! with the same codec, see [`Codec`] for the details.
//!
//! [serde]: https://serde.rs
//! [`Codec`]: crate::codec::Codec
//! [`ProstCodec`]: crate::protobuf::ProstCodec
//! [`Serialize`]: serde::Serialize
//! [`DeserializeOwned`]: serde::de::DeserializeOwned
//! [`define_service!`]: crate::define_service

mod codec;
pub use codec::{SerdeCodec, SerdeDecoder, SerdeEncoder, SerdeFormat};

#[cfg(feature = "json")]
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
mod json;
#[cfg(feature = "json")]
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
pub use json::{JsonCodec, JsonFormat};

#[cfg(all(test, feature = "json"))]
mod tests;
