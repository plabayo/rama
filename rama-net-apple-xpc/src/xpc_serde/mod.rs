//! Serde support for [`XpcMessage`].
//!
//! Provides a bidirectional mapping between [`XpcMessage`] and any type that
//! implements [`serde::Serialize`] / [`serde::de::DeserializeOwned`].
//!
//! ## Mapping
//!
//! | Serde type             | [`XpcMessage`] variant               |
//! |------------------------|--------------------------------------|
//! | `bool`                 | `Bool`                               |
//! | signed integers        | `Int64`                              |
//! | unsigned integers      | `Uint64`                             |
//! | `f32` / `f64`          | `Double`                             |
//! | `char` / `str`         | `String`                             |
//! | `bytes`                | `Data`                               |
//! | `None` / `()`          | `Null`                               |
//! | sequences / tuples     | `Array`                              |
//! | maps / structs         | `Dictionary`                         |
//! | unit enum variants     | `String` (variant name)              |
//! | newtype/tuple/struct enum variants | `Dictionary` `{"Variant": …}` |
//!
//! ## Functions
//!
//! - [`to_xpc_message`] — serialize a Rust value into an [`XpcMessage`].
//! - [`from_xpc_message`] — deserialize an [`XpcMessage`] into a Rust value.

use serde::de::DeserializeOwned;

use crate::{
    XpcError, XpcMessage,
    xpc_serde::types::{de::XpcDeserializer, ser::XpcSerializer},
};

mod types;

/// Serialize a Rust value into an [`XpcMessage`].
///
/// The mapping follows the table in the [module docs](self).
/// Returns [`XpcError::SerializationFailed`] if the value cannot be represented.
pub fn to_xpc_message<T: serde::Serialize + ?Sized>(value: &T) -> Result<XpcMessage, XpcError> {
    value.serialize(XpcSerializer).map_err(XpcError::from)
}

/// Deserialize an [`XpcMessage`] into a Rust value.
///
/// Returns [`XpcError::DeserializationFailed`] if the message does not match
/// the expected shape for `T`.
pub fn from_xpc_message<T: DeserializeOwned>(msg: XpcMessage) -> Result<T, XpcError> {
    T::deserialize(XpcDeserializer(msg)).map_err(XpcError::from)
}

#[cfg(test)]
mod tests;
