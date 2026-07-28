//! HTTP Message Signatures (RFC 9421) — component extraction, signature base,
//! and (behind `message-signature`) sign/verify layers.

pub mod base;
pub mod component;

#[cfg(feature = "message-signature")]
#[cfg_attr(docsrs, doc(cfg(feature = "message-signature")))]
mod layers;

#[doc(inline)]
pub use base::{
    SignatureBaseError, build_signature_base, build_signature_params_line,
    signature_input_for_label,
};
#[doc(inline)]
pub use component::{
    ComponentContext, ComponentError, MessageKind, StructuredFieldType, component_identity_key,
    known_structured_field_type, resolve_component_value, serialize_component_identifier,
};

#[cfg(feature = "message-signature")]
#[cfg_attr(docsrs, doc(cfg(feature = "message-signature")))]
pub use layers::*;
