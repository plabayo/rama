//! HTTP Message Signatures (RFC 9421) — component extraction and signature base.
//!
//! Sign/verify/proxy layers are available behind the `message-signature` feature
//! in follow-up PRs.

pub mod base;
pub mod component;

#[doc(inline)]
pub use base::{
    SignatureBaseError, build_signature_base, build_signature_params_line,
    signature_input_for_label,
};
#[doc(inline)]
pub use component::{
    ComponentContext, ComponentError, MessageKind, StructuredFieldType,
    known_structured_field_type, resolve_component_value, serialize_component_identifier,
};
