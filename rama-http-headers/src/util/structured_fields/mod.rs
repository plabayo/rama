//! Minimal Structured Fields (RFC 9651) subset for HTTP Message Signatures (RFC 9421).
//!
//! Covers Dictionaries, Inner Lists, Items, and Parameters needed by
//! `Signature` / `Signature-Input` (and later `Content-Digest`).
//!
//! `ponytail:` not a full RFC 9651 implementation; upgrade to a general SF
//! library (or expand this module) if other headers need the full grammar.

mod parse;
mod serialize;
mod types;

pub use parse::{ParseError, parse_dictionary};
pub use serialize::serialize_dictionary;
pub use types::{
    BareItem, Dictionary, DictionaryMember, InnerList, Item, Parameter, ParameterValue, Parameters,
};
