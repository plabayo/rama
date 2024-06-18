//! rama support for the "Forwarded HTTP Extension"
//!
//! RFC: <https://datatracker.ietf.org/doc/html/rfc7239>

mod obfuscated;
#[doc(inline)]
use obfuscated::{ObfNode, ObfPort};

mod node;
#[doc(inline)]
pub use node::NodeId;

mod element_parser;

mod element;
#[doc(inline)]
pub use element::ForwardedElement;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Forwarding information stored as a chain.
///
/// This extension (which can be stored and modified via the [`Context`])
/// allows to keep track of the forward information. E.g. what was the original
/// host used by the user, by which proxy it was forwarded, what was the intended
/// protocol (e.g. https), etc...
///
/// [`Context`]: crate::service::Context
pub struct Forwarded {
    elements: Vec<ForwardedElement>,
}
