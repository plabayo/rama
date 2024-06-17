use super::NodeId;
use crate::net::{address::Authority, Protocol};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A single entry in the [`Forwarded`] chain.
///
/// [`Forwarded`]: crate::net::forwarded::Forwarded
pub struct ForwardedEntry {
    by_node: Option<NodeId>,
    for_node: Option<NodeId>,
    host: Option<Authority>,
    proto: Option<Protocol>,
}
