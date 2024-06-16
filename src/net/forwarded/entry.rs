use super::Node;
use crate::net::{address::Authority, Protocol};

pub struct ForwardedEntry {
    by_node: Option<Node>,
    for_node: Option<Node>,
    host: Option<Authority>,
    proto: Option<Protocol>,
}
