mod name;
#[doc(inline)]
pub use name::NodeName;

mod port;
#[doc(inline)]
pub use port::NodePort;

pub struct Node {
    name: NodeName,
    port: Option<NodePort>,
}
