/// A bidirectional bridge between two streams.
#[derive(Debug, Clone)]
pub struct StreamBridge<A, B> {
    /// One side of the bridge.
    pub left: A,

    /// The other side of the bridge.
    pub right: B,
}
