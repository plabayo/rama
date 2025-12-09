/// A request to proxy between source and target (stream).
#[derive(Debug, Clone)]
pub struct ProxyRequest<S, T> {
    /// Source stream, which is usualy the initiator, e.g. the client.
    pub source: S,
    /// Target stream, which is usually the acceptor, e.g. the server.
    pub target: T,
}
