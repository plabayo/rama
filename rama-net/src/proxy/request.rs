use std::fmt;

/// A request to proxy between source and target (stream).
pub struct ProxyRequest<S, T> {
    /// Source stream, which is usualy the initiator, e.g. the client.
    pub source: S,
    /// Target stream, which is usually the acceptor, e.g. the server.
    pub target: T,
}

impl<S: fmt::Debug, T: fmt::Debug> fmt::Debug for ProxyRequest<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyRequest")
            .field("source", &self.source)
            .field("target", &self.target)
            .finish()
    }
}

impl<S: Clone, T: Clone> Clone for ProxyRequest<S, T> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            target: self.target.clone(),
        }
    }
}
