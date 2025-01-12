use rama_net::transport::{TransportContext, TransportProtocol};

/// The context as relevant to the proxy layer.
#[derive(Debug, Clone)]
pub struct ProxyContext {
    /// The transport protocol used by the proxy.
    pub protocol: TransportProtocol,
}

impl From<TransportContext> for ProxyContext {
    fn from(ctx: TransportContext) -> Self {
        Self {
            protocol: ctx.protocol,
        }
    }
}

impl From<&TransportContext> for ProxyContext {
    fn from(ctx: &TransportContext) -> Self {
        Self {
            protocol: ctx.protocol,
        }
    }
}
