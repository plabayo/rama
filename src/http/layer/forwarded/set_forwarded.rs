use crate::http::headers::HeaderMapExt;
use crate::http::{Request, RequestContext};
use crate::net::forwarded::{Forwarded, ForwardedElement, ForwardedProtocol, NodeId};
use crate::net::stream::SocketInfo;
use crate::service::{Context, Layer, Service};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
/// Layer to write forwarded information for this proxy,
/// added to the end of the chain of forwarded information already known.
pub struct SetForwardedLayer {
    for_node: bool,
    by_node: Option<NodeId>,
    authority: bool,
    proto: bool,
}

impl SetForwardedLayer {
    /// Create a [`SetForwardedLayer`] with the option enabled
    /// to add the peer's [`SocketAddr`] as the "for" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    pub fn forward_for() -> Self {
        Self {
            for_node: true,
            by_node: None,
            authority: false,
            proto: false,
        }
    }

    /// Create a [`SetForwardedLayer`] with the option enabled
    /// to add the given [`NodeId`] as the "by" property,
    /// identifying this proxy.
    pub fn forward_by(node_id: NodeId) -> Self {
        Self {
            for_node: false,
            by_node: Some(node_id),
            authority: false,
            proto: false,
        }
    }

    /// Create a [`SetForwardedLayer`] with the option enabled
    /// to add the known [`Response`]'s [`Authority`] as the "host" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`Response`]: crate::http::Response
    /// [`Authority`]: crate::net::address::Authority
    pub fn forward_authority() -> Self {
        Self {
            for_node: false,
            by_node: None,
            authority: true,
            proto: false,
        }
    }

    /// Create a [`SetForwardedLayer`] with the option enabled
    /// to add the known [`Response`]'s [`Protocol`] as the "proto" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`Response`]: crate::http::Response
    /// [`Protocol`]: crate::net::Protocol
    pub fn forward_proto() -> Self {
        Self {
            for_node: false,
            by_node: None,
            authority: false,
            proto: true,
        }
    }
}

/// Middleware [`Layer`] to write [`Forwarded`] information for this proxy,
/// added to the end of the chain of forwarded information already known.
impl SetForwardedLayer {
    /// Enables the option to add the peer's [`SocketAddr`] as the "for" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    pub fn with_forward_for(mut self) -> Self {
        self.for_node = true;
        self
    }

    /// Enables the option to add the given [`NodeId`] as the "by" property,
    /// identifying this proxy.
    pub fn with_forward_by(mut self, node_id: NodeId) -> Self {
        self.by_node = Some(node_id);
        self
    }

    /// Enables the option to add the known [`Response`]'s [`Authority`] as the "host" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`Response`]: crate::http::Response
    /// [`Authority`]: crate::net::address::Authority
    pub fn with_forward_authority(mut self) -> Self {
        self.authority = true;
        self
    }

    /// Enables the option to add the known [`Response`]'s [`Protocol`] as the "proto" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`Response`]: crate::http::Response
    /// [`Protocol`]: crate::net::Protocol
    pub fn with_forward_proto(mut self) -> Self {
        self.proto = true;
        self
    }
}

impl<S> Layer<S> for SetForwardedLayer {
    type Service = SetForwardedService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            for_node: self.for_node,
            by_node: self.by_node.clone(),
            authority: self.authority,
            proto: self.proto,
        }
    }
}

/// Middleware [`Service`] to write [`Forwarded`] information for this proxy,
/// added to the end of the chain of forwarded information already known.
pub struct SetForwardedService<S> {
    inner: S,
    for_node: bool,
    by_node: Option<NodeId>,
    authority: bool,
    proto: bool,
}

impl<S: fmt::Debug> fmt::Debug for SetForwardedService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetForwardedService")
            .field("inner", &self.inner)
            .field("for_node", &self.for_node)
            .field("by_node", &self.by_node)
            .field("authority", &self.authority)
            .field("proto", &self.proto)
            .finish()
    }
}

impl<S: Clone> Clone for SetForwardedService<S> {
    fn clone(&self) -> Self {
        SetForwardedService {
            inner: self.inner.clone(),
            for_node: self.for_node,
            by_node: self.by_node.clone(),
            authority: self.authority,
            proto: self.proto,
        }
    }
}

impl<S> SetForwardedService<S> {
    /// Create a [`SetForwardedService`] with the option enabled
    /// to add the peer's [`SocketAddr`] as the "for" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    pub fn forward_for(inner: S) -> Self {
        Self {
            inner,
            for_node: true,
            by_node: None,
            authority: false,
            proto: false,
        }
    }

    /// Create a [`SetForwardedService`] with the option enabled
    /// to add the given [`NodeId`] as the "by" property,
    /// identifying this proxy.
    pub fn forward_by(inner: S, node_id: NodeId) -> Self {
        Self {
            inner,
            for_node: false,
            by_node: Some(node_id),
            authority: false,
            proto: false,
        }
    }

    /// Create a [`SetForwardedService`] with the option enabled
    /// to add the known [`Response`]'s [`Authority`] as the "host" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`Response`]: crate::http::Response
    /// [`Authority`]: crate::net::address::Authority
    pub fn forward_authority(inner: S) -> Self {
        Self {
            inner,
            for_node: false,
            by_node: None,
            authority: true,
            proto: false,
        }
    }

    /// Create a [`SetForwardedService`] with the option enabled
    /// to add the known [`Response`]'s [`Protocol`] as the "proto" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`Response`]: crate::http::Response
    /// [`Protocol`]: crate::net::Protocol
    pub fn forward_proto(inner: S) -> Self {
        Self {
            inner,
            for_node: false,
            by_node: None,
            authority: false,
            proto: true,
        }
    }
}

impl<S> SetForwardedService<S> {
    /// Enables the option to add the peer's [`SocketAddr`] as the "for" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    pub fn with_forward_for(mut self) -> Self {
        self.for_node = true;
        self
    }

    /// Enables the option to add the given [`NodeId`] as the "by" property,
    /// identifying this proxy.
    pub fn with_forward_by(mut self, node_id: NodeId) -> Self {
        self.by_node = Some(node_id);
        self
    }

    /// Enables the option to add the known [`Response`]'s [`Authority`] as the "host" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`Response`]: crate::http::Response
    /// [`Authority`]: crate::net::address::Authority
    pub fn with_forward_authority(mut self) -> Self {
        self.authority = true;
        self
    }

    /// Enables the option to add the known [`Response`]'s [`Protocol`] as the "proto" property.
    ///
    /// In case this information is not available it will not be written.
    ///
    /// [`Response`]: crate::http::Response
    /// [`Protocol`]: crate::net::Protocol
    pub fn with_forward_proto(mut self) -> Self {
        self.proto = true;
        self
    }
}

impl<S, State, Body> Service<State, Request<Body>> for SetForwardedService<S>
where
    S: Service<State, Request<Body>>,
    Body: Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context<State>,
        mut req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let mut peer_addr: Option<SocketAddr> = if self.for_node {
            ctx.get::<SocketInfo>().map(|socket| *socket.peer_addr())
        } else {
            None
        };
        let forwarded: Option<Forwarded> = ctx.get().cloned();
        let request_ctx: &RequestContext = ctx.get_or_insert_from(&req);

        let mut forwarded_element = None;

        if let Some(peer_addr) = peer_addr.take() {
            forwarded_element = Some(ForwardedElement::forwarded_for(peer_addr));
        }

        if let Some(node_id) = self.by_node.clone() {
            forwarded_element = match forwarded_element.take() {
                Some(mut forwarded_element) => {
                    forwarded_element.set_forwarded_by(node_id);
                    Some(forwarded_element)
                }
                None => Some(ForwardedElement::forwarded_by(node_id)),
            };
        }

        if self.authority {
            if let Some(authority) = request_ctx.authority.clone() {
                forwarded_element = match forwarded_element.take() {
                    Some(mut forwarded_element) => {
                        forwarded_element.set_forwarded_host(authority);
                        Some(forwarded_element)
                    }
                    None => Some(ForwardedElement::forwarded_host(authority)),
                };
            }
        }

        if self.proto {
            let fowarded_proto: ForwardedProtocol = request_ctx.protocol.clone().into();
            forwarded_element = match forwarded_element.take() {
                Some(mut forwarded_element) => {
                    forwarded_element.set_forwarded_proto(fowarded_proto);
                    Some(forwarded_element)
                }
                None => Some(ForwardedElement::forwarded_proto(fowarded_proto)),
            };
        }

        let forwarded = match (forwarded, forwarded_element) {
            (None, None) => None,
            (Some(forwarded), None) => Some(forwarded),
            (None, Some(forwarded_element)) => Some(Forwarded::new(forwarded_element)),
            (Some(mut forwarded), Some(forwarded_element)) => {
                forwarded.append(forwarded_element);
                Some(forwarded)
            }
        };

        if let Some(forwarded) = forwarded {
            req.headers_mut().typed_insert(forwarded);
        }

        self.inner.serve(ctx, req)
    }
}
