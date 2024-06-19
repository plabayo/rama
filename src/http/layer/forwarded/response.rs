use crate::http::{IntoResponse, Request, RequestContext, Response};
use crate::net::forwarded::{Forwarded, ForwardedElement, NodeId};
use crate::net::stream::SocketInfo;
use crate::service::{Context, Layer, Service};
use std::fmt;

#[derive(Debug, Clone)]
/// Layer to write forwarded information for this proxy,
/// added to the end of the chain of forwarded information already known.
pub struct ForwardedResponseLayer {
    for_node: bool,
    by_node: Option<NodeId>,
    authority: bool,
    proto: bool,
}

impl ForwardedResponseLayer {
    /// Create a [`ForwardedResponseLayer`] with the option enabled
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

    /// Create a [`ForwardedResponseLayer`] with the option enabled
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

    /// Create a [`ForwardedResponseLayer`] with the option enabled
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

    /// Create a [`ForwardedResponseLayer`] with the option enabled
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
impl ForwardedResponseLayer {
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

impl<S> Layer<S> for ForwardedResponseLayer {
    type Service = ForwardedResponseService<S>;

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
pub struct ForwardedResponseService<S> {
    inner: S,
    for_node: bool,
    by_node: Option<NodeId>,
    authority: bool,
    proto: bool,
}

impl<S: fmt::Debug> fmt::Debug for ForwardedResponseService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardedResponseService")
            .field("inner", &self.inner)
            .field("for_node", &self.for_node)
            .field("by_node", &self.by_node)
            .field("authority", &self.authority)
            .field("proto", &self.proto)
            .finish()
    }
}

impl<S: Clone> Clone for ForwardedResponseService<S> {
    fn clone(&self) -> Self {
        ForwardedResponseService {
            inner: self.inner.clone(),
            for_node: self.for_node.clone(),
            by_node: self.by_node.clone(),
            authority: self.authority.clone(),
            proto: self.proto.clone(),
        }
    }
}

impl<S> ForwardedResponseService<S> {
    /// Create a [`ForwardedResponseService`] with the option enabled
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

    /// Create a [`ForwardedResponseService`] with the option enabled
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

    /// Create a [`ForwardedResponseService`] with the option enabled
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

    /// Create a [`ForwardedResponseService`] with the option enabled
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

impl<S> ForwardedResponseService<S> {
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

impl<S, State, Body> Service<State, Request<Body>> for ForwardedResponseService<S>
where
    S: Service<State, Request<Body>>,
    S::Response: IntoResponse,
    Body: Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let request_ctx = ctx.get_or_insert_from::<RequestContext, _>(&req).clone();
        let mut socket_info: Option<SocketInfo> = if self.for_node {
            ctx.get().cloned()
        } else {
            None
        };
        let forwarded: Option<Forwarded> = ctx.get().cloned();

        let mut response = self.inner.serve(ctx, req).await?.into_response();

        let mut forwarded_element = None;

        if let Some(socket_info) = socket_info.take() {
            forwarded_element = Some(ForwardedElement::forwarded_for(
                socket_info.peer_addr().clone(),
            ));
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
            if let Some(authority) = request_ctx.authority {
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
            forwarded_element = match forwarded_element.take() {
                Some(mut forwarded_element) => {
                    forwarded_element.set_forwarded_proto(request_ctx.protocol);
                    Some(forwarded_element)
                }
                None => Some(ForwardedElement::forwarded_proto(request_ctx.protocol)),
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

        if let Some(forwarded) = forwarded {}

        Ok(response)
    }
}
