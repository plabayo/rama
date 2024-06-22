use crate::http::headers::{
    ForwardHeader, HeaderMapExt, Via, XForwardedFor, XForwardedHost, XForwardedProto,
};
use crate::http::{Request, RequestContext};
use crate::net::address::Domain;
use crate::net::forwarded::{Forwarded, ForwardedElement, NodeId};
use crate::net::stream::SocketInfo;
use crate::service::{Context, Layer, Service};
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
/// Layer to write forwarded information for this proxy,
/// added to the end of the chain of forwarded information already known.
pub struct SetForwardedHeadersLayer<T = Forwarded> {
    by_node: NodeId,
    _headers: PhantomData<fn() -> T>,
}

impl<T> SetForwardedHeadersLayer<T> {
    /// Set the given [`NodeId`] as the "by" property, identifying this proxy.
    ///
    /// Default of `None` will be set to `rama` otherwise.
    pub fn forward_by(&mut self, node_id: NodeId) -> &mut Self {
        self.by_node = node_id;
        self
    }
}

impl<T> SetForwardedHeadersLayer<T> {
    /// Create a new `SetForwardedHeadersLayer` for the specified headers `T`.
    pub fn new() -> Self {
        Self {
            by_node: Domain::from_static("rama").into(),
            _headers: PhantomData,
        }
    }
}

impl Default for SetForwardedHeadersLayer {
    fn default() -> Self {
        Self::forwarded()
    }
}

impl SetForwardedHeadersLayer {
    #[inline]
    /// Create a new `SetForwardedHeadersLayer` for the standard [`Forwarded`] header.
    pub fn forwarded() -> Self {
        Self::new()
    }
}

impl SetForwardedHeadersLayer<Via> {
    #[inline]
    /// Create a new `SetForwardedHeadersLayer` for the canonical [`Via`] header.
    pub fn via() -> Self {
        Self::new()
    }
}

impl SetForwardedHeadersLayer<XForwardedFor> {
    #[inline]
    /// Create a new `SetForwardedHeadersLayer` for the canonical [`X-Forwarded-For`] header.
    pub fn x_forwarded_for() -> Self {
        Self::new()
    }
}

impl SetForwardedHeadersLayer<XForwardedHost> {
    #[inline]
    /// Create a new `SetForwardedHeadersLayer` for the canonical [`X-Forwarded-Host`] header.
    pub fn x_forwarded_host() -> Self {
        Self::new()
    }
}

impl SetForwardedHeadersLayer<XForwardedProto> {
    #[inline]
    /// Create a new `SetForwardedHeadersLayer` for the canonical [`X-Forwarded-Proto`] header.
    pub fn x_forwarded_proto() -> Self {
        Self::new()
    }
}

macro_rules! set_forwarded_layer_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* S> Layer<S> for SetForwardedHeadersLayer<($($ty,)*)> {
            type Service = SetForwardedHeadersService<S, ($($ty,)*)>;

            fn layer(&self, inner: S) -> Self::Service {
                Self::Service {
                    inner,
                    by_node: self.by_node.clone(),
                    _headers: PhantomData,
                }
            }
        }
    }
}

all_the_tuples_no_last_special_case!(set_forwarded_layer_for_tuple);

/// Middleware [`Service`] to write [`Forwarded`] information for this proxy,
/// added to the end of the chain of forwarded information already known.
pub struct SetForwardedHeadersService<S, T = Forwarded> {
    inner: S,
    by_node: NodeId,
    _headers: PhantomData<fn() -> T>,
}

impl<S: fmt::Debug, T> fmt::Debug for SetForwardedHeadersService<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetForwardedHeadersService")
            .field("inner", &self.inner)
            .field("by_node", &self.by_node)
            .field("_headers", &format_args!("{}", std::any::type_name::<T>()))
            .finish()
    }
}

impl<S: Clone, T> Clone for SetForwardedHeadersService<S, T> {
    fn clone(&self) -> Self {
        SetForwardedHeadersService {
            inner: self.inner.clone(),
            by_node: self.by_node.clone(),
            _headers: PhantomData,
        }
    }
}

impl<S, T> SetForwardedHeadersService<S, T> {
    /// Set the given [`NodeId`] as the "by" property, identifying this proxy.
    ///
    /// Default of `None` will be set to `rama` otherwise.
    pub fn forward_by(&mut self, node_id: NodeId) -> &mut Self {
        self.by_node = node_id;
        self
    }
}

impl<S, T> SetForwardedHeadersService<S, T> {
    /// Create a new `SetForwardedHeadersService` for the specified headers `T`.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            by_node: Domain::from_static("rama").into(),
            _headers: PhantomData,
        }
    }
}

impl<S> SetForwardedHeadersService<S> {
    #[inline]
    /// Create a new `SetForwardedHeadersService` for the standard [`Forwarded`] header.
    pub fn forwarded(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> SetForwardedHeadersService<S, Via> {
    #[inline]
    /// Create a new `SetForwardedHeadersService` for the canonical [`Via`] header.
    pub fn via(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> SetForwardedHeadersService<S, XForwardedFor> {
    #[inline]
    /// Create a new `SetForwardedHeadersService` for the canonical [`X-Forwarded-For`] header.
    pub fn x_forwarded_for(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> SetForwardedHeadersService<S, XForwardedHost> {
    #[inline]
    /// Create a new `SetForwardedHeadersService` for the canonical [`X-Forwarded-Host`] header.
    pub fn x_forwarded_host(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> SetForwardedHeadersService<S, XForwardedProto> {
    #[inline]
    /// Create a new `SetForwardedHeadersService` for the canonical [`X-Forwarded-Proto`] header.
    pub fn x_forwarded_proto(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S, H, State, Body> Service<State, Request<Body>> for SetForwardedHeadersService<S, H>
where
    S: Service<State, Request<Body>>,
    H: ForwardHeader + Send + Sync + 'static,
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
        let mut peer_addr: Option<SocketAddr> =
            ctx.get::<SocketInfo>().map(|socket| *socket.peer_addr());
        let forwarded: Option<Forwarded> = ctx.get().cloned();
        let request_ctx: &RequestContext = ctx.get_or_insert_from(&req);

        let mut forwarded_element = ForwardedElement::forwarded_by(self.by_node.clone());

        if let Some(peer_addr) = peer_addr.take() {
            forwarded_element.set_forwarded_for(peer_addr);
        }

        if let Some(authority) = request_ctx.authority.clone() {
            forwarded_element.set_forwarded_host(authority);
        }

        if let Ok(forwarded_proto) = (&request_ctx.protocol).try_into() {
            forwarded_element.set_forwarded_proto(forwarded_proto);
        }

        let forwarded = match forwarded {
            None => Some(Forwarded::new(forwarded_element)),
            Some(mut forwarded) => {
                forwarded.append(forwarded_element);
                Some(forwarded)
            }
        };

        if let Some(forwarded) = forwarded {
            if let Some(header) = H::try_from_forwarded(forwarded.iter()) {
                req.headers_mut().typed_insert(header);
            }
        }

        self.inner.serve(ctx, req)
    }
}

macro_rules! set_forwarded_service_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* S, State, Body> Service<State, Request<Body>> for SetForwardedHeadersService<S, ($($ty,)*)>
        where
            $( $ty: ForwardHeader + Send + Sync + 'static, )*
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
                let mut peer_addr: Option<SocketAddr> =
                    ctx.get::<SocketInfo>().map(|socket| *socket.peer_addr());
                let forwarded: Option<Forwarded> = ctx.get().cloned();
                let request_ctx: &RequestContext = ctx.get_or_insert_from(&req);

                let mut forwarded_element = ForwardedElement::forwarded_by(self.by_node.clone());

                if let Some(peer_addr) = peer_addr.take() {
                    forwarded_element.set_forwarded_for(peer_addr);
                }

                if let Some(authority) = request_ctx.authority.clone() {
                    forwarded_element.set_forwarded_host(authority);
                }

                if let Ok(forwarded_proto) = (&request_ctx.protocol).try_into() {
                    forwarded_element.set_forwarded_proto(forwarded_proto);
                }

                let forwarded = match forwarded {
                    None => Some(Forwarded::new(forwarded_element)),
                    Some(mut forwarded) => {
                        forwarded.append(forwarded_element);
                        Some(forwarded)
                    }
                };

                if let Some(forwarded) = forwarded {
                    $(
                        if let Some(header) = $ty::try_from_forwarded(forwarded.iter()) {
                            req.headers_mut().typed_insert(header);
                        }
                    )*
                }

                self.inner.serve(ctx, req)
            }
        }
    }
}
all_the_tuples_no_last_special_case!(set_forwarded_service_for_tuple);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::OpaqueError,
        http::{
            headers::{TrueClientIp, XClientIp},
            IntoResponse, Response, StatusCode,
        },
        service::service_fn,
    };

    fn assert_is_service<T: Service<(), Request<()>>>(_: T) {}

    async fn dummy_service_fn() -> Result<Response, OpaqueError> {
        Ok(StatusCode::OK.into_response())
    }

    #[test]
    fn test_set_forwarded_service_is_service() {
        assert_is_service(SetForwardedHeadersService::forwarded(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(SetForwardedHeadersService::via(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(SetForwardedHeadersService::x_forwarded_for(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(SetForwardedHeadersService::x_forwarded_proto(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(SetForwardedHeadersService::x_forwarded_host(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(SetForwardedHeadersService::<_, TrueClientIp>::new(
            service_fn(dummy_service_fn),
        ));
        assert_is_service(SetForwardedHeadersService::<_, (TrueClientIp,)>::new(
            service_fn(dummy_service_fn),
        ));
        assert_is_service(
            SetForwardedHeadersService::<_, (TrueClientIp, XClientIp)>::new(service_fn(
                dummy_service_fn,
            )),
        );
    }
}
