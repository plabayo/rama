use crate::http::headers::{
    ForwardHeader, HeaderMapExt, Via, XForwardedFor, XForwardedHost, XForwardedProto,
};
use crate::http::{get_request_context, Request};
use crate::net::address::Domain;
use crate::net::forwarded::{Forwarded, ForwardedElement, NodeId};
use crate::net::stream::SocketInfo;
use crate::service::{Context, Layer, Service};
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
/// Layer to write [`Forwarded`] information for this proxy,
/// added to the end of the chain of forwarded information already known.
///
/// This layer can set any header as long as you have a [`ForwardHeader`] implementation
/// for the header you want to set. You can pass it as the type to the layer when creating
/// the layer using [`SetForwardedHeadersLayer::new`]. Multiple headers (in order) can also be set
/// by specifying multiple types as a tuple.
///
/// The following headers are supported out of the box with each their own constructor:
///
/// - [`SetForwardedHeadersLayer::forwarded`]: the standard [`Forwarded`] header [`RFC 7239`](https://tools.ietf.org/html/rfc7239);
/// - [`SetForwardedHeadersLayer::via`]: the canonical [`Via`] header (non-standard);
/// - [`SetForwardedHeadersLayer::x_forwarded_for`]: the canonical [`X-Forwarded-For`][`XForwardedFor`] header (non-standard);
/// - [`SetForwardedHeadersLayer::x_forwarded_host`]: the canonical [`X-Forwarded-Host`][`XForwardedHost`] header (non-standard);
/// - [`SetForwardedHeadersLayer::x_forwarded_proto`]: the canonical [`X-Forwarded-Proto`][`XForwardedProto`] header (non-standard).
///
/// The "by" property is set to `rama` by default. Use [`SetForwardedHeadersLayer::forward_by`] to overwrite this,
/// typically with the actual [`IPv4`]/[`IPv6`] address of your proxy.
///
/// [`IPv4`]: std::net::Ipv4Addr
/// [`IPv6`]: std::net::Ipv6Addr
///
/// Rama also has the following headers already implemented for you to use:
///
/// > [`X-Real-Ip`], [`X-Client-Ip`], [`Client-Ip`], [`CF-Connecting-Ip`] and [`True-Client-Ip`].
///
/// There are no [`SetForwardedHeadersLayer`] constructors for these headers,
/// but you can use the [`SetForwardedHeadersLayer::new`] constructor and pass the header type as a type parameter,
/// alone or in a tuple with other headers.
///
/// [`X-Real-Ip`]: crate::http::headers::XRealIp
/// [`X-Client-Ip`]: crate::http::headers::XClientIp
/// [`Client-Ip`]: crate::http::headers::ClientIp
/// [`CF-Connecting-Ip`]: crate::http::headers::CFConnectingIp
/// [`True-Client-Ip`]: crate::http::headers::TrueClientIp
///
/// ## Example
///
/// This example shows how you could expose the real Client IP using the [`X-Real-IP`][`crate::http::headers::XRealIp`] header.
///
/// ```rust
/// # use rama::{http::Request, net::stream::SocketInfo};
/// use rama::{
///     http::{headers::XRealIp, layer::forwarded::SetForwardedHeadersLayer},
///     service::{Context, Service, ServiceBuilder},
/// };
/// use std::convert::Infallible;
///
/// # type Body = ();
/// # type State = ();
///
/// # #[tokio::main]
/// # async fn main() {
/// async fn svc(_ctx: Context<State>, request: Request<Body>) -> Result<(), Infallible> {
///     // ...
///     # assert_eq!(
///     #     request.headers().get("X-Real-Ip").unwrap(),
///     #     "42.37.100.50:62345",
///     # );
///     # Ok(())
/// }
///
/// let service = ServiceBuilder::new()
///     .layer(SetForwardedHeadersLayer::<XRealIp>::new())
///     .service_fn(svc);
///
/// # let req = Request::new(());
/// # let mut ctx = Context::default();
/// # ctx.insert(SocketInfo::new(None, "42.37.100.50:62345".parse().unwrap()));
/// service.serve(ctx, req).await.unwrap();
/// # }
/// ```
pub struct SetForwardedHeadersLayer<T = Forwarded> {
    by_node: NodeId,
    _headers: PhantomData<fn() -> T>,
}

impl<T> SetForwardedHeadersLayer<T> {
    /// Set the given [`NodeId`] as the "by" property, identifying this proxy.
    ///
    /// Default of `None` will be set to `rama` otherwise.
    pub fn forward_by(mut self, node_id: impl Into<NodeId>) -> Self {
        self.by_node = node_id.into();
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

impl<H, S> Layer<S> for SetForwardedHeadersLayer<H> {
    type Service = SetForwardedHeadersService<S, H>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            by_node: self.by_node.clone(),
            _headers: PhantomData,
        }
    }
}

/// Middleware [`Service`] to write [`Forwarded`] information for this proxy,
/// added to the end of the chain of forwarded information already known.
///
/// See [`SetForwardedHeadersLayer`] for more information.
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
    pub fn forward_by(mut self, node_id: impl Into<NodeId>) -> Self {
        self.by_node = node_id.into();
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
        let request_ctx = get_request_context!(ctx, req);

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
        impl<S, $($ty),* , State, Body> Service<State, Request<Body>> for SetForwardedHeadersService<S, ($($ty,)*)>
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
                let forwarded: Option<Forwarded> = ctx.get().cloned();
                let request_ctx = get_request_context!(ctx, req);

                let mut forwarded_element = ForwardedElement::forwarded_by(self.by_node.clone());

                if let Some(peer_addr) = ctx.get::<SocketInfo>().map(|socket| *socket.peer_addr()) {
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
    };
}
all_the_tuples_no_last_special_case!(set_forwarded_service_for_tuple);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::OpaqueError,
        http::{
            headers::{TrueClientIp, XClientIp, XRealIp},
            IntoResponse, Response, StatusCode,
        },
        service::{service_fn, ServiceBuilder},
    };
    use std::{convert::Infallible, net::IpAddr};

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
        assert_is_service(
            ServiceBuilder::new()
                .layer(SetForwardedHeadersLayer::via())
                .service_fn(dummy_service_fn),
        );
        assert_is_service(
            ServiceBuilder::new()
                .layer(SetForwardedHeadersLayer::<XRealIp>::new())
                .service_fn(dummy_service_fn),
        );
        assert_is_service(
            ServiceBuilder::new()
                .layer(SetForwardedHeadersLayer::<(XRealIp, XForwardedProto)>::new())
                .service_fn(dummy_service_fn),
        );
    }

    #[tokio::test]
    async fn test_set_forwarded_service_forwarded() {
        async fn svc(request: Request<()>) -> Result<(), Infallible> {
            assert_eq!(
                request.headers().get("Forwarded").unwrap(),
                "by=rama;proto=http"
            );
            Ok(())
        }

        let service = SetForwardedHeadersService::forwarded(service_fn(svc));
        let req = Request::new(());
        service.serve(Context::default(), req).await.unwrap();
    }

    #[tokio::test]
    async fn test_set_forwarded_service_forwarded_with_chain() {
        async fn svc(request: Request<()>) -> Result<(), Infallible> {
            assert_eq!(
                request.headers().get("Forwarded").unwrap(),
                "for=12.23.34.45,by=rama;for=\"127.0.0.1:62345\";host=\"www.example.com:443\";proto=https",
            );
            Ok(())
        }

        let service = SetForwardedHeadersService::forwarded(service_fn(svc));
        let req = Request::builder()
            .uri("https://www.example.com")
            .body(())
            .unwrap();
        let mut ctx = Context::default();
        ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
            IpAddr::from([12, 23, 34, 45]),
        )));
        ctx.insert(SocketInfo::new(None, "127.0.0.1:62345".parse().unwrap()));
        service.serve(ctx, req).await.unwrap();
    }

    #[tokio::test]
    async fn test_set_forwarded_service_x_forwarded_for_with_chain() {
        async fn svc(request: Request<()>) -> Result<(), Infallible> {
            assert_eq!(
                request.headers().get("X-Forwarded-For").unwrap(),
                "12.23.34.45, 127.0.0.1",
            );
            Ok(())
        }

        let service = SetForwardedHeadersService::x_forwarded_for(service_fn(svc));
        let req = Request::builder()
            .uri("https://www.example.com")
            .body(())
            .unwrap();
        let mut ctx = Context::default();
        ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
            IpAddr::from([12, 23, 34, 45]),
        )));
        ctx.insert(SocketInfo::new(None, "127.0.0.1:62345".parse().unwrap()));
        service.serve(ctx, req).await.unwrap();
    }

    #[tokio::test]
    async fn test_set_forwarded_service_forwarded_fully_defined() {
        async fn svc(request: Request<()>) -> Result<(), Infallible> {
            assert_eq!(
                request.headers().get("Forwarded").unwrap(),
                "by=12.23.34.45;for=\"127.0.0.1:62345\";host=\"www.example.com:443\";proto=https",
            );
            Ok(())
        }

        let service = SetForwardedHeadersService::forwarded(service_fn(svc))
            .forward_by(IpAddr::from([12, 23, 34, 45]));
        let req = Request::builder()
            .uri("https://www.example.com")
            .body(())
            .unwrap();
        let mut ctx = Context::default();
        ctx.insert(SocketInfo::new(None, "127.0.0.1:62345".parse().unwrap()));
        service.serve(ctx, req).await.unwrap();
    }

    #[tokio::test]
    async fn test_set_forwarded_service_forwarded_fully_defined_with_chain() {
        async fn svc(request: Request<()>) -> Result<(), Infallible> {
            assert_eq!(
                request.headers().get("Forwarded").unwrap(),
                "by=rama;for=\"127.0.0.1:62345\";host=\"www.example.com:443\";proto=https",
            );
            Ok(())
        }

        let service = SetForwardedHeadersService::forwarded(service_fn(svc));
        let req = Request::builder()
            .uri("https://www.example.com")
            .body(())
            .unwrap();
        let mut ctx = Context::default();
        ctx.insert(SocketInfo::new(None, "127.0.0.1:62345".parse().unwrap()));
        service.serve(ctx, req).await.unwrap();
    }
}
