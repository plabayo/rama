use crate::Request;
use crate::headers::forwarded::{
    ForwardHeader, Via, XForwardedFor, XForwardedHost, XForwardedProto,
};
use rama_core::extensions::ExtensionsRef;
use rama_core::{Layer, Service};
use rama_http_headers::HeaderMapExt;
use rama_http_headers::forwarded::Forwarded;
use rama_net::forwarded::ForwardedSelectionPolicy;
use rama_utils::macros::generate_set_and_with;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

/// Layer to extract [`Forwarded`] information from the specified `T` headers.
///
/// This layer can be used to extract the [`Forwarded`] information from any specified header `T`,
/// as long as the header implements the [`ForwardHeader`] trait.
///
/// The following headers are supported by default:
///
/// - [`GetForwardedHeaderLayer::forwarded`]: The standard [`Forwarded`] header [`RFC 7239`](https://github.com/plabayo/rama/blob/main/rama-http-headers/specifications/rfc7239.txt).
/// - [`GetForwardedHeaderLayer::via`]: The canonical [`Via`] header [`RFC 9110`](https://github.com/plabayo/rama/blob/main/rama-http-core/specifications/rfc9110.txt#section-7.6.3).
/// - [`GetForwardedHeaderLayer::x_forwarded_for`]: The canonical [`X-Forwarded-For`][XForwardedFor] header [`RFC 7239`](https://github.com/plabayo/rama/blob/main/rama-http-headers/specifications/rfc7239.txt#section-5.2).
/// - [`GetForwardedHeaderLayer::x_forwarded_host`]: The canonical [`X-Forwarded-Host`][XForwardedHost] header [`RFC 7239`](https://github.com/plabayo/rama/blob/main/rama-http-headers/specifications/rfc7239.txt#section-5.4).
/// - [`GetForwardedHeaderLayer::x_forwarded_proto`]: The canonical [`X-Forwarded-Proto`][XForwardedProto] header [`RFC 7239`](https://github.com/plabayo/rama/blob/main/rama-http-headers/specifications/rfc7239.txt#section-5.3).
///
/// Rama also has the following headers already implemented for you to use:
///
/// > [`X-Real-Ip`], [`X-Client-Ip`], [`Client-Ip`], [`Cf-Connecting-Ip`] and [`True-Client-Ip`].
///
/// There are no [`GetForwardedHeaderLayer`] constructors for these headers,
/// but you can use the [`GetForwardedHeaderLayer::new`] constructor and pass the header type as a type parameter,
/// alone or in a tuple with other headers.
///
/// [`X-Real-Ip`]: crate::headers::forwarded::XRealIp
/// [`X-Client-Ip`]: crate::headers::forwarded::XClientIp
/// [`Client-Ip`]: crate::headers::forwarded::ClientIp
/// [`CF-Connecting-Ip`]: crate::headers::forwarded::CFConnectingIp
/// [`True-Client-Ip`]: crate::headers::forwarded::TrueClientIp
///
/// The elements found go before those an earlier (nearer) source recorded, such as a PROXY
/// protocol header. Which element is the client's is up to the [`ForwardedSelectionPolicy`]
/// in the extensions, rightmost by default; the layer can install one.
///
/// ## Example
///
/// This example shows you can extract the client IP from the `X-Forwarded-For`
/// header in case your application is behind a proxy which sets this header.
///
/// ```rust
/// use rama_core::{service::service_fn, Service, Layer};
/// use rama_http::{layer::forwarded::GetForwardedHeaderLayer, Request};
/// use rama_net::forwarded::ForwardedClientExt as _;
/// use std::{convert::Infallible, net::IpAddr};
///
/// #[tokio::main]
/// async fn main() {
///     let service = GetForwardedHeaderLayer::x_forwarded_for()
///         .into_layer(service_fn(async |req: Request<()>| {
///             // The client element, by the request's selection policy (rightmost by default).
///             assert_eq!(req.forwarded_client_ip(), Some(IpAddr::from([12, 23, 34, 45])));
///             assert!(req.forwarded_client_proto().is_none());
///
///             // ...
///
///             Ok::<_, Infallible>(())
///         }));
///
///     let req = Request::builder()
///         .header("X-Forwarded-For", "12.23.34.45")
///         .body(())
///         .unwrap();
///
///     service.serve(req).await.unwrap();
/// }
/// ```
pub struct GetForwardedHeaderLayer<T = rama_http_headers::forwarded::Forwarded> {
    selection_policy: Option<Arc<ForwardedSelectionPolicy>>,
    keep_existing_selection_policy: bool,
    _headers: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for GetForwardedHeaderLayer<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("GetForwardedHeaderLayer")
            .field("selection_policy", &self.selection_policy)
            .field(
                "keep_existing_selection_policy",
                &self.keep_existing_selection_policy,
            )
            .field(
                "_headers",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T> Clone for GetForwardedHeaderLayer<T> {
    fn clone(&self) -> Self {
        Self {
            selection_policy: self.selection_policy.clone(),
            keep_existing_selection_policy: self.keep_existing_selection_policy,
            _headers: PhantomData,
        }
    }
}

impl Default for GetForwardedHeaderLayer {
    fn default() -> Self {
        Self::forwarded()
    }
}

impl<T> GetForwardedHeaderLayer<T> {
    /// Create a new `GetForwardedHeaderLayer` for the specified headers `T`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selection_policy: None,
            keep_existing_selection_policy: false,
            _headers: PhantomData,
        }
    }

    generate_set_and_with! {
        /// Install this [`ForwardedSelectionPolicy`], which selects the client element of the
        /// [`Forwarded`] chain, overwriting one set already unless keeping existing ones.
        ///
        /// [`Forwarded`]: rama_net::forwarded::Forwarded
        pub fn forwarded_selection_policy(mut self, policy: ForwardedSelectionPolicy) -> Self {
            self.selection_policy = Some(Arc::new(policy));
            self
        }
    }

    generate_set_and_with! {
        /// Install the [`ForwardedSelectionPolicy`] only where none is set yet.
        pub fn keep_existing_selection_policy(mut self, keep: bool) -> Self {
            self.keep_existing_selection_policy = keep;
            self
        }
    }
}

impl GetForwardedHeaderLayer {
    #[inline]
    /// Create a new `GetForwardedHeaderLayer` for the standard [`Forwarded`] header.
    #[must_use]
    pub fn forwarded() -> Self {
        Self::new()
    }
}

impl GetForwardedHeaderLayer<Via> {
    #[inline]
    /// Create a new `GetForwardedHeaderLayer` for the canonical [`Via`] header.
    #[must_use]
    pub fn via() -> Self {
        Self::new()
    }
}

impl GetForwardedHeaderLayer<XForwardedFor> {
    #[inline]
    /// Create a new `GetForwardedHeaderLayer` for the canonical [`X-Forwarded-For`][XForwardedFor] header.
    #[must_use]
    pub fn x_forwarded_for() -> Self {
        Self::new()
    }
}

impl GetForwardedHeaderLayer<XForwardedHost> {
    #[inline]
    /// Create a new `GetForwardedHeaderLayer` for the canonical [`X-Forwarded-Host`][XForwardedHost] header.
    #[must_use]
    pub fn x_forwarded_host() -> Self {
        Self::new()
    }
}

impl GetForwardedHeaderLayer<XForwardedProto> {
    #[inline]
    /// Create a new `GetForwardedHeaderLayer` for the canonical [`X-Forwarded-Proto`][XForwardedProto] header.
    #[must_use]
    pub fn x_forwarded_proto() -> Self {
        Self::new()
    }
}

impl<H, S> Layer<S> for GetForwardedHeaderLayer<H> {
    type Service = GetForwardedHeaderService<S, H>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            selection_policy: self.selection_policy.clone(),
            keep_existing_selection_policy: self.keep_existing_selection_policy,
            _headers: PhantomData,
        }
    }
}

/// Middleware service to extract [`Forwarded`] information from the specified `T` headers.
///
/// See [`GetForwardedHeaderLayer`] for more information.
pub struct GetForwardedHeaderService<S, T = Forwarded> {
    inner: S,
    selection_policy: Option<Arc<ForwardedSelectionPolicy>>,
    keep_existing_selection_policy: bool,
    _headers: PhantomData<fn() -> T>,
}

impl<S: fmt::Debug, T> fmt::Debug for GetForwardedHeaderService<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetForwardedHeaderService")
            .field("inner", &self.inner)
            .field("selection_policy", &self.selection_policy)
            .field(
                "keep_existing_selection_policy",
                &self.keep_existing_selection_policy,
            )
            .field("_headers", &format_args!("{}", std::any::type_name::<T>()))
            .finish()
    }
}

impl<S: Clone, T> Clone for GetForwardedHeaderService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            selection_policy: self.selection_policy.clone(),
            keep_existing_selection_policy: self.keep_existing_selection_policy,
            _headers: PhantomData,
        }
    }
}

impl<S, T> GetForwardedHeaderService<S, T> {
    /// Create a new `GetForwardedHeaderService` for the specified headers `T`.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            selection_policy: None,
            keep_existing_selection_policy: false,
            _headers: PhantomData,
        }
    }

    generate_set_and_with! {
        /// Install this [`ForwardedSelectionPolicy`], which selects the client element of the
        /// [`Forwarded`] chain, overwriting one set already unless keeping existing ones.
        ///
        /// [`Forwarded`]: rama_net::forwarded::Forwarded
        pub fn forwarded_selection_policy(mut self, policy: ForwardedSelectionPolicy) -> Self {
            self.selection_policy = Some(Arc::new(policy));
            self
        }
    }

    generate_set_and_with! {
        /// Install the [`ForwardedSelectionPolicy`] only where none is set yet.
        pub fn keep_existing_selection_policy(mut self, keep: bool) -> Self {
            self.keep_existing_selection_policy = keep;
            self
        }
    }
}

impl<S> GetForwardedHeaderService<S> {
    #[inline]
    /// Create a new `GetForwardedHeaderService` for the standard [`Forwarded`] header.
    pub fn forwarded(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeaderService<S, Via> {
    #[inline]
    /// Create a new `GetForwardedHeaderService` for the canonical [`Via`] header.
    pub fn via(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeaderService<S, XForwardedFor> {
    #[inline]
    /// Create a new `GetForwardedHeaderService` for the canonical [`X-Forwarded-For`](XForwardedFor) header.
    pub fn x_forwarded_for(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeaderService<S, XForwardedHost> {
    #[inline]
    /// Create a new `GetForwardedHeaderService` for the canonical [`X-Forwarded-Host`][XForwardedHost] header.
    pub fn x_forwarded_host(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeaderService<S, XForwardedProto> {
    #[inline]
    /// Create a new `GetForwardedHeaderService` for the canonical [`X-Forwarded-Proto`][XForwardedProto] header.
    pub fn x_forwarded_proto(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<H, S, Body> Service<Request<Body>> for GetForwardedHeaderService<S, H>
where
    H: ForwardHeader + Send + Sync + 'static,
    S: Service<Request<Body>>,
    Body: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        if let Some(policy) = &self.selection_policy {
            policy.install(req.extensions(), self.keep_existing_selection_policy);
        }
        if let Some(header) = req.headers().typed_get::<H>() {
            rama_net::forwarded::Forwarded::record(req.extensions(), header);
        }

        self.inner.serve(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Response, StatusCode, service::web::response::IntoResponse};
    use rama_core::{Layer, error::BoxError, extensions::ExtensionsRef, service::service_fn};
    use rama_http_headers::forwarded::{TrueClientIp, XRealIp};
    use rama_net::forwarded::ForwardedClientExt as _;
    use rama_net::forwarded::{ForwardedProtocol, ForwardedVersion};
    use std::{convert::Infallible, net::IpAddr};

    /// The client element under the default selection policy.
    fn client_of(
        forwarded: &rama_net::forwarded::Forwarded,
    ) -> &rama_net::forwarded::ForwardedElement {
        forwarded.client(&ForwardedSelectionPolicy::new()).unwrap()
    }

    fn client_ip_of(forwarded: &rama_net::forwarded::Forwarded) -> Option<IpAddr> {
        client_of(forwarded)
            .forwarded_for()
            .and_then(rama_net::forwarded::NodeId::ip)
    }

    fn assert_is_service<T: Service<Request<()>>>(_: T) {}

    async fn dummy_service_fn() -> Result<Response, BoxError> {
        Ok(StatusCode::OK.into_response())
    }

    #[test]
    fn test_get_forwarded_service_is_service() {
        assert_is_service(GetForwardedHeaderService::forwarded(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeaderService::via(service_fn(dummy_service_fn)));
        assert_is_service(GetForwardedHeaderService::x_forwarded_for(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeaderService::x_forwarded_proto(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeaderService::x_forwarded_host(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeaderService::<_, TrueClientIp>::new(
            service_fn(dummy_service_fn),
        ));
        assert_is_service(
            GetForwardedHeaderLayer::forwarded().into_layer(service_fn(dummy_service_fn)),
        );
        assert_is_service(GetForwardedHeaderLayer::via().into_layer(service_fn(dummy_service_fn)));
        assert_is_service(
            GetForwardedHeaderLayer::<XRealIp>::new().into_layer(service_fn(dummy_service_fn)),
        );
    }

    #[tokio::test]
    async fn test_get_forwarded_header_forwarded() {
        let service =
            GetForwardedHeaderLayer::forwarded().into_layer(service_fn(async |req: Request<()>| {
                let forwarded = req
                    .extensions()
                    .get_ref::<rama_net::forwarded::Forwarded>()
                    .unwrap();
                assert_eq!(
                    client_ip_of(forwarded),
                    Some(IpAddr::from([12, 23, 34, 45]))
                );
                assert_eq!(
                    client_of(forwarded).forwarded_proto(),
                    Some(ForwardedProtocol::HTTP)
                );
                Ok::<_, Infallible>(())
            }));

        let req = Request::builder()
            .header("Forwarded", "for=\"12.23.34.45:5000\";proto=http")
            .body(())
            .unwrap();

        service.serve(req).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_forwarded_header_via() {
        let service =
            GetForwardedHeaderLayer::via().into_layer(service_fn(async |req: Request<()>| {
                let forwarded = req
                    .extensions()
                    .get_ref::<rama_net::forwarded::Forwarded>()
                    .unwrap();
                assert!(client_ip_of(forwarded).is_none());
                assert_eq!(
                    forwarded.iter().next().unwrap().forwarded_by(),
                    Some(&(IpAddr::from([12, 23, 34, 45]), 5000).into())
                );
                assert!(client_of(forwarded).forwarded_proto().is_none());
                assert_eq!(
                    client_of(forwarded).forwarded_version(),
                    Some(ForwardedVersion::HTTP_11)
                );
                Ok::<_, Infallible>(())
            }));

        let req = Request::builder()
            .header("Via", "1.1 12.23.34.45:5000")
            .body(())
            .unwrap();

        service.serve(req).await.unwrap();
    }

    /// A proxy appends what it saw, so by default the client is the rightmost element; a
    /// policy can skip trusted proxies or hops, or take the client's own (leftmost) claim.
    #[tokio::test]
    async fn the_selection_policy_picks_the_client_element() {
        use rama_net::address::ip::ipnet::IpNet;
        use rama_net::forwarded::ForwardedSide;
        let trusted: IpNet = "127.0.0.0/8".parse().unwrap();
        for (policy, expected) in [
            (None, [127, 0, 0, 1]),
            (
                Some(ForwardedSelectionPolicy::new().with_hops(1)),
                [12, 23, 34, 45],
            ),
            (
                Some(ForwardedSelectionPolicy::new().with_trusted_proxies([trusted])),
                [12, 23, 34, 45],
            ),
            (
                Some(ForwardedSelectionPolicy::new().with_side(ForwardedSide::Leftmost)),
                [12, 23, 34, 45],
            ),
        ] {
            let mut layer = GetForwardedHeaderLayer::x_forwarded_for();
            if let Some(policy) = policy.clone() {
                layer.set_forwarded_selection_policy(policy);
            }
            let service = layer.into_layer(service_fn(move |req: Request<()>| async move {
                let client = req.forwarded_client().unwrap();
                assert_eq!(
                    client
                        .forwarded_for()
                        .and_then(rama_net::forwarded::NodeId::ip),
                    Some(IpAddr::from(expected)),
                );
                assert!(client.forwarded_proto().is_none());
                Ok::<_, Infallible>(())
            }));
            let req = Request::builder()
                .header("X-Forwarded-For", "12.23.34.45, 127.0.0.1")
                .body(())
                .unwrap();
            service.serve(req).await.unwrap();
        }
    }

    /// A policy set already is kept when asked, else overwritten; and a chain shorter than
    /// the hops to skip names no client.
    #[tokio::test]
    async fn the_selection_policy_is_installed_as_configured() {
        for keep_existing in [false, true] {
            let service = GetForwardedHeaderLayer::x_forwarded_for()
                .with_forwarded_selection_policy(ForwardedSelectionPolicy::new().with_hops(5))
                .with_keep_existing_selection_policy(keep_existing)
                .into_layer(service_fn(move |req: Request<()>| async move {
                    let client = req.forwarded_client();
                    assert_eq!(client.is_some(), keep_existing, "{keep_existing}");
                    Ok::<_, Infallible>(())
                }));
            let req = Request::builder()
                .header("X-Forwarded-For", "12.23.34.45")
                .body(())
                .unwrap();
            req.extensions().insert(ForwardedSelectionPolicy::new());
            service.serve(req).await.unwrap();
        }
    }
}
