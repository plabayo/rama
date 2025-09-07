use crate::Request;
use crate::headers::forwarded::{
    ForwardHeader, Via, XForwardedFor, XForwardedHost, XForwardedProto,
};
use rama_core::{Context, Layer, Service};
use rama_http_headers::HeaderMapExt;
use rama_http_headers::forwarded::Forwarded;
use rama_net::forwarded::ForwardedElement;
use std::fmt;
use std::marker::PhantomData;

/// Layer to extract [`Forwarded`] information from the specified `T` headers.
///
/// This layer can be used to extract the [`Forwarded`] information from any specified header `T`,
/// as long as the header implements the [`ForwardHeader`] trait.
///
/// The following headers are supported by default:
///
/// - [`GetForwardedHeaderLayer::forwarded`]: The standard [`Forwarded`] header [`RFC 7239`](https://tools.ietf.org/html/rfc7239).
/// - [`GetForwardedHeaderLayer::via`]: The canonical [`Via`] header [`RFC 7230`](https://tools.ietf.org/html/rfc7230#section-5.7.1).
/// - [`GetForwardedHeaderLayer::x_forwarded_for`]: The canonical [`X-Forwarded-For`] header [`RFC 7239`](https://tools.ietf.org/html/rfc7239#section-5.2).
/// - [`GetForwardedHeaderLayer::x_forwarded_host`]: The canonical [`X-Forwarded-Host`] header [`RFC 7239`](https://tools.ietf.org/html/rfc7239#section-5.4).
/// - [`GetForwardedHeaderLayer::x_forwarded_proto`]: The canonical [`X-Forwarded-Proto`] header [`RFC 7239`](https://tools.ietf.org/html/rfc7239#section-5.3).
///
/// Rama also has the following headers already implemented for you to use:
///
/// > [`X-Real-Ip`], [`X-Client-Ip`], [`Client-Ip`], [`Cf-Connecting-Ip`] and [`True-Client-Ip`].
///
/// There are no [`GetForwardedHeaderLayer`] constructors for these headers,
/// but you can use the [`GetForwardedHeaderLayer::new`] constructor and pass the header type as a type parameter,
/// alone or in a tuple with other headers.
///
/// [`X-Real-Ip`]: crate::headers::XRealIp
/// [`X-Client-Ip`]: crate::headers::XClientIp
/// [`Client-Ip`]: crate::headers::ClientIp
/// [`CF-Connecting-Ip`]: crate::headers::CFConnectingIp
/// [`True-Client-Ip`]: crate::headers::TrueClientIp
///
/// ## Example
///
/// This example shows you can extract the client IP from the `X-Forwarded-For`
/// header in case your application is behind a proxy which sets this header.
///
/// ```rust
/// use rama_core::{
///     service::service_fn,
///     Context, Service, Layer,
/// };
/// use rama_http::{headers::forwarded::Forwarded, layer::forwarded::GetForwardedHeaderLayer, Request};
/// use std::{convert::Infallible, net::IpAddr};
///
/// #[tokio::main]
/// async fn main() {
///     let service = GetForwardedHeaderLayer::x_forwarded_for()
///         .into_layer(service_fn(async |ctx: Context, _| {
///             let forwarded = ctx.get::<rama_net::forwarded::Forwarded>().unwrap();
///             assert_eq!(forwarded.client_ip(), Some(IpAddr::from([12, 23, 34, 45])));
///             assert!(forwarded.client_proto().is_none());
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
///     service.serve(Context::default(), req).await.unwrap();
/// }
/// ```
pub struct GetForwardedHeaderLayer<T = rama_http_headers::forwarded::Forwarded> {
    _headers: PhantomData<fn() -> T>,
}

impl<T: fmt::Debug> fmt::Debug for GetForwardedHeaderLayer<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("GetForwardedHeaderLayer")
            .field(
                "_headers",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T: Clone> Clone for GetForwardedHeaderLayer<T> {
    fn clone(&self) -> Self {
        Self {
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
            _headers: PhantomData,
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
    /// Create a new `GetForwardedHeaderLayer` for the canonical [`X-Forwarded-For`] header.
    #[must_use]
    pub fn x_forwarded_for() -> Self {
        Self::new()
    }
}

impl GetForwardedHeaderLayer<XForwardedHost> {
    #[inline]
    /// Create a new `GetForwardedHeaderLayer` for the canonical [`X-Forwarded-Host`] header.
    #[must_use]
    pub fn x_forwarded_host() -> Self {
        Self::new()
    }
}

impl GetForwardedHeaderLayer<XForwardedProto> {
    #[inline]
    /// Create a new `GetForwardedHeaderLayer` for the canonical [`X-Forwarded-Proto`] header.
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
            _headers: PhantomData,
        }
    }
}

/// Middleware service to extract [`Forwarded`] information from the specified `T` headers.
///
/// See [`GetForwardedHeaderLayer`] for more information.
pub struct GetForwardedHeaderService<S, T = Forwarded> {
    inner: S,
    _headers: PhantomData<fn() -> T>,
}

impl<S: fmt::Debug, T> fmt::Debug for GetForwardedHeaderService<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetForwardedHeaderService")
            .field("inner", &self.inner)
            .field("_headers", &format_args!("{}", std::any::type_name::<T>()))
            .finish()
    }
}

impl<S: Clone, T> Clone for GetForwardedHeaderService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _headers: PhantomData,
        }
    }
}

impl<S, T> GetForwardedHeaderService<S, T> {
    /// Create a new `GetForwardedHeaderService` for the specified headers `T`.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            _headers: PhantomData,
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
    /// Create a new `GetForwardedHeaderService` for the canonical [`X-Forwarded-For`] header.
    pub fn x_forwarded_for(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeaderService<S, XForwardedHost> {
    #[inline]
    /// Create a new `GetForwardedHeaderService` for the canonical [`X-Forwarded-Host`] header.
    pub fn x_forwarded_host(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeaderService<S, XForwardedProto> {
    #[inline]
    /// Create a new `GetForwardedHeaderService` for the canonical [`X-Forwarded-Proto`] header.
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
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context,
        req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let mut forwarded_elements: Vec<ForwardedElement> = Vec::with_capacity(1);

        if let Some(header) = req.headers().typed_get::<H>() {
            forwarded_elements.extend(header);
        }

        if !forwarded_elements.is_empty() {
            if let Some(ref mut f) = ctx.get_mut::<Forwarded>() {
                f.extend(forwarded_elements);
            } else {
                let mut it = forwarded_elements.into_iter();
                let mut forwarded = rama_net::forwarded::Forwarded::new(it.next().unwrap());
                forwarded.extend(it);
                ctx.insert(forwarded);
            }
        }

        self.inner.serve(ctx, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Response, StatusCode, service::web::response::IntoResponse};
    use rama_core::{Layer, error::OpaqueError, service::service_fn};
    use rama_http_headers::forwarded::{TrueClientIp, XRealIp};
    use rama_net::forwarded::{ForwardedProtocol, ForwardedVersion};
    use std::{convert::Infallible, net::IpAddr};

    fn assert_is_service<T: Service<Request<()>>>(_: T) {}

    async fn dummy_service_fn() -> Result<Response, OpaqueError> {
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
            GetForwardedHeaderLayer::forwarded().into_layer(service_fn(async |ctx: Context, _| {
                let forwarded = ctx.get::<rama_net::forwarded::Forwarded>().unwrap();
                assert_eq!(forwarded.client_ip(), Some(IpAddr::from([12, 23, 34, 45])));
                assert_eq!(forwarded.client_proto(), Some(ForwardedProtocol::HTTP));
                Ok::<_, Infallible>(())
            }));

        let req = Request::builder()
            .header("Forwarded", "for=\"12.23.34.45:5000\";proto=http")
            .body(())
            .unwrap();

        service.serve(Context::default(), req).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_forwarded_header_via() {
        let service =
            GetForwardedHeaderLayer::via().into_layer(service_fn(async |ctx: Context, _| {
                let forwarded = ctx.get::<rama_net::forwarded::Forwarded>().unwrap();
                assert!(forwarded.client_ip().is_none());
                assert_eq!(
                    forwarded.iter().next().unwrap().ref_forwarded_by(),
                    Some(&(IpAddr::from([12, 23, 34, 45]), 5000).into())
                );
                assert!(forwarded.client_proto().is_none());
                assert_eq!(forwarded.client_version(), Some(ForwardedVersion::HTTP_11));
                Ok::<_, Infallible>(())
            }));

        let req = Request::builder()
            .header("Via", "1.1 12.23.34.45:5000")
            .body(())
            .unwrap();

        service.serve(Context::default(), req).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_forwarded_header_x_forwarded_for() {
        let service = GetForwardedHeaderLayer::x_forwarded_for().into_layer(service_fn(
            async |ctx: Context, _| {
                let forwarded = ctx.get::<rama_net::forwarded::Forwarded>().unwrap();
                assert_eq!(forwarded.client_ip(), Some(IpAddr::from([12, 23, 34, 45])));
                assert!(forwarded.client_proto().is_none());
                Ok::<_, Infallible>(())
            },
        ));

        let req = Request::builder()
            .header("X-Forwarded-For", "12.23.34.45, 127.0.0.1")
            .body(())
            .unwrap();

        service.serve(Context::default(), req).await.unwrap();
    }
}
