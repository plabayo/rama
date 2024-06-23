use crate::http::headers::{
    ForwardHeader, HeaderMapExt, Via, XForwardedFor, XForwardedHost, XForwardedProto,
};
use crate::net::forwarded::ForwardedElement;
use crate::{
    http::Request,
    net::forwarded::Forwarded,
    service::{Context, Layer, Service},
};
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
/// Layer to extract [`Forwarded`] information from the specified `T` headers.
///
/// This layer can be used to extract the [`Forwarded`] information from any specified header `T`,
/// as long as the header implements the [`ForwardHeader`] trait. Multiple headers can be specified
/// as a tuple, and the layer will extract information from them all, and combine the information.
///
/// Please take into consideration the following when combining headers:
///
/// - The last header in the tuple will take precedence over the previous headers,
///   if the same information is present in multiple headers.
/// - Headers that can contain multiple elements, (e.g. X-Forwarded-For, Via)
///   will combine their elements in the order as specified. That does however mean that in
///   case one header has less elements then the other, that the combination down the line
///   will not be accurate.
///
/// The following headers are supported by default:
///
/// - [`GetForwardedHeadersLayer::forwarded`]: The standard [`Forwarded`] header [`RFC 7239`](https://tools.ietf.org/html/rfc7239).
/// - [`GetForwardedHeadersLayer::via`]: The canonical [`Via`] header [`RFC 7230`](https://tools.ietf.org/html/rfc7230#section-5.7.1).
/// - [`GetForwardedHeadersLayer::x_forwarded_for`]: The canonical [`X-Forwarded-For`] header [`RFC 7239`](https://tools.ietf.org/html/rfc7239#section-5.2).
/// - [`GetForwardedHeadersLayer::x_forwarded_host`]: The canonical [`X-Forwarded-Host`] header [`RFC 7239`](https://tools.ietf.org/html/rfc7239#section-5.4).
/// - [`GetForwardedHeadersLayer::x_forwarded_proto`]: The canonical [`X-Forwarded-Proto`] header [`RFC 7239`](https://tools.ietf.org/html/rfc7239#section-5.3).
///
/// Rama also has the following headers already implemented for you to use:
///
/// > [`X-Real-Ip`], [`X-Client-Ip`], [`Client-Ip`], [`Cf-Connecting-Ip`] and [`True-Client-Ip`].
///
/// There are no [`GetForwardedHeadersLayer`] constructors for these headers,
/// but you can use the [`GetForwardedHeadersLayer::new`] constructor and pass the header type as a type parameter,
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
/// This example shows you can extract the client IP from the `X-Forwarded-For`
/// header in case your application is behind a proxy which sets this header.
///
/// ```rust
/// use rama::{
///     http::{headers::Forwarded, layer::forwarded::GetForwardedHeadersLayer, Request},
///     service::{Context, Service, ServiceBuilder},
/// };
/// use std::{convert::Infallible, net::IpAddr};
///
/// #[tokio::main]
/// async fn main() {
///     let service = ServiceBuilder::new()
///         .layer(GetForwardedHeadersLayer::x_forwarded_for())
///         .service_fn(|ctx: Context<()>, _| async move {
///             let forwarded = ctx.get::<Forwarded>().unwrap();
///             assert_eq!(forwarded.client_ip(), Some(IpAddr::from([12, 23, 34, 45])));
///             assert!(forwarded.client_proto().is_none());
///
///             // ...
///
///             Ok::<_, Infallible>(())
///         });
///
///     let req = Request::builder()
///         .header("X-Forwarded-For", "12.23.34.45")
///         .body(())
///         .unwrap();
///
///     service.serve(Context::default(), req).await.unwrap();
/// }
/// ```
pub struct GetForwardedHeadersLayer<T = Forwarded> {
    _headers: PhantomData<fn() -> T>,
}

impl Default for GetForwardedHeadersLayer {
    fn default() -> Self {
        Self::forwarded()
    }
}

impl<T> GetForwardedHeadersLayer<T> {
    /// Create a new `GetForwardedHeadersLayer` for the specified headers `T`.
    pub fn new() -> Self {
        Self {
            _headers: PhantomData,
        }
    }
}

impl GetForwardedHeadersLayer {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the standard [`Forwarded`] header.
    pub fn forwarded() -> Self {
        Self::new()
    }
}

impl GetForwardedHeadersLayer<Via> {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the canonical [`Via`] header.
    pub fn via() -> Self {
        Self::new()
    }
}

impl GetForwardedHeadersLayer<XForwardedFor> {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the canonical [`X-Forwarded-For`] header.
    pub fn x_forwarded_for() -> Self {
        Self::new()
    }
}

impl GetForwardedHeadersLayer<XForwardedHost> {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the canonical [`X-Forwarded-Host`] header.
    pub fn x_forwarded_host() -> Self {
        Self::new()
    }
}

impl GetForwardedHeadersLayer<XForwardedProto> {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the canonical [`X-Forwarded-Proto`] header.
    pub fn x_forwarded_proto() -> Self {
        Self::new()
    }
}

impl<H, S> Layer<S> for GetForwardedHeadersLayer<H> {
    type Service = GetForwardedHeadersService<S, H>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            _headers: PhantomData,
        }
    }
}

/// Middleware service to extract [`Forwarded`] information from the specified `T` headers.
///
/// See [`GetForwardedHeadersLayer`] for more information.
pub struct GetForwardedHeadersService<S, T = Forwarded> {
    inner: S,
    _headers: PhantomData<fn() -> T>,
}

impl<S: fmt::Debug, T> fmt::Debug for GetForwardedHeadersService<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetForwardedHeadersService")
            .field("inner", &self.inner)
            .field("_headers", &format_args!("{}", std::any::type_name::<T>()))
            .finish()
    }
}

impl<S: Clone, T> Clone for GetForwardedHeadersService<S, T> {
    fn clone(&self) -> Self {
        GetForwardedHeadersService {
            inner: self.inner.clone(),
            _headers: PhantomData,
        }
    }
}

impl<S, T> GetForwardedHeadersService<S, T> {
    /// Create a new `GetForwardedHeadersService` for the specified headers `T`.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            _headers: PhantomData,
        }
    }
}

impl<S> GetForwardedHeadersService<S> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the standard [`Forwarded`] header.
    pub fn forwarded(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeadersService<S, Via> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the canonical [`Via`] header.
    pub fn via(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeadersService<S, XForwardedFor> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the canonical [`X-Forwarded-For`] header.
    pub fn x_forwarded_for(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeadersService<S, XForwardedHost> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the canonical [`X-Forwarded-Host`] header.
    pub fn x_forwarded_host(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeadersService<S, XForwardedProto> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the canonical [`X-Forwarded-Proto`] header.
    pub fn x_forwarded_proto(inner: S) -> Self {
        Self::new(inner)
    }
}

macro_rules! get_forwarded_service_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* S, State, Body> Service<State, Request<Body>> for GetForwardedHeadersService<S, ($($ty,)*)>
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
                req: Request<Body>,
            ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
                let mut forwarded_elements: Vec<ForwardedElement> = Vec::with_capacity(1);

                $(
                    if let Some($ty) = req.headers().typed_get::<$ty>() {
                        let mut iter = $ty.into_iter();
                        for element in forwarded_elements.iter_mut() {
                            let other = iter.next();
                            match other {
                                Some(other) => {
                                    element.merge(other);
                                }
                                None => break,
                            }
                        }
                        for other in iter {
                            forwarded_elements.push(other);
                        }
                    }
                )*

                if !forwarded_elements.is_empty() {
                    match ctx.get_mut::<Forwarded>() {
                        Some(ref mut f) => {
                            f.extend(forwarded_elements);
                        }
                        None => {
                            let mut it = forwarded_elements.into_iter();
                            let mut forwarded = Forwarded::new(it.next().unwrap());
                            forwarded.extend(it);
                            ctx.insert(forwarded);
                        }
                    }
                }

                self.inner.serve(ctx, req)
            }
        }
    }
}

impl<H, S, State, Body> Service<State, Request<Body>> for GetForwardedHeadersService<S, H>
where
    H: ForwardHeader + Send + Sync + 'static,
    S: Service<State, Request<Body>>,
    Body: Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let mut forwarded_elements: Vec<ForwardedElement> = Vec::with_capacity(1);

        if let Some(header) = req.headers().typed_get::<H>() {
            forwarded_elements.extend(header);
        }

        if !forwarded_elements.is_empty() {
            match ctx.get_mut::<Forwarded>() {
                Some(ref mut f) => {
                    f.extend(forwarded_elements);
                }
                None => {
                    let mut it = forwarded_elements.into_iter();
                    let mut forwarded = Forwarded::new(it.next().unwrap());
                    forwarded.extend(it);
                    ctx.insert(forwarded);
                }
            }
        }

        self.inner.serve(ctx, req)
    }
}

all_the_tuples_no_last_special_case!(get_forwarded_service_for_tuple);

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, net::IpAddr};

    use super::*;
    use crate::{
        error::OpaqueError,
        http::{
            headers::{ClientIp, TrueClientIp, XClientIp, XRealIp},
            IntoResponse, Response, StatusCode,
        },
        net::forwarded::{ForwardedProtocol, ForwardedVersion},
        service::{service_fn, ServiceBuilder},
    };

    fn assert_is_service<T: Service<(), Request<()>>>(_: T) {}

    async fn dummy_service_fn() -> Result<Response, OpaqueError> {
        Ok(StatusCode::OK.into_response())
    }

    #[test]
    fn test_get_forwarded_service_is_service() {
        assert_is_service(GetForwardedHeadersService::forwarded(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::via(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::x_forwarded_for(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::x_forwarded_proto(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::x_forwarded_host(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::<_, TrueClientIp>::new(
            service_fn(dummy_service_fn),
        ));
        assert_is_service(GetForwardedHeadersService::<_, (TrueClientIp,)>::new(
            service_fn(dummy_service_fn),
        ));
        assert_is_service(
            GetForwardedHeadersService::<_, (TrueClientIp, XClientIp)>::new(service_fn(
                dummy_service_fn,
            )),
        );
        assert_is_service(
            ServiceBuilder::new()
                .layer(GetForwardedHeadersLayer::forwarded())
                .service_fn(dummy_service_fn),
        );
        assert_is_service(
            ServiceBuilder::new()
                .layer(GetForwardedHeadersLayer::via())
                .service_fn(dummy_service_fn),
        );
        assert_is_service(
            ServiceBuilder::new()
                .layer(GetForwardedHeadersLayer::<XRealIp>::new())
                .service_fn(dummy_service_fn),
        );
        assert_is_service(
            ServiceBuilder::new()
                .layer(GetForwardedHeadersLayer::<(ClientIp, TrueClientIp)>::new())
                .service_fn(dummy_service_fn),
        );
    }

    #[tokio::test]
    async fn test_get_forwarded_header_forwarded() {
        let service = ServiceBuilder::new()
            .layer(GetForwardedHeadersLayer::forwarded())
            .service_fn(|ctx: Context<()>, _| async move {
                let forwarded = ctx.get::<Forwarded>().unwrap();
                assert_eq!(forwarded.client_ip(), Some(IpAddr::from([12, 23, 34, 45])));
                assert_eq!(forwarded.client_proto(), Some(ForwardedProtocol::HTTP));
                Ok::<_, Infallible>(())
            });

        let req = Request::builder()
            .header("Forwarded", "for=\"12.23.34.45:5000\";proto=http")
            .body(())
            .unwrap();

        service.serve(Context::default(), req).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_forwarded_header_via() {
        let service = ServiceBuilder::new()
            .layer(GetForwardedHeadersLayer::via())
            .service_fn(|ctx: Context<()>, _| async move {
                let forwarded = ctx.get::<Forwarded>().unwrap();
                assert!(forwarded.client_ip().is_none());
                assert_eq!(
                    forwarded.iter().next().unwrap().ref_forwarded_by(),
                    Some(&(IpAddr::from([12, 23, 34, 45]), 5000).into())
                );
                assert!(forwarded.client_proto().is_none());
                assert_eq!(forwarded.client_version(), Some(ForwardedVersion::HTTP_11));
                Ok::<_, Infallible>(())
            });

        let req = Request::builder()
            .header("Via", "1.1 12.23.34.45:5000")
            .body(())
            .unwrap();

        service.serve(Context::default(), req).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_forwarded_header_x_forwarded_for() {
        let service = ServiceBuilder::new()
            .layer(GetForwardedHeadersLayer::x_forwarded_for())
            .service_fn(|ctx: Context<()>, _| async move {
                let forwarded = ctx.get::<Forwarded>().unwrap();
                assert_eq!(forwarded.client_ip(), Some(IpAddr::from([12, 23, 34, 45])));
                assert!(forwarded.client_proto().is_none());
                Ok::<_, Infallible>(())
            });

        let req = Request::builder()
            .header("X-Forwarded-For", "12.23.34.45, 127.0.0.1")
            .body(())
            .unwrap();

        service.serve(Context::default(), req).await.unwrap();
    }
}
