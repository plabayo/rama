use crate::Request;
use crate::headers::forwarded::ForwardHeader;
use rama_core::{Layer, Service, extensions::ExtensionsMut};
use rama_http_headers::HeaderMapExt;
use rama_net::forwarded::Forwarded;
use rama_net::forwarded::ForwardedElement;
use rama_utils::macros::all_the_tuples_no_last_special_case;
use std::fmt;
use std::marker::PhantomData;

/// Layer to extract [`Forwarded`] information from the specified `T` headers.
///
/// Use [`GetForwardedHeaderLayer`] if you only need a single a header.
///
/// [`GetForwardedHeaderLayer`]: super::GetForwardedHeaderLayer
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
/// Rama also has the following headers already implemented for you to use:
///
/// > [`X-Real-Ip`], [`X-Client-Ip`], [`Client-Ip`], [`Cf-Connecting-Ip`] and [`True-Client-Ip`].
///
/// There are no [`GetForwardedHeadersLayer`] constructors for these headers,
/// but you can use the [`GetForwardedHeadersLayer::new`] constructor and pass the header type as a type parameter in a tuple with other headers.
///
/// [`X-Real-Ip`]: crate::headers::XRealIp
/// [`X-Client-Ip`]: crate::headers::XClientIp
/// [`Client-Ip`]: crate::headers::ClientIp
/// [`CF-Connecting-Ip`]: crate::headers::CFConnectingIp
/// [`True-Client-Ip`]: crate::headers::TrueClientIp
pub struct GetForwardedHeadersLayer<T = Forwarded> {
    _headers: PhantomData<fn() -> T>,
}

impl<T: fmt::Debug> fmt::Debug for GetForwardedHeadersLayer<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("GetForwardedHeadersLayer")
            .field(
                "_headers",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T: Clone> Clone for GetForwardedHeadersLayer<T> {
    fn clone(&self) -> Self {
        Self {
            _headers: PhantomData,
        }
    }
}

impl<T> Default for GetForwardedHeadersLayer<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> GetForwardedHeadersLayer<T> {
    /// Create a new `GetForwardedHeadersLayer` for the specified headers `T`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _headers: PhantomData,
        }
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
        Self {
            inner: self.inner.clone(),
            _headers: PhantomData,
        }
    }
}

impl<S, T> GetForwardedHeadersService<S, T> {
    /// Create a new `GetForwardedHeadersService` for the specified headers `T`.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            _headers: PhantomData,
        }
    }
}

macro_rules! get_forwarded_service_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* S, Body> Service<Request<Body>> for GetForwardedHeadersService<S, ($($ty,)*)>
        where
            $( $ty: ForwardHeader + Send + Sync + 'static, )*
            S: Service<Request<Body>>,
            Body: Send + 'static,

        {
            type Response = S::Response;
            type Error = S::Error;

            fn serve(
                &self,
                mut req: Request<Body>,
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
                    match req.extensions_mut().get_mut::<Forwarded>() {
                        Some(ref mut f) => {
                            f.extend(forwarded_elements);
                        }
                        None => {
                            let mut it = forwarded_elements.into_iter();
                            let mut forwarded = Forwarded::new(it.next().unwrap());
                            forwarded.extend(it);
                            req.extensions_mut().insert(forwarded);
                        }
                    }
                }

                self.inner.serve(req)
            }
        }
    }
}

all_the_tuples_no_last_special_case!(get_forwarded_service_for_tuple);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Response, StatusCode,
        headers::forwarded::{ClientIp, TrueClientIp, XClientIp},
        service::web::response::IntoResponse,
    };
    use rama_core::{Layer, error::OpaqueError, extensions::ExtensionsRef, service::service_fn};
    use rama_net::forwarded::ForwardedProtocol;
    use std::{convert::Infallible, net::IpAddr};

    fn assert_is_service<T: Service<Request<()>>>(_: T) {}

    async fn dummy_service_fn() -> Result<Response, OpaqueError> {
        Ok(StatusCode::OK.into_response())
    }

    #[test]
    fn test_get_forwarded_service_is_service() {
        assert_is_service(GetForwardedHeadersService::<_, (TrueClientIp,)>::new(
            service_fn(dummy_service_fn),
        ));
        assert_is_service(
            GetForwardedHeadersService::<_, (TrueClientIp, XClientIp)>::new(service_fn(
                dummy_service_fn,
            )),
        );
        assert_is_service(
            GetForwardedHeadersLayer::<(ClientIp, TrueClientIp)>::new()
                .into_layer(service_fn(dummy_service_fn)),
        );
    }

    #[tokio::test]
    async fn test_get_forwarded_headers() {
        let service = GetForwardedHeadersLayer::<(rama_http_headers::forwarded::Forwarded,)>::new()
            .into_layer(service_fn(async |req: Request<()>| {
                let forwarded = req.extensions().get::<Forwarded>().unwrap();
                assert_eq!(forwarded.client_ip(), Some(IpAddr::from([12, 23, 34, 45])));
                assert_eq!(forwarded.client_proto(), Some(ForwardedProtocol::HTTP));
                Ok::<_, Infallible>(())
            }));

        let req = Request::builder()
            .header("Forwarded", "for=\"12.23.34.45:5000\";proto=http")
            .body(())
            .unwrap();

        service.serve(req).await.unwrap();
    }
}
