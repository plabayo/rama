#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use crate::Request;
use crate::headers::forwarded::ForwardHeader;
use rama_core::{Layer, Service, extensions::ExtensionsRef};
use rama_http_headers::HeaderMapExt;
use rama_net::forwarded::Forwarded;
use rama_net::forwarded::{ForwardedElement, ForwardedSelectionPolicy};
use rama_utils::macros::{all_the_tuples_no_last_special_case, generate_set_and_with};
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

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
/// [`X-Real-Ip`]: crate::headers::forwarded::XRealIp
/// [`X-Client-Ip`]: crate::headers::forwarded::XClientIp
/// [`Client-Ip`]: crate::headers::forwarded::ClientIp
/// [`CF-Connecting-Ip`]: crate::headers::forwarded::CFConnectingIp
/// [`True-Client-Ip`]: crate::headers::forwarded::TrueClientIp
pub struct GetForwardedHeadersLayer<T = Forwarded> {
    selection_policy: Option<Arc<ForwardedSelectionPolicy>>,
    keep_existing_selection_policy: bool,
    _headers: PhantomData<fn() -> T>,
}

impl<T: fmt::Debug> fmt::Debug for GetForwardedHeadersLayer<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("GetForwardedHeadersLayer")
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

impl<T: Clone> Clone for GetForwardedHeadersLayer<T> {
    fn clone(&self) -> Self {
        Self {
            selection_policy: self.selection_policy.clone(),
            keep_existing_selection_policy: self.keep_existing_selection_policy,
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

impl<H, S> Layer<S> for GetForwardedHeadersLayer<H> {
    type Service = GetForwardedHeadersService<S, H>;

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
/// See [`GetForwardedHeadersLayer`] for more information.
pub struct GetForwardedHeadersService<S, T = Forwarded> {
    inner: S,
    selection_policy: Option<Arc<ForwardedSelectionPolicy>>,
    keep_existing_selection_policy: bool,
    _headers: PhantomData<fn() -> T>,
}

impl<S: fmt::Debug, T> fmt::Debug for GetForwardedHeadersService<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetForwardedHeadersService")
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

impl<S: Clone, T> Clone for GetForwardedHeadersService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            selection_policy: self.selection_policy.clone(),
            keep_existing_selection_policy: self.keep_existing_selection_policy,
            _headers: PhantomData,
        }
    }
}

impl<S, T> GetForwardedHeadersService<S, T> {
    /// Create a new `GetForwardedHeadersService` for the specified headers `T`.
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

macro_rules! get_forwarded_service_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* S, Body> Service<Request<Body>> for GetForwardedHeadersService<S, ($($ty,)*)>
        where
            $( $ty: ForwardHeader + Send + Sync + 'static, )*
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
                let mut forwarded_elements: Vec<ForwardedElement> = Vec::with_capacity(1);

                $(
                    if let Some($ty) = req.headers().typed_get::<$ty>() {
                        // Each header's values describe the hops nearest this service, so the
                        // headers pair from the right.
                        let mut farther: Vec<ForwardedElement> = $ty.into_iter().collect();
                        let shared = farther.len().min(forwarded_elements.len());
                        let nearer = farther.split_off(farther.len() - shared);
                        let offset = forwarded_elements.len() - shared;
                        for (element, other) in forwarded_elements[offset..].iter_mut().zip(nearer) {
                            element.merge(other);
                        }
                        forwarded_elements.splice(0..0, farther);
                    }
                )*

                Forwarded::record(req.extensions(), forwarded_elements);

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

    /// The client element under the default selection policy.
    fn client_of(
        forwarded: &rama_net::forwarded::Forwarded,
    ) -> &rama_net::forwarded::ForwardedElement {
        forwarded.client(&ForwardedSelectionPolicy::new()).unwrap()
    }

    fn client_ip_of(forwarded: &rama_net::forwarded::Forwarded) -> Option<std::net::IpAddr> {
        client_of(forwarded)
            .forwarded_for()
            .and_then(rama_net::forwarded::NodeId::ip)
    }
    use rama_core::{Layer, error::BoxError, extensions::ExtensionsRef, service::service_fn};
    use rama_net::forwarded::ForwardedProtocol;
    use std::{convert::Infallible, net::IpAddr};

    fn assert_is_service<T: Service<Request<()>>>(_: T) {}

    async fn dummy_service_fn() -> Result<Response, BoxError> {
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

    /// The edge writes one X-Forwarded-Host and -Proto: they pair with the rightmost
    /// X-Forwarded-For entry, the address that edge saw, never the client's own claim.
    #[tokio::test]
    async fn x_forwarded_headers_pair_from_the_right() {
        use crate::headers::forwarded::{XForwardedFor, XForwardedHost, XForwardedProto};
        use rama_net::forwarded::ForwardedClientExt as _;
        let service =
            GetForwardedHeadersLayer::<(XForwardedFor, XForwardedHost, XForwardedProto)>::new()
                .into_layer(service_fn(async |req: Request<()>| {
                    assert_eq!(req.forwarded_client_ip(), Some(IpAddr::from([10, 0, 0, 1])));
                    assert_eq!(
                        req.forwarded_client_host()
                            .map(|host| host.to_string())
                            .as_deref(),
                        Some("public.test")
                    );
                    assert_eq!(req.forwarded_client_proto(), Some(ForwardedProtocol::HTTPS));
                    let first = req
                        .extensions()
                        .get_ref::<Forwarded>()
                        .unwrap()
                        .iter()
                        .next()
                        .unwrap();
                    assert!(first.forwarded_host().is_none() && first.forwarded_proto().is_none());
                    Ok::<_, Infallible>(())
                }));
        let req = Request::builder()
            .header("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
            .header("X-Forwarded-Host", "public.test")
            .header("X-Forwarded-Proto", "https")
            .body(())
            .unwrap();
        service.serve(req).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_forwarded_headers() {
        let service = GetForwardedHeadersLayer::<(rama_http_headers::forwarded::Forwarded,)>::new()
            .into_layer(service_fn(async |req: Request<()>| {
                let forwarded = req.extensions().get_ref::<Forwarded>().unwrap();
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
}
