use std::{fmt, sync::Arc};

use crate::dep::http::{
    header::{HeaderName, HeaderValue},
    request::Parts as RequestParts,
};

/// Holds configuration for how to set the [`Access-Control-Allow-Private-Network`][wicg] header.
///
/// See [`CorsLayer::allow_private_network`] for more details.
///
/// [wicg]: https://wicg.github.io/private-network-access/
/// [`CorsLayer::allow_private_network`]: super::CorsLayer::allow_private_network
#[derive(Clone, Default)]
#[must_use]
pub struct AllowPrivateNetwork(AllowPrivateNetworkInner);

static TRUE: HeaderValue = HeaderValue::from_static("true");

impl AllowPrivateNetwork {
    /// Allow requests via a more private network than the one used to access the origin
    ///
    /// See [`CorsLayer::allow_private_network`] for more details.
    ///
    /// [`CorsLayer::allow_private_network`]: super::CorsLayer::allow_private_network
    pub fn yes() -> Self {
        Self(AllowPrivateNetworkInner::Yes)
    }

    /// Allow requests via private network for some requests, based on a given predicate
    ///
    /// The first argument to the predicate is the request origin.
    ///
    /// See [`CorsLayer::allow_private_network`] for more details.
    ///
    /// [`CorsLayer::allow_private_network`]: super::CorsLayer::allow_private_network
    pub fn predicate<F>(f: F) -> Self
    where
        F: Fn(&HeaderValue, &RequestParts) -> bool + Send + Sync + 'static,
    {
        Self(AllowPrivateNetworkInner::Predicate(Arc::new(f)))
    }

    pub(super) fn to_header(
        &self,
        origin: Option<&HeaderValue>,
        parts: &RequestParts,
    ) -> Option<(HeaderName, HeaderValue)> {
        #[allow(clippy::declare_interior_mutable_const)]
        const REQUEST_PRIVATE_NETWORK: HeaderName =
            HeaderName::from_static("access-control-request-private-network");

        #[allow(clippy::declare_interior_mutable_const)]
        const ALLOW_PRIVATE_NETWORK: HeaderName =
            HeaderName::from_static("access-control-allow-private-network");

        // Cheapest fallback: allow_private_network hasn't been set
        if matches!(&self.0, AllowPrivateNetworkInner::No) {
            return None;
        }

        // Access-Control-Allow-Private-Network is only relevant if the request
        // has the Access-Control-Request-Private-Network header set, else skip
        if parts.headers.get(REQUEST_PRIVATE_NETWORK) != Some(&TRUE) {
            return None;
        }

        let allow_private_network = match &self.0 {
            AllowPrivateNetworkInner::Yes => true,
            AllowPrivateNetworkInner::No => false, // unreachable, but not harmful
            AllowPrivateNetworkInner::Predicate(c) => c(origin?, parts),
        };

        allow_private_network.then_some((ALLOW_PRIVATE_NETWORK, TRUE.clone()))
    }
}

impl From<bool> for AllowPrivateNetwork {
    fn from(v: bool) -> Self {
        match v {
            true => Self(AllowPrivateNetworkInner::Yes),
            false => Self(AllowPrivateNetworkInner::No),
        }
    }
}

impl fmt::Debug for AllowPrivateNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            AllowPrivateNetworkInner::Yes => f.debug_tuple("Yes").finish(),
            AllowPrivateNetworkInner::No => f.debug_tuple("No").finish(),
            AllowPrivateNetworkInner::Predicate(_) => f.debug_tuple("Predicate").finish(),
        }
    }
}

#[derive(Clone)]
enum AllowPrivateNetworkInner {
    Yes,
    No,
    Predicate(
        Arc<dyn for<'a> Fn(&'a HeaderValue, &'a RequestParts) -> bool + Send + Sync + 'static>,
    ),
}

impl Default for AllowPrivateNetworkInner {
    fn default() -> Self {
        Self::No
    }
}

#[cfg(test)]
mod tests {
    use super::AllowPrivateNetwork;

    use crate::Body;
    use crate::dep::http::{
        HeaderName, HeaderValue, Request, Response, header::ORIGIN, request::Parts,
    };
    use crate::layer::cors::CorsLayer;
    use rama_core::error::BoxError;
    use rama_core::service::service_fn;
    use rama_core::{Context, Layer, Service};

    static REQUEST_PRIVATE_NETWORK: HeaderName =
        HeaderName::from_static("access-control-request-private-network");

    static ALLOW_PRIVATE_NETWORK: HeaderName =
        HeaderName::from_static("access-control-allow-private-network");

    static TRUE: HeaderValue = HeaderValue::from_static("true");

    #[tokio::test]
    async fn cors_private_network_header_is_added_correctly() {
        let service = CorsLayer::new()
            .allow_private_network(true)
            .into_layer(service_fn(echo));

        let req = Request::builder()
            .header(REQUEST_PRIVATE_NETWORK.clone(), TRUE.clone())
            .body(Body::empty())
            .unwrap();
        let res = service.serve(Context::default(), req).await.unwrap();

        assert_eq!(res.headers().get(&ALLOW_PRIVATE_NETWORK).unwrap(), TRUE);

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = service.serve(Context::default(), req).await.unwrap();

        assert!(res.headers().get(&ALLOW_PRIVATE_NETWORK).is_none());
    }

    #[tokio::test]
    async fn cors_private_network_header_is_added_correctly_with_predicate() {
        let allow_private_network =
            AllowPrivateNetwork::predicate(|origin: &HeaderValue, parts: &Parts| {
                parts.uri.path() == "/allow-private" && origin == "localhost"
            });
        let service = CorsLayer::new()
            .allow_private_network(allow_private_network)
            .into_layer(service_fn(echo));

        let req = Request::builder()
            .header(ORIGIN, "localhost")
            .header(REQUEST_PRIVATE_NETWORK.clone(), TRUE.clone())
            .uri("/allow-private")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.headers().get(&ALLOW_PRIVATE_NETWORK).unwrap(), TRUE);

        let req = Request::builder()
            .header(ORIGIN, "localhost")
            .header(REQUEST_PRIVATE_NETWORK.clone(), TRUE.clone())
            .uri("/other")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), req).await.unwrap();

        assert!(res.headers().get(&ALLOW_PRIVATE_NETWORK).is_none());

        let req = Request::builder()
            .header(ORIGIN, "not-localhost")
            .header(REQUEST_PRIVATE_NETWORK.clone(), TRUE.clone())
            .uri("/allow-private")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), req).await.unwrap();

        assert!(res.headers().get(&ALLOW_PRIVATE_NETWORK).is_none());
    }

    async fn echo<Body>(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        Ok(Response::new(req.into_body()))
    }
}
