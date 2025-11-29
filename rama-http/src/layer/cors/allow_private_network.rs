use crate::{
    header::{HeaderMap, HeaderValue},
    headers::{
        AccessControlAllowPrivateNetwork, AccessControlRequestPrivateNetwork, HeaderMapExt as _,
    },
    request::Parts as RequestParts,
};
use std::{fmt, sync::Arc};

#[derive(Clone)]
pub(super) enum AllowPrivateNetwork {
    Const,
    Predicate(
        Arc<dyn for<'a> Fn(&'a HeaderValue, &'a RequestParts) -> bool + Send + Sync + 'static>,
    ),
}

impl AllowPrivateNetwork {
    pub(super) fn extend_headers(
        &self,
        headers: &mut HeaderMap,
        origin: Option<&HeaderValue>,
        parts: &RequestParts,
    ) {
        // Access-Control-Allow-Private-Network is only relevant if the request
        // has the Access-Control-Request-Private-Network header set, else skip
        if parts
            .headers
            .typed_get::<AccessControlRequestPrivateNetwork>()
            .is_none()
        {
            return;
        }

        match self {
            Self::Const => headers.typed_insert(AccessControlAllowPrivateNetwork::default()),
            Self::Predicate(predicate) => {
                if let Some(origin) = origin
                    && predicate(origin, parts)
                {
                    headers.typed_insert(AccessControlAllowPrivateNetwork::default())
                }
            }
        }
    }
}

impl fmt::Debug for AllowPrivateNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const => f.debug_tuple("Yes").finish(),
            Self::Predicate(_) => f.debug_tuple("Predicate").finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::layer::cors::CorsLayer;
    use crate::{Body, HeaderName, HeaderValue, Request, Response, header::ORIGIN, request::Parts};
    use rama_core::error::BoxError;
    use rama_core::service::service_fn;
    use rama_core::telemetry::tracing;
    use rama_core::{Layer, Service};

    static REQUEST_PRIVATE_NETWORK: HeaderName =
        HeaderName::from_static("access-control-request-private-network");

    static ALLOW_PRIVATE_NETWORK: HeaderName =
        HeaderName::from_static("access-control-allow-private-network");

    static TRUE: HeaderValue = HeaderValue::from_static("true");

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn cors_private_network_header_is_added_correctly() {
        let service = CorsLayer::new()
            .with_allow_private_network()
            .into_layer(service_fn(echo));

        let req = Request::builder()
            .header(REQUEST_PRIVATE_NETWORK.clone(), TRUE.clone())
            .body(Body::empty())
            .unwrap();
        let res = service.serve(req).await.unwrap();

        assert_eq!(res.headers().get(&ALLOW_PRIVATE_NETWORK).unwrap(), TRUE);

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = service.serve(req).await.unwrap();

        assert!(res.headers().get(&ALLOW_PRIVATE_NETWORK).is_none());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn cors_private_network_header_is_added_correctly_with_predicate() {
        let service = CorsLayer::new()
            .with_allow_private_network_if(|origin: &HeaderValue, parts: &Parts| {
                let result = parts.uri.path() == "/allow-private" && origin == "localhost";
                tracing::info!(
                    "path = {}; origin = {:?}; result = {result}",
                    parts.uri.path(),
                    origin
                );
                result
            })
            .into_layer(service_fn(echo));

        let req = Request::builder()
            .header(ORIGIN, "localhost")
            .header(REQUEST_PRIVATE_NETWORK.clone(), TRUE.clone())
            .uri("/allow-private")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(req).await.unwrap();
        tracing::info!("response headers = {:?}", res.headers());
        assert_eq!(res.headers().get(&ALLOW_PRIVATE_NETWORK).unwrap(), TRUE);

        let req = Request::builder()
            .header(ORIGIN, "localhost")
            .header(REQUEST_PRIVATE_NETWORK.clone(), TRUE.clone())
            .uri("/other")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(req).await.unwrap();

        assert!(res.headers().get(&ALLOW_PRIVATE_NETWORK).is_none());

        let req = Request::builder()
            .header(ORIGIN, "not-localhost")
            .header(REQUEST_PRIVATE_NETWORK.clone(), TRUE.clone())
            .uri("/allow-private")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(req).await.unwrap();

        assert!(res.headers().get(&ALLOW_PRIVATE_NETWORK).is_none());
    }

    async fn echo<Body>(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        Ok(Response::new(req.into_body()))
    }
}
