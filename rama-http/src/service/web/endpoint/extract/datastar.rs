//! [🚀 Datastar](https://data-star.dev/) support extractor for rama.

use crate::service::web::{
    extract::{FromRequest, FromRequestBody, OptionalFromRequest, OptionalFromRequestBody},
    response::IntoResponse,
};
use rama_core::telemetry::tracing;
use rama_http_types::{BodyExtractExt, Method, Request, Response, StatusCode};
use serde::{Deserialize, de::DeserializeOwned};

/// [`ReadSignals`] is a request extractor that reads Datastar signals from the request.
///
/// `GET` and `DELETE` requests read the URL-encoded `datastar` query parameter.
/// Other methods read JSON from the request body. A missing query parameter is
/// treated as JSON `null`, allowing `ReadSignals<Option<T>>` to extract `None`.
#[derive(Debug)]
pub struct ReadSignals<T>(pub T);

#[derive(Deserialize)]
struct DatastarParam {
    datastar: Option<serde_json::Value>,
}

impl<T> FromRequest for ReadSignals<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Response;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let future = <Self as FromRequestBody>::from_request_body(&parts, body);
        future.await
    }
}

impl<T> FromRequestBody for ReadSignals<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    fn from_request_body(
        parts: &crate::request::Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        let query_result = if parts.method == Method::GET || parts.method == Method::DELETE {
            Some((|| {
                let param = parts.uri.query_params::<DatastarParam>().map_err(|err| {
                    tracing::debug!("failed to parse datastar query params from request: {err:?}");
                    (StatusCode::BAD_REQUEST, err.to_string()).into_response()
                })?;

                let signals = match param.datastar.as_ref() {
                    Some(value) => value.as_str().ok_or_else(|| {
                        tracing::debug!("datastar query value is not a string");
                        (StatusCode::BAD_REQUEST, "Failed to parse JSON").into_response()
                    })?,
                    None => "null",
                };

                serde_json::from_str(signals)
                    .map_err(|err| {
                        tracing::debug!(
                            "failed to parse datastar query JSON value from request: {err:?}"
                        );
                        (StatusCode::BAD_REQUEST, err.to_string()).into_response()
                    })
                    .map(Self)
            })())
        } else {
            None
        };

        async move {
            if let Some(result) = query_result {
                return result;
            }

            let json = body.try_into_json().await.map_err(|err| {
                tracing::debug!("failed to parse datastar JSON request body: {err:?}");
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            })?;

            Ok(Self(json))
        }
    }
}

impl<T> OptionalFromRequest for ReadSignals<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Response;

    async fn from_request(req: Request) -> Result<Option<Self>, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let future = <Self as OptionalFromRequestBody>::from_optional_request_body(&parts, body);
        future.await
    }
}

impl<T> OptionalFromRequestBody for ReadSignals<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    fn from_optional_request_body(
        parts: &crate::request::Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send + 'static {
        let future = if parts.headers.get("datastar-request").is_none() {
            tracing::trace!(
                "no datastar request header present: returning no read signals as such"
            );
            None
        } else {
            Some(<Self as FromRequestBody>::from_request_body(parts, body))
        };

        async move {
            match future {
                Some(future) => future.await.map(Some),
                None => Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Signals {
        count: u64,
    }

    fn build_request(method: Method, uri: &str, body: impl Into<crate::Body>) -> Request {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(body.into())
            .unwrap()
    }

    #[tokio::test]
    async fn required_extractor_reads_query_signals() {
        for method in [Method::GET, Method::DELETE] {
            let request = build_request(
                method,
                "/?datastar=%7B%22count%22%3A42%7D",
                crate::Body::empty(),
            );

            let ReadSignals(signals) = <ReadSignals<Signals> as FromRequest>::from_request(request)
                .await
                .unwrap();

            assert_eq!(signals, Signals { count: 42 });
        }
    }

    #[tokio::test]
    async fn required_extractor_reads_body_signals() {
        for method in [Method::POST, Method::PUT, Method::PATCH] {
            let request = build_request(method, "/", r#"{"count":42}"#);

            let ReadSignals(signals) = <ReadSignals<Signals> as FromRequest>::from_request(request)
                .await
                .unwrap();

            assert_eq!(signals, Signals { count: 42 });
        }
    }

    #[tokio::test]
    async fn missing_query_signals_deserialize_as_null() {
        let request = build_request(Method::GET, "/", crate::Body::empty());

        let ReadSignals(signals) =
            <ReadSignals<Option<Signals>> as FromRequest>::from_request(request)
                .await
                .unwrap();

        assert_eq!(signals, None);

        let request = build_request(Method::GET, "/", crate::Body::empty());
        let rejection = <ReadSignals<Signals> as FromRequest>::from_request(request)
            .await
            .unwrap_err();
        assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_signals_are_rejected() {
        for request in [
            build_request(Method::GET, "/?datastar=not-json", crate::Body::empty()),
            build_request(Method::POST, "/", "not-json"),
        ] {
            let rejection = <ReadSignals<Signals> as FromRequest>::from_request(request)
                .await
                .unwrap_err();
            assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn optional_extractor_ignores_non_datastar_requests() {
        let request = build_request(Method::POST, "/", "not-json");

        let signals = <Option<ReadSignals<Signals>> as FromRequest>::from_request(request)
            .await
            .unwrap();

        assert!(signals.is_none());
    }

    #[tokio::test]
    async fn optional_terminal_extractor_reads_get_signals() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/?datastar=%7B%22count%22%3A42%7D")
            .header("datastar-request", "true")
            .body(crate::Body::empty())
            .unwrap();

        let ReadSignals(signals) =
            <Option<ReadSignals<Signals>> as FromRequest>::from_request(request)
                .await
                .unwrap()
                .expect("datastar header makes optional signals present");

        assert_eq!(signals.count, 42);
    }
}
