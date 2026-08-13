//! [🚀 Datastar](https://data-star.dev/) support extractor for rama.

use crate::service::web::{
    extract::{FromRequest, FromRequestBody, OptionalFromRequest, OptionalFromRequestBody},
    response::IntoResponse,
};
use rama_core::telemetry::tracing;
use rama_http_types::{BodyExtractExt, Method, Request, Response, StatusCode};
use serde::{Deserialize, de::DeserializeOwned};

/// [`ReadSignals`] is a request extractor that reads datastar signals from the request.
#[derive(Debug)]
pub struct ReadSignals<T>(pub T);

#[derive(Deserialize)]
struct DatastarParam {
    datastar: serde_json::Value,
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
        let get_result = if parts.method == Method::GET {
            Some((|| {
                let param = parts.uri.query_params::<DatastarParam>().map_err(|err| {
                    tracing::debug!(
                        "failed to parse datastar query params from GET request: {err:?}"
                    );
                    (StatusCode::BAD_REQUEST, err.to_string()).into_response()
                })?;

                let signals = param.datastar.as_str().ok_or_else(|| {
                    tracing::debug!("failed to get datastar query value from GET request");
                    (StatusCode::BAD_REQUEST, "Failed to parse JSON").into_response()
                })?;

                serde_json::from_str(signals)
                    .map_err(|err| {
                        tracing::debug!(
                            "failed to parse datastar query json value from GET request: {err:?}"
                        );
                        (StatusCode::BAD_REQUEST, err.to_string()).into_response()
                    })
                    .map(Self)
            })())
        } else {
            None
        };

        async move {
            if let Some(result) = get_result {
                return result;
            }

            let json = body.try_into_json().await.map_err(|err| {
                tracing::debug!("failed to parse datastar json payload from POST request: {err:?}");
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

    #[derive(Debug, Deserialize)]
    struct Signals {
        count: u64,
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
