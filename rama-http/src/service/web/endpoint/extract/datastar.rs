//! [🚀 Datastar](https://data-star.dev/) support extractor for rama.

use crate::service::web::{
    extract::{FromRequest, OptionalFromRequest, Query},
    response::IntoResponse,
};
use rama_core::telemetry::tracing;
use rama_http_types::{BodyExtractExt, Method, Request, Response, StatusCode};
use serde::{Deserialize, de::DeserializeOwned};

/// [`ReadSignals`] is a request extractor that reads datastar signals from the request.
#[derive(Debug)]
pub struct ReadSignals<T: DeserializeOwned>(pub T);

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
        let json = match *req.method() {
            Method::GET => {
                let query =
                    Query::<DatastarParam>::parse_query_str(req.uri().query().unwrap_or(""))
                        .map_err(IntoResponse::into_response)?;

                let signals = query.0.datastar.as_str().ok_or_else(|| {
                    tracing::debug!("failed to get datastar query value from GET request");
                    (StatusCode::BAD_REQUEST, "Failed to parse JSON").into_response()
                })?;

                serde_json::from_str(signals)
                    .map_err(|err| {
                        tracing::debug!(%err, "failed to parse datastar query json value from GET request");
                        (StatusCode::BAD_REQUEST, err.to_string()).into_response()}
                    )?
            }
            _ => req.into_body().try_into_json().await.map_err(|err| {
                tracing::debug!(%err, "failed to parse datastar json payload from POST request");
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            })?,
        };

        Ok(Self(json))
    }
}

impl<T> OptionalFromRequest for ReadSignals<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Response;

    async fn from_request(req: Request) -> Result<Option<Self>, Self::Rejection> {
        if req.headers().get("datastar-request").is_none() {
            tracing::trace!(
                "no datastar request header present: returning no read signals as such"
            );
            return Ok(None);
        }
        Ok(Some(<Self as FromRequest>::from_request(req).await?))
    }
}
