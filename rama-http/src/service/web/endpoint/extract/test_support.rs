//! Helpers shared by the extractor unit tests.

use std::convert::Infallible;

use rama_core::Service;
use rama_core::bytes::Bytes;

use crate::body::util::BodyExt;
use crate::{Body, HeaderName, Request, Response, StatusCode};

/// Serve a GET request for `uri` with `headers`, returning the status and the collected body.
pub(super) async fn serve_get(
    svc: &impl Service<Request, Output = Response, Error = Infallible>,
    uri: &str,
    headers: &[(&HeaderName, &str)],
) -> (StatusCode, Bytes) {
    let mut builder = Request::builder().method("GET").uri(uri);
    for (header, value) in headers {
        builder = builder.header(*header, *value);
    }
    let res = svc
        .serve(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}
