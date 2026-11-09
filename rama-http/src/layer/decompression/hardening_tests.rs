use std::{convert::Infallible, io::Write};

use flate2::{Compression as GzLevel, write::GzEncoder};
use rama_core::{
    Layer as _, Service,
    bytes::Bytes,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _, Ingress},
    service::service_fn,
};
use rama_http_types::{
    Body, BodyLimit, Request, Response, StatusCode, body::util::LengthLimitError, header,
};

use rama_utils::octets::{kib, mib};

use super::{Decompression, DecompressionBody, RequestDecompression, RequestDecompressionLayer};
use crate::{body::util::BodyExt, layer::body_limit::BodyLimitLayer};

const PLAIN_LEN: usize = mib(1);

fn brotli(large_window: bool) -> Vec<u8> {
    let params = brotli::enc::BrotliEncoderParams {
        large_window,
        lgwin: if large_window { 25 } else { 22 },
        ..Default::default()
    };
    let mut out = Vec::new();
    brotli::BrotliCompress(&mut &vec![b'a'; PLAIN_LEN][..], &mut out, &params).unwrap();
    out
}

fn zstd_with_window_log(window_log: u32) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    encoder
        .set_parameter(zstd::zstd_safe::CParameter::WindowLog(window_log))
        .unwrap();
    encoder.include_contentsize(false).unwrap();
    encoder.write_all(&vec![0u8; PLAIN_LEN]).unwrap();
    encoder.finish().unwrap()
}

fn gzip() -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), GzLevel::default());
    encoder.write_all(&vec![0u8; PLAIN_LEN]).unwrap();
    encoder.finish().unwrap()
}

fn encoded_request(encoding: &'static str, body: Vec<u8>) -> Request {
    Request::builder()
        .header(header::CONTENT_ENCODING, encoding)
        .body(Body::from(body))
        .unwrap()
}

/// Collect the decoded request body: 200 when it decodes, 413 on a length limit, 400 otherwise.
async fn collect_status(req: Request<DecompressionBody<Body>>) -> Result<Response, Infallible> {
    let status = match req.into_body().collect().await.map(|c| c.to_bytes().len()) {
        Ok(PLAIN_LEN) => StatusCode::OK,
        Ok(_) => StatusCode::INTERNAL_SERVER_ERROR,
        Err(err) if is_length_limit(&err) => StatusCode::PAYLOAD_TOO_LARGE,
        Err(_) => StatusCode::BAD_REQUEST,
    };
    Ok(Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap())
}

fn is_length_limit(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(err);
    while let Some(err) = source {
        if err.is::<LengthLimitError>() {
            return true;
        }
        source = err.source();
    }
    false
}

async fn request_status<S>(svc: &S, req: Request) -> StatusCode
where
    S: Service<Request, Output = Response, Error = BoxError>,
{
    svc.serve(req).await.unwrap().status()
}

#[tokio::test]
async fn request_brotli_large_window_is_rejected() {
    let svc = RequestDecompression::new(service_fn(collect_status));
    assert_eq!(
        request_status(&svc, encoded_request("br", brotli(false))).await,
        StatusCode::OK
    );
    let large = brotli(true);
    assert_eq!(
        large[0] & 0x7f,
        0x11,
        "fixture must use the large-window header"
    );
    assert_eq!(
        request_status(&svc, encoded_request("br", large)).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn request_zstd_window_is_capped_at_8_mib() {
    let svc = RequestDecompression::new(service_fn(collect_status));
    assert_eq!(
        request_status(&svc, encoded_request("zstd", zstd_with_window_log(23))).await,
        StatusCode::OK
    );
    assert_eq!(
        request_status(&svc, encoded_request("zstd", zstd_with_window_log(27))).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn request_decoded_size_limit() {
    let limited =
        RequestDecompression::new(service_fn(collect_status)).with_max_decoded_size(kib(64));
    assert_eq!(
        request_status(&limited, encoded_request("gzip", gzip())).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let roomy =
        RequestDecompression::new(service_fn(collect_status)).with_max_decoded_size(PLAIN_LEN);
    assert_eq!(
        request_status(&roomy, encoded_request("gzip", gzip())).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn request_decoded_size_inherits_transport_limit() {
    let svc = RequestDecompression::new(service_fn(collect_status));
    let req = encoded_request("gzip", gzip());
    let ingress = Extensions::new();
    ingress.insert(BodyLimit::request_only(kib(64)));
    req.extensions().insert(Ingress(ingress));
    assert_eq!(
        request_status(&svc, req).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn request_decoded_size_inherits_outer_body_limit_layer() {
    let compressed = gzip();
    assert!(compressed.len() < kib(64));
    let svc = (
        BodyLimitLayer::new(kib(64)),
        RequestDecompressionLayer::new(),
    )
        .into_layer(service_fn(collect_status));
    assert_eq!(
        svc.serve(encoded_request("gzip", compressed))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

fn encoded_response(
    encoding: &'static str,
    body: Vec<u8>,
) -> impl Fn(Request) -> std::future::Ready<Result<Response, Infallible>> + Clone {
    let body = Bytes::from(body);
    move |_req: Request| {
        std::future::ready(Ok(Response::builder()
            .header(header::CONTENT_ENCODING, encoding)
            .body(Body::from(body.clone()))
            .unwrap()))
    }
}

async fn response_body<S>(client: &S) -> Result<Bytes, BoxError>
where
    S: Service<Request, Output = Response<DecompressionBody<Body>>, Error: Into<BoxError>>,
{
    let req = Request::builder().body(Body::empty()).unwrap();
    let res = client.serve(req).await.map_err(Into::into)?;
    Ok(res.into_body().collect().await?.to_bytes())
}

#[tokio::test]
async fn response_brotli_large_window_is_rejected() {
    let ok = Decompression::new(service_fn(encoded_response("br", brotli(false))));
    assert_eq!(response_body(&ok).await.unwrap().len(), PLAIN_LEN);

    let large = Decompression::new(service_fn(encoded_response("br", brotli(true))));
    response_body(&large).await.unwrap_err();
}

#[tokio::test]
async fn response_zstd_window_is_capped_at_8_mib() {
    let large = Decompression::new(service_fn(encoded_response(
        "zstd",
        zstd_with_window_log(27),
    )));
    response_body(&large).await.unwrap_err();
}

#[tokio::test]
async fn response_decoded_size_limit() {
    let client = Decompression::new(service_fn(encoded_response("gzip", gzip())))
        .with_max_decoded_size(kib(64));
    let err = response_body(&client).await.unwrap_err();
    assert!(is_length_limit(err.as_ref()), "{err}");
}
