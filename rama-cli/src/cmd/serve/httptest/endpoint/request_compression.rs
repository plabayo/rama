use rama::{
    Layer as _, Service,
    http::{
        Request, Response, StatusCode,
        body::util::BodyExt,
        layer::{
            body_limit::BodyLimitLayer, decompression::RequestDecompressionLayer,
            map_request_body::MapRequestBodyLayer,
        },
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    service::service_fn,
};
use std::convert::Infallible;

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    (
        ConsumeErrLayer::trace_as_debug(),
        BodyLimitLayer::new(8 * 1024 * 1024), // EMS 3.2 4life
        RequestDecompressionLayer::new(),
        MapRequestBodyLayer::new_boxed_streaming_body(),
    )
        .into_layer(service_fn(async |req: Request| {
            match req.into_body().collect().await.map(|c| c.to_bytes()) {
                Ok(bytes) => Ok::<_, Infallible>(bytes.into_response()),
                Err(err) => Ok((StatusCode::BAD_REQUEST, err.to_string()).into_response()),
            }
        }))
}
