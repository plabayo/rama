use rama::{
    Layer as _, Service,
    http::{
        Request, Response, StatusCode,
        body::util::BodyExt,
        layer::{body_limit::BodyLimitLayer, map_response_body::MapResponseBodyLayer},
        service::web::response::{IntoResponse, OctetStream as OctetStreamResponse},
    },
    layer::ConsumeErrLayer,
    service::service_fn,
    stream::io::ReaderStream,
    utils::octets::mib,
};
use std::convert::Infallible;

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    (
        ConsumeErrLayer::trace_as_debug(),
        BodyLimitLayer::new(mib(8)),
        MapResponseBodyLayer::new_boxed_streaming_body(),
    )
        .into_layer(service_fn(async |req: Request| {
            match req.into_body().collect().await.map(|c| c.to_bytes()) {
                Ok(bytes) => {
                    let size = bytes.len() as u64;
                    let stream = ReaderStream::new(std::io::Cursor::new(bytes));
                    Ok::<_, Infallible>(
                        OctetStreamResponse::new(stream)
                            .with_content_size(size)
                            .into_response(),
                    )
                }
                Err(err) => {
                    Ok::<_, Infallible>((StatusCode::BAD_REQUEST, err.to_string()).into_response())
                }
            }
        }))
}
