use rama::{
    Layer as _, Service,
    bytes::Bytes,
    futures::{StreamExt as _, async_stream::stream_fn},
    http::{
        Request, Response, StatusCode,
        layer::map_response_body::MapResponseBodyLayer,
        service::web::response::{IntoResponse, OctetStream as OctetStreamResponse},
    },
    service::service_fn,
    utils::octets::mib,
};
use std::convert::Infallible;

const DEFAULT_BYTES: u64 = 1024;
const MAX_BYTES: u64 = mib(32);
const CHUNK_BYTES: usize = 16 * 1024;

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    MapResponseBodyLayer::new_boxed_streaming_body().into_layer(service_fn(async |req: Request| {
        let size = match parse_size(req.uri().query()) {
            Ok(size) => size,
            Err(err) => return Ok::<_, Infallible>((StatusCode::BAD_REQUEST, err).into_response()),
        };

        let stream = stream_fn(move |mut yielder| async move {
            let mut remaining = size;
            let chunk = Bytes::from(vec![0; CHUNK_BYTES]);
            while remaining > 0 {
                let len = remaining.min(CHUNK_BYTES as u64) as usize;
                yielder.yield_item(chunk.slice(..len)).await;
                remaining -= len as u64;
            }
        })
        .map(Ok::<_, Infallible>);
        Ok::<_, Infallible>(
            OctetStreamResponse::new(stream)
                .with_content_size(size)
                .into_response(),
        )
    }))
}

fn parse_size(query: Option<&str>) -> Result<u64, &'static str> {
    let size = query
        .and_then(|query| {
            query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key == "size").then_some(value)
            })
        })
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_e| "invalid size query parameter")?
        .unwrap_or(DEFAULT_BYTES);

    if size > MAX_BYTES {
        return Err("size exceeds maximum allowed payload");
    }

    Ok(size)
}
