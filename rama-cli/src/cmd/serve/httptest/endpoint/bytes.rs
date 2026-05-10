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
use std::{convert::Infallible, time::Duration};

const DEFAULT_BYTES: u64 = 1024;
const MAX_BYTES: u64 = mib(32);
const DEFAULT_CHUNK: usize = 16 * 1024;
const MAX_CHUNK: usize = 4 * 1024 * 1024;
const MAX_DELAY_MS: u64 = 60_000;

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    MapResponseBodyLayer::new_boxed_streaming_body().into_layer(service_fn(async |req: Request| {
        let params = match parse_params(req.uri().query()) {
            Ok(p) => p,
            Err(err) => return Ok::<_, Infallible>((StatusCode::BAD_REQUEST, err).into_response()),
        };

        let delay = Duration::from_millis(params.delay_ms);
        let chunk_size = params.chunk;

        let stream = stream_fn(move |mut yielder| async move {
            let mut remaining = params.size;
            let chunk = Bytes::from(vec![0u8; chunk_size]);
            let mut first = true;
            while remaining > 0 {
                if !first && !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                first = false;
                let len = remaining.min(chunk_size as u64) as usize;
                yielder.yield_item(chunk.slice(..len)).await;
                remaining -= len as u64;
            }
        })
        .map(Ok::<_, Infallible>);
        Ok::<_, Infallible>(
            OctetStreamResponse::new(stream)
                .with_content_size(params.size)
                .into_response(),
        )
    }))
}

struct BytesParams {
    size: u64,
    chunk: usize,
    delay_ms: u64,
}

fn parse_params(query: Option<&str>) -> Result<BytesParams, &'static str> {
    let mut size = None::<u64>;
    let mut chunk = None::<usize>;
    let mut delay_ms = None::<u64>;

    if let Some(query) = query {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                match key {
                    "size" => {
                        size = Some(
                            value
                                .parse::<u64>()
                                .map_err(|_e| "invalid size query parameter")?,
                        );
                    }
                    "chunk" => {
                        chunk = Some(
                            value
                                .parse::<usize>()
                                .map_err(|_e| "invalid chunk query parameter")?,
                        );
                    }
                    "delay_ms" => {
                        delay_ms = Some(
                            value
                                .parse::<u64>()
                                .map_err(|_e| "invalid delay_ms query parameter")?,
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    let size = size.unwrap_or(DEFAULT_BYTES);
    if size > MAX_BYTES {
        return Err("size exceeds maximum allowed payload");
    }

    let chunk = chunk.unwrap_or(DEFAULT_CHUNK);
    if chunk == 0 {
        return Err("chunk must be greater than zero");
    }
    if chunk > MAX_CHUNK {
        return Err("chunk exceeds maximum allowed chunk size");
    }

    let delay_ms = delay_ms.unwrap_or(0);
    if delay_ms > MAX_DELAY_MS {
        return Err("delay_ms exceeds maximum allowed delay");
    }

    Ok(BytesParams {
        size,
        chunk,
        delay_ms,
    })
}
