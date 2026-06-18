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
    utils::octets::{kib, mib, mib_u64},
};
use std::{convert::Infallible, time::Duration};

const DEFAULT_BYTES: u64 = 1024;
const MAX_BYTES: u64 = mib_u64(32);
const DEFAULT_CHUNK: usize = kib(16);
const MAX_CHUNK: usize = mib(4);
const MAX_DELAY_MS: u64 = 60_000;

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    MapResponseBodyLayer::new_boxed_streaming_body().into_layer(service_fn(async |req: Request| {
        let params: BytesParams = match req.uri().query_params() {
            Ok(p) => p,
            Err(_) => {
                return Ok::<_, Infallible>(
                    (StatusCode::BAD_REQUEST, "invalid query parameters").into_response(),
                );
            }
        };
        if let Err(err) = params.validate() {
            return Ok::<_, Infallible>((StatusCode::BAD_REQUEST, err).into_response());
        }

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

#[derive(Debug, serde::Deserialize)]
struct BytesParams {
    #[serde(default = "default_bytes")]
    size: u64,
    #[serde(default = "default_chunk")]
    chunk: usize,
    #[serde(default)]
    delay_ms: u64,
}

fn default_bytes() -> u64 {
    DEFAULT_BYTES
}

fn default_chunk() -> usize {
    DEFAULT_CHUNK
}

impl BytesParams {
    fn validate(&self) -> Result<(), &'static str> {
        if self.size > MAX_BYTES {
            return Err("size exceeds maximum allowed payload");
        }
        if self.chunk == 0 {
            return Err("chunk must be greater than zero");
        }
        if self.chunk > MAX_CHUNK {
            return Err("chunk exceeds maximum allowed chunk size");
        }
        if self.delay_ms > MAX_DELAY_MS {
            return Err("delay_ms exceeds maximum allowed delay");
        }
        Ok(())
    }
}
