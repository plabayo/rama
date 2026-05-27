use rama::{
    Service,
    futures::StreamExt as _,
    http::{
        Request, Response, StatusCode,
        service::web::response::{IntoResponse, Json},
    },
    service::service_fn,
};
use serde::Serialize;
use std::convert::Infallible;

#[derive(Serialize)]
struct SinkResponse {
    bytes: u64,
}

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(async |req: Request| {
        let mut stream = req.into_body().into_data_stream();
        let mut total: u64 = 0;
        loop {
            match stream.next().await {
                None => break,
                Some(Ok(chunk)) => total += chunk.len() as u64,
                Some(Err(err)) => {
                    return Ok::<_, Infallible>(
                        (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
                    );
                }
            }
        }
        Ok::<_, Infallible>(Json(SinkResponse { bytes: total }).into_response())
    })
}
