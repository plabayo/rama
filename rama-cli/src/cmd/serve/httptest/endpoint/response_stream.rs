use rama::{
    Service,
    bytes::Bytes,
    futures::{StreamExt as _, async_stream::stream_fn},
    http::{
        Body, Request, Response,
        headers::ContentType,
        service::web::response::{Headers, IntoResponse},
    },
    service::service_fn,
};
use std::{convert::Infallible, time::Duration};

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(async || {
        Ok::<_, Infallible>(
            (
                Headers::single(ContentType::html_utf8()),
                Body::from_stream(
                    stream_fn(move |mut yielder| async move {
                        yielder
                            .yield_item(Bytes::from_static(
                                b"<!DOCTYPE html>
<html lang=en>
<head>
<meta charset='utf-8'>
<title>Chunked transfer encoding test</title>
</head>
<body><h1>Chunked transfer encoding test</h1>",
                            ))
                            .await;

                        tokio::time::sleep(Duration::from_millis(100)).await;

                        yielder
                            .yield_item(Bytes::from_static(
                                b"<h5>This is a chunked response after 100 ms.</h5>",
                            ))
                            .await;

                        tokio::time::sleep(Duration::from_secs(1)).await;

                        yielder
                            .yield_item(Bytes::from_static(
                                b"<h5>This is a chunked response after 1 second.
The server should not close the stream before all chunks are sent to a client.</h5></body></html>",
                            ))
                            .await;
                    })
                    .map(Ok::<_, Infallible>),
                ),
            )
                .into_response(),
        )
    })
}
