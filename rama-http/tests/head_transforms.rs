//! HEAD responses may retain the GET representation's size hint (HTTP/2) or
//! report zero bytes while waiting for stream completion (HTTP/3).
#![cfg(feature = "compression")]
#![expect(
    clippy::panic,
    clippy::unwrap_used,
    reason = "integration test helpers fail on unexpected input or polling"
)]

use rama_core::{Service, bytes::Bytes, error::BoxError, service::service_fn};
use rama_http::{
    Body, Method, Request, Response,
    body::{Frame, SizeHint, StreamingBody, util::BodyExt},
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, VARY},
    layer::{
        compression::{Compression, stream::StreamCompression},
        decompression::Decompression,
    },
};
use std::{
    convert::Infallible,
    fmt::Debug,
    io::Read,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

#[derive(Clone, Copy)]
enum HeadState {
    RepresentationLength,
    AwaitingFin,
}

const HEAD_STATES: [HeadState; 2] = [HeadState::RepresentationLength, HeadState::AwaitingFin];

struct RepresentationBody {
    bytes: Option<Bytes>,
    head: bool,
    head_state: HeadState,
    head_polls: Arc<AtomicUsize>,
}

impl StreamingBody for RepresentationBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.head {
            self.head_polls.fetch_add(1, Ordering::Relaxed);
            panic!("a transformed HEAD must not poll its representation body");
        }
        Poll::Ready(self.bytes.take().map(|bytes| Ok(Frame::data(bytes))))
    }

    fn is_end_stream(&self) -> bool {
        (self.head && matches!(self.head_state, HeadState::RepresentationLength))
            || self.bytes.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        let length = if self.head && matches!(self.head_state, HeadState::AwaitingFin) {
            0
        } else {
            self.bytes.as_ref().map_or(0, |bytes| bytes.len() as u64)
        };
        SizeHint::with_exact(length)
    }
}

fn origin(
    bytes: Bytes,
    encoding: Option<&'static str>,
    head_polls: Arc<AtomicUsize>,
    head_state: HeadState,
) -> impl Service<Request<Body>, Output = Response<RepresentationBody>, Error = Infallible> {
    service_fn(move |request: Request<Body>| {
        let mut response = Response::builder().header(CONTENT_LENGTH, bytes.len());
        if let Some(encoding) = encoding {
            response = response.header(CONTENT_ENCODING, encoding);
        }
        std::future::ready(Ok(response
            .body(RepresentationBody {
                bytes: Some(bytes.clone()),
                head: request.method() == Method::HEAD,
                head_state,
                head_polls: head_polls.clone(),
            })
            .unwrap()))
    })
}

fn request(method: Method, encoding: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .header(ACCEPT_ENCODING, encoding)
        .body(Body::empty())
        .unwrap()
}

async fn assert_transformed_head<B: StreamingBody>(response: Response<B>)
where
    B::Error: Into<BoxError>,
{
    assert!(!response.headers().contains_key(CONTENT_LENGTH));
    // The server must not infer the old representation length after the layer
    // removed it. This is the observable contract used by H1/H2/H3 encoders.
    assert_eq!(response.body().size_hint().exact(), Some(0));
    assert!(response.body().is_end_stream());
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
}

fn decode(encoding: &str, bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    match encoding {
        "gzip" => {
            flate2::read::GzDecoder::new(bytes)
                .read_to_end(&mut decoded)
                .unwrap();
        }
        "deflate" => {
            flate2::read::ZlibDecoder::new(bytes)
                .read_to_end(&mut decoded)
                .unwrap();
        }
        "br" => {
            brotli::Decompressor::new(bytes, 4096)
                .read_to_end(&mut decoded)
                .unwrap();
        }
        "zstd" => {
            decoded = zstd::stream::decode_all(bytes).unwrap();
        }
        _ => panic!("unexpected encoding"),
    }
    decoded
}

async fn compression_case<S, B>(service: S, encoding: &str, plain: &[u8])
where
    S: Service<Request<Body>, Output = Response<B>>,
    S::Error: Debug,
    B: StreamingBody,
    B::Error: Into<BoxError>,
{
    let get = service.serve(request(Method::GET, encoding)).await.unwrap();
    let head = service
        .serve(request(Method::HEAD, encoding))
        .await
        .unwrap();
    assert_eq!(get.headers()[CONTENT_ENCODING], encoding);
    for name in [CONTENT_ENCODING, CONTENT_LENGTH, VARY] {
        assert_eq!(head.headers().get(&name), get.headers().get(&name));
    }
    assert_transformed_head(head).await;
    let encoded = get.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(decode(encoding, &encoded), plain);
}

#[tokio::test]
async fn compression_clears_a_bodyless_heads_representation_size_hint() {
    let plain = Bytes::from("representation body ".repeat(256));
    for encoding in ["gzip", "deflate", "br", "zstd"] {
        for head_state in HEAD_STATES {
            let polls = Arc::new(AtomicUsize::new(0));
            Box::pin(compression_case(
                Compression::new(origin(plain.clone(), None, polls.clone(), head_state)),
                encoding,
                &plain,
            ))
            .await;
            assert_eq!(polls.load(Ordering::Relaxed), 0);
        }
    }
}

#[tokio::test]
async fn stream_compression_clears_a_bodyless_heads_representation_size_hint() {
    let plain = Bytes::from("representation body ".repeat(256));
    for encoding in ["gzip", "deflate", "br", "zstd"] {
        for head_state in HEAD_STATES {
            let polls = Arc::new(AtomicUsize::new(0));
            compression_case(
                StreamCompression::new(origin(plain.clone(), None, polls.clone(), head_state)),
                encoding,
                &plain,
            )
            .await;
            assert_eq!(polls.load(Ordering::Relaxed), 0);
        }
    }
}

#[tokio::test]
async fn decompression_clears_a_bodyless_heads_representation_size_hint() {
    let plain = Bytes::from("representation body ".repeat(256));
    for encoding in ["gzip", "deflate", "br", "zstd"] {
        for head_state in HEAD_STATES {
            let polls = Arc::new(AtomicUsize::new(0));
            let compressed =
                Compression::new(origin(plain.clone(), None, polls.clone(), head_state))
                    .serve(request(Method::GET, encoding))
                    .await
                    .unwrap()
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes();
            let service = Decompression::new(origin(
                compressed,
                Some(encoding),
                polls.clone(),
                head_state,
            ));
            let get = service.serve(request(Method::GET, encoding)).await.unwrap();
            let head = service
                .serve(request(Method::HEAD, encoding))
                .await
                .unwrap();
            for name in [CONTENT_ENCODING, CONTENT_LENGTH] {
                assert!(!head.headers().contains_key(&name));
                assert!(!get.headers().contains_key(&name));
            }
            assert_transformed_head(head).await;
            assert_eq!(get.into_body().collect().await.unwrap().to_bytes(), plain);
            assert_eq!(polls.load(Ordering::Relaxed), 0);
        }
    }
}

/// A proxy decoding its upstream and encoding for its client with the default predicate: the
/// HEAD response advertises the same encoding as the GET one, though its body is empty.
#[tokio::test]
async fn recompression_after_decompression_mirrors_get_for_head() {
    let plain = Bytes::from("representation body ".repeat(256));
    for head_state in HEAD_STATES {
        let polls = Arc::new(AtomicUsize::new(0));
        let gzipped = Compression::new(origin(plain.clone(), None, polls.clone(), head_state))
            .serve(request(Method::GET, "gzip"))
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let proxy = Compression::new(Decompression::new(origin(
            gzipped,
            Some("gzip"),
            polls.clone(),
            head_state,
        )));
        let get = proxy.serve(request(Method::GET, "gzip")).await.unwrap();
        let head = proxy.serve(request(Method::HEAD, "gzip")).await.unwrap();
        for name in [CONTENT_ENCODING, VARY, CONTENT_LENGTH] {
            assert_eq!(
                head.headers().get_all(&name).iter().collect::<Vec<_>>(),
                get.headers().get_all(&name).iter().collect::<Vec<_>>(),
                "{name}"
            );
        }
        assert_eq!(head.headers()[CONTENT_ENCODING], "gzip");
        assert!(
            head.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        assert_eq!(polls.load(Ordering::Relaxed), 0);
    }
}
