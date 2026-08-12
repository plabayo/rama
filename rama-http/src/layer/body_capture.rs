//! Asynchronous streaming request and response body capture.
//!
//! [`BodyCaptureLayer`] creates a dedicated [`BodyCaptureSink`] for each
//! selected HTTP message. Each sink receives owned frame copies while the
//! original body continues downstream.

use std::{fmt, future::Future};

use rama_core::{Layer, Service, bytes::Bytes, error::BoxError};
use rama_http_types::{
    Body, BodyCaptureSink, CaptureBody, Request, Response, StreamingBody, body::util::BodyExt as _,
    request, response,
};
use rama_utils::macros::define_inner_service_accessors;

/// The HTTP head associated with a captured body stream.
#[derive(Clone)]
pub enum CapturedHead {
    /// An inbound request head.
    Request(request::Parts),
    /// An outbound response head.
    Response(response::Parts),
}

impl fmt::Debug for CapturedHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(parts) => f.debug_tuple("Request").field(parts).finish(),
            Self::Response(parts) => f.debug_tuple("Response").field(parts).finish(),
        }
    }
}

/// Creates a dedicated streaming capture sink for an HTTP message.
///
/// Returning `None` skips body capture for that message. The factory future is
/// awaited after the HTTP head is available and before its body starts flowing.
pub trait MakeBodyCaptureSink: Send + Sync + 'static {
    /// The per-message capture sink.
    type Sink: BodyCaptureSink;

    /// Create a capture sink from the request or response head.
    fn make_sink(&self, head: CapturedHead)
    -> impl Future<Output = Option<Self::Sink>> + Send + '_;
}

impl<F, Fut, S> MakeBodyCaptureSink for F
where
    F: Fn(CapturedHead) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<S>> + Send + 'static,
    S: BodyCaptureSink,
{
    type Sink = S;

    fn make_sink(
        &self,
        head: CapturedHead,
    ) -> impl Future<Output = Option<Self::Sink>> + Send + '_ {
        self(head)
    }
}

/// Layer that captures request bodies, response bodies, or both while they
/// continue streaming through the service.
#[derive(Clone)]
pub struct BodyCaptureLayer<M> {
    make_sink: M,
    capture_request: bool,
    capture_response: bool,
}

impl<M> BodyCaptureLayer<M> {
    /// Capture request bodies.
    #[must_use]
    pub const fn request(make_sink: M) -> Self {
        Self {
            make_sink,
            capture_request: true,
            capture_response: false,
        }
    }

    /// Capture response bodies.
    #[must_use]
    pub const fn response(make_sink: M) -> Self {
        Self {
            make_sink,
            capture_request: false,
            capture_response: true,
        }
    }

    /// Capture request and response bodies.
    #[must_use]
    pub const fn bidirectional(make_sink: M) -> Self {
        Self {
            make_sink,
            capture_request: true,
            capture_response: true,
        }
    }

    /// Return the capture sink factory.
    #[must_use]
    pub const fn make_sink(&self) -> &M {
        &self.make_sink
    }

    /// Return whether request capture is enabled.
    #[must_use]
    pub const fn captures_requests(&self) -> bool {
        self.capture_request
    }

    /// Return whether response capture is enabled.
    #[must_use]
    pub const fn captures_responses(&self) -> bool {
        self.capture_response
    }
}

impl<M: fmt::Debug> fmt::Debug for BodyCaptureLayer<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyCaptureLayer")
            .field("make_sink", &self.make_sink)
            .field("capture_request", &self.capture_request)
            .field("capture_response", &self.capture_response)
            .finish()
    }
}

impl<M, S> Layer<S> for BodyCaptureLayer<M>
where
    M: Clone,
{
    type Service = BodyCaptureService<M, S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyCaptureService {
            inner,
            make_sink: self.make_sink.clone(),
            capture_request: self.capture_request,
            capture_response: self.capture_response,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        BodyCaptureService {
            inner,
            make_sink: self.make_sink,
            capture_request: self.capture_request,
            capture_response: self.capture_response,
        }
    }
}

/// Service produced by [`BodyCaptureLayer`].
#[derive(Clone)]
pub struct BodyCaptureService<M, S> {
    inner: S,
    make_sink: M,
    capture_request: bool,
    capture_response: bool,
}

impl<M, S> BodyCaptureService<M, S> {
    /// Create a service that captures request and response bodies.
    #[must_use]
    pub const fn bidirectional(inner: S, make_sink: M) -> Self {
        Self {
            inner,
            make_sink,
            capture_request: true,
            capture_response: true,
        }
    }

    define_inner_service_accessors!();
}

impl<M: fmt::Debug, S: fmt::Debug> fmt::Debug for BodyCaptureService<M, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyCaptureService")
            .field("inner", &self.inner)
            .field("make_sink", &self.make_sink)
            .field("capture_request", &self.capture_request)
            .field("capture_response", &self.capture_response)
            .finish()
    }
}

impl<M, S, ReqBody, ResBody> Service<Request<ReqBody>> for BodyCaptureService<M, S>
where
    M: MakeBodyCaptureSink,
    S: Service<Request<Body>, Output = Response<ResBody>>,
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response<Body>;
    type Error = S::Error;

    async fn serve(&self, request: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let request = if self.capture_request {
            let (parts, body) = request.into_parts();
            let body = match self
                .make_sink
                .make_sink(CapturedHead::Request(parts.clone()))
                .await
            {
                Some(sink) => Body::new(CaptureBody::new(body.map_err(Into::into), sink)),
                None => Body::new(body),
            };
            Request::from_parts(parts, body)
        } else {
            request.map(Body::new)
        };

        let response = self.inner.serve(request).await?;
        Ok(if self.capture_response {
            let (parts, body) = response.into_parts();
            let body = match self
                .make_sink
                .make_sink(CapturedHead::Response(parts.clone()))
                .await
            {
                Some(sink) => Body::new(CaptureBody::new(body.map_err(Into::into), sink)),
                None => Body::new(body),
            };
            Response::from_parts(parts, body)
        } else {
            response.map(Body::new)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use rama_core::{Layer as _, Service as _, futures::StreamExt as _, service::service_fn};
    use rama_http_types::{
        BodyCaptureEvent, CaptureOutcome, StatusCode, body::Frame, body::util::BodyExt as _,
    };

    use super::*;

    type Capture = (
        CapturedHead,
        tokio::sync::mpsc::UnboundedReceiver<BodyCaptureEvent>,
    );

    async fn recv<T>(receiver: &mut tokio::sync::mpsc::UnboundedReceiver<T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
            .await
            .expect("capture should arrive promptly")
            .expect("capture channel should remain open")
    }

    #[tokio::test]
    async fn bidirectional_capture_streams_both_messages() {
        let request_polls = Arc::new(AtomicUsize::new(0));
        let polled = Arc::clone(&request_polls);
        let request_body = Body::from_stream(
            rama_core::futures::stream::iter([
                Ok::<_, Infallible>(Bytes::from_static(b"request ")),
                Ok(Bytes::from_static(b"body")),
            ])
            .inspect(move |_| {
                polled.fetch_add(1, Ordering::Relaxed);
            }),
        );

        let (captures, mut captured) = tokio::sync::mpsc::unbounded_channel::<Capture>();
        let make_sink = move |head| {
            let captures = captures.clone();
            async move {
                let (events, receiver) = tokio::sync::mpsc::unbounded_channel();
                captures.send((head, receiver)).unwrap();
                Some(events)
            }
        };
        let layer = BodyCaptureLayer::bidirectional(make_sink);
        let service_polls = Arc::clone(&request_polls);
        let service = layer.into_layer(service_fn(move |request: Request<Body>| {
            let request_polls = Arc::clone(&service_polls);
            async move {
                assert_eq!(request_polls.load(Ordering::Relaxed), 0);
                assert_eq!(
                    request.into_body().collect().await.unwrap().to_bytes(),
                    Bytes::from_static(b"request body")
                );
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .body(Body::from("response body"))
                        .unwrap(),
                )
            }
        }));

        let response = service
            .serve(
                Request::builder()
                    .method("POST")
                    .uri("https://example.com/")
                    .body(request_body)
                    .unwrap(),
            )
            .await
            .unwrap();

        let (head, mut request_events) = recv(&mut captured).await;
        assert!(matches!(head, CapturedHead::Request(ref parts) if parts.method == "POST"));
        let mut request_bytes = Vec::new();
        loop {
            let event = recv(&mut request_events).await;
            match event {
                BodyCaptureEvent::Frame(frame) => {
                    if let Ok(data) = frame.into_data() {
                        request_bytes.extend_from_slice(&data);
                    }
                }
                BodyCaptureEvent::End(outcome) => {
                    assert_eq!(outcome, CaptureOutcome::Complete);
                    break;
                }
            }
        }
        assert_eq!(request_bytes, b"request body");

        let (head, mut response_events) = recv(&mut captured).await;
        assert!(
            matches!(head, CapturedHead::Response(ref parts) if parts.status == StatusCode::CREATED)
        );
        response_events.try_recv().unwrap_err();

        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"response body")
        );
        let BodyCaptureEvent::Frame(frame) = recv(&mut response_events).await else {
            panic!("expected a captured response frame");
        };
        assert_eq!(
            frame.into_data().unwrap(),
            Bytes::from_static(b"response body")
        );
        assert!(matches!(
            recv(&mut response_events).await,
            BodyCaptureEvent::End(CaptureOutcome::Complete)
        ));
    }

    #[tokio::test]
    async fn factory_can_skip_capture_from_the_head() {
        let make_sink = |head| async move {
            match head {
                CapturedHead::Request(parts) if parts.method == "GET" => None,
                _ => Some(|_event: BodyCaptureEvent| async {}),
            }
        };
        let service = BodyCaptureLayer::request(make_sink).into_layer(service_fn(
            |request: Request<Body>| async move {
                request.into_body().collect().await.unwrap();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            },
        ));

        service
            .serve(
                Request::builder()
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    #[test]
    fn frame_is_cloneable_when_its_data_is_cloneable() {
        let frame = Frame::data(Bytes::from_static(b"shared"));
        assert_eq!(
            frame.clone().into_data().unwrap(),
            frame.into_data().unwrap()
        );
    }

    #[test]
    fn constructors_and_debug_report_capture_directions() {
        let request = BodyCaptureLayer::request("factory");
        assert_eq!(request.make_sink(), &"factory");
        assert!(request.captures_requests());
        assert!(!request.captures_responses());
        assert!(format!("{request:?}").contains("BodyCaptureLayer"));

        let response = BodyCaptureLayer::response("factory");
        assert!(!response.captures_requests());
        assert!(response.captures_responses());

        let both = BodyCaptureLayer::bidirectional("factory");
        assert!(both.captures_requests());
        assert!(both.captures_responses());

        let service = BodyCaptureService::bidirectional("inner", "factory");
        assert!(format!("{service:?}").contains("BodyCaptureService"));

        let (request_parts, ()) = Request::builder()
            .method("POST")
            .body(())
            .unwrap()
            .into_parts();
        let request_head = format!("{:?}", CapturedHead::Request(request_parts));
        assert!(request_head.starts_with("Request("));
        assert!(request_head.contains("POST"));

        let (response_parts, ()) = Response::builder()
            .status(StatusCode::CREATED)
            .body(())
            .unwrap()
            .into_parts();
        let response_head = format!("{:?}", CapturedHead::Response(response_parts));
        assert!(response_head.starts_with("Response("));
        assert!(response_head.contains("201"));
    }
}
