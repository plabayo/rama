//! HTTP operation recording shared by HTTP/1, HTTP/2 and HTTP/3.
//!
//! The backend client and core server adapter use this automatically with their
//! dial9 feature. Use [`Dial9Layer`] around a logical request service to also
//! correlate its retries, redirects, DNS and connection selection. Each attempt
//! remains a child operation. Bodies retain the context after response headers;
//! dropping a streaming response records cancellation, not successful completion.
//! No URLs, headers or body contents are recorded.

use crate::{
    Body, Request, Response, Version,
    body::{Frame, SizeHint, StreamingBody},
    service::web::response::IntoResponse,
};
use dial9_trace_format::TraceEvent;
use pin_project_lite::pin_project;
use rama_core::extensions::ExtensionsRef as _;
use rama_core::{
    Layer, Service,
    bytes::Buf,
    futures::{
        FutureExt as _,
        future::{Either, lazy},
    },
    telemetry::dial9::{Operation, Outcome, TraceContext, core::clock_monotonic_ns},
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(test)]
pub(crate) fn recorder_slot() -> parking_lot::MutexGuard<'static, ()> {
    static SLOT: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    SLOT.lock()
}

/// HTTP request metadata. `version` is 9, 10, 11, 20 or 30.
#[derive(TraceEvent)]
pub struct HttpRequestStarted<'a> {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub method: &'a str,
    pub version: u32,
}

/// Response headers arrived; the operation continues through the response body.
#[derive(TraceEvent)]
pub struct HttpResponseHeaders {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub status: u32,
    pub version: u32,
}

fn version_code(version: Version) -> u32 {
    match version {
        Version::HTTP_09 => 9,
        Version::HTTP_10 => 10,
        Version::HTTP_11 => 11,
        Version::HTTP_2 => 20,
        Version::HTTP_3 => 30,
    }
}

/// Record a logical request, including work performed by the inner service.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct Dial9Layer;

impl Dial9Layer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for Dial9Layer {
    type Service = Dial9<S>;
    fn layer(&self, inner: S) -> Self::Service {
        Dial9 { inner }
    }
}

#[derive(Debug, Clone)]
pub struct Dial9<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for Dial9<S>
where
    S: Service<Request<B>, Output: IntoResponse>,
    B: Send + 'static,
{
    type Output = Response;
    type Error = S::Error;

    fn serve(
        &self,
        request: Request<B>,
    ) -> impl Future<Output = Result<Response, S::Error>> + Send {
        observe_request("http.request", request, |request| self.inner.serve(request))
    }
}

/// Shared request boundary for protocol adapters. Response byte totals count
/// data yielded to the consumer, not bytes acknowledged by the peer. HTTP error
/// status codes are recorded separately from transport/body failures.
pub fn observe_request<B, R, E, F, Fut>(
    name: &'static str,
    request: Request<B>,
    serve: F,
) -> impl Future<Output = Result<Response, E>>
where
    R: IntoResponse,
    F: FnOnce(Request<B>) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
    // Reuse the initial request's storage for the in-flight future. Recording
    // still starts on the first poll, without allocating a boxed request future.
    lazy(move |_| {
        let operation = Operation::new(name);
        if !operation.is_recorded() {
            return Either::Left(
                serve(request).map(|response| response.map(IntoResponse::into_response)),
            );
        }
        let context = operation.context();
        request.extensions().insert(context);
        let connect = request.method() == crate::Method::CONNECT;
        operation.record_event_with(|context| HttpRequestStarted {
            timestamp_ns: clock_monotonic_ns(),
            flow_id: context.flow_id(),
            operation_id: context.operation_id(),
            method: request.method().as_str(),
            version: version_code(request.version()),
        });
        let response = context.scope(serve(request));
        Either::Right(response.map(move |response| {
            let response = match response {
                Ok(response) => response.into_response(),
                Err(error) => {
                    operation.finish(Outcome::Error);
                    return Err(error);
                }
            };
            response.extensions().insert(context);
            operation.record_event_with(|context| HttpResponseHeaders {
                timestamp_ns: clock_monotonic_ns(),
                flow_id: context.flow_id(),
                operation_id: context.operation_id(),
                status: u32::from(response.status().as_u16()),
                version: version_code(response.version()),
            });
            // Upgraded traffic belongs to its own protocol lifecycle, including an
            // extended CONNECT over HTTP/2 or HTTP/3.
            if response.body().is_end_stream()
                || response.status() == crate::StatusCode::SWITCHING_PROTOCOLS
                || (connect && response.status().is_success())
            {
                operation.finish(Outcome::Success);
                return Ok(response);
            }
            Ok(response.map(|body| {
                Body::new(RecordedBody {
                    inner: body,
                    state: BodyState {
                        operation: Some(operation),
                        context,
                        bytes: 0,
                    },
                })
            }))
        }))
    })
    .flatten()
}

pin_project! {
    struct RecordedBody<B> {
        #[pin]
        inner: B,
        state: BodyState,
    }
}

struct BodyState {
    operation: Option<Operation>,
    context: TraceContext,
    bytes: u64,
}

impl BodyState {
    fn finish(&mut self, outcome: Outcome) {
        if let Some(operation) = self.operation.take() {
            operation.finish_with_bytes(outcome, 0, self.bytes);
        }
    }
}

impl Drop for BodyState {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled);
    }
}

impl<B: StreamingBody> StreamingBody for RecordedBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        let mut this = self.project();
        let result = this
            .state
            .context
            .scope_sync(|| this.inner.as_mut().poll_frame(cx));
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.state.bytes = this.state.bytes.saturating_add(data.remaining() as u64);
                }
                if this.inner.is_end_stream() || frame.is_trailers() {
                    this.state.finish(Outcome::Success);
                }
            }
            Poll::Ready(Some(Err(_))) => this.state.finish(Outcome::Error),
            Poll::Ready(None) => this.state.finish(Outcome::Success),
            Poll::Pending => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::util::BodyExt as _;
    use dial9_trace_format::{decoder::Decoder, types::FieldValueRef};
    use rama_core::{
        bytes::Bytes,
        futures::stream,
        telemetry::dial9::{DiskBuffer, TokioAttachOptions, recorder_or_disabled},
    };
    use std::{collections::BTreeMap, convert::Infallible, time::Duration};

    #[test]
    fn streaming_bodies_record_completion_error_and_cancellation_with_partial_bytes() {
        let _slot = recorder_slot();
        let dir = rama_utils::fs::tempdir().unwrap();
        let recorder = recorder_or_disabled(
            DiskBuffer::builder()
                .base_path(dir.path())
                .max_total_size(4 << 20)
                .build(),
        )
        .build();
        assert!(recorder.handle().is_enabled());
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all().worker_threads(1);
        let runtime = rama_core::rt::OwnedRuntime::attach_dial9(
            recorder.handle().clone(),
            builder,
            TokioAttachOptions::default(),
        )
        .unwrap();
        runtime.block_on(async {
            let body = || {
                Body::from_stream(stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
                    b"abc",
                ))]))
            };
            let request = || Request::new(Body::empty());
            drop(observe_request(
                "unpolled",
                request(),
                |_| -> std::future::Ready<Result<Response, Infallible>> {
                    panic!("an unpolled request must not call the service")
                },
            ));
            let response = observe_request("complete", request(), |_| async {
                Ok::<_, Infallible>(Response::new(body()))
            })
            .await
            .unwrap();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "abc"
            );
            let response = observe_request("error", request(), |_| async {
                Ok::<_, Infallible>(Response::new(Body::from_stream(stream::iter([
                    Ok(Bytes::from_static(b"abc")),
                    Err(std::io::Error::other("injected body failure")),
                ]))))
            })
            .await
            .unwrap();
            response.into_body().collect().await.unwrap_err();
            let response = observe_request("cancel", request(), |_| async {
                Ok::<_, Infallible>(Response::new(body()))
            })
            .await
            .unwrap();
            // The stream has yielded data but has not yet reported EOF.
            let mut body = response.into_body();
            body.frame().await.unwrap().unwrap();
            drop(body);
            let failure = observe_request("service_error", request(), |_| async {
                Err::<Response, _>("failed before headers")
            })
            .await;
            failure.unwrap_err();
        });
        runtime.shutdown_bounded(Duration::from_secs(1));
        recorder.graceful_shutdown(Duration::from_secs(1));
        let bytes = std::fs::read(dir.path().join("trace.0.bin")).unwrap();
        let mut finished = BTreeMap::new();
        Decoder::new(&bytes)
            .unwrap()
            .for_each_event(|event| {
                if event.name != "RamaOperationFinished" {
                    return;
                }
                let fields: BTreeMap<_, _> = event.field_names().zip(event.fields.iter()).collect();
                let FieldValueRef::String(name) = fields["name"] else {
                    panic!("name");
                };
                let FieldValueRef::Varint(outcome) = fields["outcome"] else {
                    panic!("outcome");
                };
                let FieldValueRef::Varint(bytes) = fields["bytes_received"] else {
                    panic!("bytes");
                };
                assert!(
                    finished
                        .insert(name.to_string(), (*outcome, *bytes))
                        .is_none()
                );
            })
            .unwrap();
        assert_eq!(finished.len(), 4);
        assert_eq!(finished["complete"], (Outcome::Success as u64, 3));
        assert_eq!(finished["error"], (Outcome::Error as u64, 3));
        assert_eq!(finished["cancel"], (Outcome::Cancelled as u64, 3));
        assert_eq!(finished["service_error"], (Outcome::Error as u64, 0));
    }
}
