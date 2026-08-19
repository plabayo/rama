use rama_core::bytes::Bytes;
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use rama_http::body::util::BodyExt as _;
use rama_http::layer::har::layer::HARExportLayer;
use rama_http::layer::har::recorder::{
    BodyCaptureStream, HttpRequestCapture, HttpResponseCapture, Recorder, RecorderSession,
    StreamingRecorder, WebSocketCapture, WebSocketCaptureRecorder,
};
use rama_http::layer::har::spec::{Log, WebSocketMessage, WebSocketMessageType};
use rama_http::{Body, BodyCaptureEvent, Request, Response};
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct NetworkLikeRecorder {
    exchanges: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>,
}

struct NetworkLikeSession {
    request_body: tokio::task::JoinHandle<Vec<u8>>,
    exchanges: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>,
}

async fn drain_body(mut body: BodyCaptureStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while let Some(event) = body.next_event().await {
        match event {
            BodyCaptureEvent::Frame(frame) => {
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data);
                }
            }
            BodyCaptureEvent::End(_) => break,
        }
    }
    bytes
}

impl Recorder for NetworkLikeRecorder {
    async fn record(&self, _log: Log) -> Option<Extensions> {
        None
    }

    async fn stop_record(&self) {}
}

impl StreamingRecorder for NetworkLikeRecorder {
    type Session = NetworkLikeSession;

    async fn start_http_recording(&self, request: HttpRequestCapture) -> Option<Self::Session> {
        Some(NetworkLikeSession {
            request_body: tokio::spawn(drain_body(request.body)),
            exchanges: self.exchanges.clone(),
        })
    }
}

impl RecorderSession for NetworkLikeSession {
    async fn record_response(self, response: HttpResponseCapture) -> Option<Extensions> {
        tokio::spawn(async move {
            let (request, response) = tokio::join!(self.request_body, drain_body(response.body));
            if let Ok(request) = request {
                self.exchanges.lock().await.push((request, response));
            }
        });
        None
    }

    async fn record_request_only(self) -> Option<Extensions> {
        tokio::spawn(async move {
            if let Ok(request) = self.request_body.await {
                self.exchanges.lock().await.push((request, Vec::new()));
            }
        });
        None
    }
}

#[tokio::test]
async fn external_recorder_can_stream_through_har_export_layer() {
    let recorder = NetworkLikeRecorder::default();
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn(
        async |request: Request| {
            let request = request.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(request, Bytes::from_static(b"request"));
            Ok::<_, Infallible>(Response::new(Body::from("response")))
        },
    ));

    let response = service
        .serve(Request::new(Body::from("request")))
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"response")
    );

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !recorder.exchanges.lock().await.is_empty() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("custom recorder completion");

    let exchanges = recorder.exchanges.lock().await;
    assert_eq!(
        exchanges.as_slice(),
        &[(b"request".to_vec(), b"response".to_vec())]
    );
}

#[derive(Clone)]
struct CaptureIdentityRecorder {
    calls: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
}

struct CaptureIdentitySession {
    calls: Arc<AtomicUsize>,
    capture: WebSocketCapture,
}

impl Recorder for CaptureIdentityRecorder {
    async fn record(&self, _log: Log) -> Option<Extensions> {
        None
    }

    async fn stop_record(&self) {}
}

impl StreamingRecorder for CaptureIdentityRecorder {
    type Session = CaptureIdentitySession;

    async fn start_http_recording(&self, _request: HttpRequestCapture) -> Option<Self::Session> {
        let closed = self.closed.clone();
        Some(CaptureIdentitySession {
            calls: self.calls.clone(),
            capture: WebSocketCapture::new(
                ExternalWebSocketRecorder(Arc::new(parking_lot::Mutex::new(Vec::new()))),
                move || closed.store(true, Ordering::Release),
            ),
        })
    }
}

impl RecorderSession for CaptureIdentitySession {
    fn web_socket_capture(&self) -> Option<WebSocketCapture> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Some(self.capture.clone())
    }

    async fn record_response(self, _response: HttpResponseCapture) -> Option<Extensions> {
        None
    }

    async fn record_request_only(self) -> Option<Extensions> {
        None
    }
}

#[tokio::test]
async fn har_export_claims_one_capture_identity_per_session() {
    let calls = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicBool::new(false));
    let service = HARExportLayer::new(
        CaptureIdentityRecorder {
            calls: calls.clone(),
            closed,
        },
        true,
    )
    .into_layer(service_fn(|_request: Request| async move {
        Response::builder()
            .status(rama_http::StatusCode::SWITCHING_PROTOCOLS)
            .version(rama_http::Version::HTTP_11)
            .body(Body::empty())
    }));
    let request = Request::builder()
        .uri("ws://example.test/capture-identity")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .expect("WebSocket request");

    service.serve(request).await.expect("upgrade response");

    assert_eq!(calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn service_error_closes_capture_retained_by_inner_service() {
    let closed = Arc::new(AtomicBool::new(false));
    let retained = Arc::new(parking_lot::Mutex::new(None));
    let service = HARExportLayer::new(
        CaptureIdentityRecorder {
            calls: Arc::new(AtomicUsize::new(0)),
            closed: closed.clone(),
        },
        true,
    )
    .into_layer(service_fn({
        let retained = retained.clone();
        move |request: Request| {
            *retained.lock() = request.extensions().get_ref::<WebSocketCapture>().cloned();
            async move { Err::<Response, _>(std::io::Error::other("WebSocket service failed")) }
        }
    }));
    let request = Request::builder()
        .uri("ws://example.test/service-error")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .expect("WebSocket request");

    service.serve(request).await.expect_err("service error");

    assert!(retained.lock().is_some(), "inner service retained a clone");
    assert!(
        closed.load(Ordering::Acquire),
        "HAR service closes a failed handshake without waiting for clones"
    );
}

struct ExternalWebSocketRecorder(Arc<parking_lot::Mutex<Vec<WebSocketMessage>>>);

impl WebSocketCaptureRecorder for ExternalWebSocketRecorder {
    async fn record(&self, message: WebSocketMessage) -> Result<(), rama_core::error::BoxError> {
        self.0.lock().push(message);
        Ok(())
    }
}

#[tokio::test]
async fn external_web_socket_recorder_is_shared_and_closable() {
    let messages = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let closed = Arc::new(AtomicBool::new(false));
    let capture = WebSocketCapture::new(ExternalWebSocketRecorder(messages.clone()), {
        let closed = closed.clone();
        move || closed.store(true, Ordering::Release)
    });

    let lease = capture.lease().expect("first observer");
    assert!(capture.lease().is_none());
    lease
        .record(WebSocketMessage::text(
            WebSocketMessageType::Send,
            1.0,
            "message",
        ))
        .await
        .unwrap();
    drop(lease);

    assert_eq!(messages.lock().len(), 1);
    assert!(closed.load(Ordering::Acquire));
}
