use std::pin::pin;

use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _, ErrorExt as _},
    extensions::{Egress, Extensions, ExtensionsRef},
};
use rama_http::{
    Body, Method, Request, Response, Version,
    layer::version_adapter::ensure_valid_request_for_version,
};
use rama_http_core::h3::{
    Error as Http3Error, PriorityHandle, PriorityObserver, client::SendRequest,
};
use tokio::sync::oneshot;

use crate::client::{SendAttempts, classify_http3_error, note_http3_unprocessed};

/// The egress side of [`super::Http3MitmRelay`]: requests sent on the relay's own HTTP/3
/// client connection, with downstream priority changes carried to the upstream stream.
///
/// It is the inner service the relay's HTTP middleware wraps, as `HttpClientService` is for
/// the HTTP/1 and HTTP/2 relay.
#[derive(Debug, Clone)]
pub struct Http3EgressService {
    sender: SendRequest<Body>,
    extensions: Extensions,
}

impl Http3EgressService {
    pub(super) fn new(sender: SendRequest<Body>, extensions: Extensions) -> Self {
        extensions.insert(sender.connection_admission());
        Self { sender, extensions }
    }
}

impl ExtensionsRef for Http3EgressService {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Service<Request> for Http3EgressService {
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, mut request: Request) -> Result<Self::Output, Self::Error> {
        let attempts = request.extensions().get_arc::<SendAttempts>();
        if let Some(attempts) = &attempts {
            attempts.begin();
        }
        request.extensions().insert(Egress(self.extensions.clone()));
        if request.version() != Version::HTTP_3 {
            return Err(BoxError::from_static_str(
                "HTTP/3 relay egress cannot send request with version",
            )
            .context_debug_field("version", request.version()));
        }
        if request.method() == Method::CONNECT && request.uri().host().is_none() {
            return Err(BoxError::from_static_str("missing host in CONNECT request"));
        }
        ensure_valid_request_for_version(&mut request)?;

        let mut sender = self.sender.clone();
        match send(&mut sender, request).await {
            Ok(response) => Ok(response.map(Body::new)),
            Err(error) => {
                note_http3_unprocessed(attempts.as_deref(), &error);
                Err(classify_http3_error(error))
            }
        }
    }
}

/// Send `request`, carrying the ingress stream's priority changes to the upstream stream until
/// the response head arrives; the relay continues from there with the response's handle.
async fn send(
    sender: &mut SendRequest<Body>,
    request: Request,
) -> Result<Response<rama_http_core::body::Incoming>, Http3Error> {
    let Some(mut observer) = request.extensions().get_ref::<PriorityObserver>().cloned() else {
        return sender.send_request(request).await;
    };
    let (opened, stream) = oneshot::channel();
    let mut response = pin!(sender.send_request_with_priority(request, move |handle| {
        let _cancelled_request = opened.send(handle);
    }));
    let updates = async move {
        let Ok(handle) = stream.await else {
            return;
        };
        forward_priority(&mut observer, &handle).await;
    };
    tokio::select! {
        result = &mut response => result,
        () = updates => response.await,
    }
}

/// Coalescing follows the scheduler's effective priority rather than queueing every update; the
/// caller's lifetime (response or tunnel) ends the wait.
pub(super) async fn forward_priority(observer: &mut PriorityObserver, handle: &PriorityHandle) {
    while let Ok(priority) = observer.changed().await {
        if handle.update(priority).is_err() {
            return;
        }
    }
}
