use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _, ErrorExt, error_chain},
    extensions::{Egress, Extensions, ExtensionsRef},
    rt::Executor,
    telemetry::tracing,
};
use rama_http::{
    StreamingBody, io::upgrade::OnUpgrade, layer::version_adapter::ensure_valid_request_for_version,
};
use rama_http_core::{
    Error as HttpError,
    client::conn::{http1, http2},
    h2::Error as Http2Error,
    h3::{Error as Http3Error, client as http3, connection::Config as Http3Config},
};
use rama_http_types::{
    Body as ResponseBody, Method, Request, Response, Version,
    body::{OnIncompleteBody, util::BodyExt as _},
    proto::h1::ext::ConnectionClose,
};
use rama_net::{
    client::{ConnectionError, ConnectionErrorKind},
    conn::{ConnectionHealthWatcher, MaxConcurrency, is_connection_error},
};
use rama_quic::Connection as QuicConnection;
use rama_utils::guard::DropGuard;
use std::{fmt, io, pin::pin};
use tokio::sync::Mutex;

pub(super) enum SendRequest<Body> {
    Http1(Mutex<http1::SendRequest<Body>>),
    Http2(http2::SendRequest<Body>),
    Http3(http3::SendRequest<Body>),
}

impl<Body: fmt::Debug> fmt::Debug for SendRequest<Body> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("SendRequest");
        match self {
            Self::Http1(send_request) => f.field(send_request).finish(),
            Self::Http2(send_request) => f.field(send_request).finish(),
            Self::Http3(send_request) => f.field(send_request).finish(),
        }
    }
}

/// Internal http sender used to send the actual requests.
pub struct HttpClientService<Body> {
    pub(super) sender: SendRequest<Body>,
    pub(super) extensions: Extensions,
}

impl<Body> Service<Request<Body>> for HttpClientService<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<Body>) -> Result<Self::Output, Self::Error> {
        // Request-target encoding must follow the connection that survived
        // route fallback and pool selection, never the requested ProxyRoute.
        // A fresh snapshot also shadows stale markers when the connection
        // has no established route. Request-side route intent stays intact.
        // Keep this independent of EasyHttpWebClient/HttpForwardProxyLayer:
        // standalone backend callers need the same encoding guarantee.
        req.extensions().insert(Egress(self.extensions.clone()));

        // Check if this http connection can actually be used for this request version
        match (&self.sender, req.version()) {
            (SendRequest::Http1(_), Version::HTTP_10 | Version::HTTP_11)
            | (SendRequest::Http2(_), Version::HTTP_2)
            | (SendRequest::Http3(_), Version::HTTP_3) => (),
            (SendRequest::Http1(_), version) => Err(BoxError::from_static_str(
                "Http1 connector cannot send request with version",
            )
            .context_debug_field("version", version))?,
            (SendRequest::Http3(_), version) => Err(BoxError::from_static_str(
                "Http3 connector cannot send request with version",
            )
            .context_debug_field("version", version))?,
            (SendRequest::Http2(_), version) => Err(BoxError::from_static_str(
                "Http2 connector cannot send request with version",
            )
            .context_debug_field("version", version))?,
        }

        // CONNECT must carry an authority
        if req.method() == Method::CONNECT && req.uri().host().is_none() {
            return Err(BoxError::from_static_str("missing host in CONNECT request"));
        }

        ensure_valid_request_for_version(&mut req)?;

        let resp = match &self.sender {
            SendRequest::Http3(sender) => {
                let mut sender = sender.clone();
                match sender.send_request(req).await {
                    Ok(response) => response,
                    Err(error) => {
                        mark_broken_if_closed(
                            sender.is_closed() || sender.is_draining(),
                            &self.extensions,
                        );
                        return Err(classify_http3_error(error));
                    }
                }
            }
            SendRequest::Http1(sender) => {
                let mut sender = sender.lock().await;
                if let Err(err) = sender.ready().await {
                    // an h1 sender only fails readiness when its connection is gone
                    mark_broken(&self.extensions);
                    tracing::debug!(
                        sender_closed = sender.is_closed(),
                        "http1 upstream sender ready failed: {err}"
                    );
                    return Err(classify_http_error(err));
                }
                // Dropping an in-flight h1 request future closes the shared
                // connection, so mark it broken right here (guard) rather than on
                // the connection task, which a racing pool checkout can beat.
                let extensions = self.extensions.clone();
                let mut cancel_guard = DropGuard::new(move || mark_broken(&extensions));
                let result = sender.send_request(req).await;
                match result {
                    Ok(resp) => {
                        cancel_guard.disarm();
                        resp
                    }
                    Err(err) => {
                        // h1 has no request-level recovery: any send/receive error
                        // leaves the connection mid-message or closed.
                        cancel_guard.fire();
                        tracing::debug!(
                            sender_closed = sender.is_closed(),
                            "http1 upstream send_request failed: {err}"
                        );
                        return Err(classify_http_error(err));
                    }
                }
            }
            SendRequest::Http2(sender) => {
                let mut sender = sender.clone();
                if let Err(err) = sender.ready().await {
                    mark_broken_if_closed(sender.is_closed(), &self.extensions);
                    tracing::debug!(
                        sender_closed = sender.is_closed(),
                        "http2 upstream sender ready failed: {err}"
                    );
                    return Err(classify_http_error(err));
                }
                match sender.send_request(req).await {
                    Ok(resp) => resp,
                    Err(err) => {
                        mark_broken_if_closed(sender.is_closed(), &self.extensions);
                        tracing::debug!(
                            sender_closed = sender.is_closed(),
                            "http2 upstream send_request failed: {err}"
                        );
                        return Err(classify_http_error(err));
                    }
                }
            }
        };

        // Keep classification inside the existing erased body, without an
        // additional allocation or observing successful body frames.
        let resp = resp.map(|body| body.map_err(classify_http_error));

        match &self.sender {
            SendRequest::Http1(_) => {
                // Evict upgraded h1 connections before the response can release its pool lease.
                if resp.extensions().contains::<OnUpgrade>()
                    || resp.extensions().contains::<ConnectionClose>()
                {
                    mark_broken(&self.extensions);
                }
                // An h1 connection is only reusable once its response body is read
                // to end-of-stream: evict it the moment the body is abandoned or
                // errors, before the pool can hand it to the next request.
                let extensions = self.extensions.clone();
                Ok(resp.map(|body| {
                    ResponseBody::new(OnIncompleteBody::new(body, move || {
                        mark_broken(&extensions)
                    }))
                }))
            }
            // h2 recovers per stream: an abandoned body resets only its stream.
            SendRequest::Http2(_) | SendRequest::Http3(_) => Ok(resp.map(ResponseBody::new)),
        }
    }
}

// Preserve the same provenance for response-head and streaming-body failures.
// Classification never authorizes replay of a sent request.
// Bound traversal of application-supplied sources, which can contain cycles.
const MAX_RESPONSE_ERROR_DEPTH: usize = 32;

fn classify_http_error(error: HttpError) -> BoxError {
    if error_chain(&error, MAX_RESPONSE_ERROR_DEPTH).any(|cause| {
        cause
            .downcast_ref::<HttpError>()
            .is_some_and(HttpError::is_user)
    }) {
        return ConnectionError::local(error, ConnectionErrorKind::Other).into_box_error();
    }
    let kind = if error.is_timeout() {
        Some(ConnectionErrorKind::Timeout)
    } else if error.is_parse() {
        Some(ConnectionErrorKind::Protocol)
    } else if error.is_incomplete_message() {
        Some(ConnectionErrorKind::Unavailable)
    } else {
        error_chain(&error, MAX_RESPONSE_ERROR_DEPTH).find_map(|cause| {
            if let Some(error) = cause.downcast_ref::<Http2Error>() {
                // A reset generated by the caller's upload is not evidence
                // that the advertised service is unhealthy.
                return if error.is_remote() {
                    Some(ConnectionErrorKind::Unavailable)
                } else {
                    error.get_io().and_then(remote_io_failure)
                };
            }
            if let Some(error) = cause.downcast_ref::<Http3Error>() {
                return error
                    .is_remote_failure()
                    .then_some(ConnectionErrorKind::Unavailable);
            }
            cause
                .downcast_ref::<io::Error>()
                .and_then(remote_io_failure)
        })
    };
    match kind {
        Some(kind) => ConnectionError::application(error, kind).into_box_error(),
        None => ConnectionError::unknown(error).into_box_error(),
    }
}

fn remote_io_failure(error: &io::Error) -> Option<ConnectionErrorKind> {
    if error.kind() == io::ErrorKind::TimedOut {
        Some(ConnectionErrorKind::Timeout)
    } else if is_connection_error(error) && error.kind() != io::ErrorKind::Interrupted {
        Some(ConnectionErrorKind::Unavailable)
    } else {
        None
    }
}

fn classify_http3_error(error: Http3Error) -> BoxError {
    if error.is_remote_failure() {
        ConnectionError::application(error, ConnectionErrorKind::Unavailable).into_box_error()
    } else {
        ConnectionError::unknown(error).into_box_error()
    }
}

fn mark_broken_if_closed(is_closed: bool, extensions: &Extensions) {
    if is_closed {
        mark_broken(extensions);
    }
}

fn mark_broken(extensions: &Extensions) {
    extensions
        .get_ref_or_insert(ConnectionHealthWatcher::default)
        .mark_broken();
}

impl<B> ExtensionsRef for HttpClientService<B> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<Body> HttpClientService<Body> {
    /// Build an HTTP/3 service on an established QUIC connection and drive its critical streams.
    pub(super) fn http3(
        input: QuicConnection,
        config: Http3Config,
        executor: Executor,
    ) -> Result<Self, Http3Error> {
        let extensions = input.extensions().clone();
        extensions.insert(MaxConcurrency::new(config.max_requests));
        let (sender, driver) = http3::handshake(input, config, executor.clone())?;
        let driver_extensions = extensions.clone();
        let draining = sender.closed_or_draining();
        executor.into_spawn_task(async move {
            let driver = driver.run();
            let mut driver = pin!(driver);
            tokio::select! {
                _ = &mut driver => mark_broken(&driver_extensions),
                _ = draining => {
                    mark_broken(&driver_extensions);
                    _ = driver.await;
                }
            }
        });
        Ok(Self {
            sender: SendRequest::Http3(sender),
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{ServiceInput, bytes::Bytes, futures::stream};
    use rama_http_core::h2::{Reason as Http2Reason, server as http2_server};
    use rama_http_types::{
        Body,
        body::{Frame, util::StreamBody},
    };
    use rama_net::{
        address::ProxyAddress,
        client::{ConnectionErrorDomain, EstablishedProxyRoute, ProxyRoute},
        conn::ConnectionHealth,
    };
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, copy, duplex, sink},
        sync::oneshot,
        time::timeout,
    };

    #[cfg(feature = "tls")]
    use {
        rama_http::header::HOST,
        rama_net::{Protocol, ProtocolInputExt},
        rama_tls::SecureTransport,
    };

    fn is_broken(extensions: &Extensions) -> bool {
        extensions
            .get_ref::<ConnectionHealthWatcher>()
            .is_some_and(|watcher| watcher.health() == ConnectionHealth::Broken)
    }

    fn mark_broken_on_incomplete(body: Body, extensions: &Extensions) -> Body {
        let extensions = extensions.clone();
        Body::new(OnIncompleteBody::new(body, move || {
            mark_broken(&extensions)
        }))
    }

    #[tokio::test]
    async fn http1_sender_replaces_stale_connection_snapshots_before_encoding() {
        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        for route in [
            None,
            Some(EstablishedProxyRoute::Direct),
            Some(EstablishedProxyRoute::Tunnel(proxy.clone())),
            Some(EstablishedProxyRoute::Tunnel(
                "socks5://proxy.example:1080".parse().unwrap(),
            )),
            Some(EstablishedProxyRoute::Forward(proxy.clone())),
        ] {
            let is_forward = route
                .as_ref()
                .is_some_and(EstablishedProxyRoute::is_http_forward);
            let (io, mut peer) = duplex(4096);
            let (sender, connection) = http1::handshake(ServiceInput::new(io)).await.unwrap();
            tokio::spawn(async move {
                drop(connection.await);
            });
            let extensions = Extensions::new();
            if let Some(route) = route.clone() {
                extensions.insert(route);
            }
            let service = HttpClientService {
                sender: SendRequest::Http1(Mutex::new(sender)),
                extensions,
            };
            let request = Request::builder()
                .uri("http://origin.example/resource")
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(ProxyRoute::Proxy(proxy.clone()));
            let stale_route = if is_forward {
                EstablishedProxyRoute::Direct
            } else {
                EstablishedProxyRoute::Forward(proxy.clone())
            };
            request.extensions().insert(stale_route.clone());
            let stale_egress = Extensions::new();
            stale_egress.insert(stale_route);
            request.extensions().insert(Egress(stale_egress));

            let (response, head) = timeout(Duration::from_secs(2), async {
                tokio::join!(service.serve(request), async {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        peer.read_exact(&mut byte).await.unwrap();
                        head.push(byte[0]);
                    }
                    peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                    head
                })
            })
            .await
            .expect("HTTP exchange timed out");
            response.unwrap();
            let expected = if is_forward {
                b"GET http://origin.example/resource HTTP/1.1\r\n".as_slice()
            } else {
                b"GET /resource HTTP/1.1\r\n".as_slice()
            };
            assert!(
                head.starts_with(expected),
                "route: {route:?}, head: {head:?}"
            );
        }
    }

    async fn http1_test_service() -> (HttpClientService<Body>, DuplexStream) {
        let (io, peer) = duplex(4096);
        let (sender, connection) = http1::handshake(ServiceInput::new(io)).await.unwrap();
        tokio::spawn(async move { drop(connection.await) });
        (
            HttpClientService {
                sender: SendRequest::Http1(Mutex::new(sender)),
                extensions: Extensions::new(),
            },
            peer,
        )
    }

    #[tokio::test]
    async fn http1_remote_response_failures_retain_connection_classification() {
        for malformed in [false, true] {
            let (service, mut peer) = http1_test_service().await;
            let peer = tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    peer.read_exact(&mut byte).await.unwrap();
                    head.push(byte[0]);
                }
                if malformed {
                    peer.write_all(b"invalid response\r\n\r\n").await.unwrap();
                }
            });
            let request = Request::builder()
                .uri("http://origin.example/")
                .body(Body::empty())
                .unwrap();
            let error = service.serve(request).await.unwrap_err();
            let classified = error.downcast_ref::<ConnectionError>().unwrap();
            assert_eq!(classified.domain(), ConnectionErrorDomain::Application);
            assert_eq!(
                classified.kind(),
                if malformed {
                    ConnectionErrorKind::Protocol
                } else {
                    ConnectionErrorKind::Unavailable
                }
            );
            assert!(
                error_chain(error.as_ref(), MAX_RESPONSE_ERROR_DEPTH)
                    .any(|error| error.is::<HttpError>())
            );
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn http1_caller_body_failure_does_not_implicate_remote_service() {
        let (service, mut peer) = http1_test_service().await;
        let peer = tokio::spawn(async move {
            drop(copy(&mut peer, &mut sink()).await);
        });
        // Even an application-supplied error carrying remote classification
        // belongs to the caller when produced by its request body.
        let body_error = ConnectionError::application(
            io::Error::from(io::ErrorKind::ConnectionReset),
            ConnectionErrorKind::Unavailable,
        )
        .into_box_error();
        let body = Body::new(StreamBody::new(stream::iter([Err::<Frame<Bytes>, _>(
            body_error,
        )])));
        let request = Request::builder()
            .method(Method::POST)
            .uri("http://origin.example/")
            .body(body)
            .unwrap();
        let error = service.serve(request).await.unwrap_err();
        let classified = error.downcast_ref::<ConnectionError>().unwrap();
        assert_eq!(classified.domain(), ConnectionErrorDomain::Local);
        assert!(is_broken(&service.extensions));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn http2_peer_reset_is_classified_but_caller_body_failure_is_not() {
        for remote_reset in [true, false] {
            let (io, peer) = duplex(4096);
            let peer = tokio::spawn(async move {
                let mut connection = http2_server::handshake(ServiceInput::new(peer))
                    .await
                    .unwrap();
                while let Some(request) = connection.accept().await {
                    if let Ok((_request, mut response)) = request
                        && remote_reset
                    {
                        response.send_reset(Http2Reason::REFUSED_STREAM);
                    }
                }
            });
            let (sender, connection) = http2::handshake(Executor::new(), ServiceInput::new(io))
                .await
                .unwrap();
            let connection = tokio::spawn(async move { drop(connection.await) });
            let service = HttpClientService {
                sender: SendRequest::Http2(sender),
                extensions: Extensions::new(),
            };
            let body = if remote_reset {
                Body::empty()
            } else {
                Body::new(StreamBody::new(stream::iter([Err::<Frame<Bytes>, _>(
                    io::Error::from(io::ErrorKind::ConnectionReset),
                )])))
            };
            let request = Request::builder()
                .method(Method::POST)
                .version(Version::HTTP_2)
                .uri("https://origin.example/")
                .body(body)
                .unwrap();
            let error = timeout(Duration::from_secs(2), service.serve(request))
                .await
                .expect("HTTP/2 failure did not complete")
                .unwrap_err();
            let classified = error.downcast_ref::<ConnectionError>().unwrap();
            if remote_reset {
                assert_eq!(classified.domain(), ConnectionErrorDomain::Application);
                assert_eq!(classified.kind(), ConnectionErrorKind::Unavailable);
            } else {
                assert_ne!(classified.domain(), ConnectionErrorDomain::Application);
                assert_ne!(classified.domain(), ConnectionErrorDomain::Transport);
            }
            peer.abort();
            connection.abort();
        }
    }

    #[tokio::test]
    async fn http1_truncated_response_body_retains_remote_classification() {
        let (service, mut peer) = http1_test_service().await;
        let peer = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                peer.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nx")
                .await
                .unwrap();
        });
        let request = Request::builder()
            .uri("http://origin.example/")
            .body(Body::empty())
            .unwrap();
        let mut response = service.serve(request).await.unwrap();
        let error = timeout(Duration::from_secs(2), async {
            loop {
                if let Err(error) = response.body_mut().frame().await.expect("body truncated") {
                    break error;
                }
            }
        })
        .await
        .expect("response body failure timeout");
        let classified = error.downcast_ref::<ConnectionError>().unwrap();
        assert_eq!(classified.domain(), ConnectionErrorDomain::Application);
        assert_eq!(classified.kind(), ConnectionErrorKind::Unavailable);
        assert!(is_broken(&service.extensions));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn http2_response_body_reset_retains_remote_classification() {
        let (io, peer) = duplex(4096);
        let (reset_tx, reset_rx) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut connection = http2_server::handshake(ServiceInput::new(peer))
                .await
                .unwrap();
            let (_request, mut response) = connection.accept().await.unwrap().unwrap();
            let mut body = response.send_response(Response::new(()), false).unwrap();
            let reset = tokio::spawn(async move {
                reset_rx.await.unwrap();
                body.send_reset(Http2Reason::CANCEL);
            });
            while connection.accept().await.is_some() {}
            reset.abort();
        });
        let (sender, connection) = http2::handshake(Executor::new(), ServiceInput::new(io))
            .await
            .unwrap();
        let connection = tokio::spawn(async move { drop(connection.await) });
        let service = HttpClientService {
            sender: SendRequest::Http2(sender),
            extensions: Extensions::new(),
        };
        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://origin.example/")
            .body(Body::empty())
            .unwrap();
        let mut response = timeout(Duration::from_secs(2), service.serve(request))
            .await
            .expect("response headers timeout")
            .unwrap();
        // The peer resets only after successful response headers were delivered.
        reset_tx.send(()).unwrap();
        let error = timeout(Duration::from_secs(2), response.body_mut().frame())
            .await
            .expect("response body failure timeout")
            .expect("reset body frame")
            .unwrap_err();
        let classified = error.downcast_ref::<ConnectionError>().unwrap();
        assert_eq!(classified.domain(), ConnectionErrorDomain::Application);
        assert_eq!(classified.kind(), ConnectionErrorKind::Unavailable);
        assert!(!is_broken(&service.extensions));
        peer.abort();
        connection.abort();
    }

    #[test]
    fn incomplete_body_marks_broken_on_early_drop() {
        let extensions = Extensions::new();
        drop(mark_broken_on_incomplete(Body::from("hello"), &extensions));
        assert!(is_broken(&extensions));
    }

    #[tokio::test]
    async fn consumed_body_does_not_mark_broken() {
        let extensions = Extensions::new();
        mark_broken_on_incomplete(Body::from("hello"), &extensions)
            .collect()
            .await
            .unwrap();
        assert!(!is_broken(&extensions));
    }

    #[test]
    fn empty_body_does_not_mark_broken_when_never_polled() {
        let extensions = Extensions::new();
        drop(mark_broken_on_incomplete(Body::empty(), &extensions));
        assert!(!is_broken(&extensions));
    }

    // Regression: a forwarded request received over a terminated TLS connection
    // (e.g. a MITM proxy upstream hop) arrives in origin-form with no scheme in
    // the URI. Its protocol MUST resolve to HTTPS via the `SecureTransport`
    // extension so the auto TLS connector secures the upstream hop. This
    // silently regressed to HTTP whenever `rama-http-types/tls` was not enabled
    // alongside `rama-tls`: `input_ext` then matched against a dummy
    // `SecureTransport` type instead of the real one inserted by the TLS
    // acceptor, so the connector went plaintext to a TLS upstream and the
    // upstream's TLS alert surfaced as `Parse(Version)` (http_mitm_proxy_boring).
    #[cfg(feature = "tls")]
    #[test]
    fn origin_form_request_over_terminated_tls_resolves_https() {
        let req = Request::builder()
            .uri("/ping")
            .header(HOST, "example.com:8443")
            .body(())
            .unwrap();
        req.extensions().insert(SecureTransport::default());

        assert_eq!(req.protocol(), Some(&Protocol::HTTPS));
    }
}
