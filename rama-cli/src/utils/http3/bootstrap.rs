//! A TCP door for HTTP/3-only origins: browsers start over TCP, so it hands out `Alt-Svc`
//! and reloads them onto QUIC; nothing else is served over TCP.

use std::{
    convert::Infallible,
    sync::{Arc, OnceLock},
};

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsRef as _,
    http::{
        HeaderMap, HeaderValue, Request, Response, StatusCode,
        header::{COOKIE, REFRESH, SET_COOKIE},
        headers::{AltSvc, CacheControl, Connection, Cookie, HeaderMapExt as _},
        proto::h3::observation::{
            H3ObservationSnapshot, H3RequestObservation, InsertionFieldMatch,
        },
        protocols::html::*,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    net::{address::SocketAddress, tls::ApplicationProtocol, uri::Uri},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::{boring::server::TlsAcceptorLayer, server::TlsServerConfig},
};

const STYLE_CSS: &str = include_str!("bootstrap.css");

/// Marks a browser that was already sent back once, so a client that keeps
/// using TCP gets an explanation instead of an endless reload.
const COOKIE_NAME: &str = "rama-h3-bootstrap";
/// Query marker on the reload, the loop guard for browsers that refuse the cookie.
const MARKER: &str = "h3-bootstrap";
const COOKIE_SET: &str = "rama-h3-bootstrap=1; Max-Age=60; Path=/; Secure; HttpOnly; SameSite=Lax";
const COOKIE_CLEAR: &str = "rama-h3-bootstrap=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax";

/// Answers every TCP request by advertising `alt_svc` and asking the browser to come back.
#[derive(Debug, Clone)]
pub(crate) struct Http3Bootstrap {
    alt_svc: AltSvc,
}

impl Http3Bootstrap {
    pub(crate) fn new(alt_svc: AltSvc) -> Self {
        Self { alt_svc }
    }

    fn respond(&self, request: &Request) -> Response {
        let retried = request
            .headers()
            .typed_get::<Cookie>()
            .is_some_and(|cookie| cookie.get(COOKIE_NAME).is_some())
            || request.uri().contains_query_name(MARKER);
        let reload = reload_target(request.uri());
        let mut response = if retried {
            page(
                "This browser did not switch to HTTP/3",
                (
                    p!("This origin is served over HTTP/3 (QUIC) only, and your browser kept connecting over TCP."),
                    p!("Your network may block UDP, or the browser may have HTTP/3 disabled. Reload to try again."),
                ),
                None,
            )
            .into_response()
        } else {
            page(
                "Switching to HTTP/3…",
                p!("This origin is served over HTTP/3 (QUIC) only. Your browser is being sent back over HTTP/3."),
                Some(reload.clone()),
            )
            .into_response()
        };
        *response.status_mut() = StatusCode::OK;
        let headers = response.headers_mut();
        headers.typed_insert(self.alt_svc.clone());
        headers.typed_insert(CacheControl::new().with_no_store());
        // The reload must open a new connection, the first one Alt-Svc can apply to.
        headers.typed_insert(Connection::close());
        if retried {
            headers.insert(SET_COOKIE, HeaderValue::from_static(COOKIE_CLEAR));
        } else {
            headers.insert(REFRESH, reload);
            headers.insert(SET_COOKIE, HeaderValue::from_static(COOKIE_SET));
        }
        response
    }
}

/// `Refresh` to the same path with the marker; a query-only reference cannot leave the origin.
fn reload_target(uri: &Uri) -> HeaderValue {
    let mut uri = uri.clone();
    uri.query_mut().remove(MARKER);
    uri.query_mut().push_pair(MARKER, "1");
    HeaderValue::try_from(format!("1; url=?{}", uri.query_or_empty()))
        .unwrap_or_else(|_error| HeaderValue::from_static("1"))
}

/// Keeps the door's cookie and marker out of HTTP/3 handlers and captures, and clears the cookie.
///
/// Without a door in front (`None` bind) requests pass through untouched.
#[derive(Debug, Clone)]
pub(crate) struct Http3BootstrapCleanupLayer {
    door: Option<SocketAddress>,
}

impl Http3BootstrapCleanupLayer {
    pub(crate) fn new(door: Option<SocketAddress>) -> Self {
        Self { door }
    }
}

impl<S> Layer<S> for Http3BootstrapCleanupLayer {
    type Service = Http3BootstrapCleanup<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Http3BootstrapCleanup {
            inner,
            active: self.door.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Http3BootstrapCleanup<S> {
    inner: S,
    active: bool,
}

impl<S, B> Service<Request<B>> for Http3BootstrapCleanup<S>
where
    B: Send + 'static,
    S: Service<Request<B>, Output: IntoResponse>,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, mut request: Request<B>) -> Result<Self::Output, Self::Error> {
        if self.active && request.uri().contains_query_name(MARKER) {
            request.uri_mut().query_mut().remove(MARKER);
        }
        let cookie = self.active && strip_cookie(&mut request);
        let mut response = self.inner.serve(request).await?.into_response();
        if cookie {
            response
                .headers_mut()
                .append(SET_COOKIE, HeaderValue::from_static(COOKIE_CLEAR));
        }
        Ok(response)
    }
}

/// Remove the door's cookie pair; whole field lines leave the H3 observation too.
fn strip_cookie<B>(request: &mut Request<B>) -> bool {
    let carries = |value: &HeaderValue| {
        value
            .as_bytes()
            .split(|byte| *byte == b';')
            .any(|pair| cookie_name(pair) == COOKIE_NAME.as_bytes())
    };
    if !request.headers().get_all(COOKIE).iter().any(carries) {
        return false;
    }
    let original = std::mem::take(request.headers_mut());
    let count = original.len();
    let mut removed = Vec::new();
    let mut headers = HeaderMap::with_capacity(count);
    for (index, (name, value)) in original.into_ordered_iter().enumerate() {
        if name != COOKIE || !carries(&value) {
            headers.append(name, value);
            continue;
        }
        let kept: Vec<&[u8]> = value
            .as_bytes()
            .split(|byte| *byte == b';')
            .filter(|pair| cookie_name(pair) != COOKIE_NAME.as_bytes())
            .map(<[u8]>::trim_ascii)
            .filter(|pair| !pair.is_empty())
            .collect();
        match HeaderValue::from_bytes(&kept.join(&b"; "[..])) {
            Ok(value) if !kept.is_empty() => {
                headers.append(name, value);
            }
            _ => removed.push(index),
        }
    }
    *request.headers_mut() = headers;
    if !removed.is_empty()
        && let Some(observed) = request.extensions().get_ref::<H3RequestObservation>()
        && let Some(observed) = without_fields(observed, count, &removed)
    {
        request.extensions().insert(observed);
    }
    true
}

fn cookie_name(pair: &[u8]) -> &[u8] {
    pair.split(|byte| *byte == b'=')
        .next()
        .unwrap_or_default()
        .trim_ascii()
}

/// The observation without the given regular fields, keeping QPACK insertions aligned.
fn without_fields(
    observed: &H3RequestObservation,
    headers: usize,
    removed: &[usize],
) -> Option<H3RequestObservation> {
    // Regular fields follow the pseudo-headers, one per header map entry.
    let pseudo = observed.fields.len().checked_sub(headers)?;
    let removed: Vec<usize> = removed.iter().map(|index| pseudo + index).collect();
    let mut observed = observed.clone();
    observed.fields = observed
        .fields
        .iter()
        .enumerate()
        .filter(|(index, _field)| !removed.contains(index))
        .map(|(_index, field)| *field)
        .collect();
    let stream_id = observed.stream_id;
    observed.connection = Arc::new(rebind(&observed.connection, stream_id, &removed));
    if let Some(first) = observed.first_request.get() {
        let first = Arc::new(rebind(first, stream_id, &removed));
        observed.first_request = Arc::new(OnceLock::from(first));
    }
    Some(observed)
}

fn rebind(
    snapshot: &H3ObservationSnapshot,
    stream_id: u64,
    removed: &[usize],
) -> H3ObservationSnapshot {
    let mut snapshot = snapshot.clone();
    if let Some(bindings) = snapshot
        .encoder_bindings
        .as_mut()
        .filter(|bindings| bindings.stream_id == stream_id)
    {
        for insertion in &mut bindings.insertions {
            if let InsertionFieldMatch::Unique { field_index } = insertion.field {
                insertion.field = if removed.contains(&field_index) {
                    InsertionFieldMatch::Absent
                } else {
                    InsertionFieldMatch::Unique {
                        field_index: field_index
                            - removed.iter().filter(|index| **index < field_index).count(),
                    }
                };
            }
        }
    }
    snapshot
}

impl Service<Request> for Http3Bootstrap {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
        Ok(self.respond(&request))
    }
}

fn page(
    heading: &'static str,
    notice: impl IntoHtml,
    refresh: Option<HeaderValue>,
) -> impl IntoHtml + IntoResponse {
    let refresh = refresh.and_then(|value| value.to_str().ok().map(str::to_owned));
    html!(
        lang = "en",
        head!(
            meta!(charset = "UTF-8"),
            meta!(
                name = "viewport",
                content = "width=device-width, initial-scale=1.0"
            ),
            refresh.map(|content| meta!("http-equiv" = "refresh", content = content)),
            meta!(name = "robots", content = "none"),
            title!("ラマ | HTTP/3"),
            style!(PreEscaped(STYLE_CSS)),
        ),
        body!(main!(
            h1!(a!(href = "/", "ラマ"), " | ", heading),
            div!(class = "notice", notice),
            p!(
                class = "small",
                "Served by ",
                a!(href = "https://ramaproxy.org", "rama"),
                "."
            ),
        )),
    )
}

/// Serve the bootstrap door on `addr` with `tls`, over HTTP/1.1 so the connection can close.
pub(crate) async fn serve(
    exec: Executor,
    addr: SocketAddress,
    tls: TlsServerConfig,
    alt_svc: AltSvc,
) -> Result<(), BoxError> {
    let listener = TcpListener::build(exec.clone())
        .bind_address(addr)
        .await
        .context("bind HTTP/3 bootstrap TCP listener")?;
    let bound = listener
        .local_addr()
        .context("HTTP/3 bootstrap listener address")?;
    tracing::info!(
        network.local.address = %bound.ip(),
        network.local.port = bound.port(),
        "HTTP/3 bootstrap listening",
    );
    let service = (
        ConsumeErrLayer::trace_as(tracing::Level::DEBUG),
        // Only HTTP/1.1 can close the connection the reload must not reuse.
        TlsAcceptorLayer::new(tls.with_alpn([ApplicationProtocol::HTTP_11].into_iter().collect())),
    )
        .into_layer(HttpServer::new_http1(exec.clone()).service(Http3Bootstrap::new(alt_svc)));
    exec.into_spawn_task(listener.serve(service));
    Ok(())
}

#[cfg(test)]
mod tests {
    use rama::http::{
        Body,
        header::CONNECTION,
        proto::h3::observation::{
            FieldRepresentation, ObservedEncoderBindings, ObservedFieldRepresentation,
            ObservedInsertionBinding,
        },
    };

    use super::*;

    fn bootstrap() -> Http3Bootstrap {
        Http3Bootstrap::new(super::super::alt_svc(443).unwrap())
    }

    #[test]
    fn a_first_visit_advertises_h3_and_reloads_on_a_new_connection() {
        let response = bootstrap().respond(&Request::new(Body::empty()));
        let headers = response.headers();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(headers.typed_get::<AltSvc>().is_some());
        assert_eq!(headers.get(REFRESH).unwrap(), "1; url=?h3-bootstrap=1");
        assert_eq!(headers.get(SET_COOKIE).unwrap(), COOKIE_SET);
        assert_eq!(headers.get(CONNECTION).unwrap(), "close");
    }

    #[test]
    fn the_reload_keeps_the_query_and_stays_on_the_origin() {
        let request = Request::builder()
            .uri("https://example.test//evil.example/?a=1")
            .body(Body::empty())
            .unwrap();
        let response = bootstrap().respond(&request);
        assert_eq!(
            response.headers().get(REFRESH).unwrap(),
            "1; url=?a=1&h3-bootstrap=1"
        );
    }

    #[test]
    fn a_marked_reload_back_over_tcp_without_cookies_gets_the_fallback() {
        let request = Request::builder()
            .uri("https://example.test/report?h3-bootstrap=1")
            .body(Body::empty())
            .unwrap();
        let response = bootstrap().respond(&request);
        assert!(response.headers().get(REFRESH).is_none());
    }

    async fn cleaned(active: bool, request: Request) -> (Request, Response) {
        let seen = Arc::new(parking_lot::Mutex::new(None));
        let inner = {
            let seen = seen.clone();
            rama::service::service_fn(move |request: Request| {
                let seen = seen.clone();
                async move {
                    *seen.lock() = Some(request);
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                }
            })
        };
        let door = active.then(|| SocketAddress::local_ipv4(0));
        let response = Http3BootstrapCleanupLayer::new(door)
            .into_layer(inner)
            .serve(request)
            .await
            .unwrap();
        let request = seen.lock().take().unwrap();
        (request, response)
    }

    #[tokio::test]
    async fn h3_requests_lose_the_marker_and_cookie_pair_and_clear_it() {
        let request = Request::builder()
            .uri("https://example.test/report?h3-bootstrap=1&a=1")
            .header(COOKIE, "other=1; rama-h3-bootstrap=1")
            .body(Body::empty())
            .unwrap();
        let (seen, response) = cleaned(true, request).await;
        assert_eq!(seen.uri().query_or_empty(), "a=1");
        assert_eq!(seen.headers().get(COOKIE).unwrap(), "other=1");
        assert_eq!(response.headers().get(SET_COOKIE).unwrap(), COOKIE_CLEAR);

        let request = Request::builder()
            .uri("https://example.test/report?h3-bootstrap=1")
            .header(COOKIE, "rama-h3-bootstrap=1")
            .body(Body::empty())
            .unwrap();
        let (seen, response) = cleaned(false, request).await;
        assert_eq!(seen.uri().query_or_empty(), "h3-bootstrap=1");
        assert!(seen.headers().contains_key(COOKIE));
        assert!(response.headers().get(SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn a_removed_cookie_line_leaves_the_h3_observation_aligned() {
        let representation = ObservedFieldRepresentation {
            representation: FieldRepresentation::StaticIndex,
            index: Some(1),
            name_huffman: false,
            value_huffman: false,
            never_index: false,
        };
        let marked = ObservedFieldRepresentation {
            index: Some(2),
            ..representation
        };
        let binding = |instruction_index, field_index| ObservedInsertionBinding {
            instruction_index,
            insertion_index: instruction_index as u64,
            field: InsertionFieldMatch::Unique { field_index },
        };
        let snapshot = Arc::new(H3ObservationSnapshot {
            encoder_bindings: Some(ObservedEncoderBindings {
                stream_id: 0,
                insertions: vec![binding(0, 1), binding(1, 2), binding(2, 3)],
                complete: true,
            }),
            ..Default::default()
        });
        let request = Request::builder()
            .uri("https://example.test/")
            .header("accept", "*/*")
            .header(COOKIE, "rama-h3-bootstrap=1")
            .header("user-agent", "fixture")
            .body(Body::empty())
            .unwrap();
        // One pseudo-header, then one field per header map entry.
        request.extensions().insert(H3RequestObservation {
            stream_id: 0,
            connection: snapshot.clone(),
            first_request: Arc::new(OnceLock::from(snapshot)),
            fields: vec![representation, representation, marked, representation],
            fields_complete: true,
            priority: None,
        });
        let (seen, _response) = cleaned(true, request).await;
        assert!(!seen.headers().contains_key(COOKIE));
        let observed = seen.extensions().get_ref::<H3RequestObservation>().unwrap();
        assert_eq!(observed.fields.len(), 3);
        assert!(observed.fields.iter().all(|field| field.index == Some(1)));
        for snapshot in [&observed.connection, observed.first_request.get().unwrap()] {
            let fields: Vec<_> = snapshot
                .encoder_bindings
                .as_ref()
                .unwrap()
                .insertions
                .iter()
                .map(|insertion| insertion.field)
                .collect();
            assert_eq!(
                fields,
                [
                    InsertionFieldMatch::Unique { field_index: 1 },
                    InsertionFieldMatch::Absent,
                    InsertionFieldMatch::Unique { field_index: 2 },
                ]
            );
        }
    }

    #[test]
    fn a_browser_that_returns_over_tcp_gets_no_further_reload() {
        let mut request = Request::new(Body::empty());
        request.headers_mut().insert(
            COOKIE,
            HeaderValue::from_static("other=1; rama-h3-bootstrap=1"),
        );
        let response = bootstrap().respond(&request);
        let headers = response.headers();
        assert!(headers.get(REFRESH).is_none());
        assert_eq!(headers.get(SET_COOKIE).unwrap(), COOKIE_CLEAR);
        assert!(headers.typed_get::<AltSvc>().is_some());
    }
}
