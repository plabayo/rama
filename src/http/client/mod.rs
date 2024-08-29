//! Rama HTTP client module,
//! which provides the [`HttpClient`] type to serve HTTP requests.

use crate::{
    error::BoxError,
    http::{
        dep::http::uri::PathAndQuery,
        header::HOST,
        headers::{self, HeaderMapExt},
        Request, RequestContext, Response, Version,
    },
    net::{address::ProxyAddress, client::EstablishedClientConnection, stream::Stream},
    service::{Context, Layer, Service},
    tcp::client::service::TcpConnector,
    tls::rustls::client::{AutoTlsStream, HttpsConnector},
};
use hyper_util::rt::TokioIo;
use std::fmt;
use tokio::{net::TcpStream, sync::Mutex};

mod error;
#[doc(inline)]
pub use error::HttpClientError;

mod ext;
#[doc(inline)]
pub use ext::{HttpClientExt, IntoUrl, RequestBuilder};

/// An http client that can be used to serve HTTP requests.
///
/// The underlying connections are established using the provided connection [`Service`],
/// which is a [`Service`] that is expected to return as output an [`EstablishedClientConnection`].
pub struct HttpClient<C, S, L> {
    connector: C,
    sender_layer_stack: L,
    _phantom: std::marker::PhantomData<S>,
}

impl<C: fmt::Debug, L: fmt::Debug, S> fmt::Debug for HttpClient<C, S, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("connector", &self.connector)
            .field("sender_layer_stack", &self.sender_layer_stack)
            .finish()
    }
}

impl<C: Clone, L: Clone, S> Clone for HttpClient<C, S, L> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            sender_layer_stack: self.sender_layer_stack.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<C, S> HttpClient<C, S, ()> {
    /// Create a new [`HttpClient`] using the specified connection [`Service`]
    /// to establish connections to the server in the form of an [`EstablishedClientConnection`] as output.
    pub const fn new(connector: C) -> Self {
        Self {
            connector,
            sender_layer_stack: (),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Define an [`Layer`] (stack) to create a [`Service`] stack
    /// through which the http [`Request`] will have to pass
    /// before actually being send of the the "target".
    pub fn layer<L>(self, layer_stack: L) -> HttpClient<C, S, L> {
        HttpClient {
            connector: self.connector,
            sender_layer_stack: layer_stack,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl Default for HttpClient<HttpsConnector<TcpConnector>, AutoTlsStream<TcpStream>, ()> {
    fn default() -> Self {
        Self::new(HttpsConnector::auto(TcpConnector::default()))
    }
}

impl<State, Body, C, S, L> Service<State, Request<Body>> for HttpClient<C, S, L>
where
    State: Send + Sync + 'static,
    Body: http_body::Body + Unpin + Send + 'static,
    Body::Data: Send + 'static,
    Body::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    C: Service<
        State,
        Request<Body>,
        Response = EstablishedClientConnection<S, State, Request<Body>>,
    >,
    C::Error: Into<BoxError>,
    S: Stream + Sync + Unpin,
    L: Layer<HttpRequestSender<Body>> + Send + Sync + 'static,
    L::Service: Service<State, Request<Body>, Response = Response, Error = BoxError>,
{
    type Response = Response;
    type Error = HttpClientError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        // sanitize subject line request uri
        // because Hyper (http) writes the URI as-is
        //
        // Originally reported in and fixed for:
        // <https://github.com/plabayo/rama/issues/250>
        //
        // TODO: fix this in hyper fork (embedded in rama http core)
        // directly instead of here...
        let req = sanitize_client_req_header(&mut ctx, req)?;

        // clone the request uri for error reporting
        let uri = req.uri().clone();

        let EstablishedClientConnection { ctx, req, conn, .. } = self
            .connector
            .serve(ctx, req)
            .await
            .map_err(|err| HttpClientError::from_boxed(err.into()).with_uri(uri.clone()))?;

        let io = TokioIo::new(Box::pin(conn));

        match req.version() {
            Version::HTTP_2 => {
                let executor = ctx.executor().clone();
                let (sender, conn) = hyper::client::conn::http2::handshake(executor, io)
                    .await
                    .map_err(|err| HttpClientError::from_std(err).with_uri(uri.clone()))?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        tracing::debug!("connection failed: {:?}", err);
                    }
                });

                let sender =
                    self.sender_layer_stack
                        .layer(HttpRequestSender(SendRequestService::Http2(Mutex::new(
                            sender,
                        ))));

                sender
                    .serve(ctx, req)
                    .await
                    .map_err(|err: BoxError| HttpClientError::from_boxed(err).with_uri(uri))
            }
            Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
                let (sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(|err| HttpClientError::from_std(err).with_uri(uri.clone()))?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        tracing::debug!("connection failed: {:?}", err);
                    }
                });

                let sender =
                    self.sender_layer_stack
                        .layer(HttpRequestSender(SendRequestService::Http1(Mutex::new(
                            sender,
                        ))));

                sender
                    .serve(ctx, req)
                    .await
                    .map_err(|err| HttpClientError::from_boxed(err).with_uri(uri))
            }
            version => Err(HttpClientError::from_display(format!(
                "unsupported Http version: {:?}",
                version
            ))
            .with_uri(uri)),
        }
    }
}

fn sanitize_client_req_header<S, B>(
    ctx: &mut Context<S>,
    req: Request<B>,
) -> Result<Request<B>, HttpClientError> {
    Ok(match req.method() {
        &http::Method::CONNECT => {
            // CONNECT
            if req.uri().host().is_none() {
                return Err(
                    HttpClientError::from_display("missing host in CONNECT request")
                        .with_uri(req.uri().clone()),
                );
            }
            req
        }
        _ => {
            // GET | HEAD | POST | PUT | DELETE | OPTIONS | TRACE | PATCH
            if !ctx.contains::<ProxyAddress>()
                && req.uri().host().is_some()
                && req.version() <= Version::HTTP_11
            {
                // ensure request context is defined prior to doing this, as otherwise we can get issues
                let _ = ctx
                    .get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into())
                    .map_err(HttpClientError::from_std)?;

                tracing::trace!(
                    "remove authority and scheme from non-connect direct http(~1) request"
                );
                let (mut parts, body) = req.into_parts();
                let mut uri_parts = parts.uri.into_parts();
                uri_parts.scheme = None;
                let authority = uri_parts
                    .authority
                    .take()
                    .expect("to exist due to our host existence test");
                if uri_parts.path_and_query.as_ref().map(|pq| pq.as_str()) == Some("/") {
                    uri_parts.path_and_query = Some(PathAndQuery::from_static("/"));
                }

                if !parts.headers.contains_key(HOST) {
                    parts.headers.typed_insert(headers::Host::from(authority));
                }

                parts.uri =
                    crate::http::Uri::from_parts(uri_parts).map_err(HttpClientError::from_std)?;
                Request::from_parts(parts, body)
            } else {
                req
            }
        }
    })
}

#[derive(Debug)]
// TODO: once we have hyper as `rama::http::core` we can
// drop this mutex as there is no inherint reason for `sender` to be mutable...
enum SendRequestService<B> {
    Http1(Mutex<hyper::client::conn::http1::SendRequest<B>>),
    Http2(Mutex<hyper::client::conn::http2::SendRequest<B>>),
}

#[derive(Debug)]
/// Internal http sender used to send the actual requests.
pub struct HttpRequestSender<B>(SendRequestService<B>);

impl<State, Body> Service<State, Request<Body>> for HttpRequestSender<Body>
where
    State: Send + Sync + 'static,
    Body: http_body::Body + Unpin + Send + 'static,
    Body::Data: Send + 'static,
    Body::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        _ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let resp = match &self.0 {
            SendRequestService::Http1(sender) => sender.lock().await.send_request(req).await,
            SendRequestService::Http2(sender) => sender.lock().await.send_request(req).await,
        }?;
        Ok(resp.map(crate::http::Body::new))
    }
}
