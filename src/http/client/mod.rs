//! Rama HTTP client module,
//! which provides the [`HttpClient`] type to serve HTTP requests.

use crate::{
    error::BoxError,
    http::{
        dep::http::uri::PathAndQuery,
        get_request_context,
        header::HOST,
        headers::{self, HeaderMapExt},
        Request, Response, Version,
    },
    net::{address::ProxyAddress, stream::Stream},
    service::{Context, Service},
    tcp::client::service::HttpConnector,
    tls::rustls::client::{AutoTlsStream, HttpsConnector},
};
use hyper_util::rt::TokioIo;
use std::fmt;
use tokio::net::TcpStream;

mod error;
#[doc(inline)]
pub use error::HttpClientError;

mod ext;
#[doc(inline)]
pub use ext::{HttpClientExt, IntoUrl, RequestBuilder};

mod conn;
#[doc(inline)]
pub use conn::{ClientConnection, EstablishedClientConnection};

/// An http client that can be used to serve HTTP requests.
///
/// The underlying connections are established using the provided connection [`Service`],
/// which is a [`Service`] that is expected to return as output an [`EstablishedClientConnection`].
pub struct HttpClient<C, S> {
    connector: C,
    _phantom: std::marker::PhantomData<S>,
}

impl<C: fmt::Debug, S> fmt::Debug for HttpClient<C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("connector", &self.connector)
            .finish()
    }
}

impl<C: Clone, S> Clone for HttpClient<C, S> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<C, S> HttpClient<C, S> {
    /// Create a new [`HttpClient`] using the specified connection [`Service`]
    /// to establish connections to the server in the form of an [`EstablishedClientConnection`] as output.
    pub fn new(connector: C) -> Self {
        Self {
            connector,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl Default for HttpClient<HttpsConnector<HttpConnector>, AutoTlsStream<TcpStream>> {
    fn default() -> Self {
        Self {
            connector: HttpsConnector::auto(HttpConnector::default()),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<State, Body, C, S> Service<State, Request<Body>> for HttpClient<C, S>
where
    State: Send + Sync + 'static,
    Body: http_body::Body + Unpin + Send + 'static,
    Body::Data: Send + 'static,
    Body::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    C: Service<State, Request<Body>, Response = EstablishedClientConnection<S, Body, State>>,
    C::Error: Into<BoxError>,
    S: Stream + Unpin,
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

        let EstablishedClientConnection { ctx, req, conn } =
            self.connector
                .serve(ctx, req)
                .await
                .map_err(|err| HttpClientError::from_boxed(err.into()).with_uri(uri.clone()))?;

        let io = TokioIo::new(Box::pin(conn));

        let resp = match req.version() {
            Version::HTTP_2 => {
                let executor = ctx.executor().clone();
                let (mut sender, conn) = hyper::client::conn::http2::handshake(executor, io)
                    .await
                    .map_err(|err| HttpClientError::from_std(err).with_uri(uri.clone()))?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        tracing::debug!("connection failed: {:?}", err);
                    }
                });

                sender
                    .send_request(req)
                    .await
                    .map_err(|err: hyper::Error| HttpClientError::from_std(err).with_uri(uri))?
            }
            Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(|err| HttpClientError::from_std(err).with_uri(uri.clone()))?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        tracing::debug!("connection failed: {:?}", err);
                    }
                });

                sender
                    .send_request(req)
                    .await
                    .map_err(|err| HttpClientError::from_std(err).with_uri(uri))?
            }
            version => {
                return Err(HttpClientError::from_display(format!(
                    "unsupported Http version: {:?}",
                    version
                ))
                .with_uri(uri));
            }
        };

        let resp = resp.map(crate::http::Body::new);
        Ok(resp)
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
            if !ctx.contains::<ProxyAddress>() && req.uri().host().is_some() {
                // ensure request context is defined prior to doing this, as otherwise we can get issues
                let _ = get_request_context!(*ctx, req);

                tracing::trace!("remove authority and scheme from non-connect direct http request");
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
