use rama_core::{
    Context, Service,
    context::{self, RequestContextExt},
    error::{BoxError, ErrorContext, OpaqueError},
    inspect::RequestInspector,
    telemetry::tracing,
};
use rama_http::{
    conn::TargetHttpVersion, header::SEC_WEBSOCKET_KEY, utils::RequestSwitchVersionExt,
};
use rama_http_headers::{HeaderMapExt, Host};
use rama_http_types::{
    Method, Request, Response, Version,
    dep::{http::uri::PathAndQuery, http_body},
    header::{CONNECTION, HOST, KEEP_ALIVE, PROXY_CONNECTION, TRANSFER_ENCODING, UPGRADE},
};
use rama_net::{address::ProxyAddress, http::RequestContext};
use std::fmt;
use tokio::sync::Mutex;

pub(super) enum SendRequest<Body> {
    Http1(Mutex<rama_http_core::client::conn::http1::SendRequest<Body>>),
    Http2(rama_http_core::client::conn::http2::SendRequest<Body>),
}

impl<Body: fmt::Debug> fmt::Debug for SendRequest<Body> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("SendRequest");
        match self {
            Self::Http1(send_request) => f.field(send_request).finish(),
            Self::Http2(send_request) => f.field(send_request).finish(),
        }
    }
}

/// Internal http sender used to send the actual requests.
pub struct HttpClientService<Body, I = ()> {
    pub(super) sender: SendRequest<Body>,
    pub(super) http_req_inspector: I,
}

impl<State, BodyIn, BodyOut, I> Service<State, Request<BodyIn>> for HttpClientService<BodyOut, I>
where
    State: Clone + Send + Sync + 'static,
    BodyIn: Send + 'static,
    BodyOut: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    I: RequestInspector<
            State,
            Request<BodyIn>,
            Error: Into<BoxError>,
            RequestOut = Request<BodyOut>,
        >,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        mut req: Request<BodyIn>,
    ) -> Result<Self::Response, Self::Error> {
        // Check if this http connection can actually be used for TargetHttpVersion
        if let Some(target_version) = ctx.get::<TargetHttpVersion>() {
            match (&self.sender, target_version.0) {
                (SendRequest::Http1(_), Version::HTTP_10 | Version::HTTP_11)
                | (SendRequest::Http2(_), Version::HTTP_2) => (),
                (SendRequest::Http1(_), version) => Err(OpaqueError::from_display(format!(
                    "Http1 connector cannot send TargetHttpVersion {version:?}"
                ))
                .into_boxed())?,
                (SendRequest::Http2(_), version) => Err(OpaqueError::from_display(format!(
                    "Http2 connector cannot send TargetHttpVersion {version:?}"
                ))
                .into_boxed())?,
            }
        }

        let original_http_version = req.version();

        match self.sender {
            SendRequest::Http1(_) => match original_http_version {
                Version::HTTP_10 | Version::HTTP_11 => {
                    tracing::trace!(
                        "request version {original_http_version:?} is already h1 compatible, it will remain unchanged",
                    );
                }
                _ => {
                    tracing::debug!(
                        "modify request version {original_http_version:?} to compatible h1 connection version: {:?}",
                        Version::HTTP_11
                    );
                    req.switch_version(Version::HTTP_11)?;
                }
            },
            SendRequest::Http2(_) => {
                if original_http_version == Version::HTTP_2 {
                    tracing::trace!(
                        "request version {original_http_version:?} is already h2 compatible, it will remain unchanged",
                    );
                } else {
                    tracing::debug!(
                        "modify request version {original_http_version:?} to compatible h2 connection version: {:?}",
                        Version::HTTP_2,
                    );
                    req.switch_version(Version::HTTP_2)?;
                }
            }
        }

        let (mut ctx, req) = self
            .http_req_inspector
            .inspect_request(ctx, req)
            .await
            .map_err(Into::into)?;

        // sanitize subject line request uri
        // because Hyper (http) writes the URI as-is
        //
        // Originally reported in and fixed for:
        // <https://github.com/plabayo/rama/issues/250>
        //
        // TODO: fix this in hyper fork (embedded in rama http core)
        // directly instead of here...
        let req = sanitize_client_req_header(&mut ctx, req)?;

        let context::Parts { extensions, .. } = ctx.into_parts();

        let mut resp = match &self.sender {
            SendRequest::Http1(sender) => {
                let mut sender = sender.lock().await;
                sender.ready().await?;
                sender.send_request(req).await
            }
            SendRequest::Http2(sender) => {
                let mut sender = sender.clone();
                sender.ready().await?;
                sender.send_request(req).await
            }
        }?;

        resp.extensions_mut()
            .insert(RequestContextExt::from(extensions));

        let original_resp_http_version = resp.version();
        if original_resp_http_version == original_http_version {
            tracing::trace!(
                "response version {original_http_version:?} matches original http request version, it will remain unchanged",
            );
        } else {
            *resp.version_mut() = original_http_version;
            tracing::trace!(
                "change the response http version {original_http_version:?} into the original http request version {original_resp_http_version:?}",
            );
        }

        Ok(resp.map(rama_http_types::Body::new))
    }
}

fn sanitize_client_req_header<S, B>(
    ctx: &mut Context<S>,
    req: Request<B>,
) -> Result<Request<B>, BoxError> {
    // logic specific to this method
    if req.method() == Method::CONNECT && req.uri().host().is_none() {
        return Err(OpaqueError::from_display("missing host in CONNECT request").into());
    }

    let is_request_proxied = ctx.contains::<ProxyAddress>();
    let request_ctx = ctx
        .get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into())
        .context("fetch request context")?;

    // logic specific to http versions
    Ok(match req.version() {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
            // remove authority and scheme for non-connect requests
            // cfr: <https://datatracker.ietf.org/doc/html/rfc2616#section-5.1.2>
            if !is_request_proxied && req.uri().host().is_some() {
                tracing::trace!(
                    "remove authority and scheme from non-connect direct http(~1) request"
                );
                let (mut parts, body) = req.into_parts();
                let mut uri_parts = parts.uri.into_parts();
                uri_parts.scheme = None;
                uri_parts.authority = None;

                // NOTE: in case the requested resource was the root ("/") it is possible
                // that the path is now empty. Hyper (currently used) has h1 built-in and
                // has a difference between the header encoding and the `as_str` method. The
                // encoding will be empty, which is invalid according to
                // <https://datatracker.ietf.org/doc/html/rfc2616#section-5.1.2> and will fail.
                // As such we force it here to `/` (the path) incase it is empty,
                // as there is no way if this required or no... Sad sad sad...
                //
                // NOTE: once we fork hyper we can just handle it there, as there
                // is no valid reason for that encoding every to be empty... *sigh*
                if uri_parts.path_and_query.as_ref().map(|pq| pq.as_str()) == Some("/") {
                    uri_parts.path_and_query = Some(PathAndQuery::from_static("/"));
                }

                // add required host header if not defined
                if !parts.headers.contains_key(HOST) {
                    if request_ctx.authority_has_default_port() {
                        let host = request_ctx.authority.host().clone();
                        tracing::trace!("add missing host {host} from authority as host header");
                        parts.headers.typed_insert(&Host::from(host));
                    } else {
                        let authority = request_ctx.authority.clone();
                        tracing::trace!("add missing authority {authority} as host header");
                        parts.headers.typed_insert(&Host::from(authority));
                    }
                }

                parts.uri = rama_http_types::Uri::from_parts(uri_parts)?;
                Request::from_parts(parts, body)
            } else if !req.headers().contains_key(HOST) {
                let mut req = req;

                if request_ctx.authority_has_default_port() {
                    let authority = request_ctx.authority.clone();
                    tracing::trace!(
                        url.full = %req.uri(),
                        server.address = %authority.host(),
                        server.port = %authority.port(),
                        "add host from authority as HOST header to req (was missing it)",
                    );
                    req.headers_mut().typed_insert(&Host::from(authority));
                } else {
                    let host = request_ctx.authority.host().clone();
                    tracing::trace!(
                        url.full = %req.uri(),
                        "add {host} as HOST header to req (was missing it)",
                    );
                    req.headers_mut().typed_insert(&Host::from(host));
                }

                req
            } else {
                req
            }
        }
        Version::HTTP_2 => {
            // set scheme/host if not defined as otherwise pseudo
            // headers won't be possible to be set in the h2 crate
            let mut req = if req.uri().host().is_none() {
                let request_ctx = ctx.get::<RequestContext>().ok_or_else(|| {
                    OpaqueError::from_display("[h2+] add scheme/host: missing RequestCtx")
                        .into_boxed()
                })?;

                tracing::trace!(
                    network.protocol.name = "http",
                    network.protocol.version = ?req.version(),
                    "defining authority and scheme to non-connect direct http request"
                );

                let (mut parts, body) = req.into_parts();
                let mut uri_parts = parts.uri.into_parts();
                uri_parts.scheme = Some(
                    request_ctx
                        .protocol
                        .as_str()
                        .try_into()
                        .context("use RequestContext.protocol as http scheme")?,
                );
                // NOTE: in a green future we might not need to stringify
                // this entire thing first... maybe something someone at some
                // point can take a look at this mess

                // Default port is stripped in browsers. It's important that we also do this
                // as some reverse proxies such as nginx respond 404 if authority is not an exact match
                let authority = if request_ctx.authority_has_default_port() {
                    request_ctx.authority.host().to_string()
                } else {
                    request_ctx.authority.to_string()
                };

                uri_parts.authority = Some(
                    authority
                        .try_into()
                        .context("use RequestContext.authority as http authority")?,
                );

                parts.uri = rama_http_types::Uri::from_parts(uri_parts)
                    .context("create http uri from parts")?;

                Request::from_parts(parts, body)
            } else {
                req
            };

            // remove illegal headers
            for illegal_h2_header in [
                &CONNECTION,
                &TRANSFER_ENCODING,
                &PROXY_CONNECTION,
                &UPGRADE,
                &SEC_WEBSOCKET_KEY,
                &KEEP_ALIVE,
                &HOST,
            ] {
                if let Some(header) = req.headers_mut().remove(illegal_h2_header) {
                    tracing::trace!(
                        http.header.name = ?header,
                        "removed illegal (~http1) header from h2 request",
                    );
                }
            }

            req
        }
        Version::HTTP_3 => {
            tracing::debug!(
                url.full = %req.uri(),
                "h3 request detected, but sanitize_client_req_header does not yet support this",
            );
            req
        }
        _ => {
            tracing::debug!(
                url.full = %req.uri(),
                http.method = ?req.method(),
                "request with unknown version detected, sanitize_client_req_header cannot support this",
            );
            req
        }
    })
}
