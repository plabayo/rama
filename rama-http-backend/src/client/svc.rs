use hyper::header::{CONNECTION, TRANSFER_ENCODING, UPGRADE};
use rama_core::{
    error::{BoxError, ErrorContext, OpaqueError},
    Context, Service,
};
use rama_http_types::{
    dep::{http::uri::PathAndQuery, http_body},
    header::{HOST, KEEP_ALIVE, PROXY_CONNECTION},
    headers::HeaderMapExt,
    Method, Request, Response, Version,
};
use rama_net::{address::ProxyAddress, http::RequestContext};
use tokio::sync::Mutex;

#[derive(Debug)]
// TODO: once we have hyper as `rama_core` we can
// drop this mutex as there is no inherint reason for `sender` to be mutable...
pub(super) enum SendRequest<Body> {
    Http1(Mutex<hyper::client::conn::http1::SendRequest<Body>>),
    Http2(Mutex<hyper::client::conn::http2::SendRequest<Body>>),
}

#[derive(Debug)]
/// Internal http sender used to send the actual requests.
pub struct HttpClientService<Body>(pub(super) SendRequest<Body>);

impl<State, Body> Service<State, Request<Body>> for HttpClientService<Body>
where
    State: Clone + Send + Sync + 'static,
    Body: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Response = Response;
    type Error = BoxError;

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

        let resp = match &self.0 {
            SendRequest::Http1(sender) => sender.lock().await.send_request(req).await,
            SendRequest::Http2(sender) => sender.lock().await().send_request(req).await,
        }?;

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

    // logic specific to http versions
    Ok(match req.version() {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
            // remove authority and scheme for non-connect requests
            // cfr: <https://datatracker.ietf.org/doc/html/rfc2616#section-5.1.2>
            if !ctx.contains::<ProxyAddress>() && req.uri().host().is_some() {
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
                    parts
                        .headers
                        .typed_insert(rama_http_types::headers::Host::from(authority));
                }

                parts.uri = rama_http_types::Uri::from_parts(uri_parts)?;
                Request::from_parts(parts, body)
            } else if !req.headers().contains_key(HOST) {
                tracing::trace!(uri = %req.uri(), "add authority as HOST header to req (was missing it)");
                let authority = req
                    .uri()
                    .authority()
                    .ok_or_else(|| {
                        OpaqueError::from_display(
                            "[http1] missing authority in uri and missing host",
                        )
                    })?
                    .clone();
                let mut req = req;
                req.headers_mut()
                    .typed_insert(rama_http_types::headers::Host::from(authority));
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
                    http_version = ?req.version(),
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
                uri_parts.authority = Some(
                    request_ctx
                        .authority
                        .to_string()
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
                &KEEP_ALIVE,
                &HOST,
            ] {
                if let Some(header) = req.headers_mut().remove(illegal_h2_header) {
                    tracing::trace!(?header, "removed illegal (~http1) header from h2 request");
                }
            }

            req
        }
        Version::HTTP_3 => {
            tracing::debug!(
                uri = %req.uri(),
                "h3 request detected, but sanitize_client_req_header does not yet support this",
            );
            req
        }
        _ => {
            tracing::warn!(
                uri = %req.uri(),
                method = ?req.method(),
                "request with unknown version detected, sanitize_client_req_header cannot support this",
            );
            req
        }
    })
}
