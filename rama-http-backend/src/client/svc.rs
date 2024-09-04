use rama_core::{
    error::{BoxError, OpaqueError},
    Context, Service,
};
use rama_http_types::{
    dep::http::uri::PathAndQuery, dep::http_body, header::HOST, headers::HeaderMapExt,
    Request, Response, Version, Method,
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
    State: Send + Sync + 'static,
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
            SendRequest::Http2(sender) => sender.lock().await.send_request(req).await,
        }?;

        Ok(resp.map(rama_http_types::Body::new))
    }
}

fn sanitize_client_req_header<S, B>(
    ctx: &mut Context<S>,
    req: Request<B>,
) -> Result<Request<B>, BoxError> {
    Ok(match req.method() {
        &Method::CONNECT => {
            // CONNECT
            if req.uri().host().is_none() {
                return Err(OpaqueError::from_display("missing host in CONNECT request").into());
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
                let _ = ctx.get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| {
                    (ctx, &req).try_into()
                })?;

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
                    parts.headers.typed_insert(rama_http_types::headers::Host::from(authority));
                }

                parts.uri = rama_http_types::Uri::from_parts(uri_parts)?;
                Request::from_parts(parts, body)
            } else {
                req
            }
        }
    })
}
