use std::sync::Arc;

use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _, ErrorExt as _},
    extensions::{Extension, ExtensionsRef},
    io::Io,
};
use rama_http_types::{
    Body, Request as HttpRequest, Response as HttpResponse, body::StreamingBody,
    header as http_header,
};
use rama_net::client::{ConnectRequest, ConnectorService, EstablishedClientConnection};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

use super::{
    endpoint::ServiceEndpoint,
    headers::{
        normalize_request_authority, response_proxy_headers, restore_proxy_header,
        restore_trailer_header, sanitize_adapted_http_headers, sanitize_http_headers,
        trailer_header_values,
    },
};
use crate::{
    client::ClientConnection,
    http::ClientRequest,
    message::Response as IcapResponse,
    proto::{Method, header},
};

/// ICAP metadata returned by the REQMOD service.
#[derive(Clone, Debug, Extension)]
pub struct ReqmodResult(IcapResponse);

impl ReqmodResult {
    /// Return the ICAP response metadata.
    #[must_use]
    pub const fn response(&self) -> &IcapResponse {
        &self.0
    }
}

/// ICAP metadata returned by the RESPMOD service.
#[derive(Clone, Debug, Extension)]
pub struct RespmodResult(IcapResponse);

impl RespmodResult {
    /// Return the ICAP response metadata.
    #[must_use]
    pub const fn response(&self) -> &IcapResponse {
        &self.0
    }
}

/// Rama layer that detours HTTP requests and responses through ICAP.
#[derive(Debug)]
pub struct AdaptationLayer<C> {
    client: Arc<C>,
    request_service: Option<ServiceEndpoint>,
    response_service: Option<ServiceEndpoint>,
}

impl<C> Clone for AdaptationLayer<C> {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            request_service: self.request_service.clone(),
            response_service: self.response_service.clone(),
        }
    }
}

impl<C> AdaptationLayer<C> {
    /// Create a layer using `client` to establish ICAP connections.
    pub fn new(client: C) -> Self {
        Self {
            client: Arc::new(client),
            request_service: None,
            response_service: None,
        }
    }

    generate_set_and_with! {
        /// Set the optional REQMOD service.
        pub fn request_service(
            mut self,
            service: Option<ServiceEndpoint>,
        ) -> Self {
            self.request_service = service;
            self
        }
    }

    /// Return the optional REQMOD service.
    #[must_use]
    pub const fn request_service(&self) -> Option<&ServiceEndpoint> {
        self.request_service.as_ref()
    }

    generate_set_and_with! {
        /// Set the optional RESPMOD service.
        ///
        /// This adapts origin responses. Responses returned directly by a
        /// REQMOD service are considered final and bypass RESPMOD.
        pub fn response_service(
            mut self,
            service: Option<ServiceEndpoint>,
        ) -> Self {
            self.response_service = service;
            self
        }
    }

    /// Return the optional RESPMOD service.
    #[must_use]
    pub const fn response_service(&self) -> Option<&ServiceEndpoint> {
        self.response_service.as_ref()
    }
}

impl<C, S> Layer<S> for AdaptationLayer<C> {
    type Service = Adaptation<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        Adaptation {
            inner,
            client: self.client.clone(),
            request_service: self.request_service.clone(),
            response_service: self.response_service.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        Adaptation {
            inner,
            client: self.client,
            request_service: self.request_service,
            response_service: self.response_service,
        }
    }
}

/// HTTP service produced by [`AdaptationLayer`].
#[derive(Debug)]
pub struct Adaptation<S, C> {
    inner: S,
    client: Arc<C>,
    request_service: Option<ServiceEndpoint>,
    response_service: Option<ServiceEndpoint>,
}

impl<S, C> Clone for Adaptation<S, C>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: Arc::clone(&self.client),
            request_service: self.request_service.clone(),
            response_service: self.response_service.clone(),
        }
    }
}

impl<S, C> Adaptation<S, C> {
    define_inner_service_accessors!();

    /// Return the ICAP client connector.
    #[must_use]
    pub fn client(&self) -> &C {
        self.client.as_ref()
    }

    /// Return the optional REQMOD service.
    #[must_use]
    pub const fn request_service(&self) -> Option<&ServiceEndpoint> {
        self.request_service.as_ref()
    }

    /// Return the optional RESPMOD service.
    #[must_use]
    pub const fn response_service(&self) -> Option<&ServiceEndpoint> {
        self.response_service.as_ref()
    }
}

impl<S, C, IO, RequestBody, ResponseBody> Service<HttpRequest<RequestBody>> for Adaptation<S, C>
where
    S: Service<HttpRequest<Body>, Output = HttpResponse<ResponseBody>>,
    S::Error: Into<BoxError>,
    C: ConnectorService<ConnectRequest, Connection = ClientConnection<IO>>,
    IO: Io + Unpin + ExtensionsRef,
    RequestBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResponseBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = HttpResponse<Body>;
    type Error = BoxError;

    async fn serve(&self, request: HttpRequest<RequestBody>) -> Result<Self::Output, Self::Error> {
        let request = request.map(Body::new);
        let request = if let Some(service) = &self.request_service {
            adapt_request(self.client.as_ref(), service, request).await?
        } else {
            ReqmodOutcome::Request(request)
        };
        let (request_head, reqmod, response) = match request {
            ReqmodOutcome::Request(request) => {
                let request_head = self
                    .response_service
                    .as_ref()
                    .map(|_| HttpRequest::from_parts(request.clone_parts(), ()));
                let reqmod = request.extensions().get_ref::<ReqmodResult>().cloned();
                let response = self
                    .inner
                    .serve(request)
                    .await
                    .map_err(|error| error.context("serve ICAP-adapted HTTP request"))?
                    .map(Body::new);
                (request_head, reqmod, response)
            }
            ReqmodOutcome::Response(response) => return Ok(response),
        };
        let response = if let Some(service) = &self.response_service {
            adapt_response(
                self.client.as_ref(),
                service,
                request_head.as_ref().ok_or_else(|| {
                    BoxError::from_static_str("RESPMOD request metadata disappeared")
                })?,
                response,
            )
            .await?
        } else {
            response
        };
        if let Some(reqmod) = reqmod {
            response.extensions().insert(reqmod);
        }
        Ok(response)
    }
}

enum ReqmodOutcome {
    Request(HttpRequest<Body>),
    Response(HttpResponse<Body>),
}

async fn adapt_request<C, IO>(
    client: &C,
    service: &ServiceEndpoint,
    mut request: HttpRequest<Body>,
) -> Result<ReqmodOutcome, BoxError>
where
    C: ConnectorService<ConnectRequest, Connection = ClientConnection<IO>>,
    IO: Io + Unpin + ExtensionsRef,
{
    let original_trailers = trailer_header_values(request.headers());
    let forwarded = sanitize_http_headers(request.headers_mut());
    normalize_request_authority(&mut request)?;
    let preview = (!request.body().is_end_stream())
        .then_some(service.preview())
        .flatten();
    let headers = service.request_headers(&forwarded)?;
    let request = ClientRequest::reqmod_for_uri(
        service.uri(),
        service.host_header(),
        &headers,
        request,
        preview,
    )
    .map_err(|error| error.context("build ICAP REQMOD request"))?
    .with_replay_limits(service.replay_limits());
    let EstablishedClientConnection { conn, .. } = client
        .connect(service.connect_request())
        .await
        .map_err(|error| error.context("connect to ICAP REQMOD service"))?;
    let response = conn
        .send_http_owned(request)
        .await
        .map_err(|error| error.context("execute ICAP REQMOD transaction"))?;
    validate_success_status(Method::Reqmod, response.icap().status())?;
    let returned = response_proxy_headers(response.icap())?;
    let result = ReqmodResult(response.icap().clone());
    if response.request().is_some() {
        let mut request = response
            .into_request()
            .map_err(|error| error.context("decode ICAP REQMOD request result"))?;
        sanitize_adapted_http_headers(request.headers_mut());
        restore_trailer_header(request.headers_mut(), &original_trailers);
        normalize_request_authority(&mut request)?;
        restore_proxy_header(
            request.headers_mut(),
            &http_header::PROXY_AUTHORIZATION,
            header::PROXY_AUTHORIZATION,
            &forwarded,
            &returned,
        );
        request.extensions().insert(result);
        Ok(ReqmodOutcome::Request(request))
    } else if response.response().is_some() {
        let mut response = response
            .into_response()
            .map_err(|error| error.context("decode ICAP REQMOD response result"))?;
        sanitize_adapted_http_headers(response.headers_mut());
        restore_proxy_header(
            response.headers_mut(),
            &http_header::PROXY_AUTHENTICATE,
            header::PROXY_AUTHENTICATE,
            &[],
            &returned,
        );
        response.extensions().insert(result);
        Ok(ReqmodOutcome::Response(response))
    } else {
        Err(BoxError::from_static_str(
            "ICAP REQMOD result has no HTTP request or response",
        ))
    }
}

async fn adapt_response<C, IO>(
    client: &C,
    service: &ServiceEndpoint,
    request: &HttpRequest<()>,
    mut response: HttpResponse<Body>,
) -> Result<HttpResponse<Body>, BoxError>
where
    C: ConnectorService<ConnectRequest, Connection = ClientConnection<IO>>,
    IO: Io + Unpin + ExtensionsRef,
{
    let mut request = HttpRequest::from_parts(request.clone_parts(), ());
    let mut forwarded = sanitize_http_headers(request.headers_mut());
    let original_trailers = trailer_header_values(response.headers());
    normalize_request_authority(&mut request)?;
    let original_response_headers = sanitize_http_headers(response.headers_mut());
    forwarded.extend(original_response_headers.iter().cloned());
    let preview = (!response.body().is_end_stream())
        .then_some(service.preview())
        .flatten();
    let headers = service.request_headers(&forwarded)?;
    let request = ClientRequest::respmod_for_uri(
        service.uri(),
        service.host_header(),
        &headers,
        &request,
        response,
        preview,
    )
    .map_err(|error| error.context("build ICAP RESPMOD request"))?
    .with_replay_limits(service.replay_limits());
    let EstablishedClientConnection { conn, .. } = client
        .connect(service.connect_request())
        .await
        .map_err(|error| error.context("connect to ICAP RESPMOD service"))?;
    let response = conn
        .send_http_owned(request)
        .await
        .map_err(|error| error.context("execute ICAP RESPMOD transaction"))?;
    validate_success_status(Method::Respmod, response.icap().status())?;
    let returned = response_proxy_headers(response.icap())?;
    let result = RespmodResult(response.icap().clone());
    let mut response = response
        .into_response()
        .map_err(|error| error.context("decode ICAP RESPMOD result"))?;
    sanitize_adapted_http_headers(response.headers_mut());
    restore_trailer_header(response.headers_mut(), &original_trailers);
    restore_proxy_header(
        response.headers_mut(),
        &http_header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHENTICATE,
        &original_response_headers,
        &returned,
    );
    response.extensions().insert(result);
    Ok(response)
}

pub(super) fn validate_success_status(
    method: Method<'static>,
    status: crate::proto::StatusCode,
) -> Result<(), BoxError> {
    let success = match method {
        Method::Reqmod | Method::Respmod => matches!(
            status,
            crate::proto::StatusCode::OK
                | crate::proto::StatusCode::NO_MODIFICATION_NEEDED
                | crate::proto::StatusCode::PARTIAL_CONTENT
        ),
        _ => false,
    };
    if success {
        Ok(())
    } else {
        Err(BoxError::from_static_str("ICAP adaptation failed")
            .context_field("method", method.as_str())
            .context_field("status", status.as_u16()))
    }
}
