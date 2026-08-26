use std::{borrow::Cow, sync::Arc};

use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
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
        normalize_request_authority, restore_trailer_header, sanitize_adapted_http_headers,
        trailer_header_values,
    },
};
use crate::{
    client::{
        ClientConnection,
        options::{MethodSupport, OptionsRequest, ServiceCapabilities, TransferDisposition},
    },
    http::{
        ClientRequest,
        headers::{restore_proxy_header, sanitize_http_headers},
    },
    message::Response as IcapResponse,
    proto::{Method, header},
};

/// Marker service used when automatic OPTIONS discovery is disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoOptionsDiscovery;

impl Service<OptionsRequest> for NoOptionsDiscovery {
    type Output = Arc<ServiceCapabilities>;
    type Error = BoxError;

    async fn serve(&self, _input: OptionsRequest) -> Result<Self::Output, Self::Error> {
        Err(BoxError::from_static_str(
            "ICAP OPTIONS discovery is disabled",
        ))
    }
}

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
pub struct AdaptationLayer<C, D = NoOptionsDiscovery> {
    client: C,
    options: Option<D>,
    request_service: Option<ServiceEndpoint>,
    response_service: Option<ServiceEndpoint>,
}

impl<C, D> Clone for AdaptationLayer<C, D>
where
    C: Clone,
    D: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            options: self.options.clone(),
            request_service: self.request_service.clone(),
            response_service: self.response_service.clone(),
        }
    }
}

impl<C> AdaptationLayer<C, NoOptionsDiscovery> {
    /// Create a layer using `client` to establish ICAP connections.
    pub fn new(client: C) -> Self {
        Self {
            client,
            options: None,
            request_service: None,
            response_service: None,
        }
    }
}

impl<C, D> AdaptationLayer<C, D> {
    /// Enable automatic OPTIONS discovery through `options`.
    ///
    /// Compose an [`OptionsCacheLayer`](crate::client::options::OptionsCacheLayer)
    /// around an always-fetching service to avoid discovery per request. A
    /// provider may return either an owned capability snapshot or an `Arc`.
    pub fn with_options_service<D2>(self, options: D2) -> AdaptationLayer<C, D2> {
        AdaptationLayer {
            client: self.client,
            options: Some(options),
            request_service: self.request_service,
            response_service: self.response_service,
        }
    }

    /// Return the optional OPTIONS discovery service.
    #[must_use]
    pub fn options_service(&self) -> Option<&D> {
        self.options.as_ref()
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

impl<C, D, S> Layer<S> for AdaptationLayer<C, D>
where
    C: Clone,
    D: Clone,
{
    type Service = Adaptation<S, C, D>;

    fn layer(&self, inner: S) -> Self::Service {
        Adaptation {
            inner,
            client: self.client.clone(),
            options: self.options.clone(),
            request_service: self.request_service.clone(),
            response_service: self.response_service.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        Adaptation {
            inner,
            client: self.client,
            options: self.options,
            request_service: self.request_service,
            response_service: self.response_service,
        }
    }
}

/// HTTP service produced by [`AdaptationLayer`].
#[derive(Debug)]
pub struct Adaptation<S, C, D = NoOptionsDiscovery> {
    inner: S,
    client: C,
    options: Option<D>,
    request_service: Option<ServiceEndpoint>,
    response_service: Option<ServiceEndpoint>,
}

impl<S, C, D> Clone for Adaptation<S, C, D>
where
    S: Clone,
    C: Clone,
    D: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: self.client.clone(),
            options: self.options.clone(),
            request_service: self.request_service.clone(),
            response_service: self.response_service.clone(),
        }
    }
}

impl<S, C, D> Adaptation<S, C, D> {
    define_inner_service_accessors!();

    /// Return the ICAP client connector.
    #[must_use]
    pub fn client(&self) -> &C {
        &self.client
    }

    /// Return the optional OPTIONS discovery service.
    #[must_use]
    pub fn options_service(&self) -> Option<&D> {
        self.options.as_ref()
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

impl<S, C, D, IO, RequestBody, ResponseBody> Service<HttpRequest<RequestBody>>
    for Adaptation<S, C, D>
where
    S: Service<HttpRequest<Body>, Output = HttpResponse<ResponseBody>>,
    S::Error: Into<BoxError>,
    C: ConnectorService<ConnectRequest, Connection = ClientConnection<IO>>,
    D: Service<OptionsRequest>,
    D::Output: Into<Arc<ServiceCapabilities>>,
    D::Error: Into<BoxError>,
    IO: Io + Unpin + ExtensionsRef,
    RequestBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResponseBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = HttpResponse<Body>;
    type Error = BoxError;

    async fn serve(&self, request: HttpRequest<RequestBody>) -> Result<Self::Output, Self::Error> {
        let request = request.map(Body::new);
        let request = if let Some(service) = &self.request_service {
            let capabilities = discover(self.options.as_ref(), service).await?;
            adapt_request(&self.client, service, capabilities, request).await?
        } else {
            ReqmodOutcome::Request(request)
        };
        let (request_head, reqmod, reqmod_capabilities, response) = match request {
            ReqmodOutcome::Request(request) => {
                let request_head = self
                    .response_service
                    .as_ref()
                    .map(|_| HttpRequest::from_parts(request.clone_parts(), ()));
                let reqmod = request.extensions().get_ref::<ReqmodResult>().cloned();
                let capabilities = request.extensions().get_arc::<ServiceCapabilities>();
                let response = self
                    .inner
                    .serve(request)
                    .await
                    .context("serve ICAP-adapted HTTP request")?
                    .map(Body::new);
                (request_head, reqmod, capabilities, response)
            }
            ReqmodOutcome::Response(response) => return Ok(response),
        };
        let response = if let Some(service) = &self.response_service {
            let capabilities = discover(self.options.as_ref(), service).await?;
            adapt_response(
                &self.client,
                service,
                capabilities,
                request_head
                    .as_ref()
                    .context("RESPMOD request metadata disappeared")?,
                response,
            )
            .await?
        } else {
            response
        };
        if response
            .extensions()
            .get_ref::<ServiceCapabilities>()
            .is_none()
            && let Some(capabilities) = reqmod_capabilities
        {
            response.extensions().insert_arc(capabilities);
        }
        if let Some(reqmod) = reqmod {
            response.extensions().insert(reqmod);
        }
        Ok(response)
    }
}

async fn discover<D>(
    options: Option<&D>,
    service: &ServiceEndpoint,
) -> Result<Option<Arc<ServiceCapabilities>>, BoxError>
where
    D: Service<OptionsRequest>,
    D::Output: Into<Arc<ServiceCapabilities>>,
    D::Error: Into<BoxError>,
{
    let Some(options) = options else {
        return Ok(None);
    };
    options
        .serve(service.options_request()?)
        .await
        .map(|capabilities| Some(capabilities.into()))
        .context("discover ICAP service capabilities")
}

#[derive(Clone, Copy)]
pub(super) struct EffectivePolicy {
    pub(super) adapt: bool,
    pub(super) preview: Option<crate::proto::Preview>,
    allow_204: bool,
    allow_206: bool,
    pub(super) allow_icap_trailers: bool,
}

pub(super) fn effective_policy(
    service: &ServiceEndpoint,
    capabilities: Option<&ServiceCapabilities>,
    method: crate::proto::MethodKind,
    extension: &str,
) -> Result<EffectivePolicy, BoxError> {
    let Some(capabilities) = capabilities else {
        return Ok(EffectivePolicy {
            adapt: true,
            preview: service.preview(),
            allow_204: service.allows_204(),
            allow_206: service.allows_206(),
            allow_icap_trailers: service.allows_icap_trailers(),
        });
    };
    match capabilities.methods().support(method) {
        MethodSupport::Supported => {}
        MethodSupport::Unsupported => {
            return Err(BoxError::from_static_str(
                "ICAP service does not advertise the adaptation method",
            ));
        }
        MethodSupport::Unknown => {
            return Err(BoxError::from_static_str(
                "ICAP service returned no usable Methods capability",
            ));
        }
    }
    let disposition = capabilities.transfer_rules().classify(extension);
    Ok(EffectivePolicy {
        adapt: disposition != TransferDisposition::Ignore,
        preview: (disposition == TransferDisposition::Preview)
            .then(|| {
                service
                    .preview()
                    .zip(capabilities.preview())
                    .map(|(local, peer)| local.min(peer))
            })
            .flatten(),
        allow_204: service.allows_204() && capabilities.allows_204(),
        allow_206: service.allows_206() && capabilities.allows_206(),
        allow_icap_trailers: service.allows_icap_trailers() && capabilities.allows_icap_trailers(),
    })
}

enum ReqmodOutcome {
    Request(HttpRequest<Body>),
    Response(HttpResponse<Body>),
}

async fn adapt_request<C, IO>(
    client: &C,
    service: &ServiceEndpoint,
    capabilities: Option<Arc<ServiceCapabilities>>,
    mut request: HttpRequest<Body>,
) -> Result<ReqmodOutcome, BoxError>
where
    C: ConnectorService<ConnectRequest, Connection = ClientConnection<IO>>,
    IO: Io + Unpin + ExtensionsRef,
{
    let policy = effective_policy(
        service,
        capabilities.as_deref(),
        crate::proto::MethodKind::Reqmod,
        request_target_extension(request.uri())
            .as_deref()
            .unwrap_or(""),
    )?;
    if let Some(capabilities) = capabilities {
        request.extensions().insert_arc(capabilities);
    }
    if !policy.adapt {
        return Ok(ReqmodOutcome::Request(request));
    }
    let original_trailers = trailer_header_values(request.headers());
    let forwarded = sanitize_http_headers(request.headers_mut());
    normalize_request_authority(&mut request)?;
    let preview = (!request.body().is_end_stream())
        .then_some(policy.preview)
        .flatten();
    let headers = service.adaptation_headers(
        &forwarded,
        policy.allow_204,
        policy.allow_206,
        policy.allow_icap_trailers,
    )?;
    let request = ClientRequest::reqmod_for_uri(service.uri(), &headers, request, preview)
        .context("build ICAP REQMOD request")?
        .with_replay_limits(service.replay_limits());
    let connect = service
        .connect_request()
        .context("build ICAP REQMOD connection request")?;
    let EstablishedClientConnection { conn, .. } = client
        .connect(connect)
        .await
        .context("connect to ICAP REQMOD service")?;
    let response = conn
        .send_http_owned(request)
        .await
        .context("execute ICAP REQMOD transaction")?;
    validate_success_status(Method::Reqmod, response.icap().status())?;
    let result = ReqmodResult(response.icap().clone());
    if response.request().is_some() {
        let mut request = response
            .into_request()
            .context("decode ICAP REQMOD request result")?;
        let effective_proxy_headers = sanitize_adapted_http_headers(request.headers_mut());
        restore_trailer_header(request.headers_mut(), &original_trailers);
        normalize_request_authority(&mut request)?;
        restore_proxy_header(
            request.headers_mut(),
            &http_header::PROXY_AUTHORIZATION,
            header::PROXY_AUTHORIZATION,
            &forwarded,
            &effective_proxy_headers,
        );
        request.extensions().insert(result);
        Ok(ReqmodOutcome::Request(request))
    } else if response.response().is_some() {
        let mut response = response
            .into_response()
            .context("decode ICAP REQMOD response result")?;
        let effective_proxy_headers = sanitize_adapted_http_headers(response.headers_mut());
        restore_proxy_header(
            response.headers_mut(),
            &http_header::PROXY_AUTHENTICATE,
            header::PROXY_AUTHENTICATE,
            &[],
            &effective_proxy_headers,
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
    capabilities: Option<Arc<ServiceCapabilities>>,
    request: &HttpRequest<()>,
    mut response: HttpResponse<Body>,
) -> Result<HttpResponse<Body>, BoxError>
where
    C: ConnectorService<ConnectRequest, Connection = ClientConnection<IO>>,
    IO: Io + Unpin + ExtensionsRef,
{
    let policy = effective_policy(
        service,
        capabilities.as_deref(),
        crate::proto::MethodKind::Respmod,
        request_target_extension(request.uri())
            .as_deref()
            .unwrap_or(""),
    )?;
    if let Some(capabilities) = capabilities {
        response.extensions().insert_arc(capabilities);
    }
    if !policy.adapt {
        return Ok(response);
    }
    let mut request = HttpRequest::from_parts(request.clone_parts(), ());
    let mut forwarded = sanitize_http_headers(request.headers_mut());
    let original_trailers = trailer_header_values(response.headers());
    normalize_request_authority(&mut request)?;
    let original_response_headers = sanitize_http_headers(response.headers_mut());
    forwarded.extend(original_response_headers.iter().cloned());
    let preview = (!response.body().is_end_stream())
        .then_some(policy.preview)
        .flatten();
    let headers = service.adaptation_headers(
        &forwarded,
        policy.allow_204,
        policy.allow_206,
        policy.allow_icap_trailers,
    )?;
    let request =
        ClientRequest::respmod_for_uri(service.uri(), &headers, &request, response, preview)
            .context("build ICAP RESPMOD request")?
            .with_replay_limits(service.replay_limits());
    let connect = service
        .connect_request()
        .context("build ICAP RESPMOD connection request")?;
    let EstablishedClientConnection { conn, .. } = client
        .connect(connect)
        .await
        .context("connect to ICAP RESPMOD service")?;
    let response = conn
        .send_http_owned(request)
        .await
        .context("execute ICAP RESPMOD transaction")?;
    validate_success_status(Method::Respmod, response.icap().status())?;
    let result = RespmodResult(response.icap().clone());
    let mut response = response
        .into_response()
        .context("decode ICAP RESPMOD result")?;
    let effective_proxy_headers = sanitize_adapted_http_headers(response.headers_mut());
    restore_trailer_header(response.headers_mut(), &original_trailers);
    restore_proxy_header(
        response.headers_mut(),
        &http_header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHENTICATE,
        &original_response_headers,
        &effective_proxy_headers,
    );
    response.extensions().insert(result);
    Ok(response)
}

pub(super) fn request_target_extension(uri: &rama_net::uri::Uri) -> Option<Cow<'_, str>> {
    let segment = uri.last_path_segment()?.as_decoded_str();
    let separator = segment.rfind('.')?;
    Some(match segment {
        Cow::Borrowed(segment) => Cow::Borrowed(&segment[separator + 1..]),
        Cow::Owned(mut segment) => Cow::Owned(segment.split_off(separator + 1)),
    })
}

pub(super) fn validate_success_status(
    method: Method<'static>,
    status: crate::proto::StatusCode,
) -> Result<(), BoxError> {
    let success = match method {
        Method::Reqmod | Method::Respmod => matches!(
            status,
            crate::proto::StatusCode::OK
                | crate::proto::StatusCode::CREATED
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
