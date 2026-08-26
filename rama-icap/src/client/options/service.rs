use std::{fmt, sync::Arc};

use rama_core::{
    Fork, Service,
    bytes::BytesMut,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsRef,
    io::Io,
};
use rama_net::{
    client::{ConnectRequest, ConnectorService, EstablishedClientConnection},
    uri::{ParseError as UriParseError, Uri},
};
use rama_utils::macros::generate_set_and_with;

use crate::{
    client::ClientConnection,
    codec::{HeaderSlot, ParseError},
    message::Request,
    proto::MethodKind,
};

use super::{OptionsValidation, ServiceCapabilities};

/// Default maximum retained OPTIONS body size.
pub const DEFAULT_MAX_OPTIONS_BODY_BYTES: usize = 64 * 1024;

/// Error constructing an ICAP OPTIONS discovery request.
#[derive(Debug)]
#[non_exhaustive]
pub enum OptionsRequestError {
    /// The supplied message is not an OPTIONS request.
    Method,
    /// The validated owned request head could not be decoded.
    RequestHead(ParseError),
    /// The request target is not a strict service URI.
    ServiceUri(UriParseError),
}

impl fmt::Display for OptionsRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Method => "OPTIONS discovery requires an OPTIONS request",
            Self::RequestHead(_) => "invalid OPTIONS request head",
            Self::ServiceUri(_) => "invalid OPTIONS service URI",
        })
    }
}

impl std::error::Error for OptionsRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Method => None,
            Self::RequestHead(error) => Some(error),
            Self::ServiceUri(error) => Some(error),
        }
    }
}

/// One prebuilt OPTIONS exchange.
#[derive(Clone)]
pub struct OptionsRequest {
    service_uri: Uri,
    connect: ConnectRequest,
    request: Request,
    allow_204_offered: bool,
    allow_206_offered: bool,
    allow_icap_trailers_offered: bool,
    partition: OptionsCachePartition,
}

impl fmt::Debug for OptionsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OptionsRequest")
            .field("service_uri", &self.service_uri)
            .field("authority", &self.connect.authority)
            .field("allow_204_offered", &self.allow_204_offered)
            .field("allow_206_offered", &self.allow_206_offered)
            .field(
                "allow_icap_trailers_offered",
                &self.allow_icap_trailers_offered,
            )
            .field("request_head_len", &self.request.head_bytes().len())
            .field("cache_partition", &self.partition)
            .finish_non_exhaustive()
    }
}

/// Opaque cache identity for one OPTIONS authentication/configuration scope.
///
/// Clones share a partition. Independently constructed values never share
/// cached capabilities, even for the same URI. The HTTP `ServiceEndpoint`
/// retains one partition across its generated discovery requests.
#[derive(Clone, Debug, Default)]
pub struct OptionsCachePartition(Arc<()>);

impl OptionsCachePartition {
    /// Create an isolated cache partition.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return whether two values identify the same cache partition.
    #[must_use]
    pub fn shares_cache_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl OptionsRequest {
    /// Create a discovery request from validated transport and message parts.
    ///
    /// The cache service URI is derived from the encoded request target, so
    /// wire routing and cached capabilities cannot disagree.
    ///
    /// The request starts in a fresh cache partition. Clone this request or
    /// set a stable [`OptionsCachePartition`] when independently constructed
    /// requests should share cached state.
    pub fn new(connect: ConnectRequest, request: Request) -> Result<Self, OptionsRequestError> {
        Self::new_in_partition(connect, request, OptionsCachePartition::new())
    }

    pub(crate) fn new_in_partition(
        connect: ConnectRequest,
        request: Request,
        partition: OptionsCachePartition,
    ) -> Result<Self, OptionsRequestError> {
        if request.method() != MethodKind::Options {
            return Err(OptionsRequestError::Method);
        }
        let service_uri = service_uri_from_request(&request)?;
        let allow_204_offered = request.allows_204();
        let allow_206_offered = request.allows_206();
        let allow_icap_trailers_offered = request.allows_icap_trailers();
        Ok(Self {
            service_uri,
            connect,
            request,
            allow_204_offered,
            allow_206_offered,
            allow_icap_trailers_offered,
            partition,
        })
    }

    generate_set_and_with! {
        /// Set the cache partition for authentication and connector policy.
        pub fn cache_partition(
            mut self,
            partition: OptionsCachePartition,
        ) -> Self {
            self.partition = partition;
            self
        }
    }

    /// Return the exact ICAP service URI used as the cache identity.
    #[must_use]
    pub const fn service_uri(&self) -> &Uri {
        &self.service_uri
    }

    /// Return the transport connection request template.
    ///
    /// A discovery provider must fork this template for each connection
    /// attempt. [`OptionsService`] does so automatically.
    #[must_use]
    pub const fn connect_request(&self) -> &ConnectRequest {
        &self.connect
    }

    /// Return the encoded ICAP OPTIONS request.
    #[must_use]
    pub const fn request(&self) -> &Request {
        &self.request
    }

    pub(super) const fn allow_206_offered(&self) -> bool {
        self.allow_206_offered
    }

    pub(super) const fn allow_204_offered(&self) -> bool {
        self.allow_204_offered
    }

    pub(super) const fn allow_icap_trailers_offered(&self) -> bool {
        self.allow_icap_trailers_offered
    }

    pub(super) const fn cache_partition(&self) -> &OptionsCachePartition {
        &self.partition
    }
}

fn service_uri_from_request(request: &Request) -> Result<Uri, OptionsRequestError> {
    let line_count = request
        .head_bytes()
        .windows(2)
        .filter(|bytes| *bytes == b"\r\n")
        .count();
    let mut slots = vec![HeaderSlot::EMPTY; line_count.saturating_sub(2)];
    let head = request
        .parse_head(&mut slots)
        .map_err(OptionsRequestError::RequestHead)?;
    Uri::parse_strict(head.line().uri().as_str()).map_err(OptionsRequestError::ServiceUri)
}

/// Executes one OPTIONS exchange through an ICAP connector.
#[derive(Clone, Debug)]
pub struct OptionsService<C> {
    client: C,
    max_body_bytes: usize,
    validation: OptionsValidation,
}

impl<C> OptionsService<C> {
    /// Create a discovery service that performs one OPTIONS exchange per call.
    ///
    /// Wrap this service in [`super::OptionsCacheLayer`] to reuse discovered
    /// capabilities. The client is stored as supplied; callers that want
    /// shared ownership can supply an `Arc<C>` themselves.
    pub fn new(client: C) -> Self {
        Self {
            client,
            max_body_bytes: DEFAULT_MAX_OPTIONS_BODY_BYTES,
            validation: OptionsValidation::Compatible,
        }
    }

    generate_set_and_with! {
        /// Set the maximum retained opaque OPTIONS body size.
        pub const fn max_body_bytes(mut self, max_body_bytes: usize) -> Self {
            self.max_body_bytes = max_body_bytes;
            self
        }
    }

    generate_set_and_with! {
        /// Set semantic capability validation.
        pub const fn validation(mut self, validation: OptionsValidation) -> Self {
            self.validation = validation;
            self
        }
    }

    /// Return the ICAP connector.
    #[must_use]
    pub fn client(&self) -> &C {
        &self.client
    }

    /// Return the maximum retained opaque OPTIONS body size.
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Return semantic capability validation.
    #[must_use]
    pub const fn validation(&self) -> OptionsValidation {
        self.validation
    }
}

impl<C, IO> Service<OptionsRequest> for OptionsService<C>
where
    C: ConnectorService<ConnectRequest, Connection = ClientConnection<IO>>,
    IO: Io + Unpin + ExtensionsRef,
{
    type Output = ServiceCapabilities;
    type Error = BoxError;

    async fn serve(&self, input: OptionsRequest) -> Result<Self::Output, Self::Error> {
        let allow_206_offered = input.allow_206_offered();
        let connect = input.connect.fork();
        let request = input.request;
        let EstablishedClientConnection { mut conn, .. } = self
            .client
            .connect(connect)
            .await
            .context("connect to ICAP OPTIONS service")?;
        let max_headers = conn.options().max_headers();
        let transaction = conn
            .start(request)
            .await
            .context("start ICAP OPTIONS transaction")?;
        let mut response = transaction
            .finish()
            .await
            .context("finish ICAP OPTIONS request")?;
        if response.response().status() != crate::proto::StatusCode::OK {
            return Err(BoxError::from_static_str("ICAP OPTIONS request failed")
                .context_field("status", response.response().status().as_u16()));
        }

        let has_opt_body = response
            .response()
            .encapsulated()
            .is_some_and(|parts| parts.has_body());
        let mut body = BytesMut::new();
        while let Some(data) = response
            .next_data()
            .await
            .context("read ICAP OPTIONS body")?
        {
            if body
                .len()
                .checked_add(data.len())
                .is_none_or(|len| len > self.max_body_bytes)
            {
                return Err(BoxError::from_static_str(
                    "ICAP OPTIONS body exceeds configured limit",
                ));
            }
            body.extend_from_slice(&data);
        }
        let response = response
            .into_response()
            .context("complete ICAP OPTIONS response")?;
        drop(conn);
        let body = has_opt_body.then(|| body.freeze());
        ServiceCapabilities::from_options_response(
            response,
            body,
            max_headers,
            allow_206_offered,
            self.validation,
        )
        .map_err(|error| Box::new(error) as BoxError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::convert::Infallible;

    use rama_core::{bytes::Bytes, extensions::Extension, service::service_fn};
    use rama_net::{
        address::HostWithPort,
        test_utils::client::{MockConnectorService, MockSocket},
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::{
        client::Client,
        codec::{Header, RequestLine},
        message::EncapsulatedParts,
        proto::{Method, header},
    };

    fn request() -> OptionsRequest {
        let uri = Uri::parse_strict("icap://icap.test/service").unwrap();
        let uri_text = uri.as_str();
        let request = Request::new(
            RequestLine::new(Method::Options, uri_text.as_ref()).unwrap(),
            &[
                Header::new(header::HOST, b"icap.test").unwrap(),
                Header::new(header::ALLOW, b"206").unwrap(),
            ],
            Some(EncapsulatedParts::null()),
        )
        .unwrap();
        OptionsRequest::new(
            ConnectRequest::new("icap.test:1344".parse::<HostWithPort>().unwrap()),
            request,
        )
        .unwrap()
    }

    #[derive(Extension)]
    struct ProbeSecret;

    struct NonCloneClient;

    impl fmt::Debug for ProbeSecret {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("extension-secret")
        }
    }

    #[test]
    fn stores_the_supplied_client_without_shared_ownership() {
        assert_eq!(OptionsService::new(()).max_body_bytes(), 65_536);
        let service = OptionsService::new(NonCloneClient)
            .with_max_body_bytes(123)
            .with_validation(OptionsValidation::Strict);
        let _client: &NonCloneClient = service.client();
        assert_eq!(service.max_body_bytes(), 123);
        assert_eq!(service.validation(), OptionsValidation::Strict);
    }

    #[test]
    fn discovery_request_rejects_a_non_options_method() {
        let parts = EncapsulatedParts::new(
            Some(Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n")),
            None,
            crate::proto::EncapsulatedKind::NullBody,
        )
        .unwrap();
        let request = Request::new(
            RequestLine::new(Method::Reqmod, "icap://icap.test/service").unwrap(),
            &[Header::new(header::HOST, b"icap.test").unwrap()],
            Some(parts),
        )
        .unwrap();
        let error = OptionsRequest::new(
            ConnectRequest::new("icap.test:1344".parse::<HostWithPort>().unwrap()),
            request,
        )
        .unwrap_err();

        assert!(matches!(error, OptionsRequestError::Method));
        assert_eq!(
            error.to_string(),
            "OPTIONS discovery requires an OPTIONS request"
        );
        let nested = OptionsRequestError::RequestHead(ParseError::InvalidUri);
        assert!(core::error::Error::source(&nested).is_some());
    }

    #[test]
    fn request_derives_its_cache_uri_and_redacts_connection_extensions() {
        let request = request();
        assert_eq!(request.service_uri().as_str(), "icap://icap.test/service");

        let connect = request.connect_request().clone();
        connect.extensions.insert(ProbeSecret);
        let request = OptionsRequest::new(connect, request.request().clone()).unwrap();
        let debug = format!("{request:?}");
        assert!(debug.contains("OptionsRequest"));
        assert!(debug.contains("icap://icap.test/service"));
        assert!(!debug.contains("extension-secret"));
        assert!(!debug.contains("ProbeSecret"));
    }

    async fn read_head(io: &mut MockSocket) -> Vec<u8> {
        let mut head = Vec::new();
        loop {
            let byte = io.read_u8().await.unwrap();
            head.push(byte);
            if head.ends_with(b"\r\n\r\n") {
                return head;
            }
        }
    }

    fn client_for_response(
        response: &'static [u8],
    ) -> Client<impl ConnectorService<ConnectRequest, Connection = MockSocket>> {
        Client::new(
            MockConnectorService::new(move || {
                service_fn(move |mut server: MockSocket| async move {
                    let head = read_head(&mut server).await;
                    assert!(head.starts_with(b"OPTIONS icap://icap.test/service ICAP/1.0\r\n"));
                    assert!(head.windows(12).any(|value| value == b"Allow: 206\r\n"));
                    server.write_all(response).await.unwrap();
                    Ok::<_, Infallible>(())
                })
            })
            .with_max_buffer_size(4096),
        )
    }

    #[tokio::test]
    async fn discovers_and_drains_a_bounded_options_body() {
        let wire = b"ICAP/1.0 200 OK\r\n\
Methods: RESPMOD,\r\n\
\x20REQMOD\r\n\
ISTag: c-icap-tag\r\n\
Preview: 1024\r\n\
Allow: 204, 206\r\n\
Options-TTL: invalid\r\n\
Opt-body-type: opaque\r\n\
Encapsulated: opt-body=0\r\n\r\n\
4\r\ntest\r\n0\r\n\r\n";
        let client = client_for_response(wire);
        let capabilities = OptionsService::new(client)
            .with_max_body_bytes(4)
            .serve(request())
            .await
            .unwrap();

        assert_eq!(
            capabilities.opt_body().map(Bytes::as_ref),
            Some(b"test".as_slice())
        );
        assert_eq!(
            capabilities.preview(),
            Some(crate::proto::Preview::new(1024))
        );
        assert_eq!(
            capabilities.methods().support(MethodKind::Reqmod),
            super::super::MethodSupport::Supported
        );
        assert!(capabilities.allows_206());
        assert_eq!(
            capabilities.cache_lifetime(),
            Some(std::time::Duration::ZERO)
        );
    }

    #[tokio::test]
    async fn strict_semantics_are_an_explicit_subset() {
        let response = b"ICAP/1.0 200 OK\r\n\
Methods: RESPMOD\r\n\
ISTag: unquoted\r\n\r\n";
        OptionsService::new(client_for_response(response))
            .serve(request())
            .await
            .unwrap();
        OptionsService::new(client_for_response(response))
            .with_validation(OptionsValidation::Strict)
            .serve(request())
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn oversized_options_body_fails_before_unbounded_retention() {
        let client = client_for_response(
            b"ICAP/1.0 200 OK\r\n\
Methods: RESPMOD\r\n\
ISTag: \"tag\"\r\n\
Opt-body-type: opaque\r\n\
Encapsulated: opt-body=0\r\n\r\n\
5\r\nlarge\r\n0\r\n\r\n",
        );
        OptionsService::new(client)
            .with_max_body_bytes(4)
            .serve(request())
            .await
            .unwrap_err();
    }
}
