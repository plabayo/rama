use super::{
    ConnectIpLimits, ConnectIpRole, ConnectIpScope, ConnectIpSession, ConnectIpSessionConfig,
    ConnectIpTemplate, IpTarget,
};
use rama_core::{
    Service, error::BoxError, extensions::ExtensionsRef as _, futures::StreamExt as _,
    rt::Executor, telemetry::tracing,
};
use rama_dns::client::{
    GlobalDnsResolver,
    resolver::{
        BoundedDnsAddressResolver, DnsAddressResolver, DnsAnswerLimitReached,
        HappyEyeballAddressResolverExt as _,
    },
};
use rama_http::{
    Body, HeaderValue, Request, Response, StatusCode, Version,
    datagram::handshake::capsule_response,
    header,
    headers::{HeaderMapExt as _, ProxyErrorType, ProxyStatus, ProxyStatusEntry},
    io::upgrade::handle_upgrade,
    proto::ext::{HttpDatagrams, Protocol},
};
use rama_net::address::{Host, ip::ipnet::IpNet};
use rama_utils::macros::generate_set_and_with;
use std::{convert::Infallible, fmt, sync::Arc, time::Duration};

/// Input to the admission service, before DNS resolution and HTTP acceptance.
#[derive(Debug)]
pub struct ConnectIpRequest<B = Body> {
    /// The request, including authentication/tenant extensions from prior layers.
    pub request: Request<B>,
    /// Validated scope requested by the client; not yet an authorization decision.
    pub scope: ConnectIpScope,
}

/// A Rama CONNECT-IP proxy service, independent of the platform packet interface.
///
/// `A` authorizes each request and returns local packet permissions/configuration.
/// `H` handles the accepted packet/control session (e.g. an in-memory packet
/// endpoint or an application packet adapter). Authentication can be layered before
/// this service; admission must inspect the resulting request identity.
///
/// The service requires `rama_tls::SecureTransport` from a trusted TLS listener
/// (or HTTP/3, whose transport is intrinsically QUIC). Do not synthesize transport
/// metadata from client headers. A trusted TLS-termination layer may supply this
/// marker after verifying the upstream transport; this is the same metadata
/// contract used by Rama HTTP connection services. Admission and DNS run before the success response;
/// the capacity lease survives until the handler or its task ends.
pub struct ConnectIpService<A, H, R = GlobalDnsResolver, L = ConnectIpLimits> {
    template: ConnectIpTemplate,
    admission: Arc<A>,
    handler: Arc<H>,
    resolver: Arc<R>,
    exec: Executor,
    limits: L,
    open_timeout: Duration,
}

impl<A, H, R: fmt::Debug, L: fmt::Debug> fmt::Debug for ConnectIpService<A, H, R, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectIpService")
            .field("template", &self.template)
            .field("resolver", &self.resolver)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<A, H, R, L: Clone> Clone for ConnectIpService<A, H, R, L> {
    fn clone(&self) -> Self {
        Self {
            template: self.template.clone(),
            admission: self.admission.clone(),
            handler: self.handler.clone(),
            resolver: self.resolver.clone(),
            exec: self.exec.clone(),
            limits: self.limits.clone(),
            open_timeout: self.open_timeout,
        }
    }
}

impl<A, H> ConnectIpService<A, H> {
    /// Create a service with optional admission limits and a ten-second
    /// deadline covering admission, DNS and upgrade. No forwarding policy is implicit.
    pub fn new(template: ConnectIpTemplate, admission: A, handler: H, exec: Executor) -> Self {
        Self {
            template,
            admission: Arc::new(admission),
            handler: Arc::new(handler),
            resolver: Arc::new(GlobalDnsResolver::default()),
            exec,
            limits: ConnectIpLimits::default(),
            open_timeout: Duration::from_secs(10),
        }
    }
}

impl<A, H, R, L> ConnectIpService<A, H, R, L> {
    /// Use shared admission limits, optionally with a custom principal keyer.
    pub fn with_limits<L2>(self, limits: L2) -> ConnectIpService<A, H, R, L2> {
        ConnectIpService {
            template: self.template,
            admission: self.admission,
            handler: self.handler,
            resolver: self.resolver,
            exec: self.exec,
            limits,
            open_timeout: self.open_timeout,
        }
    }

    generate_set_and_with! {
        /// Total opening deadline (zero rejects immediately).
        pub fn open_timeout(mut self, timeout: Duration) -> Self {
            self.open_timeout = timeout;
            self
        }
    }

    /// Use another resolver, e.g. a tenant-aware or deterministic test resolver.
    pub fn with_resolver<R2>(self, resolver: R2) -> ConnectIpService<A, H, R2, L> {
        ConnectIpService {
            template: self.template,
            admission: self.admission,
            handler: self.handler,
            resolver: Arc::new(resolver),
            exec: self.exec,
            limits: self.limits,
            open_timeout: self.open_timeout,
        }
    }
}

impl<A, H, R, L, B> Service<Request<B>> for ConnectIpService<A, H, R, L>
where
    A: Service<ConnectIpRequest<B>, Output = ConnectIpSessionConfig, Error: Into<BoxError>>,
    H: Service<ConnectIpSession, Output = (), Error: Into<BoxError>>,
    R: DnsAddressResolver,
    L: crate::limits::AdmitTunnel<Request<B>>,
    B: Send + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, request: Request<B>) -> Result<Response, Infallible> {
        let version = request.version();
        if version != Version::HTTP_3
            && !request.extensions().contains::<rama_tls::SecureTransport>()
        {
            return Ok(refuse(version, StatusCode::FORBIDDEN));
        }
        let Ok(scope) = self.template.match_request(&request) else {
            return Ok(refuse(version, StatusCode::BAD_REQUEST));
        };
        let Ok(lease) = self.limits.admit(&request) else {
            return Ok(refuse(version, StatusCode::SERVICE_UNAVAILABLE));
        };
        let deadline = crate::time::expiration_at(tokio::time::Instant::now(), self.open_timeout);
        let upgrade = handle_upgrade(&request);
        let extensions = request.extensions().clone();
        let open = async {
            let mut config = self
                .admission
                .serve(ConnectIpRequest {
                    request,
                    scope: scope.clone(),
                })
                .await
                .map_err(|_error| StatusCode::FORBIDDEN)?;
            config.policy.scope_protocol = scope.protocol;
            config.policy.scope_targets = resolve_scope(
                &self.resolver,
                scope.target,
                &extensions,
                &config.policy.receive.destinations,
            )
            .await?;
            config.principal_budget = lease.principal_spend();
            Ok(config)
        };
        let config = match tokio::time::timeout_at(deadline, open).await {
            Ok(Ok(v)) => v,
            Ok(Err(status)) => return Ok(refuse(version, status)),
            Err(_) => return Ok(refuse(version, StatusCode::GATEWAY_TIMEOUT)),
        };
        let Ok(response) = capsule_response::<Body>(version, &Protocol::CONNECT_IP) else {
            return Ok(refuse(version, StatusCode::BAD_REQUEST));
        };
        response.extensions().insert(HttpDatagrams);
        let handler = self.handler.clone();
        self.exec.spawn_cancellable_task(async move {
            let _lease = lease;
            let Ok(Ok(upgraded)) = tokio::time::timeout_at(deadline, upgrade).await else {
                return;
            };
            let Ok(session) = ConnectIpSession::new(upgraded, ConnectIpRole::Server, config) else {
                return;
            };
            tracing::debug!(target: "rama_masque::connect_ip::audit", event = "tunnel_opened");
            let ok = handler.serve(session).await.is_ok();
            tracing::debug!(target: "rama_masque::connect_ip::audit", event = "tunnel_closed", ok);
        });
        Ok(response)
    }
}

fn refuse(version: Version, status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    let error = match status {
        StatusCode::BAD_GATEWAY => ProxyErrorType::DnsError,
        StatusCode::GATEWAY_TIMEOUT => ProxyErrorType::ConnectionTimeout,
        StatusCode::SERVICE_UNAVAILABLE => ProxyErrorType::ConnectionLimitReached,
        StatusCode::FORBIDDEN => ProxyErrorType::DestinationIpProhibited,
        _ => ProxyErrorType::HttpRequestError,
    };
    response
        .headers_mut()
        .typed_insert(ProxyStatus::new(ProxyStatusEntry::error("rama", error)));
    if version == Version::HTTP_11 {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

// Resolution is performed once at admission. The immutable result is passed to
// the packet policy; no per-packet DNS lookup can change the authorized target.
pub(super) async fn resolve_scope<R: DnsAddressResolver>(
    resolver: &Arc<R>,
    target: IpTarget,
    extensions: &rama_core::extensions::Extensions,
    destinations: &[super::IpRoute],
) -> Result<Vec<IpNet>, StatusCode> {
    match target {
        IpTarget::Any => Ok(Vec::new()),
        IpTarget::Prefix(prefix) => Ok(vec![prefix]),
        IpTarget::Hostname(name) => {
            // Bound raw answers before Happy Eyeballs deduplicates them: even a
            // resolver repeatedly yielding the same answer must finish polling.
            let resolver = BoundedDnsAddressResolver::new(
                resolver.clone(),
                const { std::num::NonZeroUsize::new(256).unwrap() },
            );
            let mut addresses = std::pin::pin!(
                resolver
                    .happy_eyeballs_resolver(Host::Name(name))
                    .with_extensions(extensions)
                    .lookup_ip()
            );
            let mut approved = Vec::new();
            let mut count = 0;
            let mut resolved = false;
            while let Some(result) = addresses.next().await {
                count += 1;
                if count > 256 {
                    return Err(StatusCode::BAD_GATEWAY);
                }
                let address = match result {
                    Ok(address) => address,
                    Err(error) => {
                        if error.into_box_error().is::<DnsAnswerLimitReached>() {
                            return Err(StatusCode::BAD_GATEWAY);
                        }
                        continue;
                    }
                };
                resolved = true;
                if destinations.iter().any(|r| r.contains(address)) {
                    let prefix = IpNet::from(address);
                    // Happy Eyeballs already deduplicates canonical IP addresses.
                    approved.push(prefix);
                }
            }
            if approved.is_empty() {
                Err(if resolved {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::BAD_GATEWAY
                })
            } else {
                Ok(approved)
            }
        }
    }
}
