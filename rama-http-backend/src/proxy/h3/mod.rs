//! HTTP/3 MITM relay over an established ingress/egress QUIC connection pair.

use std::{convert::Infallible, pin::pin, sync::Arc, time::Duration};

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, ExtensionsRef as _, Ingress},
    futures::{StreamExt as _, stream::FuturesUnordered},
    io::BridgeIo,
    layer::{ArcLayer, ConsumeErrLayer},
    matcher::Matcher,
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
};
use rama_http::{
    Body, Method, Request, Response,
    datagram::HttpDatagramRelay,
    header::trailer::ForbiddenTrailers,
    io::upgrade::handle_upgrade,
    layer::{
        remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
        upgrade::mitm::HttpUpgradeMitmRelayExtensions,
        validate_request::{BoundAuthority, ValidateRequest as _, ValidateRequestHeaderLayer},
    },
    proto::ext::HttpDatagrams,
};
use rama_http_core::{
    h3::{Error, PriorityHandle, client, connection::Config, qpack::ErrorScope, server},
    service::RamaHttpService,
};
use rama_http_types::proto::h3::{Code, SettingId, Settings};
use rama_net::proxy::IoForwardService;
use rama_quic::Connection;
use rama_quic_proto::{Side, VarInt};
use rama_utils::guard::DropGuard;
use tokio::time::Instant;

use super::mitm::{DEFAULT_EAGER_PEER_SETTINGS_TIMEOUT, DefaultErrorResponse, DefaultMiddleware};
use crate::client::SendAttempts;

mod egress;
pub use egress::Http3EgressService;
use egress::forward_priority;

#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(http))]
struct Rejected;

/// Relays HTTP/3 between a server connection (ingress) and a client connection (egress) that
/// were established and authenticated before: the HTTP/3 counterpart of
/// [`HttpMitmRelay`](super::mitm::HttpMitmRelay).
///
/// Requests pass through the same HTTP middleware model: hop-by-hop fields are consumed at the
/// boundary and [`Self::with_bound_authority`] checks every request before and after the
/// middleware. Each hop keeps its own QPACK state; egress SETTINGS arrive before
/// the ingress side advertises its own, so Extended CONNECT is offered only when the origin
/// supports it, and ingress field sections are bounded by the origin's limit. Priorities follow
/// each request upstream, CONNECT and Extended CONNECT tunnels are bridged until both
/// directions finish, and middleware selects Capsule/HTTP Datagram semantics with
/// [`HttpDatagrams`]. GOAWAY from either side drains the relay.
///
/// Both connections must have early data disabled; server push is not supported. A relay that
/// fails, or whose serve future is dropped (even before it is first polled), closes both
/// connections with `H3_INTERNAL_ERROR`.
#[derive(Debug, Clone)]
pub struct Http3MitmRelay<M = DefaultMiddleware, P = bool> {
    middleware: M,
    authority: Option<BoundAuthority<P>>,
    exec: Executor,
    ingress: Config,
    egress: Config,
    settings_timeout: Duration,
    mirror_client_settings: bool,
    mirror_server_settings: bool,
    forbidden_trailers: ForbiddenTrailers,
}

impl Http3MitmRelay {
    /// Create a relay with default per-hop configurations; ingress offers Extended CONNECT
    /// whenever the origin does.
    #[must_use]
    pub fn new(exec: Executor) -> Self {
        let ingress = Config {
            extended_connect: true,
            ..Default::default()
        };
        Self {
            middleware: (
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
                ArcLayer::new(),
            ),
            authority: None,
            exec,
            ingress,
            egress: Config::default(),
            settings_timeout: DEFAULT_EAGER_PEER_SETTINGS_TIMEOUT,
            mirror_client_settings: false,
            mirror_server_settings: false,
            forbidden_trailers: ForbiddenTrailers::AllowAll,
        }
    }
}

impl<M, P> Http3MitmRelay<M, P> {
    /// Bind the relayed connection to its trusted logical origin and policy.
    ///
    /// Mismatches return 421 without opening an upstream request stream.
    pub fn with_bound_authority<Q>(self, authority: BoundAuthority<Q>) -> Http3MitmRelay<M, Q> {
        Http3MitmRelay {
            middleware: self.middleware,
            authority: Some(authority),
            exec: self.exec,
            ingress: self.ingress,
            egress: self.egress,
            settings_timeout: self.settings_timeout,
            mirror_client_settings: self.mirror_client_settings,
            mirror_server_settings: self.mirror_server_settings,
            forbidden_trailers: self.forbidden_trailers,
        }
    }

    /// Set the HTTP middleware between the ingress server and the egress client.
    pub fn with_http_middleware<N>(self, middleware: N) -> Http3MitmRelay<N, P> {
        Http3MitmRelay {
            middleware,
            authority: self.authority,
            exec: self.exec,
            ingress: self.ingress,
            egress: self.egress,
            settings_timeout: self.settings_timeout,
            mirror_client_settings: self.mirror_client_settings,
            mirror_server_settings: self.mirror_server_settings,
            forbidden_trailers: self.forbidden_trailers,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// HTTP/3 settings of the ingress (server) side.
        pub fn ingress_config(mut self, config: Config) -> Self {
            self.ingress = config;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// HTTP/3 settings of the egress (client) side.
        pub fn egress_config(mut self, config: Config) -> Self {
            self.egress = config;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Preserve the client's initial ordered SETTINGS on the origin connection.
        ///
        /// Disabled by default. Values must fit the existing egress configuration
        /// and transport capabilities; no budget is increased. Unsupported client
        /// extension settings and conflicting literal egress settings fail before
        /// local HTTP/3 output. Compression state remains independent per hop.
        pub fn mirror_client_settings(mut self, enabled: bool) -> Self {
            self.mirror_client_settings = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Preserve known initial origin SETTINGS on the client-facing connection.
        ///
        /// Disabled by default. Values and capability grants must fit the explicit
        /// ingress configuration and both native transports. Unknown origin settings
        /// remain ignored and are not advertised. QPACK state stays independent.
        pub fn mirror_server_settings(mut self, enabled: bool) -> Self {
            self.mirror_server_settings = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// How long both QUIC handshakes, optional client SETTINGS readiness and
        /// the origin's SETTINGS may take, counted from the
        /// moment `serve` is called. Defaults to [`DEFAULT_EAGER_PEER_SETTINGS_TIMEOUT`].
        pub fn settings_timeout(mut self, timeout: Duration) -> Self {
            self.settings_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Which trailer fields are forwarded although their definitions forbid them in
        /// trailers. Defaults to [`ForbiddenTrailers::AllowAll`].
        pub fn forbidden_trailers(mut self, forbidden_trailers: ForbiddenTrailers) -> Self {
            self.forbidden_trailers = forbidden_trailers;
            self
        }
    }
}

impl<M, P> Service<BridgeIo<Connection, Connection>> for Http3MitmRelay<M, P>
where
    (
        RemoveRequestHeaderLayer,
        M,
        RemoveResponseHeaderLayer,
        ValidateRequestHeaderLayer<Option<BoundAuthority<P>>>,
    ): Layer<
            Http3EgressService,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        > + Clone,
    M: Send + Sync + 'static + Clone,
    P: Matcher<Request> + Clone,
{
    type Output = ();
    type Error = BoxError;

    fn serve(
        &self,
        BridgeIo(ingress, egress): BridgeIo<Connection, Connection>,
    ) -> impl Future<Output = Result<(), BoxError>> + Send + '_ {
        // Guards and the deadline are taken now, so a future dropped or first polled late
        // still closes both hops and cannot renew the readiness budget.
        let settings_deadline = Instant::now() + self.settings_timeout;
        let close_ingress = ingress.clone();
        let close_egress = egress.clone();
        let mut guard = DropGuard::new(move || {
            close_ended(&close_ingress);
            close_ended(&close_egress);
        });
        async move {
            let result = self
                .run(ingress.clone(), egress.clone(), settings_deadline)
                .await;
            if result.is_ok() {
                guard.disarm();
                let code = VarInt::from_u32(Code::H3_NO_ERROR.value() as u32);
                ingress.close(code, b"relay drained");
                egress.close(code, b"relay drained");
            }
            result
        }
    }
}

impl<M, P> Http3MitmRelay<M, P>
where
    (
        RemoveRequestHeaderLayer,
        M,
        RemoveResponseHeaderLayer,
        ValidateRequestHeaderLayer<Option<BoundAuthority<P>>>,
    ): Layer<
            Http3EgressService,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        > + Clone,
    M: Send + Sync + 'static + Clone,
    P: Matcher<Request> + Clone,
{
    async fn run(
        &self,
        ingress: Connection,
        egress: Connection,
        settings_deadline: Instant,
    ) -> Result<(), BoxError> {
        let mut ingress_config = self.ingress.clone();
        let mut egress_config = self.egress.clone();
        if ingress.side() != Side::Server || egress.side() != Side::Client {
            return Err(BoxError::from_static_str(
                "HTTP/3 relay requires server ingress and client egress",
            ));
        }
        tokio::time::timeout_at(settings_deadline, async {
            tokio::try_join!(ingress.handshake_confirmed(), egress.handshake_confirmed())
        })
        .await??;
        if ingress.early_data_keys_enabled() || egress.early_data_keys_enabled() {
            return Err(BoxError::from_static_str(
                "HTTP/3 relay requires early data disabled",
            ));
        }

        // QPACK and HTTP Datagram capability negotiation remain independent per
        // hop. Literal startup profiles and push need their own preservation path.
        if (ingress_config.settings_profile.is_some() && !self.mirror_server_settings)
            || ingress_config.max_pushes != 0
            || egress_config.max_pushes != 0
        {
            return Err(BoxError::from_static_str(
                "HTTP/3 relay configuration requests unsupported relay capabilities",
            ));
        }
        let received = if self.mirror_client_settings {
            let received = tokio::time::timeout_at(
                settings_deadline,
                Box::pin(server::receive_settings(ingress.clone(), &ingress_config)),
            )
            .await??;
            let settings = received.peer_settings();
            if settings
                .entries()
                .iter()
                .any(|setting| !relay_setting_supported(setting.id) && !setting.id.is_reserved())
            {
                return Err(BoxError::from_static_str(
                    "HTTP/3 relay cannot mirror unsupported client SETTINGS semantics",
                ));
            }
            if egress_config
                .settings_profile
                .as_deref()
                .is_some_and(|selected| selected != settings)
            {
                return Err(BoxError::from_static_str(
                    "HTTP/3 relay client SETTINGS conflict with the egress configuration",
                ));
            }
            egress_config = egress_config.try_with_client_settings(Arc::new(settings.clone()))?;
            Some(received)
        } else {
            None
        };
        let egress_datagrams = self.mirror_server_settings
            && egress_config.datagrams.is_some()
            && egress.datagram_receive_enabled()
            && egress.max_datagram_size().is_some();
        let ingress_extensions = ingress.extensions().clone();
        let egress_extensions = egress.extensions().clone();
        let close_egress = egress.clone();
        let (sender, driver) = client::handshake::<Body>(egress, egress_config, self.exec.clone())?;
        // Holding a sender keeps the client's clean release from closing egress before this does.
        let held = sender.clone();
        let mut egress_guard = DropGuard::new(move || {
            close_ended(&close_egress);
            drop(held);
        });
        self.exec.clone().into_spawn_task(async move {
            let _driver_result = driver.run().await;
        });
        let peer = tokio::time::timeout_at(settings_deadline, sender.peer_settings()).await??;
        // Unknown peer SETTINGS are ignored (RFC 9114 §7.2.4) and never advertised downstream.

        if self.mirror_server_settings {
            if peer.h3_datagram()
                && (!egress_datagrams
                    || !ingress.datagram_receive_enabled()
                    || ingress.max_datagram_size().is_none())
            {
                return Err(BoxError::from_static_str(
                    "HTTP/3 relay server SETTINGS require datagrams on both native hops",
                ));
            }
            let mut settings = Settings::new();
            for setting in peer.entries() {
                if relay_setting_supported(setting.id) {
                    settings.insert(*setting)?;
                }
            }
            if ingress_config
                .settings_profile
                .as_deref()
                .is_some_and(|selected| selected != &settings)
            {
                return Err(BoxError::from_static_str(
                    "HTTP/3 relay server SETTINGS conflict with the ingress configuration",
                ));
            }
            ingress_config = ingress_config.try_with_server_settings(Arc::new(settings))?;
        } else {
            // Bound ingress input without copying the origin's QPACK state.
            if let Some(limit) = peer.max_field_section_size() {
                ingress_config.decoder.max_field_section_size = ingress_config
                    .decoder
                    .max_field_section_size
                    .min(usize::try_from(limit).unwrap_or(usize::MAX));
            }
            // Plain CONNECT does not depend on this SETTINGS value.
            ingress_config.extended_connect &= peer.enable_connect_protocol();
        }
        let upstream_draining = sender.closed_or_draining();
        let upstream_draining = pin!(upstream_draining);
        let client = (
            RemoveRequestHeaderLayer::hop_by_hop(),
            self.middleware.clone(),
            RemoveResponseHeaderLayer::hop_by_hop(),
            ValidateRequestHeaderLayer::custom(self.authority.clone()),
        )
            .layer(Http3EgressService::new(sender, egress_extensions));
        let authority = self.authority.clone();
        let trailers = self.forbidden_trailers.clone();
        let service = RamaHttpService::new(service_fn(move |request: Request| {
            let client = client.clone();
            let authority = authority.clone();
            let trailers = trailers.clone();
            async move {
                let request = match authority.validate(request).await {
                    Ok(request) => request,
                    Err(response) => return Ok::<_, Infallible>(response),
                };
                request.extensions().insert(trailers);
                let attempts = request
                    .extensions()
                    .insert_arc(Arc::new(SendAttempts::default()));
                let result = client.serve(request).await;
                let response = if attempts.none_processed() {
                    let response: Response = DefaultErrorResponse::new().into();
                    response.extensions().insert(Rejected);
                    response
                } else {
                    match result {
                        Ok(response) => response,
                        Err(error) => {
                            let error: BoxError = error.into();
                            tracing::debug!(%error, "HTTP/3 relay egress request failed");
                            DefaultErrorResponse::new().into()
                        }
                    }
                };
                Ok(response)
            }
        }));

        // Egress SETTINGS are known before the ingress driver can emit any.
        let close_ingress = ingress.clone();
        // The same deadline covers readiness through final native state transfer.
        if Instant::now() >= settings_deadline {
            return Err(BoxError::from_static_str(
                "HTTP/3 relay SETTINGS deadline elapsed",
            ));
        }
        let (mut connection, driver) = if let Some(received) = received {
            received.into_connection(ingress_config)?
        } else {
            server::handshake(ingress, ingress_config)?
        };
        let mut driver = pin!(driver.run());
        // Declared after the server state, so it closes ingress before that state's clean stop.
        let mut ingress_guard = DropGuard::new(move || close_ended(&close_ingress));
        if Instant::now() >= settings_deadline {
            return Err(BoxError::from_static_str(
                "HTTP/3 relay SETTINGS deadline elapsed during finalization",
            ));
        }
        let mut upstream_draining = upstream_draining;
        let cancelled = async {
            match self.exec.guard() {
                Some(guard) => guard.cancelled().await,
                None => std::future::pending().await,
            }
        };
        let mut cancelled = pin!(cancelled);
        let forwarding = IoForwardService::new(self.exec.clone());
        let mut requests = FuturesUnordered::new();
        let mut draining = false;
        // The exchange borrows the HTTP/3 state, so the guards see its outcome while it lives.
        let result = async {
            loop {
                tokio::select! {
                    result = &mut driver => return completed(result),
                    _ = &mut cancelled, if !draining => {
                        connection.shutdown()?;
                        draining = true;
                    }
                    _ = &mut upstream_draining, if !draining => {
                        connection.shutdown()?;
                        draining = true;
                    }
                    accepted = connection.accept(), if !draining => {
                        let stream = match accepted {
                            Ok(stream) => stream,
                            Err(error) => return completed(Err(error)),
                        };
                        let service = service.clone();
                        let extensions = ingress_extensions.clone();
                        let forwarding = forwarding.clone();
                        requests.push(async move {
                            let (request, response) = stream.resolve().await?;
                            request.extensions().insert(Ingress(extensions));
                            let mut priority = response.peer_priority();
                            request.extensions().insert(priority.clone());
                            let ingress_upgrade = (request.method() == Method::CONNECT)
                                .then(|| handle_upgrade(&request));
                            let ingress_tunnel_extensions = ingress_upgrade.as_ref().and_then(|_| {
                                request.extensions()
                                    .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
                                    .cloned()
                            });
                            let output = match service.serve(request).await {
                                Ok(output) => output,
                                Err(never) => match never {},
                            };
                            if output.extensions().contains::<Rejected>() {
                                return response.reset(Code::H3_REQUEST_REJECTED);
                            }
                            let upstream_priority = output.extensions().get_arc::<PriorityHandle>();
                            let exchange = async move {
                                let upgrade = ingress_upgrade.filter(|_| output.status().is_success());
                                let egress_upgrade = upgrade.as_ref().map(|_| handle_upgrade(&output));
                                // Only explicit middleware protocol ownership selects
                                // Capsule semantics. A CONNECT token alone is insufficient.
                                let datagrams = upgrade.is_some()
                                    && output.extensions().contains::<HttpDatagrams>();
                                let egress_extensions = output
                                    .extensions()
                                    .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
                                    .cloned();
                                response.send_response(output).await?;
                                if let (Some(ingress), Some(egress)) = (upgrade, egress_upgrade) {
                                    let (ingress, egress) = tokio::try_join!(ingress, egress)
                                        .map_err(|error| {
                                            tracing::debug!(%error, "HTTP/3 relay tunnel upgrade failed");
                                            Error::stream(Code::H3_CONNECT_ERROR, "relay upgrade failed")
                                        })?;
                                    if let Some(extensions) = ingress_tunnel_extensions {
                                        ingress.extensions().extend(&extensions.0);
                                    }
                                    if let Some(extensions) = egress_extensions {
                                        egress.extensions().extend(&extensions.0);
                                    }
                                    // Keep this work in the request future: GOAWAY drains
                                    // the tunnel, and relay cancellation drops both halves.
                                    if datagrams {
                                        HttpDatagramRelay::default().serve(BridgeIo(ingress, egress))
                                            .await.map_err(|error| {
                                                tracing::debug!(%error, "HTTP/3 relay datagram tunnel failed");
                                                Error::stream(Code::H3_CONNECT_ERROR, "relay datagram tunnel failed")
                                            })?;
                                    } else {
                                    forwarding.serve(BridgeIo(ingress, egress)).await.map_err(|error| {
                                        tracing::debug!(%error, "HTTP/3 relay tunnel forwarding failed");
                                        Error::stream(Code::H3_CONNECT_ERROR, "relay tunnel failed")
                                    })?;
                                    }
                                }
                                Ok(())
                            };
                            let mut sending = pin!(exchange);
                            match upstream_priority {
                                Some(handle) => tokio::select! {
                                    result = &mut sending => result,
                                    () = forward_priority(&mut priority, &handle) => sending.await,
                                },
                                None => sending.await,
                            }
                        });
                    }
                    result = requests.next(), if !requests.is_empty() => {
                        if let Some(Err(error)) = result {
                            if error.scope() == ErrorScope::Connection {
                                return completed(Err(error));
                            }
                            tracing::debug!(%error, "HTTP/3 relay request stream failed");
                        }
                    }
                }
                if draining && requests.is_empty() {
                    return tokio::select! {
                        result = &mut driver => completed(result),
                        result = connection.drained() => completed(result),
                    };
                }
            }
        }
        .await;
        if result.is_ok() {
            ingress_guard.disarm();
            egress_guard.disarm();
        }
        result
    }
}

/// Close a hop the relay did not drain.
fn close_ended(connection: &Connection) {
    let code = VarInt::from_u32(Code::H3_INTERNAL_ERROR.value() as u32);
    connection.close(code, b"relay ended");
}

fn completed(result: Result<(), Error>) -> Result<(), BoxError> {
    match result {
        Ok(()) => Ok(()),
        Err(error)
            if error.scope() == ErrorScope::Connection && error.code() == Code::H3_NO_ERROR =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

// Known semantics implemented by this relay; reserved client values remain inert.
fn relay_setting_supported(id: SettingId) -> bool {
    matches!(
        id,
        SettingId::QPACK_MAX_TABLE_CAPACITY
            | SettingId::QPACK_BLOCKED_STREAMS
            | SettingId::MAX_FIELD_SECTION_SIZE
            | SettingId::ENABLE_CONNECT_PROTOCOL
            | SettingId::H3_DATAGRAM
    )
}

#[cfg(test)]
mod tests;
