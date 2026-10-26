//! HTTP/3 MITM relay over an established ingress/egress QUIC connection pair.

use std::{convert::Infallible, pin::pin, sync::Arc, time::Duration};

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, ExtensionsRef as _, Ingress},
    futures::{FutureExt as _, StreamExt as _, stream::FuturesUnordered},
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
    io::upgrade::{Upgraded, handle_upgrade},
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
use crate::{
    client::SendAttempts,
    h3::{clean_close, completed, drain},
};

mod egress;
pub use egress::Http3EgressService;
use egress::forward_priority;

#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(http))]
struct Rejected;

/// A relay forwards what origins accept, so the field-section size is its real bound.
const RELAY_MAX_FIELD_LINES: usize = 2048;

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
/// Each hop advertises the other peer's initial SETTINGS in their original order, limited to
/// what this relay implements plus GREASE: values are lowered to the local hop's budgets, an
/// origin's Extended CONNECT grant is dropped unless ingress offers it, and HTTP Datagram
/// grants unless both hops carry datagrams; a client's ENABLE_CONNECT_PROTOCOL grants nothing
/// and is kept. Other settings are dropped and traced. SETTINGS missing the readiness deadline
/// leave the other hop on its own. An explicit [`Config::settings_profile`] on a hop is used
/// as configured instead.
///
/// Early requests and server push are disabled on both hops. A relay that
/// fails, or whose serve future is dropped (even before it is first polled), closes both
/// connections with `H3_INTERNAL_ERROR`.
#[derive(Debug, Clone)]
pub struct Http3MitmRelay<M = DefaultMiddleware, P = bool, D = HttpDatagramRelay> {
    middleware: M,
    datagram_relay: D,
    authority: Option<BoundAuthority<P>>,
    exec: Executor,
    ingress: Config,
    egress: Config,
    settings_timeout: Duration,
    forbidden_trailers: ForbiddenTrailers,
}

impl Http3MitmRelay {
    /// Create a relay with default per-hop configurations; ingress offers Extended CONNECT
    /// whenever the origin does. Both hops accept more field lines per section than a
    /// standalone endpoint, so the relay does not refuse messages its peers accept.
    #[must_use]
    pub fn new(exec: Executor) -> Self {
        let mut ingress = Config {
            extended_connect: true,
            ..Default::default()
        };
        ingress.decoder.max_field_lines = RELAY_MAX_FIELD_LINES;
        let mut egress = Config::default();
        egress.decoder.max_field_lines = RELAY_MAX_FIELD_LINES;
        Self {
            middleware: (
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
                ArcLayer::new(),
            ),
            datagram_relay: HttpDatagramRelay::default(),
            authority: None,
            exec,
            ingress,
            egress,
            settings_timeout: DEFAULT_EAGER_PEER_SETTINGS_TIMEOUT,
            forbidden_trailers: ForbiddenTrailers::AllowAll,
        }
    }
}

impl<M, P, D> Http3MitmRelay<M, P, D> {
    /// Set the service for explicitly selected HTTP Datagram tunnels.
    ///
    /// HTTP middleware selects sessions by putting [`HttpDatagrams`] on the
    /// response itself, after accepting its protocol handshake. An inherited
    /// request marker does not select a datagram relay. The service receives
    /// the upgraded bridge and its explicitly transferred metadata, allowing ordinary
    /// Rama layers to apply destination or application policy. It can use
    /// [`rama_http::datagram::HttpDatagramSession`] to filter individual datagrams.
    /// Unselected CONNECT tunnels retain byte forwarding. A non-selection is not an
    /// access denial; HTTP middleware should reject forbidden requests.
    /// The default relay drains existing tunnels on graceful shutdown, as byte
    /// forwarding does. Supply a relay with an executor to opt into cancellation.
    #[must_use]
    pub fn with_datagram_relay<N>(self, datagram_relay: N) -> Http3MitmRelay<M, P, N> {
        Http3MitmRelay {
            middleware: self.middleware,
            datagram_relay,
            authority: self.authority,
            exec: self.exec,
            ingress: self.ingress,
            egress: self.egress,
            settings_timeout: self.settings_timeout,
            forbidden_trailers: self.forbidden_trailers,
        }
    }

    /// Bind the relayed connection to its trusted logical origin and policy.
    ///
    /// Mismatches return 421 without opening an upstream request stream.
    pub fn with_bound_authority<Q>(self, authority: BoundAuthority<Q>) -> Http3MitmRelay<M, Q, D> {
        Http3MitmRelay {
            middleware: self.middleware,
            datagram_relay: self.datagram_relay,
            authority: Some(authority),
            exec: self.exec,
            ingress: self.ingress,
            egress: self.egress,
            settings_timeout: self.settings_timeout,
            forbidden_trailers: self.forbidden_trailers,
        }
    }

    /// Set the HTTP middleware between the ingress server and the egress client.
    pub fn with_http_middleware<N>(self, middleware: N) -> Http3MitmRelay<N, P, D> {
        Http3MitmRelay {
            middleware,
            datagram_relay: self.datagram_relay,
            authority: self.authority,
            exec: self.exec,
            ingress: self.ingress,
            egress: self.egress,
            settings_timeout: self.settings_timeout,
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

impl<M, P, D> Service<BridgeIo<Connection, Connection>> for Http3MitmRelay<M, P, D>
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
    D: Service<BridgeIo<Upgraded, Upgraded>, Error: Into<BoxError>> + Clone,
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

impl<M, P, D> Http3MitmRelay<M, P, D>
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
    D: Service<BridgeIo<Upgraded, Upgraded>, Error: Into<BoxError>> + Clone,
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
        // Both handshakes are confirmed and the ingress server holds requests until then.
        if ingress.early_data_keys_enabled() || egress.early_data_keys_enabled() {
            tracing::debug!("HTTP/3 relay ignores early data keys after handshake confirmation");
        }
        if egress_config.early_requests {
            tracing::debug!("HTTP/3 relay disables egress early requests");
            egress_config.early_requests = false;
        }
        // QPACK state stays independent per hop; push is not relayed.
        if ingress_config.max_pushes != 0 || egress_config.max_pushes != 0 {
            tracing::debug!("HTTP/3 relay disables server push on both hops");
            ingress_config.max_pushes = 0;
            egress_config.max_pushes = 0;
        }
        // Kept alive past the deadline: dropping it would close ingress.
        let receive_config = ingress_config.clone();
        let mut receiving = Box::pin(server::receive_settings(ingress.clone(), &receive_config));
        let received = tokio::time::timeout_at(settings_deadline, &mut receiving)
            .await
            .ok()
            .transpose()?;
        let ingress_datagrams = ingress_config.datagrams.is_some()
            && ingress.datagram_receive_enabled()
            && ingress.max_datagram_size().is_some();
        let egress_datagrams = egress_config.datagrams.is_some()
            && egress.datagram_receive_enabled()
            && egress.max_datagram_size().is_some();
        match (&received, &egress_config.settings_profile) {
            (_, Some(_)) => {}
            (None, None) => {
                tracing::debug!("HTTP/3 relay: client SETTINGS late; egress uses its own");
                if !ingress_datagrams {
                    egress_config.datagrams = None;
                }
            }
            (Some(received), None) => {
                // Reserved client values are inert and kept; a client's Extended CONNECT
                // value grants nothing (RFC 9220 §3).
                let settings = fit_settings(
                    "client",
                    received.peer_settings(),
                    &egress_config,
                    |id| relay_setting_supported(id) || id.is_reserved(),
                    true,
                    // Origin datagrams are only useful when ingress can carry them on.
                    egress_datagrams && ingress_datagrams,
                );
                egress_config = egress_config.try_with_client_settings(Arc::new(settings))?;
            }
        }
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
        let (received, peer) = {
            let mut origin_settings = pin!(sender.peer_settings());
            let peer = tokio::time::timeout_at(settings_deadline, &mut origin_settings)
                .await
                .ok()
                .transpose()?;
            if let Some(received) = received {
                (received, peer)
            } else {
                // Ingress state needs the client's SETTINGS; its QUIC idle timeout
                // bounds this wait.
                let received = tokio::select! {
                    received = &mut receiving => received?,
                    () = cancelled(&self.exec) => {
                        egress_guard.disarm();
                        return Ok(());
                    }
                };
                // The origin may answer while the client is still late.
                let peer = match peer {
                    Some(peer) => Some(peer),
                    None => origin_settings.now_or_never().transpose()?,
                };
                (received, peer)
            }
        };
        // Unknown peer SETTINGS are ignored (RFC 9114 §7.2.4) and never advertised downstream.
        if let Some(peer) = &peer
            && ingress_config.settings_profile.is_none()
        {
            // GREASE is inert and kept, as in the client direction.
            let settings = fit_settings(
                "origin",
                peer,
                &ingress_config,
                |id| relay_setting_supported(id) || id.is_reserved(),
                ingress_config.extended_connect,
                egress_datagrams && ingress_datagrams,
            );
            ingress_config = ingress_config.try_with_server_settings(Arc::new(settings))?;
        } else if let Some(peer) = &peer {
            // Bound ingress input without copying the origin's QPACK state.
            if let Some(limit) = peer.max_field_section_size() {
                ingress_config.decoder.max_field_section_size = ingress_config
                    .decoder
                    .max_field_section_size
                    .min(usize::try_from(limit).unwrap_or(usize::MAX));
            }
            // Plain CONNECT does not depend on this SETTINGS value.
            ingress_config.extended_connect &= peer.enable_connect_protocol();
        } else if ingress_config.settings_profile.is_none() {
            // Without the origin's grants ingress cannot promise them.
            tracing::debug!("HTTP/3 relay: origin SETTINGS late; ingress uses its own");
            ingress_config.extended_connect = false;
            ingress_config.datagrams = None;
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
        let close_timeout = ingress_config.close_drain_timeout;
        let (mut connection, driver) = received.into_connection(ingress_config)?;
        let mut driver = pin!(driver.run());
        // Declared after the server state, so it closes ingress before that state's clean stop.
        let mut ingress_guard = DropGuard::new(move || close_ended(&close_ingress));
        let mut upstream_draining = upstream_draining;
        let mut cancelled = pin!(cancelled(&self.exec));
        let forwarding = IoForwardService::new(self.exec.clone());
        let mut requests = FuturesUnordered::new();
        let mut draining = false;
        // The exchange borrows the HTTP/3 state, so the guards see its outcome while it lives.
        let result = async {
            loop {
                tokio::select! {
                    result = &mut driver => return drain(std::future::ready(result), &mut requests, close_timeout, (!draining).then_some(&mut cancelled)).await,
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
                            Err(error) if clean_close(error) => return drain(driver, &mut requests, close_timeout, (!draining).then_some(&mut cancelled)).await,
                            Err(error) => return completed(Err(error)),
                        };
                        let service = service.clone();
                        let extensions = ingress_extensions.clone();
                        let forwarding = forwarding.clone();
                        let datagram_relay = self.datagram_relay.clone();
                        requests.push(async move {
                            let (request, response) = stream.resolve().await?;
                            request.extensions().insert(Ingress(extensions));
                            let mut priority = response.peer_priority();
                            request.extensions().insert(priority.clone());
                            let ingress_upgrade = (request.method() == Method::CONNECT)
                                .then(|| handle_upgrade(&request));
                            let ingress_tunnel_extensions = ingress_upgrade.as_ref().map(|_| {
                                request.extensions()
                                    .self_get_ref_or_insert(HttpUpgradeMitmRelayExtensions::default)
                                    .clone()
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
                                    && output.extensions().self_contains::<HttpDatagrams>();
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
                                        datagram_relay.serve(BridgeIo(ingress, egress))
                                            .await.map_err(|error| {
                                                let error: BoxError = error.into();
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
                            if clean_close(error) {
                                return drain(driver, &mut requests, close_timeout, (!draining).then_some(&mut cancelled)).await;
                            }
                            if error.scope() == ErrorScope::Connection {
                                return completed(Err(error));
                            }
                            tracing::debug!(%error, "HTTP/3 relay request stream failed");
                        }
                    }
                }
                if draining && requests.is_empty() {
                    return tokio::select! {
                        result = &mut driver => drain(std::future::ready(result), &mut requests, close_timeout, None::<std::future::Pending<()>>).await,
                        result = connection.drained() => match result {
                            Err(error) if clean_close(error) => drain(driver, &mut requests, close_timeout, None::<std::future::Pending<()>>).await,
                            result => completed(result),
                        },
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

/// Resolves once graceful shutdown starts; never without a guard.
async fn cancelled(exec: &Executor) {
    match exec.guard() {
        Some(guard) => guard.cancelled().await,
        None => std::future::pending().await,
    }
}

/// Close a hop the relay did not drain.
fn close_ended(connection: &Connection) {
    let code = VarInt::from_u32(Code::H3_INTERNAL_ERROR.value() as u32);
    connection.close(code, b"relay ended");
}

/// Keep `peer`'s supported SETTINGS in order within the hop's `local` budgets.
///
/// Larger values are lowered and unavailable capability grants dropped; every
/// change is traced, as the other peer never learns about it.
fn fit_settings(
    peer_name: &'static str,
    peer: &Settings,
    local: &Config,
    supported: impl Fn(SettingId) -> bool,
    extended_connect: bool,
    datagrams: bool,
) -> Settings {
    let mut fitted = Settings::new();
    for setting in peer.entries() {
        let ceiling = match setting.id {
            SettingId::QPACK_MAX_TABLE_CAPACITY => Some(local.decoder.max_table_capacity),
            SettingId::QPACK_BLOCKED_STREAMS => Some(local.decoder.max_blocked_streams),
            SettingId::MAX_FIELD_SECTION_SIZE => Some(local.decoder.max_field_section_size as u64),
            SettingId::ENABLE_CONNECT_PROTOCOL => (!extended_connect).then_some(0),
            SettingId::H3_DATAGRAM => (!datagrams).then_some(0),
            _ => None,
        };
        let value = ceiling.map_or(setting.value, |ceiling| setting.value.min(ceiling));
        let is_grant = matches!(
            setting.id,
            SettingId::ENABLE_CONNECT_PROTOCOL | SettingId::H3_DATAGRAM
        );
        if !supported(setting.id) || (is_grant && value != setting.value) {
            tracing::debug!(
                peer = peer_name,
                id = ?setting.id,
                value = setting.value,
                "HTTP/3 relay drops unsupported SETTINGS entry"
            );
            continue;
        }
        if value != setting.value {
            tracing::debug!(
                peer = peer_name,
                id = ?setting.id,
                value = setting.value,
                local = value,
                "HTTP/3 relay lowers SETTINGS value to the local budget"
            );
        }
        // Decoded peer entries are unique and valid; lowering keeps them so.
        if let Err(error) = fitted.set(setting.id, value) {
            tracing::debug!(peer = peer_name, %error, "HTTP/3 relay drops SETTINGS entry");
        }
    }
    fitted
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
