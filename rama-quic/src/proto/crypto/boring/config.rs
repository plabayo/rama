use parking_lot::Mutex;
use rama_crypto::dep::boring::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslContext, SslSession, SslSessionCacheMode, SslVersion},
};
use rama_net::address::Host;
use rama_tls::{
    ProtocolVersion, TlsSupportedVersions,
    alpn::{AlpnError, AlpnPolicy},
    client::TlsClientConfig,
    server::TlsServerConfig,
};
use rama_tls_boring::{
    client::{BoringTlsConnectorConfig, TlsConnectorContext, TlsConnectorContextBuilder},
    server::{BoringTlsAcceptorConfig, BoringTlsAuth, TlsAcceptorData},
};
use std::{collections::VecDeque, sync::Arc};

use super::{
    packet,
    session::{TlsSession, crypto_error},
};
use crate::proto::{
    ConnectError,
    crypto::{
        self,
        config::{TlsConfigError, TlsOptions},
    },
};
use rama_quic_proto::{
    ConnectionId, Side, TransportError, Version, transport_parameters::TransportParameters,
};

struct Ticket {
    host: Host,
    /// The negotiated version of the connection that issued it (RFC 9369 §5).
    version: Version,
    session: SslSession,
    params: TransportParameters,
}

struct TicketState {
    host: Host,
    /// The connection's version, which compatible negotiation may still change.
    version: Arc<Mutex<Version>>,
    params: Arc<Mutex<Option<TransportParameters>>>,
}

pub(crate) struct QuicClientConfig {
    context: TlsConnectorContext,
    tickets: Arc<Mutex<VecDeque<Ticket>>>,
    ticket_index: Index<Ssl, TicketState>,
    early_data: bool,
}

fn validate_versions(versions: Option<&TlsSupportedVersions>) -> Result<(), TlsConfigError> {
    if versions.is_some_and(|v| !v.0.is_empty() && !v.0.contains(&ProtocolVersion::TLSv1_3)) {
        return Err(TlsConfigError::Tls13Required);
    }
    Ok(())
}

fn validate_alpn(
    alpn: Option<&rama_net::tls::TlsAlpn>,
    options: TlsOptions,
) -> Result<(), TlsConfigError> {
    rama_tls::alpn::validate_alpn(
        alpn.into_iter()
            .flat_map(|list| list.0.iter().map(|protocol| protocol.as_bytes())),
        AlpnPolicy::Require,
    )
    .map_err(|error| match error {
        AlpnError::Required if options.alpn == AlpnPolicy::OutOfBandAgreement => {
            TlsConfigError::UnsupportedOutOfBandAgreement
        }
        AlpnError::Required => TlsConfigError::AlpnRequired,
        AlpnError::Invalid => TlsConfigError::InvalidAlpn,
    })
}

impl QuicClientConfig {
    pub(crate) fn from_rama(
        config: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<Self, TlsConfigError> {
        let pieces = BoringTlsConnectorConfig::from_extensions(config.as_extensions());
        validate_versions(pieces.versions)?;
        validate_alpn(pieces.alpn, options)?;
        let mut builder = TlsConnectorContextBuilder::try_from(pieces)?;
        if builder
            .config
            .max_proto_version()
            .is_some_and(|version| version != SslVersion::TLS1_3)
        {
            return Err(TlsConfigError::Tls13Required);
        }
        builder
            .config
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|error| TlsConfigError::InvalidConfiguration(error.into()))?;
        builder
            .config
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|error| TlsConfigError::InvalidConfiguration(error.into()))?;
        let tickets: Arc<Mutex<VecDeque<Ticket>>> = Arc::default();
        let callback_tickets = tickets.clone();
        let ticket_index = Ssl::new_ex_index::<TicketState>()
            .map_err(|error| TlsConfigError::InvalidConfiguration(error.into()))?;
        builder
            .config
            .set_session_cache_mode(SslSessionCacheMode::CLIENT);
        builder
            .config
            .set_new_session_callback(move |ssl, session| {
                if let Some(state) = ssl.ex_data(ticket_index)
                    && let Some(params) = state.params.lock().clone()
                {
                    let mut tickets = callback_tickets.lock();
                    if tickets.len() == 64 {
                        tickets.pop_front();
                    }
                    tickets.push_back(Ticket {
                        host: state.host.clone(),
                        version: *state.version.lock(),
                        session,
                        params,
                    });
                }
            });
        Ok(Self {
            context: builder.build(),
            tickets,
            ticket_index,
            early_data: options.early_data,
        })
    }
}

impl crypto::ClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: Version,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let wire = packet::wire(version).ok_or(ConnectError::UnsupportedVersion)?;
        let host = Host::try_from(server_name)
            .map_err(|_error| ConnectError::InvalidServerName(server_name.into()))?;
        let mut data = self
            .context
            .configure()
            .map_err(|error| ConnectError::Crypto(crypto_error(error)))?;
        let host = data.server_name.get_or_insert(host).clone();
        let mut ssl = data
            .into_ssl()
            .map_err(|error| ConnectError::Crypto(crypto_error(error)))?;
        let peer_params = Arc::new(Mutex::new(None));
        let negotiated = Arc::new(Mutex::new(version));
        ssl.set_ex_data(
            self.ticket_index,
            TicketState {
                host: host.clone(),
                version: negotiated.clone(),
                params: peer_params.clone(),
            },
        );
        // Only a ticket from a connection in this version may resume it (RFC 9369 §5).
        let ticket = {
            let mut tickets = self.tickets.lock();
            tickets
                .iter()
                .rposition(|ticket| ticket.host == host && ticket.version == version)
                .and_then(|index| tickets.remove(index))
        };
        let remembered = if let Some(ticket) = ticket {
            // This cache belongs to the immutable context that created both the ticket and SSL.
            unsafe { ssl.set_session(&ticket.session) }
                .map_err(|error| ConnectError::Crypto(crypto_error(error.into())))?;
            Some(ticket.params)
        } else {
            None
        };
        let mut session = TlsSession::new(
            ssl,
            Side::Client,
            wire,
            wire,
            params,
            self.early_data,
            remembered,
            peer_params,
        )
        .map_err(ConnectError::Crypto)?;
        session.track_version(negotiated);
        Ok(Box::new(session))
    }
    fn supports_version_switch(&self) -> bool {
        true
    }
    fn resumable_version(&self, server_name: &str) -> Option<Version> {
        let host = Host::try_from(server_name).ok()?;
        let tickets = self.tickets.lock();
        tickets
            .iter()
            .rev()
            .find(|ticket| ticket.host == host)
            .map(|ticket| ticket.version)
    }
}

impl QuicClientConfig {
    /// Tests: relabel every cached ticket as belonging to `version`, to offer a ticket from one
    /// version to a server session in another.
    #[cfg(test)]
    pub(super) fn relabel_tickets(&self, version: Version) {
        for ticket in self.tickets.lock().iter_mut() {
            ticket.version = version;
        }
    }
}

pub(crate) struct QuicServerConfig {
    /// One context per standardized version: BoringSSL resumes a session only under the
    /// session-ID context that issued it, which scopes tickets by version (RFC 9369 §5).
    contexts: [SslContext; 2],
    early_data: bool,
}

impl QuicServerConfig {
    fn context(&self, version: Version) -> &SslContext {
        match version {
            Version::V2 => &self.contexts[1],
            _ => &self.contexts[0],
        }
    }
}

impl QuicServerConfig {
    pub(crate) fn from_rama(
        config: &TlsServerConfig,
        options: TlsOptions,
    ) -> Result<Self, TlsConfigError> {
        let pieces = BoringTlsAcceptorConfig::from_extensions(config.as_extensions());
        validate_versions(pieces.versions)?;
        validate_alpn(pieces.alpn, options)?;
        if matches!(pieces.auth, Some(BoringTlsAuth::CertIssuer(_))) {
            return Err(TlsConfigError::UnsupportedDynamicConfig);
        }
        let data = TlsAcceptorData::try_from(pieces)?;
        let context = |version: Version| -> Result<SslContext, TlsConfigError> {
            let mut builder = data.clone().into_static_acceptor_builder()?;
            let invalid = |error: ErrorStack| TlsConfigError::InvalidConfiguration(error.into());
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .map_err(invalid)?;
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(invalid)?;
            builder
                .set_session_id_context(&version.to_be_bytes())
                .map_err(invalid)?;
            Ok(builder.build().into_context())
        };
        Ok(Self {
            contexts: [context(Version::V1)?, context(Version::V2)?],
            early_data: options.early_data,
        })
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn initial_keys(
        &self,
        version: Version,
        cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::InitialKeysError> {
        let wire = packet::wire(version).ok_or(crypto::InitialKeysError::UnsupportedVersion)?;
        packet::initial_keys(wire, cid, Side::Server).map_err(crypto::InitialKeysError::Crypto)
    }
    fn retry_tag(
        &self,
        version: Version,
        cid: &ConnectionId,
        packet: &[u8],
    ) -> Result<[u8; 16], crypto::CryptoError> {
        let wire = packet::wire(version).ok_or(crypto::CryptoError::new())?;
        packet::retry_tag(wire, cid, packet).map_err(|_error| crypto::CryptoError::new())
    }
    fn start_session(
        self: Arc<Self>,
        version: Version,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, TransportError> {
        self.start_with(version, version, params)
    }
    fn supports_compatible_negotiation(&self) -> bool {
        true
    }
    fn start_negotiated_session(
        self: Arc<Self>,
        original: Version,
        negotiated: Version,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, TransportError> {
        self.start_with(original, negotiated, params)
    }
    fn supports_version_switch(&self) -> bool {
        true
    }
}

impl QuicServerConfig {
    fn start_with(
        &self,
        original: Version,
        negotiated: Version,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, TransportError> {
        let unsupported = || TransportError::INTERNAL_ERROR("unsupported QUIC version");
        let wire = packet::wire(negotiated).ok_or_else(unsupported)?;
        let early_wire = packet::wire(original).ok_or_else(unsupported)?;
        let ssl = Ssl::new(self.context(negotiated)).map_err(|error| crypto_error(error.into()))?;
        Ok(Box::new(TlsSession::new(
            ssl,
            Side::Server,
            wire,
            early_wire,
            params,
            self.early_data,
            None,
            Arc::new(Mutex::new(None)),
        )?))
    }
}
