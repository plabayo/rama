use parking_lot::Mutex;
use rama_crypto::dep::boring::{
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
    ConnectError, Side, TransportError,
    crypto::{
        self,
        config::{TlsConfigError, TlsOptions},
    },
    shared::ConnectionId,
    transport_parameters::TransportParameters,
};

struct Ticket {
    host: String,
    session: SslSession,
    params: TransportParameters,
}

struct TicketState {
    host: String,
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
                    && let Some(params) = *state.params.lock()
                {
                    let mut tickets = callback_tickets.lock();
                    if tickets.len() == 64 {
                        tickets.pop_front();
                    }
                    tickets.push_back(Ticket {
                        host: state.host.clone(),
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
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if version != 1 {
            return Err(ConnectError::UnsupportedVersion);
        }
        let host = Host::try_from(server_name)
            .map_err(|_error| ConnectError::InvalidServerName(server_name.into()))?;
        let mut data = self
            .context
            .configure()
            .map_err(|error| ConnectError::Crypto(crypto_error(error)))?;
        let host = data.server_name.get_or_insert(host).to_string();
        let mut ssl = data
            .into_ssl()
            .map_err(|error| ConnectError::Crypto(crypto_error(error)))?;
        let peer_params = Arc::new(Mutex::new(None));
        ssl.set_ex_data(
            self.ticket_index,
            TicketState {
                host: host.clone(),
                params: peer_params.clone(),
            },
        );
        let ticket = {
            let mut tickets = self.tickets.lock();
            tickets
                .iter()
                .rposition(|ticket| ticket.host == host)
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
        Ok(Box::new(
            TlsSession::new(
                ssl,
                Side::Client,
                params,
                self.early_data,
                remembered,
                peer_params,
            )
            .map_err(ConnectError::Crypto)?,
        ))
    }
}

pub(crate) struct QuicServerConfig {
    context: SslContext,
    early_data: bool,
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
        let mut builder = TlsAcceptorData::try_from(pieces)?.into_static_acceptor_builder()?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|error| TlsConfigError::InvalidConfiguration(error.into()))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|error| TlsConfigError::InvalidConfiguration(error.into()))?;
        Ok(Self {
            context: builder.build().into_context(),
            early_data: options.early_data,
        })
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::InitialKeysError> {
        if version != 1 {
            return Err(crypto::InitialKeysError::UnsupportedVersion);
        }
        packet::initial_keys(cid, Side::Server).map_err(crypto::InitialKeysError::Crypto)
    }
    fn retry_tag(
        &self,
        _: u32,
        cid: &ConnectionId,
        packet: &[u8],
    ) -> Result<[u8; 16], crypto::CryptoError> {
        packet::retry_tag(cid, packet).map_err(|_error| crypto::CryptoError)
    }
    fn start_session(
        self: Arc<Self>,
        _: u32,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, TransportError> {
        let ssl = Ssl::new(&self.context).map_err(|error| crypto_error(error.into()))?;
        Ok(Box::new(TlsSession::new(
            ssl,
            Side::Server,
            params,
            self.early_data,
            None,
            Arc::new(Mutex::new(None)),
        )?))
    }
}
