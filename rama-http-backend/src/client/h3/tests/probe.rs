//! Establishment of an HTTP/3 connection up to its first QUIC endpoint, without dialing.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _},
};
use rama_http_core::h3::connection::Config;
use rama_net::client::{
    ConnectRequest, ConnectionError, ConnectionErrorKind, EstablishedClientConnection,
};
use rama_quic::client::{ClientEndpoint, QuicConnector};
use rama_quic_proto::profile::QuicProfile;

use crate::client::h3::Http3Connector;

/// Records being reached, then refuses: the QUIC connector prepares before it asks for one.
#[derive(Debug, Clone, Default)]
struct Unreached(Arc<AtomicBool>);

impl Service<ConnectRequest> for Unreached {
    type Output = EstablishedClientConnection<ClientEndpoint, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, _input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        self.0.store(true, Ordering::SeqCst);
        Err(ConnectionError::local(
            BoxError::from_static_str("preparation probe"),
            ConnectionErrorKind::Rejected,
        ))
    }
}

/// Prepare `input` as `connector` establishes it, stopping before any endpoint is used.
///
/// Returns the connection's HTTP/3 limits; the effective QUIC profile is left on `input`.
/// `input` must carry an IP target, directly or as its [`ConnectorTarget`].
///
/// [`ConnectorTarget`]: rama_net::client::ConnectorTarget
pub(in crate::client::h3) async fn prepare<E>(
    connector: &Http3Connector<E>,
    input: &ConnectRequest,
) -> Result<Arc<Config>, ConnectionError> {
    let reached = Unreached::default();
    let quic = QuicConnector::new(
        reached.clone(),
        connector.tls_config().clone(),
        connector.tls_provider().clone(),
    )
    .with_transport(connector.quic().transport().clone());
    let probe = Http3Connector {
        coalescing: quic.clone(),
        quic,
        config: connector.config.clone(),
    };
    let error = probe
        .serve(input.clone())
        .await
        .expect_err("the probe never hands out an endpoint");
    if !reached.0.load(Ordering::SeqCst) {
        return Err(error);
    }
    connector.h3_config(input, input.extensions.get_ref::<QuicProfile>())
}
