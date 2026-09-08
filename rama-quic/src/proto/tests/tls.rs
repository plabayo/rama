use super::*;

struct FailingClient;
impl crypto::ClientConfig for FailingClient {
    fn start_session(
        self: Arc<Self>,
        _: u32,
        _: &str,
        _: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        Err(ConnectError::Crypto(failure()))
    }
}

struct FailingServer(Arc<dyn crypto::ServerConfig>);
impl crypto::ServerConfig for FailingServer {
    fn initial_keys(
        &self,
        version: u32,
        cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        self.0.initial_keys(version, cid)
    }
    fn retry_tag(&self, version: u32, cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.0.retry_tag(version, cid, packet)
    }
    fn start_session(
        self: Arc<Self>,
        _: u32,
        _: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, TransportError> {
        Err(failure())
    }
}

fn failure() -> TransportError {
    TransportError::INTERNAL_ERROR("injected TLS session failure")
        .with_cause(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
}

#[test]
fn failed_client_session_releases_reserved_cid() {
    use std::error::Error as _;
    let mut endpoint = Endpoint::new(Default::default(), None, true, None);
    let config = ClientConfig::new(Arc::new(FailingClient));
    for _ in 0..3 {
        let error = endpoint
            .connect(
                Instant::now(),
                config.clone(),
                "127.0.0.1:443".parse().unwrap(),
                "localhost",
            )
            .err()
            .unwrap();
        let source = error
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(endpoint.known_cids(), 0);
        assert_eq!(endpoint.open_connections(), 0);
    }
}

#[test]
fn failed_server_session_releases_reserved_and_preferred_cids() {
    use std::error::Error as _;
    let mut config = server_config();
    config.crypto = Arc::new(FailingServer(config.crypto));
    config.preferred_address_v4 = Some("127.0.0.1:444".parse().unwrap());
    let mut pair = Pair::new(Default::default(), config);
    for _ in 0..3 {
        let client = pair.begin_connect(client_config());
        pair.drive();
        let error = pair.server.assert_accept_error();
        let source = error
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(pair.server.known_cids(), 0);
        assert_eq!(pair.server.open_connections(), 0);
        assert!(
            matches!(pair.client_conn_mut(client).poll(), Some(Event::ConnectionLost {
            reason: ConnectionError::ConnectionClosed(error),
        }) if error.error_code == TransportErrorCode::INTERNAL_ERROR)
        );
    }
}
