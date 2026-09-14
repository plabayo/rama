use super::*;

struct FailingClient(bool);
impl crypto::ClientConfig for FailingClient {
    fn start_session(
        self: Arc<Self>,
        _: u32,
        _: &str,
        _: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if self.0 {
            Ok(Box::new(FailingInitialKeys))
        } else {
            Err(ConnectError::Crypto(failure()))
        }
    }
}

struct FailingServer(Arc<dyn crypto::ServerConfig>, bool);
impl crypto::ServerConfig for FailingServer {
    fn initial_keys(
        &self,
        version: u32,
        cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::InitialKeysError> {
        self.0.initial_keys(version, cid)
    }
    fn retry_tag(
        &self,
        version: u32,
        cid: &ConnectionId,
        packet: &[u8],
    ) -> Result<[u8; 16], crypto::CryptoError> {
        self.0.retry_tag(version, cid, packet)
    }
    fn start_session(
        self: Arc<Self>,
        _: u32,
        _: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, TransportError> {
        if self.1 {
            Ok(Box::new(FailingInitialKeys))
        } else {
            Err(failure())
        }
    }
}

struct FailingInitialKeys;
impl crypto::Session for FailingInitialKeys {
    fn initial_keys(&self, _: &ConnectionId, _: Side) -> Result<crypto::Keys, TransportError> {
        Err(failure())
    }
    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        None
    }
    fn early_data_accepted(&self) -> Option<bool> {
        None
    }
    fn is_handshaking(&self) -> bool {
        true
    }
    fn read_handshake(
        &mut self,
        _: crate::proto::packet::SpaceId,
        _: &[u8],
    ) -> Result<bool, TransportError> {
        Err(failure())
    }
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Err(failure())
    }
    fn poll_handshake(&mut self) -> Result<Option<crypto::HandshakeEvent>, TransportError> {
        Err(failure())
    }
    fn next_1rtt_keys(
        &mut self,
    ) -> Result<Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>>, TransportError> {
        Err(failure())
    }
    fn is_valid_retry(&self, _: &ConnectionId, _: &[u8], _: &[u8]) -> bool {
        false
    }
    fn export_keying_material(
        &self,
        _: &mut [u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        Err(crypto::ExportKeyingMaterialError)
    }
}

fn failure() -> TransportError {
    TransportError::INTERNAL_ERROR("injected TLS session failure")
        .with_cause(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
}

#[test]
fn failed_client_session_releases_reserved_cid() {
    use std::error::Error as _;
    for initial_keys in [false, true] {
        let mut endpoint = Endpoint::new(
            Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
            None,
            true,
            None,
        );
        let config = ClientConfig::new(Arc::new(FailingClient(initial_keys)));
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
}

#[test]
fn failed_server_session_releases_reserved_and_preferred_cids() {
    use std::error::Error as _;
    for initial_keys in [false, true] {
        let mut config = server_config();
        config.crypto = Arc::new(FailingServer(config.crypto, initial_keys));
        config.preferred_address_v4 = Some("127.0.0.1:444".parse().unwrap());
        let mut pair = Pair::new(
            Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
            config,
        );
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
}
#[test]
fn retired_keys_do_not_replace_acknowledgment_of_the_current_phase() {
    let mut pair = Pair::default();
    let (client, server) = pair.connect();
    pair.drive();
    let now = pair.time + Duration::from_secs(1);
    pair.client_conn_mut(client)
        .assert_key_retirement_does_not_authorize_an_update(now);
    pair.server_conn_mut(server)
        .assert_key_retirement_does_not_authorize_an_update(now);
}

#[test]
fn server_does_not_decrypt_one_rtt_before_client_finished() {
    let mut pair = Pair::default();
    pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    let server = pair.server.assert_accept();
    assert!(pair.server_conn_mut(server).is_handshaking());
    // Complete short header and protection sample, with an invalid AEAD tag.
    // Attempting decryption would increment the authentication failure counter.
    let mut packet = BytesMut::from(&[0x40][..]);
    packet.resize(41, 0);
    let now = pair.time;
    pair.server_conn_mut(server)
        .assert_early_packet_is_not_decrypted(now, packet);
}

#[test]
fn client_does_not_decrypt_zero_rtt_while_resuming() {
    let mut pair = Pair::default();
    let config = client_config();
    pair.connect_with(config.clone());
    pair.drive();
    let client = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client).has_0rtt());
    // 0-RTT long header: version 1, eight-byte destination ID, no source ID,
    // and 32 bytes of protected packet number/payload/tag.
    let mut packet = BytesMut::from(&[0xd0, 0, 0, 0, 1, 8][..]);
    packet.extend_from_slice(&[0; 8]);
    packet.extend_from_slice(&[0, 32]);
    packet.resize(48, 0);
    let now = pair.time;
    pair.client_conn_mut(client)
        .assert_early_packet_is_not_decrypted(now, packet);
}
