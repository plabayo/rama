//! Tests specifically for tokens

use parking_lot::Mutex;

use super::*;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
fn stateless_retry() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let (client_ch, _server_ch) = pair.connect();
    // The Retry reset the client's Initial packets and the handshake discarded two packet
    // number spaces: loss recovery's in-flight count still equals what is outstanding.
    assert_eq!(
        pair.client_conn_mut(client_ch).loss_recovery_in_flight(),
        (0, 0)
    );
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn retry_token_expired() {
    let _guard = subscribe();

    let fake_time = Arc::new(FakeTimeSource::new());
    let retry_token_lifetime = Duration::from_secs(1);

    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);

    let mut config = server_config();
    config
        .set_time_source(Arc::clone(&fake_time) as _)
        .set_retry_token_lifetime(retry_token_lifetime);
    pair.server.set_server_config(Some(Arc::new(config)));

    let client_ch = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();

    // to expire retry token
    fake_time.advance(retry_token_lifetime + Duration::from_millis(1));

    pair.drive();
    match pair.client_conn_mut(client_ch).poll() {
        Some(Event::ConnectionLost {
            reason: ConnectionError::ConnectionClosed(err),
        }) if err.error_code == TransportErrorCode::INVALID_TOKEN => {}
        other => panic!(
            "assertion failed: `{other:?}` does not match `Some(Event::ConnectionLost {{ reason: ConnectionError::ConnectionClosed(err) }}) if err.error_code == TransportErrorCode::INVALID_TOKEN`"
        ),
    }

    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn use_token() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_config = client_config();
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn retry_then_use_token() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_config = client_config();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn use_token_then_retry() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_config = client_config();
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new({
        let mut i = 0;
        move |incoming| {
            if i == 0 {
                assert!(incoming.remote_address_validated());
                assert!(incoming.may_retry());
                i += 1;
                IncomingConnectionBehavior::Retry
            } else if i == 1 {
                assert!(incoming.remote_address_validated());
                assert!(!incoming.may_retry());
                i += 1;
                IncomingConnectionBehavior::Accept
            } else {
                panic!("too many handle_incoming iterations")
            }
        }
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn use_same_token_twice() {
    #[derive(Default)]
    struct EvilTokenStore(Mutex<Option<StoredToken>>);

    impl TokenStore for EvilTokenStore {
        fn insert(&self, _server_name: &str, _version: Version, token: StoredToken) {
            let mut lock = self.0.lock();
            if lock.is_none() {
                *lock = Some(token);
            }
        }

        fn take(&self, _server_name: &str, _version: Version) -> Option<StoredToken> {
            self.0.lock().clone()
        }
    }

    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut client_config = client_config();
    client_config.set_token_store(Arc::new(EvilTokenStore::default()));
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(!incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_3, _server_ch_3) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_3)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn use_token_expired() {
    let _guard = subscribe();
    let fake_time = Arc::new(FakeTimeSource::new());
    let lifetime = Duration::from_secs(10000);
    let mut server_config = server_config();
    server_config
        .set_time_source(Arc::clone(&fake_time) as _)
        .validation_token
        .set_lifetime(lifetime);
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        server_config,
    );
    let client_config = client_config();
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    fake_time.advance(lifetime + Duration::from_secs(1));

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(!incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_3, _server_ch_3) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_3)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

pub(super) struct FakeTimeSource(Mutex<SystemTime>);

impl FakeTimeSource {
    pub(super) fn new() -> Self {
        Self(Mutex::new(SystemTime::now()))
    }

    /// A clock starting at a whole second: token issue times are encoded in whole seconds, so
    /// boundary tests need an issue time without a fractional part.
    pub(super) fn at_whole_second() -> Self {
        Self(Mutex::new(UNIX_EPOCH + Duration::from_secs(1_700_000_000)))
    }

    pub(super) fn advance(&self, dur: Duration) {
        *self.0.lock() += dur;
    }
}

impl TimeSource for FakeTimeSource {
    fn now(&self) -> SystemTime {
        *self.0.lock()
    }
}

use crate::proto::crypto::{AeadKey, CryptoError, HandshakeTokenKey};

/// Where a failing token-key provider gives up.
#[derive(Debug, Clone, Copy)]
enum ProviderFailure {
    /// `aead_from_hkdf` refuses to derive the per-token key.
    Derivation,
    /// Derivation succeeds; `seal` fails after having scribbled into its buffer.
    Sealing,
}

/// A token key whose provider fails at the configured stage.
struct FailingTokenKey(ProviderFailure);

impl HandshakeTokenKey for FailingTokenKey {
    fn aead_from_hkdf(&self, _random_bytes: &[u8]) -> Result<Box<dyn AeadKey>, CryptoError> {
        match self.0 {
            ProviderFailure::Derivation => Err(CryptoError::new()),
            ProviderFailure::Sealing => Ok(Box::new(SealFails)),
        }
    }
}

/// An AEAD whose seal fails after partially writing, so any escaped output is detectable.
struct SealFails;

impl AeadKey for SealFails {
    fn seal(&self, data: &mut Vec<u8>, _additional_data: &[u8]) -> Result<(), CryptoError> {
        data.extend_from_slice(b"PARTIAL-TAG-MUST-NOT-ESCAPE");
        Err(CryptoError::new())
    }

    fn open<'a>(
        &self,
        _data: &'a mut [u8],
        _additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        Err(CryptoError::new())
    }
}

#[test]
fn retry_with_a_failing_token_key_hands_the_attempt_back_intact() {
    for failure in [ProviderFailure::Derivation, ProviderFailure::Sealing] {
        retry_with_failing_key(failure);
    }
}

struct FailingRetryIntegrity(Arc<dyn crypto::ServerConfig>);
impl crypto::ServerConfig for FailingRetryIntegrity {
    fn initial_keys(
        &self,
        version: Version,
        cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::InitialKeysError> {
        self.0.initial_keys(version, cid)
    }
    fn retry_tag(
        &self,
        _: Version,
        _: &ConnectionId,
        _: &[u8],
    ) -> Result<[u8; 16], crypto::CryptoError> {
        Err(crypto::CryptoError)
    }
    fn start_session(
        self: Arc<Self>,
        version: Version,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, TransportError> {
        self.0.clone().start_session(version, params)
    }
}

#[test]
fn failed_retry_integrity_preserves_the_attempt_and_callers_buffer() {
    let mut pair = Pair::default();
    let mut config = server_config();
    config.crypto = Arc::new(FailingRetryIntegrity(config.crypto));
    pair.server.set_server_config(Some(Arc::new(config)));
    pair.server.handle_incoming = Box::new(|_| IncomingConnectionBehavior::Wait);
    let client = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    let incoming = pair.server.waiting_incoming.pop().unwrap();
    let mut buffer = b"caller-owned".to_vec();
    let error = pair
        .server
        .endpoint
        .retry(incoming, &mut buffer)
        .unwrap_err();
    assert_eq!(error.reason(), RetryRefused::IntegrityProtection);
    assert_eq!(buffer, b"caller-owned");
    let incoming = error.into_incoming();
    assert!(incoming.may_retry());
    let server = pair.server.try_accept(incoming, pair.time).unwrap();
    pair.drive();
    assert!(!pair.client_conn_mut(client).is_handshaking());
    assert!(!pair.server_conn_mut(server).is_closed());
    assert_eq!(pair.server.known_connections(), 1);
}

fn retry_with_failing_key(failure: ProviderFailure) {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut config = server_config();
    config.token_key(Arc::new(FailingTokenKey(failure)));
    pair.server.set_server_config(Some(Arc::new(config)));
    pair.server.handle_incoming = Box::new(|_| IncomingConnectionBehavior::Wait);

    let client_ch = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    let incoming = pair
        .server
        .waiting_incoming
        .pop()
        .expect("the Initial produced an attempt");
    assert!(incoming.may_retry());

    // The caller's buffer already holds unrelated bytes; a failed Retry must leave it as is.
    let mut buf = b"caller-owned".to_vec();
    let error = pair
        .server
        .endpoint
        .retry(incoming, &mut buf)
        .expect_err("a provider that cannot seal must not produce a Retry");
    assert_eq!(error.reason(), RetryRefused::TokenSealing, "{failure:?}");
    assert_eq!(
        buf, b"caller-owned",
        "{failure:?}: nothing was written for the failed Retry"
    );
    // The attempt is untouched: it can still be accepted and the handshake completes.
    let incoming = error.into_incoming();
    assert!(incoming.may_retry());
    let server_ch = pair.server.try_accept(incoming, pair.time).unwrap();
    pair.drive();
    assert!(!pair.client_conn_mut(client_ch).is_handshaking());
    assert!(!pair.server_conn_mut(server_ch).is_closed());
    assert_eq!(pair.server.known_connections(), 1);
}

#[test]
fn new_token_with_a_failing_token_key_is_skipped_without_harming_the_connection() {
    let _guard = subscribe();
    // Control: a working key sends the configured NEW_TOKEN frames.
    let mut control = Pair::default();
    let (_, control_server_ch) = control.connect();
    control.drive();
    assert!(
        control
            .server_conn_mut(control_server_ch)
            .stats()
            .frame_tx
            .new_token
            > 0
    );

    for failure in [ProviderFailure::Derivation, ProviderFailure::Sealing] {
        new_token_with_failing_key(failure);
    }
}

fn new_token_with_failing_key(failure: ProviderFailure) {
    let mut pair = Pair::default();
    let mut config = server_config();
    config.token_key(Arc::new(FailingTokenKey(failure)));
    pair.server.set_server_config(Some(Arc::new(config)));
    let (client_ch, server_ch) = pair.connect();
    pair.drive();
    let stats = pair.server_conn_mut(server_ch).stats();
    assert_eq!(
        stats.frame_tx.new_token, 0,
        "{failure:?}: no fabricated token goes out"
    );
    assert!(
        stats.frame_tx.new_token_failed >= 1,
        "{failure:?}: the skipped frames are observable"
    );
    assert_eq!(
        pair.client_conn_mut(client_ch).stats().frame_rx.new_token,
        0,
        "{failure:?}: the client received no token"
    );
    assert!(!pair.server_conn_mut(server_ch).is_closed());
    assert!(!pair.client_conn_mut(client_ch).is_closed());
    // The client can still open a stream: the connection is fully usable.
    let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    pair.client_send(client_ch, s).write(b"ping").unwrap();
    pair.drive();
    assert!(matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))
    ));
}

/// The null log refuses every validation token in the real admission path: a client that
/// presents a token it was given is treated as unvalidated.
#[test]
fn none_token_log_refuses_presented_validation_tokens() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut config = server_config();
    config
        .validation_token
        .set_log(Arc::new(crate::proto::NoneTokenLog))
        .set_sent(1);
    pair.server.set_server_config(Some(Arc::new(config)));
    let client_config = client_config();
    let (client_ch, server_ch) = pair.connect_with(client_config.clone());
    pair.drive();
    assert!(
        pair.server_conn_mut(server_ch).stats().frame_tx.new_token > 0,
        "a token was issued to the client"
    );
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();

    let seen = Arc::new(Mutex::new(None));
    pair.server.handle_incoming = Box::new({
        let seen = seen.clone();
        move |incoming| {
            *seen.lock() = Some(incoming.remote_address_validated());
            IncomingConnectionBehavior::Accept
        }
    });
    let (_client_ch_2, _server_ch_2) = pair.connect_with(client_config);
    assert_eq!(
        *seen.lock(),
        Some(false),
        "the presented token was refused by the null log"
    );
}

/// The null store keeps nothing: the next connection has no token to present even though the
/// server issued one.
#[test]
fn none_token_store_presents_no_token() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut client_config = client_config();
    client_config.set_token_store(Arc::new(crate::proto::NoneTokenStore));
    let (client_ch, server_ch) = pair.connect_with(client_config.clone());
    pair.drive();
    assert!(pair.server_conn_mut(server_ch).stats().frame_tx.new_token > 0);
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();

    let seen = Arc::new(Mutex::new(None));
    pair.server.handle_incoming = Box::new({
        let seen = seen.clone();
        move |incoming| {
            *seen.lock() = Some(incoming.remote_address_validated());
            IncomingConnectionBehavior::Accept
        }
    });
    let (_client_ch_2, _server_ch_2) = pair.connect_with(client_config);
    assert_eq!(*seen.lock(), Some(false));
}

/// A lifetime the wall clock cannot add to the issue time never validates a token: the checked
/// arithmetic rejects it (INVALID_TOKEN) instead of overflowing.
#[test]
fn retry_token_lifetime_beyond_the_clock_rejects_the_token() {
    let _guard = subscribe();
    let fake_time = Arc::new(FakeTimeSource::at_whole_second());
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let mut config = server_config();
    config
        .set_time_source(Arc::clone(&fake_time) as _)
        .set_retry_token_lifetime(Duration::MAX);
    pair.server.set_server_config(Some(Arc::new(config)));

    let client_ch = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();
    pair.drive();
    assert!(matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::ConnectionClosed(err),
        }) if err.error_code == TransportErrorCode::INVALID_TOKEN
    ));
    assert_eq!(pair.server.known_connections(), 0);
}

/// Retry tokens are valid up to and including `issued + lifetime` and invalid one step later
/// (inclusive policy; RFC 9000 §8.1.3 leaves the lifetime to the server). Only the issue time is
/// encoded in whole seconds; the comparison itself has the time source's resolution.
#[test]
fn retry_token_lifetime_boundary_is_inclusive() {
    let _guard = subscribe();
    let lifetime = Duration::from_secs(1);
    // Immediately before, exactly at and immediately after the lifetime. Issue times are encoded
    // in whole seconds (hence the whole-second fake clock); the comparison itself is exact.
    for (elapsed, expect_connected) in [
        (lifetime.saturating_sub(Duration::from_millis(1)), true),
        (lifetime, true),
        (lifetime + Duration::from_millis(1), false),
    ] {
        let fake_time = Arc::new(FakeTimeSource::at_whole_second());
        let mut pair = Pair::default();
        pair.server.handle_incoming = Box::new(validate_incoming);
        let mut config = server_config();
        config
            .set_time_source(Arc::clone(&fake_time) as _)
            .set_retry_token_lifetime(lifetime);
        pair.server.set_server_config(Some(Arc::new(config)));

        let client_ch = pair.begin_connect(client_config());
        pair.drive_client();
        pair.drive_server(); // Retry issued at T0
        pair.drive_client(); // Initial with the retry token queued for the server
        fake_time.advance(elapsed);
        pair.drive();
        let lost = matches!(
            pair.client_conn_mut(client_ch).poll(),
            Some(Event::ConnectionLost {
                reason: ConnectionError::ConnectionClosed(err),
            }) if err.error_code == TransportErrorCode::INVALID_TOKEN
        );
        assert_eq!(
            !lost, expect_connected,
            "elapsed {elapsed:?}: expected connected={expect_connected}"
        );
        if expect_connected {
            assert!(!pair.client_conn_mut(client_ch).is_handshaking());
            assert_eq!(pair.server.known_connections(), 1);
        }
    }
}

/// Validation (NEW_TOKEN) tokens are accepted immediately before and exactly at
/// `issued + lifetime`, and treated as absent immediately after. Issue times are encoded in
/// whole seconds (hence the whole-second fake clock); the comparison itself is exact.
#[test]
fn validation_token_lifetime_boundary_is_inclusive() {
    let _guard = subscribe();
    let lifetime = Duration::from_secs(60);
    for (elapsed, expect_validated) in [
        (lifetime.saturating_sub(Duration::from_millis(1)), true),
        (lifetime, true),
        (lifetime + Duration::from_millis(1), false),
    ] {
        let fake_time = Arc::new(FakeTimeSource::at_whole_second());
        let mut pair = Pair::default();
        let mut config = server_config();
        config.set_time_source(Arc::clone(&fake_time) as _);
        config.validation_token.set_lifetime(lifetime).set_sent(1);
        pair.server.set_server_config(Some(Arc::new(config)));
        let client_config = client_config();
        let seen = Arc::new(Mutex::new(None));
        pair.server.handle_incoming = Box::new({
            let seen = seen.clone();
            move |incoming| {
                *seen.lock() = Some(incoming.remote_address_validated());
                IncomingConnectionBehavior::Accept
            }
        });
        // Token issued at T0 (a whole second).
        let (ch, server_ch) = pair.connect_with(client_config.clone());
        pair.drive();
        assert!(pair.server_conn_mut(server_ch).stats().frame_tx.new_token > 0);
        pair.client
            .connections
            .get_mut(&ch)
            .unwrap()
            .close(pair.time, VarInt(42), Bytes::new());
        pair.drive();
        fake_time.advance(elapsed);
        let (_ch, _) = pair.connect_with(client_config);
        assert_eq!(
            *seen.lock(),
            Some(expect_validated),
            "elapsed {elapsed:?}: expected validated={expect_validated}"
        );
    }
}

/// A Retry token is sealed with the server's address token key. A server holding the same
/// material reads the token another sealed and the connection completes, carrying a payload; a
/// server holding other material cannot read it, counts it as no token and asks for validation
/// again. The two configurations are built separately from the same seed, which is the case a
/// service run as several servers depends on.
#[test]
fn a_retry_token_is_read_only_under_the_key_that_sealed_it() {
    const SEED: [u8; KEY_MATERIAL_SIZE] = [0x27; KEY_MATERIAL_SIZE];
    const OTHER_SEED: [u8; KEY_MATERIAL_SIZE] = [0x74; KEY_MATERIAL_SIZE];
    const MESSAGE: &[u8] = b"through the second server";

    // The same material, configured twice: the token crosses from one server to the other.
    let (mut pair, client_ch) = retry_across_keys(SEED, SEED);
    assert_eq!(
        pair.server.retries_sent, 1,
        "the token was read, so no second validation was asked for"
    );
    let server_ch = pair.server.assert_accept();

    // Established, not merely alive: a stream opened now arrives with its payload.
    let stream = pair
        .client_streams(client_ch)
        .open(Dir::Bi)
        .expect("a stream opens");
    pair.client_send(client_ch, stream)
        .write(MESSAGE)
        .expect("the write is queued");
    pair.drive();
    assert_eq!(
        pair.server_streams(server_ch).accept(Dir::Bi),
        Some(stream),
        "the server sees the stream"
    );
    let mut received = pair.server_recv(server_ch, stream);
    let mut chunks = received.read(true).expect("the stream is readable");
    let chunk = chunks
        .next(MESSAGE.len())
        .expect("a chunk arrives")
        .expect("with the payload");
    assert_eq!(&chunk.bytes[..], MESSAGE, "the payload arrives as sent");
    let _transmit = chunks.finalize();

    // Other material: the token is unreadable, so it counts as no token (RFC 9000 §8.1.3) and
    // the server asks for validation again. The client discards a Retry once it has accepted
    // one (§17.2.5.2), so within the exchange this drives no connection is established and the
    // client is still trying rather than refused.
    let (mut pair, client_ch) = retry_across_keys(SEED, OTHER_SEED);
    assert!(
        pair.server.retries_sent > 1,
        "the token was not read, so validation was asked for again: {} retries",
        pair.server.retries_sent
    );
    assert_eq!(
        pair.server.known_connections(),
        0,
        "and no connection is established under a key that cannot read the token"
    );
    assert!(
        !pair.client_conn_mut(client_ch).is_closed(),
        "the client was not refused; its attempt simply never validated"
    );
}

/// Issue a Retry under `issuing`, then hand the client's token-bearing Initial to a server
/// configured separately from `reading`, and drive that one packet exchange.
fn retry_across_keys(
    issuing: [u8; KEY_MATERIAL_SIZE],
    reading: [u8; KEY_MATERIAL_SIZE],
) -> (Pair, ConnectionHandle) {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);

    let mut issuing_config = server_config();
    issuing_config.set_address_token_key(AddressTokenKey::from_seed(&issuing));
    pair.server
        .set_server_config(Some(Arc::new(issuing_config)));

    let client_ch = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();

    let mut reading_config = server_config();
    reading_config.set_address_token_key(AddressTokenKey::from_seed(&reading));
    pair.server
        .set_server_config(Some(Arc::new(reading_config)));
    pair.drive();
    (pair, client_ch)
}

/// A copy of an Initial that already produced an attempt, arriving after that attempt was
/// answered with a Retry or refused, is routed like any other first packet rather than to
/// endpoint state that is gone. Both orders are covered: the original before the token, and
/// the token-bearing Initial itself while its attempt is refused.
#[test]
fn a_duplicate_initial_after_retry_or_refusal_is_a_fresh_attempt() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let client_ch = pair.begin_connect(client_config());
    pair.drive_client();
    let first_initial = pair
        .server
        .inbound
        .front()
        .expect("the client's first Initial is on the wire")
        .clone();

    // The first Initial has no token: the server answers with a Retry.
    pair.drive_server();
    assert_eq!(pair.server.retries_sent, 1);

    // The same Initial again, as a duplicate or a replay would arrive.
    let now = pair.time;
    pair.server.inbound.push_back(Inbound {
        at: now,
        ..first_initial
    });
    pair.drive_server();
    assert_eq!(
        pair.server.retries_sent, 2,
        "the duplicate is a new attempt without a token, answered with another Retry"
    );
    assert_eq!(pair.server.known_connections(), 0);

    // The client acts on the first Retry only (RFC 9000 §17.2.5.2) and completes the handshake.
    pair.drive();
    let server_ch = pair.server.assert_accept();
    assert!(!pair.client_conn_mut(client_ch).is_handshaking());
    assert_eq!(pair.server.retries_sent, 2);
    assert!(!pair.server_conn_mut(server_ch).is_closed());
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt(0), Bytes::new());
    pair.drive();

    // Now the token-bearing Initial: its attempt is held, its duplicate arrives, and the attempt
    // is refused. The duplicate presents the same token and becomes an attempt of its own.
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(|incoming| {
        if incoming.remote_address_validated() {
            IncomingConnectionBehavior::Wait
        } else {
            IncomingConnectionBehavior::Retry
        }
    });
    let client_ch = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    assert_eq!(pair.server.retries_sent, 1);
    // The client takes in the Retry; pacing holds the Initial it calls for until its slot.
    pair.drive_client();
    for _ in 0..8 {
        if !pair.server.inbound.is_empty() {
            break;
        }
        let at = pair
            .client
            .next_wakeup()
            .expect("the client has a send pending");
        pair.time = pair.time.max(at);
        pair.drive_client();
    }
    let with_token = pair
        .server
        .inbound
        .front()
        .expect("the client's Initial with the Retry token is on the wire")
        .clone();
    pair.drive_server();
    assert_eq!(pair.server.waiting_incoming.len(), 1, "the attempt is held");

    let now = pair.time;
    pair.server.inbound.push_back(Inbound {
        at: now,
        ..with_token
    });
    let held = pair.server.waiting_incoming.remove(0);
    pair.server.reject(held);
    pair.drive_server();
    assert_eq!(
        pair.server.waiting_incoming.len(),
        1,
        "the duplicate is an attempt of its own once the first is gone"
    );
    let duplicate = pair.server.waiting_incoming.remove(0);
    assert!(duplicate.remote_address_validated());
    pair.server.reject(duplicate);
    pair.drive();

    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
    let mut told = None;
    while let Some(event) = pair.client_conn_mut(client_ch).poll() {
        if let Event::ConnectionLost { reason } = event {
            told = Some(reason);
        }
    }
    match told {
        Some(ConnectionError::ConnectionClosed(close))
            if close.error_code == TransportErrorCode::CONNECTION_REFUSED => {}
        other => panic!("the client learns it was refused, not {other:?}"),
    }
}
