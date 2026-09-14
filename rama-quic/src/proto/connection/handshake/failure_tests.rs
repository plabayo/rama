use super::*;
use crate::proto::{
    ConnectionId, Side, TransportErrorCode,
    crypto::{ExportKeyingMaterialError, HeaderKey, PacketKey, Session},
    tests::Pair,
};

struct FailedKeyUpdate {
    missing: bool,
}

impl Session for FailedKeyUpdate {
    #[expect(
        clippy::panic,
        reason = "the test installs this session after the handshake"
    )]
    fn initial_keys(&self, _: &ConnectionId, _: Side) -> Keys {
        panic!("handshake already completed")
    }
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }
    fn early_data_accepted(&self) -> Option<bool> {
        Some(false)
    }
    fn is_handshaking(&self) -> bool {
        false
    }
    #[expect(
        clippy::panic,
        reason = "the test injects only a post-handshake key update failure"
    )]
    fn read_handshake(&mut self, _: SpaceId, _: &[u8]) -> Result<bool, TransportError> {
        panic!("failure is injected after handshake completion")
    }
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(None)
    }
    fn poll_handshake(&mut self) -> Result<Option<crypto::HandshakeEvent>, TransportError> {
        Ok(None)
    }
    fn next_1rtt_keys(&mut self) -> Result<Option<KeyPair<Box<dyn PacketKey>>>, TransportError> {
        if self.missing {
            Ok(None)
        } else {
            Err(TransportError::INTERNAL_ERROR(
                "injected key derivation failure",
            ))
        }
    }
    fn is_valid_retry(&self, _: &ConnectionId, _: &[u8], _: &[u8]) -> bool {
        false
    }
    fn export_keying_material(
        &self,
        _: &mut [u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        Err(ExportKeyingMaterialError)
    }
}

#[test]
fn failed_key_derivation_closes_without_rotating_or_counting_an_update() {
    for missing in [false, true] {
        let mut pair = Pair::default();
        let (client, _) = pair.connect();
        let now = pair.time;
        let connection = pair.client_conn_mut(client);
        connection.crypto = Box::new(FailedKeyUpdate { missing });
        let phase = connection.key_phase;
        let sent = connection.spaces[SpaceId::Data].sent_with_keys;
        let updates = connection.stats.key_updates;
        assert!(!connection.force_key_update(now));
        assert_eq!(connection.key_phase, phase);
        assert_eq!(connection.spaces[SpaceId::Data].sent_with_keys, sent);
        assert_eq!(connection.stats.key_updates, updates);
        assert!(connection.prev_crypto.is_none());
        assert!(
            matches!(connection.ended_because(), Some(ConnectionError::TransportError(error))
            if error.code == TransportErrorCode::INTERNAL_ERROR)
        );
    }
}
