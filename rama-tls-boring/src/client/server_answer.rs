//! Records what a server answered a client's ClientHello with, for server fingerprints and
//! for a relay that answers its own client the same way.

use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;
use rama_boring::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslContentType, SslOptions, SslRef},
};
use rama_core::{error::BoxError, telemetry::tracing::debug};
use rama_tls::{CipherSuite, ExtensionId, ProtocolVersion, server::ServerHello};

use crate::type_conversion::openssl_cipher_str_from_cipher_suite;

const SERVER_HELLO: u8 = 2;
const ENCRYPTED_EXTENSIONS: u8 = 8;

static RECORDER_INDEX: LazyLock<Result<Index<Ssl, ServerAnswerRecorder>, ErrorStack>> =
    LazyLock::new(Ssl::new_ex_index::<ServerAnswerRecorder>);

/// The ServerHello and EncryptedExtensions one client connection received, recorded by its
/// message callback. A HelloRetryRequest is replaced by the ServerHello after it.
#[derive(Debug, Clone, Default)]
pub struct ServerAnswerRecorder(Arc<Mutex<Recorded>>);

#[derive(Debug, Default)]
struct Recorded {
    server_hello: Option<Vec<u8>>,
    encrypted_extensions: Option<Vec<u8>>,
}

impl ServerAnswerRecorder {
    /// The recorder of `ssl`, installing one first if it has none. A connection has one
    /// message callback, so every observer of the answer shares this recorder.
    pub fn of(ssl: &mut SslRef) -> Result<Self, BoxError> {
        let index = *RECORDER_INDEX.as_ref().map_err(|error| error.clone())?;
        if let Some(recorder) = ssl.ex_data(index) {
            return Ok(recorder.clone());
        }
        let recorder = Self::default();
        let recorded = recorder.0.clone();
        ssl.set_msg_callback(move |_, message| {
            if message.is_written() || message.content_type() != SslContentType::HANDSHAKE {
                return;
            }
            let bytes = message.bytes();
            match bytes.first() {
                Some(&SERVER_HELLO) => recorded.lock().server_hello = Some(bytes.to_vec()),
                Some(&ENCRYPTED_EXTENSIONS) => {
                    recorded.lock().encrypted_extensions = Some(bytes.to_vec());
                }
                _ => {}
            }
        });
        ssl.set_ex_data(index, recorder.clone());
        Ok(recorder)
    }

    /// The recorder `ssl` was given, if any.
    pub fn installed(ssl: &SslRef) -> Option<Self> {
        let index = *RECORDER_INDEX.as_ref().ok()?;
        ssl.ex_data(index).cloned()
    }

    /// The ServerHello received so far, read as sent over QUIC when `quic`.
    pub fn server_hello(&self, quic: bool) -> Option<ServerHello> {
        let recorded = self.0.lock();
        let bytes = recorded.server_hello.as_deref()?;
        if quic {
            ServerHello::parse_quic_handshake(bytes).ok()
        } else {
            ServerHello::parse_handshake(bytes).ok()
        }
    }

    /// What a relay's ingress repeats of this answer to a client that offered
    /// `client_ciphers` (unknown: `None`), so the client sees the answer the origin gave.
    #[must_use]
    pub fn mirror_for(&self, client_ciphers: Option<&[CipherSuite]>, quic: bool) -> AnswerMirror {
        let Some(server_hello) = self.server_hello(quic) else {
            return AnswerMirror::default();
        };
        let cipher = server_hello.cipher_suite();
        // Pinning a cipher the client did not offer would fail its handshake.
        let cipher = client_ciphers
            .is_some_and(|offered| offered.contains(&cipher))
            .then(|| {
                if server_hello.protocol_version() == ProtocolVersion::TLSv1_3 {
                    Some(PinnedCipher::Tls13(u16::from(cipher)))
                } else {
                    openssl_cipher_str_from_cipher_suite(cipher).map(PinnedCipher::Tls12)
                }
            })
            .flatten();
        let order = server_hello
            .extensions()
            .iter()
            .chain(self.encrypted_extensions().as_deref().unwrap_or_default())
            .map(|id| u16::from(*id))
            .collect();
        // A TLS 1.2 ServerHello answers a ticket offer only when the server issues tickets.
        let no_ticket = server_hello.protocol_version() != ProtocolVersion::TLSv1_3
            && !server_hello
                .extensions()
                .contains(&ExtensionId::SESSION_TICKET);
        AnswerMirror {
            cipher,
            order,
            no_ticket,
        }
    }

    /// The extensions of the EncryptedExtensions received so far (TLS 1.3), in order.
    pub fn encrypted_extensions(&self) -> Option<Vec<ExtensionId>> {
        let recorded = self.0.lock();
        rama_tls::server::parse_encrypted_extensions(recorded.encrypted_extensions.as_deref()?).ok()
    }
}

/// The origin's cipher (pinned only when the client offered it), the order of its
/// ServerHello and EncryptedExtensions extensions, and (TLS 1.2) whether it answered a
/// ticket offer, for a relay's ingress handshake.
#[derive(Debug, Clone, Default)]
pub struct AnswerMirror {
    cipher: Option<PinnedCipher>,
    order: Vec<u16>,
    no_ticket: bool,
}

#[derive(Debug, Clone)]
enum PinnedCipher {
    Tls13(u16),
    Tls12(&'static str),
}

impl AnswerMirror {
    /// Configure a server connection, before its handshake, to answer as the origin did.
    /// Each part is best effort: one the connection cannot take keeps its native behaviour.
    pub fn apply(&self, ssl: &mut SslRef) {
        let pinned = match &self.cipher {
            Some(PinnedCipher::Tls13(id)) => ssl.set_strict_tls13_server_ciphers(&[*id]),
            Some(PinnedCipher::Tls12(name)) => ssl.set_strict_cipher_list(name),
            None => Ok(()),
        };
        if let Err(error) = pinned {
            debug!(cipher = ?self.cipher, %error, "answer mirror: origin cipher not pinned");
        }
        if !self.order.is_empty()
            && let Err(error) = ssl.set_server_extension_order(&self.order)
        {
            debug!(
                order = ?self.order,
                %error,
                "answer mirror: origin extension order not mirrored"
            );
        }
        if self.no_ticket {
            ssl.set_options(SslOptions::NO_TICKET);
        }
    }
}

#[cfg(test)]
mod tests {
    use rama_boring::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};
    use rama_tls::server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig};

    use super::*;
    use crate::server::TlsAcceptorData;

    fn acceptor(version: SslVersion) -> SslAcceptor {
        let server_auth =
            ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let config = TlsServerConfig::new().with_server_auth(server_auth);
        let mut acceptor = TlsAcceptorData::try_from(&config)
            .unwrap()
            .into_static_acceptor_builder()
            .unwrap();
        acceptor.set_max_proto_version(Some(version)).unwrap();
        acceptor.build()
    }

    /// Handshakes a client capped at `version` with a server the mirror configured.
    async fn handshake(version: SslVersion, mirror: &AnswerMirror) -> (u16, SslOptions) {
        let acceptor = acceptor(version);
        let mut ssl = Ssl::new(acceptor.context()).unwrap();
        mirror.apply(&mut ssl);
        let options = ssl.set_options(SslOptions::empty());
        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        connector.set_max_proto_version(Some(version)).unwrap();
        let config = connector.build().configure().unwrap();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client, server) = tokio::join!(
            rama_boring_tokio::connect(config, Some("localhost"), client_io),
            rama_boring_tokio::SslStreamBuilder::new(ssl, server_io).accept(),
        );
        let (client, _server) = (client.unwrap(), server.unwrap());
        let cipher = client.ssl().current_cipher().unwrap().protocol_id();
        (cipher, options)
    }

    fn unorderable() -> Vec<u16> {
        (0..300).collect()
    }

    #[test]
    fn the_unappliable_mirror_steps_are_rejected_by_the_connection() {
        let acceptor = acceptor(SslVersion::TLS1_3);
        let mut ssl = Ssl::new(acceptor.context()).unwrap();
        ssl.set_strict_cipher_list("NOT-A-CIPHER").unwrap_err();
        ssl.set_strict_tls13_server_ciphers(&[0x0005]).unwrap_err();
        ssl.set_server_extension_order(&unorderable()).unwrap_err();
    }

    #[tokio::test]
    async fn an_unpinnable_cipher_keeps_the_handshake_and_the_rest_of_the_mirror() {
        let mirror = AnswerMirror {
            cipher: Some(PinnedCipher::Tls12("NOT-A-CIPHER")),
            order: vec![0xff01, 0x0017],
            no_ticket: true,
        };
        let (_, options) = handshake(SslVersion::TLS1_2, &mirror).await;
        assert!(options.contains(SslOptions::NO_TICKET));

        // 0x0005 is no TLS 1.3 cipher suite.
        let mirror = AnswerMirror {
            cipher: Some(PinnedCipher::Tls13(0x0005)),
            ..AnswerMirror::default()
        };
        handshake(SslVersion::TLS1_3, &mirror).await;
    }

    #[tokio::test]
    async fn an_unmirrorable_extension_order_keeps_the_pinned_cipher() {
        let aes_256 = u16::from(CipherSuite::TLS13_AES_256_GCM_SHA384);
        let mirror = AnswerMirror {
            cipher: Some(PinnedCipher::Tls13(aes_256)),
            order: unorderable(),
            no_ticket: false,
        };
        let (cipher, _) = handshake(SslVersion::TLS1_3, &mirror).await;
        assert_eq!(cipher, aes_256);

        let mirror = AnswerMirror {
            order: unorderable(),
            no_ticket: true,
            ..AnswerMirror::default()
        };
        let (_, options) = handshake(SslVersion::TLS1_2, &mirror).await;
        assert!(options.contains(SslOptions::NO_TICKET));
    }
}
