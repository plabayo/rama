//! Records what a server answered a client's ClientHello with, for server fingerprints and
//! for a relay that answers its own client the same way.

use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;
use rama_boring::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslContentType, SslOptions, SslRef},
};
use rama_core::error::{BoxError, ErrorContext as _};
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
    pub fn apply(&self, ssl: &mut SslRef) -> Result<(), BoxError> {
        match &self.cipher {
            Some(PinnedCipher::Tls13(id)) => ssl
                .set_strict_tls13_server_ciphers(&[*id])
                .context("pin the origin's cipher")?,
            Some(PinnedCipher::Tls12(name)) => ssl
                .set_strict_cipher_list(name)
                .context("pin the origin's cipher")?,
            None => {}
        }
        if !self.order.is_empty() {
            ssl.set_server_extension_order(&self.order)
                .context("mirror the origin's extension order")?;
        }
        if self.no_ticket {
            ssl.set_options(SslOptions::NO_TICKET);
        }
        Ok(())
    }
}
