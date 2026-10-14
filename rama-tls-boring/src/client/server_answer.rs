//! Records what a server answered a client's ClientHello with, for server fingerprints and
//! for a relay that answers its own client the same way.

use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;
use rama_boring::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslContentType, SslRef},
};
use rama_core::error::BoxError;
use rama_tls::{ExtensionId, server::ServerHello};

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

    /// The extensions of the EncryptedExtensions received so far (TLS 1.3), in order.
    pub fn encrypted_extensions(&self) -> Option<Vec<ExtensionId>> {
        let recorded = self.0.lock();
        rama_tls::server::parse_encrypted_extensions(recorded.encrypted_extensions.as_deref()?).ok()
    }
}
