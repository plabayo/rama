use std::fmt;

use rama_core::extensions::Extensions;

use crate::{
    CipherSuite, ExtensionId, ProtocolVersion, client::NegotiatedTlsParameters, server::ServerHello,
};

#[derive(Debug, Clone, PartialEq)]
/// Data which can be hashed using [`Self::hash`], and which is also displayed as a "ja3s"
/// string: a server's answer to a ClientHello.
///
/// Computed using [`Ja3S::compute`] or [`Ja3S::compute_from_server_hello`].
pub struct Ja3S {
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    extensions: Vec<ExtensionId>,
}

impl Ja3S {
    /// Compute the [`Ja3S`] of the ServerHello a client connection stored in its
    /// [`NegotiatedTlsParameters`] (see `TlsClientConfig::store_server_hello`).
    ///
    /// As specified by <https://github.com/salesforce/ja3>.
    pub fn compute(ext: &Extensions) -> Result<Self, Ja3SComputeError> {
        ext.get_ref::<NegotiatedTlsParameters>()
            .and_then(|params| params.server_hello.as_ref())
            .map(Self::compute_from_server_hello)
            .ok_or(Ja3SComputeError::MissingServerHello)
    }

    /// Compute the [`Ja3S`] of a [`ServerHello`]: its legacy version, cipher suite and
    /// extensions in the order the server sent them, GREASE included, as the reference
    /// implementation does.
    #[must_use]
    pub fn compute_from_server_hello(hello: &ServerHello) -> Self {
        Self {
            version: hello.legacy_version(),
            cipher_suite: hello.cipher_suite(),
            extensions: hello.extensions().to_vec(),
        }
    }

    #[inline]
    /// compute the "ja3s" hash from this [`Ja3S`] data structure as a String.
    #[must_use]
    pub fn hash(&self) -> String {
        format!("{self:x}")
    }

    fn write_to(&self, w: &mut impl fmt::Write) -> fmt::Result {
        write!(
            w,
            "{},{},",
            u16::from(self.version),
            u16::from(self.cipher_suite)
        )?;
        let mut first = true;
        for extension in &self.extensions {
            if !first {
                w.write_char('-')?;
            }
            first = false;
            write!(w, "{}", u16::from(*extension))?;
        }
        Ok(())
    }

    fn hash_to(&self, w: &mut impl fmt::Write, lower: bool) -> fmt::Result {
        let mut ctx = Md5Writer(md5::Context::new());
        self.write_to(&mut ctx)?;
        let digest = ctx.0.finalize();
        if lower {
            write!(w, "{digest:x}")
        } else {
            write!(w, "{digest:X}")
        }
    }
}

/// Feeds formatted text into MD5 without building the string first.
struct Md5Writer(md5::Context);

impl fmt::Write for Md5Writer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.consume(value.as_bytes());
        Ok(())
    }
}

impl fmt::Display for Ja3S {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f)
    }
}

impl fmt::LowerHex for Ja3S {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.hash_to(f, true)
    }
}

impl fmt::UpperHex for Ja3S {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.hash_to(f, false)
    }
}

#[derive(Debug, Clone)]
/// error identifying a failure in [`Ja3S::compute`]
pub enum Ja3SComputeError {
    /// missing ServerHello: not stored, or not observable by the backend
    MissingServerHello,
}

impl fmt::Display for Ja3SComputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingServerHello => write!(f, "Ja3S Compute Error: missing server hello"),
        }
    }
}

impl std::error::Error for Ja3SComputeError {}

rama_utils::macros::serde_str::impl_serde_str!(serialize display Ja3S);

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello(cipher: u16, extensions: &[(u16, &[u8])]) -> ServerHello {
        let mut extensions_bytes = Vec::new();
        for (id, data) in extensions {
            extensions_bytes.extend_from_slice(&id.to_be_bytes());
            extensions_bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            extensions_bytes.extend_from_slice(data);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x42; 32]);
        body.push(0);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        if !extensions.is_empty() {
            body.extend_from_slice(&u16::try_from(extensions_bytes.len()).unwrap().to_be_bytes());
            body.extend_from_slice(&extensions_bytes);
        }
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        let mut message = vec![2, len[1], len[2], len[3]];
        message.extend_from_slice(&body);
        ServerHello::parse_handshake(&message).unwrap()
    }

    #[test]
    fn the_string_lists_version_cipher_and_extensions_in_order() {
        let hello = server_hello(0xc02f, &[(0xff01, &[0]), (0x0000, &[]), (0x000b, &[1, 0])]);
        let ja3s = Ja3S::compute_from_server_hello(&hello);
        assert_eq!(ja3s.to_string(), "771,49199,65281-0-11");
        // `md5` of the string above (computed outside Rama), as the reference hashes it.
        assert_eq!(ja3s.hash(), "a704460bd0a887c62e4f462bf1bba96b");
        assert_eq!(format!("{ja3s:X}"), "A704460BD0A887C62E4F462BF1BBA96B");
    }

    #[test]
    fn tls13_keeps_the_legacy_version_and_grease() {
        let hello = server_hello(
            0x1301,
            &[(0x0a0a, &[]), (0x002b, &[3, 4]), (0x0033, &[0, 0x1d, 0, 0])],
        );
        assert_eq!(
            Ja3S::compute_from_server_hello(&hello).to_string(),
            "771,4865,2570-43-51"
        );
    }

    #[test]
    fn no_extensions_leave_an_empty_field() {
        let hello = server_hello(0x002f, &[]);
        assert_eq!(
            Ja3S::compute_from_server_hello(&hello).to_string(),
            "771,47,"
        );
    }

    #[test]
    fn a_connection_without_a_stored_server_hello_reports_it() {
        let ext = Extensions::new();
        assert!(matches!(
            Ja3S::compute(&ext),
            Err(Ja3SComputeError::MissingServerHello)
        ));
    }
}
