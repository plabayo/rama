//! TLS certificate verifier support for rustls usage in Rama.

use crate::dep::rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use rama_core::conversion::RamaTryFrom;
use rama_net::address::Host;
#[cfg(test)]
use rama_tls::client::{TlsServerCertPin, TlsServerCertPinSet};
use rama_tls::client::{TlsServerCertPinCheck, TlsServerCertPins};
use std::sync::Arc;

/// Exact leaf certificate pinning layered in front of another verifier.
#[derive(Debug)]
pub struct PinnedServerCertVerifier {
    pins: TlsServerCertPins,
    child: Arc<dyn ServerCertVerifier>,
    verify_with_child: bool,
}

impl PinnedServerCertVerifier {
    /// Create a pin verifier that delegates matching certificates to `child`.
    #[must_use]
    pub fn new(pins: TlsServerCertPins, child: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            pins,
            child,
            verify_with_child: true,
        }
    }

    pub(crate) fn pin_only(
        pins: TlsServerCertPins,
        signature_verifier: Arc<dyn ServerCertVerifier>,
    ) -> Self {
        Self {
            pins,
            child: signature_verifier,
            verify_with_child: false,
        }
    }
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin_server_name = Host::rama_try_from(server_name).ok();
        match self.pins.check(pin_server_name.as_ref(), end_entity) {
            TlsServerCertPinCheck::Matched | TlsServerCertPinCheck::NotApplicable => {}
            TlsServerCertPinCheck::Mismatched => {
                return Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ));
            }
        }
        if self.verify_with_child {
            self.child.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
        } else {
            Ok(ServerCertVerified::assertion())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.child.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.child.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.child.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.child.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.child.root_hint_subjects()
    }
}

/// Cert verifier that does not verify the server certificate.
#[derive(Debug)]
#[non_exhaustive]
pub struct NoServerCertVerifier;

impl NoServerCertVerifier {
    /// Create a new instance of the [`NoServerCertVerifier`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for NoServerCertVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerCertVerifier for NoServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct CountingVerifier(AtomicUsize);

    impl ServerCertVerifier for CountingVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    #[test]
    fn pin_match_delegates_to_child() {
        let cert = CertificateDer::from(vec![1, 2, 3]);
        let child = Arc::new(CountingVerifier(AtomicUsize::new(0)));
        let verifier = PinnedServerCertVerifier::new(
            TlsServerCertPins::new(
                TlsServerCertPinSet::try_new([CertificateDer::from(vec![9, 9, 9]), cert.clone()])
                    .unwrap(),
            ),
            child.clone(),
        );

        verifier
            .verify_server_cert(
                &cert,
                &[],
                &ServerName::try_from("example.com").unwrap(),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO),
            )
            .unwrap();

        assert_eq!(child.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![SignatureScheme::ED25519]
        );
    }

    #[test]
    fn pin_mismatch_does_not_call_child() {
        let child = Arc::new(CountingVerifier(AtomicUsize::new(0)));
        let verifier = PinnedServerCertVerifier::new(
            TlsServerCertPins::new(
                TlsServerCertPinSet::try_new([
                    CertificateDer::from(vec![1]),
                    CertificateDer::from(vec![2]),
                ])
                .unwrap(),
            ),
            child.clone(),
        );

        let result = verifier.verify_server_cert(
            &CertificateDer::from(vec![3]),
            &[],
            &ServerName::try_from("example.com").unwrap(),
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::ZERO),
        );

        assert!(matches!(
            result,
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure
            ))
        ));
        assert_eq!(child.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn scoped_pin_set_does_not_apply_to_another_server_name() {
        let cert = CertificateDer::from(vec![3]);
        let child = Arc::new(CountingVerifier(AtomicUsize::new(0)));
        let verifier = PinnedServerCertVerifier::new(
            TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1]))
                    .with_server_name(Host::from_static("other.example.com")),
            ),
            child.clone(),
        );

        verifier
            .verify_server_cert(
                &cert,
                &[],
                &ServerName::try_from("example.com").unwrap(),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO),
            )
            .unwrap();

        assert_eq!(child.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn applicable_pin_sets_are_alternatives() {
        let cert = CertificateDer::from(vec![3]);
        let child = Arc::new(CountingVerifier(AtomicUsize::new(0)));
        let verifier = PinnedServerCertVerifier::new(
            TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1]))
                    .with_server_name(Host::from_static("example.com")),
            )
            .with_pin_set(
                TlsServerCertPinSet::new(cert.clone())
                    .with_server_name(Host::from_static("example.com")),
            ),
            child.clone(),
        );

        verifier
            .verify_server_cert(
                &cert,
                &[],
                &ServerName::try_from("example.com").unwrap(),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO),
            )
            .unwrap();

        assert_eq!(child.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn pin_only_does_not_call_child_certificate_verification() {
        let cert = CertificateDer::from(vec![1, 2, 3]);
        let child = Arc::new(CountingVerifier(AtomicUsize::new(0)));
        let verifier =
            PinnedServerCertVerifier::pin_only(TlsServerCertPins::new(cert.clone()), child.clone());

        verifier
            .verify_server_cert(
                &cert,
                &[],
                &ServerName::try_from("example.com").unwrap(),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO),
            )
            .unwrap();

        assert_eq!(child.0.load(Ordering::Relaxed), 0);
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![SignatureScheme::ED25519]
        );
    }

    #[test]
    fn pin_only_allows_a_server_name_without_an_applicable_pin_set() {
        let child = Arc::new(CountingVerifier(AtomicUsize::new(0)));
        let verifier = PinnedServerCertVerifier::pin_only(
            TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1]))
                    .with_server_name(Host::from_static("other.example.com")),
            ),
            child.clone(),
        );

        verifier
            .verify_server_cert(
                &CertificateDer::from(vec![2]),
                &[],
                &ServerName::try_from("example.com").unwrap(),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO),
            )
            .unwrap();

        assert_eq!(child.0.load(Ordering::Relaxed), 0);
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[test]
    fn matching_pin_still_requires_child_verification() {
        use crate::dep::rustls::{RootCertStore, client::WebPkiServerVerifier};
        use rama_crypto::cert::{SelfSignedData, self_signed_server_auth};

        crate::ensure_default_crypto_provider();
        let (chain, _) = self_signed_server_auth(SelfSignedData::default()).unwrap();
        let leaf = chain[0].clone();
        let ca = chain[1].clone();
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let child = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let verifier = PinnedServerCertVerifier::new(TlsServerCertPins::new(leaf.clone()), child);

        verifier
            .verify_server_cert(
                &leaf,
                std::slice::from_ref(&ca),
                &ServerName::try_from("localhost").unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap();

        let result = verifier.verify_server_cert(
            &leaf,
            &[ca],
            &ServerName::try_from("example.com").unwrap(),
            &[],
            UnixTime::now(),
        );
        result.unwrap_err();
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[test]
    fn spki_pin_matches_leaf_key_through_full_verification() {
        use crate::dep::rustls::{RootCertStore, client::WebPkiServerVerifier};
        use rama_crypto::cert::{SelfSignedData, self_signed_server_auth};

        crate::ensure_default_crypto_provider();
        let (chain, _) = self_signed_server_auth(SelfSignedData::default()).unwrap();
        let leaf = chain[0].clone();
        let ca = chain[1].clone();
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let child = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let verifier = PinnedServerCertVerifier::new(
            TlsServerCertPins::new(TlsServerCertPin::spki_sha256_of(&leaf).unwrap()),
            child,
        );

        verifier
            .verify_server_cert(
                &leaf,
                std::slice::from_ref(&ca),
                &ServerName::try_from("localhost").unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap();
    }
}
