//! Chain verification that exposes the verified chain to a chain policy, and
//! delegation to the platform verifier.

use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use crate::dep::rustls::{
    self, CertificateError, DigitallySignedStruct, OtherError, RootCertStore, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_name,
    },
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
};
use rama_core::{conversion::RamaTryFrom as _, telemetry::tracing};
use rama_crypto::platform_verifier::{PlatformVerifier, PlatformVerifyErrorKind};
use rama_net::address::Host;
use rama_tls::client::{
    ServerCertChain, ServerCertChainKind, ServerChainCertificate, TlsServerCertChainPolicy,
};

/// Where the chain handed to the policy comes from.
#[derive(Debug)]
pub(crate) enum ChainSource {
    /// Verification is disabled: the policy sees the presented chain.
    Presented,
    /// A custom verifier decides: the policy sees the presented chain.
    Delegate(Arc<dyn ServerCertVerifier>),
    /// The chain is verified against `roots`; the policy sees the built path.
    Roots(Arc<RootCertStore>),
    /// The platform verifies the chain; the policy sees the path it built.
    Platform(Arc<PlatformVerifier>),
}

/// Verify the server chain from `source`, then apply an optional chain policy.
#[derive(Debug)]
pub(crate) struct ChainVerifier {
    source: ChainSource,
    chain_policy: Option<TlsServerCertChainPolicy>,
    provider: Arc<CryptoProvider>,
}

impl ChainVerifier {
    pub(crate) fn new(
        source: ChainSource,
        chain_policy: Option<TlsServerCertChainPolicy>,
        provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            source,
            chain_policy,
            provider,
        }
    }

    fn verified_path(
        &self,
        roots: &RootCertStore,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<Vec<ServerChainCertificate<'static>>, rustls::Error> {
        let certificate = webpki::EndEntityCert::try_from(end_entity).map_err(pki_error)?;
        let path = certificate
            .verify_for_usage(
                self.provider.signature_verification_algorithms.all,
                &roots.roots,
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(pki_error)?;
        verify_server_name(&ParsedCertificate::try_from(end_entity)?, server_name)?;

        let mut chain = vec![ServerChainCertificate::certificate(
            end_entity.clone().into_owned(),
        )];
        chain.extend(path.intermediate_certificates().map(|certificate| {
            ServerChainCertificate::certificate(certificate.der().into_owned())
        }));
        chain.push(ServerChainCertificate::trust_anchor(
            der_sequence(&path.anchor().subject_public_key_info).into(),
        ));
        Ok(chain)
    }
}

impl ServerCertVerifier for ChainVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let host = Host::rama_try_from(server_name).ok();
        let (kind, chain) = match &self.source {
            ChainSource::Presented => (
                ServerCertChainKind::Presented,
                presented(end_entity, intermediates),
            ),
            ChainSource::Delegate(verifier) => {
                verifier.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )?;
                (
                    ServerCertChainKind::Presented,
                    presented(end_entity, intermediates),
                )
            }
            ChainSource::Roots(roots) => (
                ServerCertChainKind::Verified,
                self.verified_path(roots, end_entity, intermediates, server_name, now)?,
            ),
            ChainSource::Platform(platform) => {
                let host = host.as_ref().ok_or(rustls::Error::InvalidCertificate(
                    CertificateError::NotValidForName,
                ))?;
                let verify = || {
                    platform.verify_server_chain(
                        end_entity,
                        intermediates,
                        host,
                        Some(ocsp_response),
                        UNIX_EPOCH + Duration::from_secs(now.as_secs()),
                    )
                };
                // rustls verifies inline, while the platform may block on
                // network fetches: hand the worker's other tasks off first.
                let blocking = tokio::runtime::Handle::try_current().is_ok_and(|runtime| {
                    runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
                });
                let verified = if blocking {
                    tokio::task::block_in_place(verify)
                } else {
                    verify()
                };
                let chain = verified.map_err(|err| {
                    tracing::debug!(
                        %host,
                        %err,
                        "rustls connector: platform verifier rejected the server certificate"
                    );
                    platform_error(err.kind(), err)
                })?;
                (
                    ServerCertChainKind::Verified,
                    chain
                        .into_iter()
                        .map(ServerChainCertificate::certificate)
                        .collect(),
                )
            }
        };

        if let Some(policy) = &self.chain_policy
            && let Err(err) = policy.check(&ServerCertChain::new(kind, host.as_ref(), &chain))
        {
            tracing::debug!(
                ?host,
                %err,
                "rustls connector: server certificate chain rejected by policy"
            );
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match &self.source {
            ChainSource::Delegate(verifier) => verifier.verify_tls12_signature(message, cert, dss),
            _ => verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            ),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match &self.source {
            ChainSource::Delegate(verifier) => verifier.verify_tls13_signature(message, cert, dss),
            _ => verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            ),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        match &self.source {
            ChainSource::Delegate(verifier) => verifier.supported_verify_schemes(),
            _ => self
                .provider
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

fn presented(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Vec<ServerChainCertificate<'static>> {
    std::iter::once(end_entity)
        .chain(intermediates)
        .map(|certificate| ServerChainCertificate::certificate(certificate.clone().into_owned()))
        .collect()
}

/// Wrap DER `contents` in a SEQUENCE header: trust anchors keep only the
/// contents of their `SubjectPublicKeyInfo`.
fn der_sequence(contents: &[u8]) -> Vec<u8> {
    let mut der = Vec::with_capacity(contents.len() + 6);
    der.push(0x30);
    match contents.len() {
        len @ 0..0x80 => der.push(len as u8),
        len => {
            let bytes = len.to_be_bytes();
            let skip = bytes.iter().take_while(|byte| **byte == 0).count();
            der.push(0x80 | (bytes.len() - skip) as u8);
            der.extend_from_slice(&bytes[skip..]);
        }
    }
    der.extend_from_slice(contents);
    der
}

fn platform_error(
    kind: PlatformVerifyErrorKind,
    err: rama_crypto::platform_verifier::PlatformVerifyError,
) -> rustls::Error {
    let error = match kind {
        PlatformVerifyErrorKind::UnknownIssuer => CertificateError::UnknownIssuer,
        PlatformVerifyErrorKind::Expired => CertificateError::Expired,
        PlatformVerifyErrorKind::NotValidForName => CertificateError::NotValidForName,
        PlatformVerifyErrorKind::Revoked => CertificateError::Revoked,
        PlatformVerifyErrorKind::InvalidPurpose => CertificateError::InvalidPurpose,
        PlatformVerifyErrorKind::BadEncoding => CertificateError::BadEncoding,
        _ => CertificateError::Other(OtherError(Arc::new(err))),
    };
    rustls::Error::InvalidCertificate(error)
}

/// The rustls equivalent of a path building failure, as rustls maps it.
fn pki_error(error: webpki::Error) -> rustls::Error {
    use webpki::Error;

    let error = match error {
        Error::BadDer | Error::BadDerTime | Error::TrailingData(_) => CertificateError::BadEncoding,
        Error::CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }
        }
        Error::CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }
        }
        Error::InvalidCertValidity => CertificateError::Expired,
        Error::UnknownIssuer => CertificateError::UnknownIssuer,
        Error::CertNotValidForName(webpki::InvalidNameContext {
            expected,
            presented,
        }) => CertificateError::NotValidForNameContext {
            expected,
            presented,
        },
        Error::CertRevoked => CertificateError::Revoked,
        Error::UnknownRevocationStatus => CertificateError::UnknownRevocationStatus,
        Error::InvalidSignatureForPublicKey => CertificateError::BadSignature,
        Error::RequiredEkuNotFoundContext(_) => CertificateError::InvalidPurpose,
        error => CertificateError::Other(OtherError(Arc::new(error))),
    };
    rustls::Error::InvalidCertificate(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_sequence_encodes_short_and_long_lengths() {
        assert_eq!(der_sequence(&[1, 2]), [0x30, 2, 1, 2]);
        let long = vec![7; 300];
        let encoded = der_sequence(&long);
        assert_eq!(&encoded[..4], &[0x30, 0x82, 0x01, 0x2c]);
        assert_eq!(&encoded[4..], long.as_slice());
    }
}
