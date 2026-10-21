//! Per-connection server certificate checks: platform verification, pins and
//! chain policies.

use std::{sync::Arc, time::SystemTime};

use rama_boring::{
    ssl::{
        BoxCustomVerifyFinish, ConnectConfiguration, SslAlert, SslRef, SslVerifyError,
        SslVerifyMode,
    },
    stack::StackRef,
    x509::{X509, X509StoreContext, X509StoreContextRef},
};
use rama_core::telemetry::tracing;
use rama_crypto::{
    pki_types::CertificateDer,
    platform_verifier::{PlatformVerifier, PlatformVerifyErrorKind},
};
use rama_net::address::{Domain, Host};
use rama_tls::client::{
    ServerCertChain, ServerCertChainKind, ServerChainCertificate, ServerVerifyMode,
    TlsServerCertChainPolicy, TlsServerCertPinCheck, TlsServerCertPins,
};

/// The checks a connection applies to the server certificate.
pub(super) struct ServerVerification {
    pub(super) mode: ServerVerifyMode,
    pub(super) pins: Option<TlsServerCertPins>,
    pub(super) chain_policy: Option<TlsServerCertChainPolicy>,
    /// Set when the trust source delegates chain validation to the platform.
    pub(super) platform: Option<Arc<PlatformVerifier>>,
}

/// Install the callbacks enforcing `verification` on one connection.
pub(super) fn configure_server_verification(
    config: &mut ConnectConfiguration,
    verification: ServerVerification,
    server_name: Option<&Host>,
) {
    let ServerVerification {
        mode,
        pins,
        chain_policy,
        platform,
    } = verification;
    let checks = PostVerifyChecks {
        pins,
        chain_policy,
        server_name: server_name.cloned(),
    };

    match (mode, platform) {
        (ServerVerifyMode::Disable, _) => {
            if checks.is_empty() {
                return;
            }
            config.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                let ech_public_name = ech_public_name(ssl).map_err(SslVerifyError::Invalid)?;
                if !checks.need_certificate(ech_public_name.as_ref()) {
                    return Ok(());
                }
                presented_chain(ssl)
                    .and_then(|presented| {
                        checks.check(
                            ServerCertChainKind::Presented,
                            &presented,
                            ech_public_name.as_ref(),
                        )
                    })
                    .map_err(SslVerifyError::Invalid)
            });
        }
        (ServerVerifyMode::Auto, Some(platform)) => {
            let checks = Arc::new(checks);
            config.set_async_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                let presented = presented_chain(ssl)?;
                let ocsp_response = ssl.ocsp_status().map(<[u8]>::to_vec);
                let ech_public_name = ech_public_name(ssl)?;
                // Connections that verify always carry a server identity.
                let server_name = ech_public_name
                    .clone()
                    .or_else(|| checks.server_name.clone())
                    .ok_or(SslAlert::INTERNAL_ERROR)?;
                let platform = platform.clone();
                let checks = checks.clone();
                Ok(Box::pin(async move {
                    let outcome =
                        verify_with_platform(platform, presented, server_name, ocsp_response)
                            .await
                            .and_then(|chain| {
                                checks.check(
                                    ServerCertChainKind::Verified,
                                    &chain,
                                    ech_public_name.as_ref(),
                                )
                            });
                    Ok(Box::new(move |_: &mut SslRef| outcome) as BoxCustomVerifyFinish)
                }))
            });
        }
        (ServerVerifyMode::Auto, None) => {
            if checks.is_empty() {
                return;
            }
            config.set_verify_callback(SslVerifyMode::PEER, move |preverified, store_ctx| {
                // Only the leaf, after every issuer verified, sees the built path.
                if !preverified || store_ctx.error_depth() != 0 {
                    return preverified;
                }
                let Some(chain) = store_ctx.chain() else {
                    return false;
                };
                // BoringSSL already verified the name against an ECH public name.
                let Ok(ech_public_name) = store_ech_public_name(store_ctx) else {
                    return false;
                };
                der_chain(chain)
                    .and_then(|chain| {
                        checks.check(
                            ServerCertChainKind::Verified,
                            &chain,
                            ech_public_name.as_ref(),
                        )
                    })
                    .is_ok()
            });
        }
    }
}

/// Pins and chain policy, enforced after the chain is otherwise accepted.
struct PostVerifyChecks {
    pins: Option<TlsServerCertPins>,
    chain_policy: Option<TlsServerCertChainPolicy>,
    server_name: Option<Host>,
}

impl PostVerifyChecks {
    fn is_empty(&self) -> bool {
        self.pins.is_none() && self.chain_policy.is_none()
    }

    /// Whether any check applies to this server, and therefore needs its certificate.
    fn need_certificate(&self, ech_public_name: Option<&Host>) -> bool {
        self.chain_policy.is_some()
            || (ech_public_name.is_none()
                && self
                    .pins
                    .as_ref()
                    .is_some_and(|pins| pins.applies_to(self.server_name.as_ref())))
    }

    /// Check `chain`. After an ECH rejection it belongs to the ECH public name,
    /// not to the pinned origin, and only authenticates the retry configs.
    fn check(
        &self,
        kind: ServerCertChainKind,
        chain: &[CertificateDer<'static>],
        ech_public_name: Option<&Host>,
    ) -> Result<(), SslAlert> {
        let Some(leaf) = chain.first() else {
            return Err(SslAlert::BAD_CERTIFICATE);
        };
        let server_name = ech_public_name.or(self.server_name.as_ref());
        if ech_public_name.is_none()
            && let Some(pins) = &self.pins
            && pins.check(server_name, leaf) == TlsServerCertPinCheck::Mismatched
        {
            tracing::debug!(
                ?server_name,
                "boring connector: server certificate pin mismatch"
            );
            return Err(SslAlert::BAD_CERTIFICATE);
        }
        if let Some(policy) = &self.chain_policy {
            let certificates: Vec<_> = chain
                .iter()
                .map(|certificate| ServerChainCertificate::certificate(certificate.clone()))
                .collect();
            if let Err(err) = policy.check(&ServerCertChain::new(kind, server_name, &certificates))
            {
                tracing::debug!(
                    ?server_name,
                    %err,
                    "boring connector: server certificate chain rejected by policy"
                );
                return Err(SslAlert::BAD_CERTIFICATE);
            }
        }
        Ok(())
    }
}

/// The ECH public name to verify against, set only when the server rejected
/// ECH: such a handshake never completes and only authenticates retry configs.
fn ech_public_name(ssl: &SslRef) -> Result<Option<Host>, SslAlert> {
    match ssl.get_ech_name_override() {
        None | Some([]) => Ok(None),
        Some(name) => std::str::from_utf8(name)
            .ok()
            .and_then(|name| Domain::try_from(name).ok())
            .map(|name| Some(Host::from(name)))
            .ok_or(SslAlert::BAD_CERTIFICATE),
    }
}

fn store_ech_public_name(store_ctx: &X509StoreContextRef) -> Result<Option<Host>, SslAlert> {
    let index = X509StoreContext::ssl_idx().map_err(|_no_index| SslAlert::INTERNAL_ERROR)?;
    let ssl = store_ctx.ex_data(index).ok_or(SslAlert::INTERNAL_ERROR)?;
    ech_public_name(ssl)
}

/// The chain as the server sent it; on a client, the leaf comes first.
fn presented_chain(ssl: &SslRef) -> Result<Vec<CertificateDer<'static>>, SslAlert> {
    ssl.peer_cert_chain().map_or(Ok(Vec::new()), der_chain)
}

/// Every certificate, so no position shifts onto another certificate.
fn der_chain(chain: &StackRef<X509>) -> Result<Vec<CertificateDer<'static>>, SslAlert> {
    chain
        .iter()
        .map(|certificate| {
            certificate
                .to_der()
                .map(CertificateDer::from)
                .map_err(|_encode_error| SslAlert::BAD_CERTIFICATE)
        })
        .collect()
}

/// Verify off the async executor: the platform may block on network fetches.
async fn verify_with_platform(
    platform: Arc<PlatformVerifier>,
    presented: Vec<CertificateDer<'static>>,
    server_name: Host,
    ocsp_response: Option<Vec<u8>>,
) -> Result<Vec<CertificateDer<'static>>, SslAlert> {
    let verify = move || {
        let (leaf, intermediates) = presented
            .split_first()
            .ok_or(PlatformVerifyErrorKind::BadEncoding)?;
        platform
            .verify_server_chain(
                leaf,
                intermediates,
                &server_name,
                ocsp_response.as_deref(),
                SystemTime::now(),
            )
            .map_err(|err| {
                tracing::debug!(
                    %server_name,
                    %err,
                    "boring connector: platform verifier rejected the server certificate"
                );
                err.kind()
            })
    };
    let outcome = match tokio::runtime::Handle::try_current() {
        Ok(runtime) => runtime
            .spawn_blocking(verify)
            .await
            .map_err(|_join_error| SslAlert::INTERNAL_ERROR)?,
        Err(_no_runtime) => verify(),
    };
    outcome.map_err(alert_for)
}

fn alert_for(kind: PlatformVerifyErrorKind) -> SslAlert {
    match kind {
        PlatformVerifyErrorKind::UnknownIssuer => SslAlert::UNKNOWN_CA,
        PlatformVerifyErrorKind::Expired => SslAlert::CERTIFICATE_EXPIRED,
        PlatformVerifyErrorKind::Revoked => SslAlert::CERTIFICATE_REVOKED,
        PlatformVerifyErrorKind::NotValidForName | PlatformVerifyErrorKind::BadEncoding => {
            SslAlert::BAD_CERTIFICATE
        }
        PlatformVerifyErrorKind::InvalidPurpose => SslAlert::UNSUPPORTED_CERTIFICATE,
        PlatformVerifyErrorKind::Unavailable => SslAlert::INTERNAL_ERROR,
        _ => SslAlert::CERTIFICATE_UNKNOWN,
    }
}
