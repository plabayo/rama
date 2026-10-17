//! Compile captured TLS connections for this connector's native backend.
//!
//! Preparation borrows the consuming connector's policy before transport I/O.
//! The connector future owns the native session; caller TLS extensions retain
//! their original meaning throughout selection, dialing and pool reuse.

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
};
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt,
    address::{Host, HostWithOptPort},
};
use rama_tls::client::{TlsClientConfig, TlsConnectionReuse, TlsPoolId};
use rama_ua::profile::{
    capture::{
        joint::CapturedSlotKind,
        tls::{TlsCapture, TlsCaptureTransport, TlsCapturedExtensionValue},
    },
    replay::connection::{compiler::CompiledConnectionProfile, preparation::ConnectionPreparation},
};

use super::{
    BoringTlsClientConfigProvider, BoringTlsConnectorConfig, connector::PreparedHandshake,
};

#[cfg(feature = "http")]
use rama_net::http::{FallbackHttpVersion, HttpRequestVersion, TargetHttpVersion, Version};
#[cfg(feature = "http")]
use rama_ua::profile::{model::http::HttpProfile, replay::connection::http::apply_legacy_settings};

pub mod wire;

/// Borrows the policy of the connector that will consume the native session.
#[derive(Debug)]
pub(super) struct Compiler<'a> {
    pub(super) base: Option<&'a TlsClientConfig>,
    pub(super) has_sessions: bool,
}

#[derive(Debug)]
struct CompiledConnection {
    tls: Option<NativeConnection>,
}

/// Held by the connector future, never installed in request extensions.
#[derive(Debug)]
pub(super) struct PreparedProfile {
    preparation: ConnectionPreparation,
    native: CompiledConnection,
}

#[derive(Debug)]
struct NativeConnection {
    authority: HostWithOptPort,
    protocol: Protocol,
    #[cfg(feature = "http")]
    target_version: Option<Version>,
    caller_policy: Option<TlsPoolId>,
    fallback: TlsConnectionReuse<BoringTlsClientConfigProvider>,
    prepared: PreparedHandshake,
}

/// Selection publication outlives the move of the native handshake into TLS.
pub(super) struct Publication {
    preparation: ConnectionPreparation,
    fallback: Option<TlsConnectionReuse<BoringTlsClientConfigProvider>>,
}

fn effective(extensions: &Extensions, base: Option<&TlsClientConfig>) -> Extensions {
    let effective = extensions.fork();
    match base {
        Some(base) => effective.with_base(base.as_extensions()),
        None => effective,
    }
}

impl Compiler<'_> {
    pub(super) fn prepare_profile(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
    ) -> Result<Option<PreparedProfile>, BoxError> {
        let Some((mut preparation, native)) =
            ConnectionPreparation::prepare(input, |_, components, _| {
                match components.tls.take() {
                    Some(capture) => self.prepare(input, &capture),
                    None => Ok(CompiledConnection { tls: None }),
                }
            })?
        else {
            return Ok(None);
        };
        preparation.apply_http(input)?;
        Ok(Some(PreparedProfile {
            preparation,
            native,
        }))
    }

    fn prepare(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        capture: &TlsCapture,
    ) -> Result<CompiledConnection, BoxError> {
        if !matches!(capture.transport, TlsCaptureTransport::Tcp) {
            return Ok(CompiledConnection { tls: None });
        }
        // A fresh-only compiler cannot silently ignore a configured session
        // store, or offer a ticket absent from the selected captured variant.
        if self.has_sessions {
            return Err(BoxError::from_static_str(
                "captured TLS replay with a session store is not implemented",
            ));
        }
        let authority = input.target_authority().ok_or_else(|| {
            BoxError::from_static_str("captured TLS replay requires a destination")
        })?;
        let protocol = input
            .target_protocol()
            .filter(|protocol| protocol.is_secure())
            .ok_or_else(|| {
                BoxError::from_static_str("captured TLS replay requires a secure protocol")
            })?
            .clone();
        let effective = effective(input.extensions(), self.base);
        let current = BoringTlsConnectorConfig::from_extensions(&effective);
        let wire = wire::compile_for_policy(wire::TransportShape::Tcp, capture, &current)?;
        let identity = current
            .server_name
            .map(|name| &name.0)
            .unwrap_or(&authority.host);
        let sends_sni = matches!(identity, Host::Name(_));
        let captured_sni = capture.extensions.iter().any(|extension| {
            matches!(
                extension.value,
                TlsCapturedExtensionValue::ServerName { present: true }
            )
        });
        if sends_sni != captured_sni {
            return Err(BoxError::from_static_str(
                "destination identity and captured SNI presence differ",
            ));
        }
        #[cfg(feature = "http")]
        let target_version = input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|version| version.0);
        #[cfg(feature = "http")]
        if let Some(target) = target_version {
            let wanted = match target {
                Version::HTTP_11 => rama_net::tls::ApplicationProtocol::HTTP_11,
                Version::HTTP_2 => rama_net::tls::ApplicationProtocol::HTTP_2,
                _ => {
                    return Err(BoxError::from_static_str(
                        "captured TCP TLS target HTTP version is unsupported",
                    ));
                }
            };
            if !wire.alpn().is_some_and(|offer| offer.0.contains(&wanted)) {
                return Err(BoxError::from_static_str(
                    "captured ALPN offer excludes the required HTTP version",
                ));
            }
        }
        let caller_policy = current.pool_id();
        if caller_policy
            .as_ref()
            .is_some_and(|policy| !policy.is_reusable())
        {
            return Err(BoxError::from_static_str(
                "captured TLS caller policy cannot be compared safely",
            ));
        }
        wire.write_to(&effective);
        let native = BoringTlsConnectorConfig::from_extensions(&effective);
        native
            .pool_id()
            .filter(TlsPoolId::is_reusable)
            .ok_or_else(|| {
                BoxError::from_static_str("captured TLS policy cannot be compared safely")
            })?;
        let fallback = TlsConnectionReuse::new(BoringTlsClientConfigProvider, &effective);
        let mut data = super::TlsConnectorData::try_from(native)?;
        if data.server_name.is_none() {
            data.server_name = Some(authority.host.clone());
        }
        let prepared = PreparedHandshake::try_from(data)?;
        let native = NativeConnection {
            authority,
            protocol,
            #[cfg(feature = "http")]
            target_version,
            caller_policy,
            fallback,
            prepared,
        };
        Ok(CompiledConnection { tls: Some(native) })
    }
}

impl CompiledConnectionProfile for CompiledConnection {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        self.tls.is_some() && component == CapturedSlotKind::TcpTls
    }
}

impl PreparedProfile {
    pub(super) fn check(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        base: Option<&TlsClientConfig>,
    ) -> Result<(), BoxError> {
        self.preparation.check_context(input.extensions())?;
        let Some(native) = &self.native.tls else {
            return Ok(());
        };
        let effective = effective(input.extensions(), base);
        let policy = BoringTlsConnectorConfig::from_extensions(&effective).pool_id();
        if input.target_authority().as_ref() != Some(&native.authority)
            || input.target_protocol() != Some(&native.protocol)
            || policy != native.caller_policy
        {
            return Err(BoxError::from_static_str(
                "prepared TLS destination or policy changed before handshake",
            ));
        }
        #[cfg(feature = "http")]
        if input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|version| version.0)
            != native.target_version
        {
            return Err(BoxError::from_static_str(
                "prepared TLS target HTTP version changed before handshake",
            ));
        }
        Ok(())
    }

    pub(super) fn into_parts(self) -> (Option<PreparedHandshake>, Publication) {
        let (prepared, fallback) = match self.native.tls {
            Some(native) => (Some(native.prepared), Some(native.fallback)),
            None => (None, None),
        };
        (
            prepared,
            Publication {
                preparation: self.preparation,
                fallback,
            },
        )
    }
}

impl Publication {
    pub(super) fn publish(
        self,
        input: &Extensions,
        connection: &Extensions,
        caller: TlsConnectionReuse<BoringTlsClientConfigProvider>,
    ) -> Result<(), BoxError> {
        #[cfg(feature = "http")]
        let version = connection
            .get_ref::<TargetHttpVersion>()
            .map(|version| version.0);
        #[cfg(not(feature = "http"))]
        let version = None;
        if version.is_none() && self.fallback.is_none() {
            return Err(BoxError::from_static_str(
                "captured connection without native TLS requires an HTTP version",
            ));
        }
        self.preparation.publish(input, connection, version)?;
        if version.is_none()
            && let Some(fallback) = self.fallback
        {
            fallback.publish(connection);
            return Ok(());
        }
        caller.publish(connection);
        Ok(())
    }
}

#[cfg(feature = "http")]
pub(super) fn apply_legacy_http(
    input: &Extensions,
    connection: &Extensions,
) -> Result<(), BoxError> {
    if let Some(profile) = input.clone_to_if_absent::<HttpProfile>(connection)
        && let Some(version) = connection.get_ref::<TargetHttpVersion>()
    {
        apply_legacy_settings(input, version.0, &profile)?;
    }
    Ok(())
}

/// Plain streams have no ALPN. Follow the HTTP connector's established,
/// explicit-target, fallback, then initiating-request version precedence.
#[cfg(feature = "http")]
pub(super) fn apply_plaintext_http(
    input: &Extensions,
    connection: &Extensions,
) -> Result<(), BoxError> {
    let version = connection
        .get_ref::<TargetHttpVersion>()
        .map(|version| version.0)
        .or_else(|| {
            input
                .get_ref::<TargetHttpVersion>()
                .map(|version| version.0)
        })
        .or_else(|| {
            input
                .get_ref::<FallbackHttpVersion>()
                .map(|version| version.0)
        })
        .or_else(|| {
            input
                .get_ref::<HttpRequestVersion>()
                .map(|version| version.0)
        });
    if let Some(version) = version {
        connection.insert(TargetHttpVersion(version));
    }
    apply_legacy_http(input, connection)
}

#[cfg(test)]
mod tests;
