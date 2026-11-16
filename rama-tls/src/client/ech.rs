use super::{ServerVerifyMode, TlsEncryptedClientHello, TlsServerVerify};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, Extensions},
};
use rama_net::{
    address::HostWithPort,
    tls::{TargetEchConfig, TargetEchServiceBinding},
};

/// Caller policy for requiring successful ECH negotiation.
///
/// ECH is enabled opportunistically when intent is unspecified. Explicitly disabling
/// ECH conflicts with `Required` and fails before network I/O. Backends without
/// ECH support must reject `Required`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub enum EchRequirement {
    /// No caller-imposed requirement. Protocol-derived ECH requirements still apply.
    #[default]
    Optional,
    /// Fail unless the connection accepts real ECH. GREASE is insufficient.
    Required,
}

impl EchRequirement {
    /// Effective intent, checking contradictory caller policy without DNS or I/O.
    pub fn intent(self, intent: Option<&TlsEncryptedClientHello>) -> Result<bool, BoxError> {
        match (self, intent.map(|value| value.0)) {
            (Self::Required, Some(false)) => Err(BoxError::from_static_str(
                "required ECH conflicts with disabled ECH intent",
            )),
            (_, Some(false)) => Ok(false),
            _ => Ok(true),
        }
    }

    /// Read the caller requirement and its effective intent from `extensions`.
    ///
    /// Absent policy is [`Self::Optional`]; a conflict fails as [`Self::intent`] does.
    pub fn effective(extensions: &Extensions) -> Result<(Self, bool), BoxError> {
        let requirement = extensions.get_ref::<Self>().copied().unwrap_or_default();
        let intent = requirement.intent(extensions.get_ref::<TlsEncryptedClientHello>())?;
        Ok((requirement, intent))
    }
}

/// Whether the backend reports ECH acceptance after handshake completion.
///
/// `true` means real ECH was accepted. `false` means it was not, including when
/// ECH was not attempted or only GREASE was sent; it does not identify the cause.
/// An absent extension means no result was reported, not acceptance.
///
/// Acceptance does not replace server authentication, which is reported separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
#[extension(tags(tls))]
pub struct TlsEchAccepted(pub bool);

/// Resolve caller policy and endpoint discovery facts after final TLS/profile
/// settings are installed. This does not mutate caller policy or pool identity.
///
/// Unlike [`resolve_target_ech`], this does not require a matching configuration.
pub fn target_ech_required(
    extensions: &Extensions,
    target: &HostWithPort,
    backend_supports_ech: bool,
) -> Result<bool, BoxError> {
    let (requirement, intent) = EchRequirement::effective(extensions)?;
    required_for_target(
        extensions,
        target,
        backend_supports_ech,
        requirement,
        intent,
    )
}

fn required_for_target(
    extensions: &Extensions,
    target: &HostWithPort,
    backend_supports_ech: bool,
    requirement: EchRequirement,
    intent: bool,
) -> Result<bool, BoxError> {
    let binding = extensions
        .get_ref::<TargetEchServiceBinding>()
        .filter(|binding| &binding.target == target);
    let authenticated = extensions
        .get_ref::<TlsServerVerify>()
        .is_none_or(|verify| verify.0 != ServerVerifyMode::Disable);
    if binding.is_some_and(|binding| binding.mandatory)
        && (!intent || !backend_supports_ech || !authenticated)
    {
        return Err(BoxError::from_static_str(
            "HTTPS service requires an ECH-capable client",
        ));
    }
    Ok(requirement == EchRequirement::Required
        || (intent
            && backend_supports_ech
            && authenticated
            && binding.is_some_and(|binding| binding.reliant || binding.mandatory)))
}

/// ECH settings resolved for one TLS hop by [`resolve_target_ech`].
#[derive(Debug, Clone)]
pub struct TargetEchResolution {
    /// Matching configuration to offer, present only for a capable backend.
    pub config: Option<Bytes>,
    /// Whether the handshake must accept real ECH, as [`target_ech_required`] reports.
    pub required: bool,
}

/// Resolve ECH for the actual TLS hop from effective caller/connector settings.
///
/// The caller supplies the hop endpoint, not a potentially stale proxy routing
/// override. The result contains only a matching configuration. This helper does
/// no DNS and can be used by unsupported backends to enforce required ECH too.
/// Native backends still validate supported configuration contents and require
/// acceptance after the handshake.
pub fn resolve_target_ech(
    extensions: &Extensions,
    target: &HostWithPort,
    backend_supports_ech: bool,
) -> Result<TargetEchResolution, BoxError> {
    let (requirement, intent) = EchRequirement::effective(extensions)?;
    let config = intent
        .then(|| extensions.get_ref::<TargetEchConfig>())
        .flatten()
        .filter(|config| config.matches_target(target));
    let required = required_for_target(
        extensions,
        target,
        backend_supports_ech,
        requirement,
        intent,
    )?;
    if required && (!backend_supports_ech || config.is_none()) {
        return Err(BoxError::from_static_str(
            "required ECH needs a matching configuration and a capable TLS backend",
        ));
    }
    Ok(TargetEchResolution {
        config: config
            .filter(|_| backend_supports_ech)
            .map(|config| config.config_list().clone()),
        required,
    })
}

// Kept separate from configuration identity: optional callers may reuse either
// result, but required callers may never reuse a connection without acceptance.
#[derive(Debug)]
pub(super) struct EchConnectionReuse {
    pub accepted: bool,
    pub required: bool,
}

impl rama_net::client::pool::ConnectionReusePolicy for EchConnectionReuse {
    fn classifier(&self) -> rama_net::client::pool::ReuseKey {
        rama_net::client::pool::ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<rama_net::client::pool::ReuseKey> {
        Some(self.classifier())
    }

    fn request_key(&self, request: &Extensions) -> Option<rama_net::client::pool::ReuseKey> {
        let requirement =
            request
                .get_ref::<EchRequirement>()
                .copied()
                .unwrap_or(if self.required {
                    EchRequirement::Required
                } else {
                    EchRequirement::Optional
                });
        requirement
            .intent(request.get_ref::<TlsEncryptedClientHello>())
            .ok()?;
        (requirement != EchRequirement::Required || self.accepted).then(|| self.classifier())
    }
}

/// Fresh ECH configuration authenticated by a rejecting server's public name.
///
/// Only a TLS backend that completed rejection authentication may construct this
/// error. A connector may retry it once on a fresh transport, within the original
/// connection deadline. Empty lists never authorize a cleartext retry.
#[derive(Clone)]
pub struct EchRetryConfig(Bytes);

impl EchRetryConfig {
    /// Report an authenticated rejection with a nonempty, bounded ECHConfigList.
    pub fn new(config: Bytes) -> Option<Self> {
        (config.len() > 2 && config.len() <= usize::from(u16::MAX)).then_some(Self(config))
    }

    /// The server's replacement ECHConfigList; never a reusable TLS context.
    pub fn config_list(&self) -> &Bytes {
        &self.0
    }

    /// Prepare `extensions` for the single retry towards `target`.
    ///
    /// Authenticated replacement data never authorizes a clear retry, so this
    /// also requires real ECH acceptance on the retried handshake.
    pub fn apply(&self, extensions: &Extensions, target: HostWithPort) {
        extensions.insert(EchRequirement::Required);
        extensions.insert(TargetEchConfig::new(target, self.0.clone()));
    }
}

impl std::fmt::Debug for EchRetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EchRetryConfig")
            .field("length", &self.0.len())
            .finish()
    }
}

impl std::fmt::Display for EchRetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authenticated ECH rejection with replacement configuration")
    }
}

impl std::error::Error for EchRetryConfig {}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_net::client::pool::ConnectionReuse;
    #[test]
    fn required_intent_and_endpoint_capability_matrix() {
        let target: HostWithPort = "origin.example:443".parse().unwrap();
        for required in [false, true] {
            for intent in [None, Some(false), Some(true)] {
                for capable in [false, true] {
                    for matching in [false, true] {
                        let extensions = Extensions::new();
                        extensions.insert(if required {
                            EchRequirement::Required
                        } else {
                            EchRequirement::Optional
                        });
                        if let Some(intent) = intent {
                            extensions.insert(TlsEncryptedClientHello(intent));
                        }
                        extensions.insert(TargetEchConfig::new(
                            if matching {
                                target.clone()
                            } else {
                                "proxy.example:443".parse().unwrap()
                            },
                            Bytes::from_static(b"config"),
                        ));
                        let result = resolve_target_ech(&extensions, &target, capable);
                        let enabled = intent.unwrap_or(true);
                        assert_eq!(
                            result.is_err(),
                            required && (!enabled || !capable || !matching)
                        );
                        if let Ok(resolution) = result {
                            assert_eq!(resolution.config.is_some(), enabled && capable && matching);
                            assert_eq!(resolution.required, required);
                            assert_eq!(
                                Some(resolution.required),
                                target_ech_required(&extensions, &target, capable).ok()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn sparse_configuration_enables_only_available_real_ech() {
        let base = super::super::TlsClientConfig::new().with_encrypted_client_hello(false);
        let request = super::super::TlsClientConfig::new();
        assert!(
            !request
                .as_extensions()
                .contains::<TlsEncryptedClientHello>()
        );
        assert!(EchRequirement::Optional.intent(None).unwrap());
        assert!(
            resolve_target_ech(
                request.as_extensions(),
                &"origin.example:443".parse().unwrap(),
                true
            )
            .unwrap()
            .config
            .is_none()
        );
        let effective = base.with_overrides(request.as_extensions());
        assert!(
            !EchRequirement::Optional
                .intent(
                    effective
                        .as_extensions()
                        .get_ref::<TlsEncryptedClientHello>()
                )
                .unwrap()
        );
    }

    #[test]
    fn required_without_configuration_fails() {
        let extensions = Extensions::new();
        extensions.insert(EchRequirement::Required);
        resolve_target_ech(&extensions, &"origin.example:443".parse().unwrap(), true).unwrap_err();
    }

    #[test]
    fn retry_config_requires_ech_for_its_target_only() {
        let target: HostWithPort = "origin.example:443".parse().unwrap();
        let retry = EchRetryConfig::new(Bytes::from_static(b"\x00\x04\xfe\x0d\x00\x00")).unwrap();
        let extensions = Extensions::new();
        retry.apply(&extensions, target.clone());
        let resolution = resolve_target_ech(&extensions, &target, true).unwrap();
        assert!(resolution.required);
        assert_eq!(resolution.config.as_ref(), Some(retry.config_list()));
        resolve_target_ech(&extensions, &"proxy.example:443".parse().unwrap(), true).unwrap_err();
        extensions.insert(TlsEncryptedClientHello(false));
        resolve_target_ech(&extensions, &target, true).unwrap_err();
    }

    #[test]
    fn reuse_requires_acceptance_and_rejects_conflicting_intent() {
        let request = Extensions::new();
        for accepted in [false, true] {
            let policy = ConnectionReuse::new(EchConnectionReuse {
                accepted,
                required: false,
            });
            request.insert(EchRequirement::Optional);
            request.insert(TlsEncryptedClientHello(true));
            assert_eq!(policy.request_key(&request).as_ref(), policy.key());
            request.insert(EchRequirement::Required);
            assert_eq!(policy.request_key(&request).is_some(), accepted);
            request.insert(TlsEncryptedClientHello(false));
            assert!(policy.request_key(&request).is_none());
        }
    }

    #[test]
    fn required_connector_default_cannot_reuse_for_disabled_intent() {
        let policy = ConnectionReuse::new(EchConnectionReuse {
            accepted: true,
            required: true,
        });
        let request = Extensions::new();
        assert!(policy.request_key(&request).is_some());
        request.insert(TlsEncryptedClientHello(false));
        assert!(policy.request_key(&request).is_none());
        request.insert(EchRequirement::Optional);
        assert!(policy.request_key(&request).is_some());
    }

    #[test]
    fn discovery_facts_use_final_intent_and_do_not_change_caller_requirement() {
        let target: HostWithPort = "origin.example:443".parse().unwrap();
        let request = Extensions::new();
        request.insert(TargetEchServiceBinding {
            target: target.clone(),
            reliant: true,
            mandatory: false,
        });
        resolve_target_ech(&request, &target, true).unwrap_err();
        request.insert(TargetEchConfig::new(target.clone(), vec![0, 1, 2]));
        assert!(target_ech_required(&request, &target, true).unwrap());
        assert!(
            resolve_target_ech(&request, &target, true)
                .unwrap()
                .config
                .is_some()
        );
        assert!(!request.contains::<EchRequirement>());
        request.insert(TlsEncryptedClientHello(false));
        assert!(!target_ech_required(&request, &target, true).unwrap());
        assert!(
            resolve_target_ech(&request, &target, true)
                .unwrap()
                .config
                .is_none()
        );
        request.insert(TlsEncryptedClientHello(true));
        request.insert(TlsServerVerify(ServerVerifyMode::Disable));
        assert!(!target_ech_required(&request, &target, true).unwrap());
        assert!(
            resolve_target_ech(&request, &target, true)
                .unwrap()
                .config
                .is_some()
        );
        assert!(
            !target_ech_required(&request, &"proxy.example:443".parse().unwrap(), true).unwrap()
        );
    }

    #[test]
    fn mandatory_ech_rejects_final_disabled_intent_and_unsupported_backend() {
        let target: HostWithPort = "origin.example:443".parse().unwrap();
        let request = Extensions::new();
        request.insert(TargetEchServiceBinding {
            target: target.clone(),
            reliant: false,
            mandatory: true,
        });
        request.insert(TargetEchConfig::new(target.clone(), vec![0, 1, 2]));
        assert!(
            resolve_target_ech(&request, &target, true)
                .unwrap()
                .config
                .is_some()
        );
        request.insert(TlsEncryptedClientHello(false));
        resolve_target_ech(&request, &target, true).unwrap_err();
        request.insert(TlsEncryptedClientHello(true));
        resolve_target_ech(&request, &target, false).unwrap_err();
        assert!(target_ech_required(&request, &target, true).unwrap());
    }
}
