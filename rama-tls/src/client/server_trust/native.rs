use std::time::Duration;

use rama_core::error::BoxError;
use rama_crypto::pki_types::CertificateDer;
use rama_utils::macros::generate_set_and_with;

#[cfg(not(any(target_vendor = "apple", windows, target_os = "android")))]
use super::PlatformTrustPolicy;
use super::{NativeTrustPolicy, ServerTrustSource, TlsServerTrust};
use crate::client::{
    IntoNativeTrustReloadTrigger,
    native_trust::{NativeTrustReload, NativeTrustSnapshot},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct NativeTrustState {
    reload: Option<NativeTrustReload>,
    max_age: Option<Duration>,
    snapshot: Option<NativeTrustSnapshot>,
}

impl NativeTrustState {
    pub(super) const STATIC: Self = Self {
        reload: None,
        max_age: None,
        snapshot: None,
    };

    fn set_trigger<T>(&mut self, trigger: impl IntoNativeTrustReloadTrigger<T>) {
        self.reload = Some(NativeTrustReload::new(Some(Box::pin(
            trigger.into_reload_stream(),
        ))));
        self.snapshot = None;
    }

    fn set_max_age(&mut self, max_age: Option<Duration>) {
        self.max_age = max_age;
        if max_age.is_some() && self.reload.is_none() {
            self.reload = Some(NativeTrustReload::new(None));
        } else if max_age.is_none()
            && self
                .reload
                .as_ref()
                .is_some_and(|reload| !reload.has_trigger())
        {
            self.reload = None;
        }
        self.snapshot = None;
    }

    fn pin_native_roots(&self) -> Result<Option<Self>, BoxError> {
        let Some(reload) = self.reload.as_ref() else {
            return Ok(None);
        };
        let snapshot = reload.pin(self.max_age)?;
        Ok(Some(self.with_native_snapshot(snapshot)))
    }

    async fn pin_native_roots_async(&self) -> Result<Option<Self>, BoxError> {
        let Some(reload) = self.reload.as_ref() else {
            return Ok(None);
        };
        let snapshot = reload.pin_async(self.max_age).await?;
        Ok(Some(self.with_native_snapshot(snapshot)))
    }

    fn with_native_snapshot(&self, snapshot: NativeTrustSnapshot) -> Self {
        Self {
            snapshot: Some(snapshot),
            max_age: self.max_age,
            reload: None,
        }
    }
}

impl NativeTrustPolicy {
    generate_set_and_with! {
        /// Refresh native roots when the trigger fires.
        ///
        /// Pass a stream of unit events or a tuple of streams. A handshake
        /// processes pending events and pins one trust generation.
        pub fn reload_trigger<T>(mut self, trigger: impl IntoNativeTrustReloadTrigger<T>) -> Self {
            self.state.set_trigger(trigger);
            self
        }
    }

    generate_set_and_with! {
        /// Limit how long a handshake may rely on its native trust snapshot.
        ///
        /// At the age limit, a fresh read is required even if no trigger has fired.
        /// If the read fails, the handshake fails. A limit of zero requires a
        /// successful read for every handshake.
        pub fn max_age(mut self, max_age: Option<Duration>) -> Self {
            self.state.set_max_age(max_age);
            self
        }
    }
}

impl ServerTrustSource {
    fn native_policy_mut(&mut self) -> Option<&mut NativeTrustPolicy> {
        match self {
            Self::Native(policy) => Some(policy),
            #[cfg(not(any(target_vendor = "apple", windows, target_os = "android")))]
            Self::Platform(policy) => Some(&mut policy.native_fallback),
            _ => None,
        }
    }

    fn native_policy(&self) -> Option<&NativeTrustPolicy> {
        match self {
            Self::Native(policy) => Some(policy),
            #[cfg(not(any(target_vendor = "apple", windows, target_os = "android")))]
            Self::Platform(policy) => Some(&policy.native_fallback),
            _ => None,
        }
    }
}

impl TlsServerTrust {
    generate_set_and_with! {
        /// Refresh native roots when the trigger fires.
        ///
        /// Select a source before setting a reload policy. This applies to
        /// [`ServerTrustSource::Native`] and the native fallback of
        /// [`ServerTrustSource::Platform`] on targets without an operating
        /// system verifier. Replacing the source discards its reload settings.
        ///
        /// Pass a stream of unit events or a tuple of streams. A handshake
        /// processes pending events and pins one trust generation.
        ///
        /// A failed refresh keeps the most recent successful snapshot until its
        /// configured maximum age is reached. Established connections retain
        /// their original verification.
        ///
        /// Combine native store changes with a request from the application.
        ///
        /// ```
        /// use rama_tls::client::{ChannelReloadTrigger, NativeTrustStoreChanges, TlsServerTrust};
        ///
        /// let (reload, channel) = ChannelReloadTrigger::new();
        /// let trust = TlsServerTrust::native_roots()
        ///     .with_reload_trigger((NativeTrustStoreChanges::default(), channel));
        /// // Install trust on the client connector. A config update can then request a read.
        /// reload.request_reload()?;
        /// # drop(trust);
        /// # Ok::<(), Box<dyn std::error::Error>>(())
        /// ```
        pub fn reload_trigger<T>(mut self, trigger: impl IntoNativeTrustReloadTrigger<T>) -> Self {
            if let Some(native) = self.source.native_policy_mut() {
                native.set_reload_trigger(trigger);
            }
            self
        }
    }

    generate_set_and_with! {
        /// Limit how long a handshake may rely on its native trust snapshot.
        ///
        /// At the age limit, a fresh read is required even if no trigger has fired.
        /// If the read fails, the handshake fails. With a limit of zero, every
        /// handshake requires a successful read.
        ///
        /// Select a source before setting a reload policy. This applies to
        /// [`ServerTrustSource::Native`] and the native fallback of
        /// [`ServerTrustSource::Platform`] on targets without an operating
        /// system verifier. Replacing the source discards its reload settings.
        pub fn max_age(mut self, max_age: Option<Duration>) -> Self {
            if let Some(native) = self.source.native_policy_mut() {
                native.maybe_set_max_age(max_age);
            }
            self
        }
    }

    fn native_state(&self) -> Option<&NativeTrustState> {
        self.source.native_policy().map(|policy| &policy.state)
    }

    /// Whether this policy will consult reloadable native roots at handshake start.
    pub fn uses_reloadable_native_roots(&self) -> bool {
        self.native_state()
            .is_some_and(|state| state.reload.is_some())
    }

    /// Resolve this policy to one immutable snapshot for a new handshake.
    /// Returns `None` when the current policy already has fixed roots or uses
    /// another verifier. May block on filesystem or system store access.
    /// Async connectors should use [`Self::pin_native_roots_async`].
    pub fn pin_native_roots(&self) -> Result<Option<Self>, BoxError> {
        let Some(native) = self.native_state() else {
            return Ok(None);
        };
        Ok(native
            .pin_native_roots()?
            .map(|state| self.with_pinned_state(state)))
    }

    /// Resolve one snapshot for a new handshake on a Tokio runtime. Trust store
    /// reads and waits for an expired snapshot run on a blocking worker.
    /// Returns `None` under the same conditions as [`Self::pin_native_roots`].
    pub async fn pin_native_roots_async(&self) -> Result<Option<Self>, BoxError> {
        let Some(native) = self.native_state() else {
            return Ok(None);
        };
        Ok(native
            .pin_native_roots_async()
            .await?
            .map(|state| self.with_pinned_state(state)))
    }

    fn with_pinned_state(&self, state: NativeTrustState) -> Self {
        let policy = NativeTrustPolicy { state };
        let source = match &self.source {
            #[cfg(not(any(target_vendor = "apple", windows, target_os = "android")))]
            ServerTrustSource::Platform(_) => ServerTrustSource::Platform(PlatformTrustPolicy {
                native_fallback: policy,
            }),
            _ => ServerTrustSource::Native(policy),
        };
        Self {
            source,
            additional_anchors: self.additional_anchors.clone(),
        }
    }

    /// Native roots selected by [`Self::pin_native_roots`] or [`Self::pin_native_roots_async`].
    /// Includes environment-supplied extra roots. Consult [`Self::additional_anchors`]
    /// for anchors supplied directly by the application.
    pub fn pinned_native_roots(&self) -> Option<&[CertificateDer<'static>]> {
        self.native_state()?
            .snapshot
            .as_ref()
            .map(NativeTrustSnapshot::anchors)
    }
}

#[cfg(test)]
mod tests {
    use rama_crypto::platform_verifier::PlatformVerifier;

    use super::{CertificateDer, Duration, NativeTrustPolicy, ServerTrustSource, TlsServerTrust};
    use crate::client::{ChannelReloadTrigger, TlsServerTrustAnchors};

    #[test]
    fn replacing_native_source_discards_reload_policy() {
        let anchors = [CertificateDer::from(vec![1])];
        let custom = TlsServerTrustAnchors::try_new(anchors).unwrap();
        let (_sender, trigger) = ChannelReloadTrigger::new();
        let native = TlsServerTrust::native_roots()
            .with_reload_trigger(trigger)
            .with_max_age(Duration::ZERO);
        assert!(native.uses_reloadable_native_roots());
        assert_eq!(native, native.clone());

        for source in [ServerTrustSource::WebPki, ServerTrustSource::Custom(custom)] {
            let (_sender, trigger) = ChannelReloadTrigger::new();
            let switched = native
                .clone()
                .with_source(source.clone())
                .with_reload_trigger(trigger)
                .with_max_age(Duration::ZERO);
            assert_eq!(switched, TlsServerTrust::new(source));
            assert_eq!(
                switched.with_source(ServerTrustSource::native_roots()),
                TlsServerTrust::native_roots()
            );
        }
    }

    #[test]
    fn platform_reload_targets_only_the_native_fallback() {
        let age_only = TlsServerTrust::platform_verifier()
            .without_max_age()
            .with_max_age(Duration::ZERO);
        let (_sender, trigger) = ChannelReloadTrigger::new();
        let triggered = TlsServerTrust::platform_verifier().with_reload_trigger(trigger);

        assert!(matches!(triggered.source(), ServerTrustSource::Platform(_)));
        if PlatformVerifier::IS_AVAILABLE {
            assert_eq!(age_only, TlsServerTrust::platform_verifier());
            assert_eq!(triggered, TlsServerTrust::platform_verifier());
        } else {
            assert!(age_only.uses_reloadable_native_roots());
            assert!(triggered.uses_reloadable_native_roots());
            assert_eq!(
                age_only.without_max_age(),
                TlsServerTrust::platform_verifier()
            );
        }
    }

    #[test]
    fn clearing_an_age_limit_retains_the_native_trigger() {
        let (_sender, trigger) = ChannelReloadTrigger::new();
        let native = NativeTrustPolicy::new().with_reload_trigger(trigger);
        assert_eq!(
            native
                .clone()
                .with_max_age(Duration::ZERO)
                .without_max_age(),
            native
        );
        assert!(
            TlsServerTrust::new(ServerTrustSource::Native(native)).uses_reloadable_native_roots()
        );
    }
}
