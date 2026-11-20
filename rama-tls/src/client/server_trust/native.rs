use std::time::Duration;

use rama_core::error::BoxError;
use rama_crypto::{pki_types::CertificateDer, platform_verifier::PlatformVerifier};
use rama_utils::macros::generate_set_and_with;

use super::{ConfiguredServerTrustSource, ServerTrustSource, TlsServerTrust};
use crate::client::{
    IntoNativeTrustReloadTrigger,
    native_trust::{NativeTrustReload, NativeTrustSnapshot},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct NativeTrustPolicy {
    reload: Option<NativeTrustReload>,
    max_age: Option<Duration>,
    snapshot: Option<NativeTrustSnapshot>,
}

impl NativeTrustPolicy {
    pub(super) const EMPTY: Self = Self {
        reload: None,
        max_age: None,
        snapshot: None,
    };

    pub(super) fn clear_snapshot(&mut self) {
        self.snapshot = None;
    }

    fn set_trigger<T>(&mut self, trigger: impl IntoNativeTrustReloadTrigger<T>) {
        self.reload = Some(NativeTrustReload::new(Some(Box::pin(
            trigger.into_reload_stream(),
        ))));
        self.clear_snapshot();
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
        self.clear_snapshot();
    }
}

impl ConfiguredServerTrustSource {
    fn native_reload(&self) -> Option<&NativeTrustReload> {
        // Only Native and the Platform fallback consult a Rama-owned snapshot.
        match self.kind {
            ServerTrustSource::Native => self.native.reload.as_ref(),
            ServerTrustSource::Platform if !PlatformVerifier::IS_AVAILABLE => {
                self.native.reload.as_ref()
            }
            _ => None,
        }
    }

    fn pin_native_roots(&self) -> Result<Option<Self>, BoxError> {
        let Some(reload) = self.native_reload() else {
            return Ok(None);
        };
        let snapshot = reload.pin(self.native.max_age)?;
        Ok(Some(self.with_native_snapshot(snapshot)))
    }

    async fn pin_native_roots_async(&self) -> Result<Option<Self>, BoxError> {
        let Some(reload) = self.native_reload() else {
            return Ok(None);
        };
        let snapshot = reload.pin_async(self.native.max_age).await?;
        Ok(Some(self.with_native_snapshot(snapshot)))
    }

    fn with_native_snapshot(&self, snapshot: NativeTrustSnapshot) -> Self {
        Self {
            kind: self.kind.clone(),
            native: NativeTrustPolicy {
                reload: None,
                max_age: self.native.max_age,
                snapshot: Some(snapshot),
            },
        }
    }
}

impl TlsServerTrust {
    generate_set_and_with! {
        /// Refresh native roots when the trigger fires. This also applies where
        /// platform verification falls back to native roots.
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
            self.source.native.set_trigger(trigger);
            self
        }
    }

    generate_set_and_with! {
        /// Limit how long a handshake may rely on its native trust snapshot.
        ///
        /// At the age limit, a fresh read is required even if no trigger has fired.
        /// If the read fails, the handshake fails. With a limit of zero, every
        /// handshake requires a successful read.
        pub fn max_age(mut self, max_age: Option<Duration>) -> Self {
            self.source.native.set_max_age(max_age);
            self
        }
    }

    /// Whether this policy will consult reloadable native roots at handshake start.
    /// Includes the native fallback for a platform verifier unavailable on this target.
    pub fn uses_reloadable_native_roots(&self) -> bool {
        self.source.native_reload().is_some()
    }

    /// Resolve this policy to one immutable snapshot for a new handshake.
    /// Returns `None` when the current policy already has fixed roots or uses
    /// another verifier. May block on filesystem or system store access.
    /// Async connectors should use [`Self::pin_native_roots_async`].
    pub fn pin_native_roots(&self) -> Result<Option<Self>, BoxError> {
        Ok(self
            .source
            .pin_native_roots()?
            .map(|source| self.with_pinned_source(source)))
    }

    /// Resolve one snapshot for a new handshake on a Tokio runtime. Trust store
    /// reads and waits for an expired snapshot run on a blocking worker.
    /// Returns `None` under the same conditions as [`Self::pin_native_roots`].
    pub async fn pin_native_roots_async(&self) -> Result<Option<Self>, BoxError> {
        Ok(self
            .source
            .pin_native_roots_async()
            .await?
            .map(|source| self.with_pinned_source(source)))
    }

    fn with_pinned_source(&self, source: ConfiguredServerTrustSource) -> Self {
        Self {
            source,
            additional_anchors: self.additional_anchors.clone(),
        }
    }

    /// Native roots selected by [`Self::pin_native_roots`] or [`Self::pin_native_roots_async`].
    /// Includes environment-supplied extra roots. Consult [`Self::additional_anchors`]
    /// for anchors supplied directly by the application.
    pub fn pinned_native_roots(&self) -> Option<&[CertificateDer<'static>]> {
        self.source
            .native
            .snapshot
            .as_ref()
            .map(NativeTrustSnapshot::anchors)
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, PlatformVerifier, ServerTrustSource, TlsServerTrust};
    use crate::client::ChannelReloadTrigger;

    #[test]
    fn native_reload_settings_follow_the_effective_trust_source() {
        let (_sender, trigger) = ChannelReloadTrigger::new();
        let trust = TlsServerTrust::webpki_roots()
            .with_max_age(Duration::from_secs(60))
            .with_reload_trigger(trigger)
            .without_max_age();

        assert!(!trust.uses_reloadable_native_roots());

        let platform = trust.with_source(ServerTrustSource::Platform);
        assert_eq!(
            platform.uses_reloadable_native_roots(),
            !PlatformVerifier::IS_AVAILABLE
        );

        let native = platform.with_source(ServerTrustSource::Native);
        assert!(native.uses_reloadable_native_roots());
        assert_eq!(native, native.clone());
        assert_ne!(native, TlsServerTrust::native_roots());

        let age_only = TlsServerTrust::native_roots().with_max_age(Duration::ZERO);
        assert!(age_only.uses_reloadable_native_roots());
        assert_eq!(age_only.without_max_age(), TlsServerTrust::native_roots());
    }
}
