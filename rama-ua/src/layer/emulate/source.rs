use std::sync::Arc;

use rama_core::extensions::Extension;

use crate::profile::selection::{
    DrawKey, ProfileSeed,
    database::UserAgentDatabase,
    variants::{ProfileSelector, SelectedProfile, SelectionError, SelectionRequest},
};

/// Source of captured profiles for [`ProfileEmulateLayer`](super::ProfileEmulateLayer).
///
/// [`UserAgentDatabase`] is the reference implementation; a single profile is a
/// one-entry database. Custom sources can route requests to different databases.
pub trait ProfileSource: Send + Sync + 'static {
    /// Draw a profile for one request flow.
    fn select_profile(
        &self,
        request: &SelectionRequest,
        seed: ProfileSeed,
        key: DrawKey,
    ) -> Result<SelectedProfile, SelectionError>;
}

impl ProfileSource for UserAgentDatabase {
    #[inline]
    fn select_profile(
        &self,
        request: &SelectionRequest,
        seed: ProfileSeed,
        key: DrawKey,
    ) -> Result<SelectedProfile, SelectionError> {
        self.select(request, seed, key)
    }
}

impl<P: ProfileSource> ProfileSource for Arc<P> {
    #[inline]
    fn select_profile(
        &self,
        request: &SelectionRequest,
        seed: ProfileSeed,
        key: DrawKey,
    ) -> Result<SelectedProfile, SelectionError> {
        self.as_ref().select_profile(request, seed, key)
    }
}

impl<P: ProfileSource> ProfileSource for Box<P> {
    #[inline]
    fn select_profile(
        &self,
        request: &SelectionRequest,
        seed: ProfileSeed,
        key: DrawKey,
    ) -> Result<SelectedProfile, SelectionError> {
        self.as_ref().select_profile(request, seed, key)
    }
}

macro_rules! impl_profile_source_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> ProfileSource for ::rama_core::combinators::$id<$($param),+>
        where
            $($param: ProfileSource,)+
        {
            fn select_profile(
                &self,
                request: &SelectionRequest,
                seed: ProfileSeed,
                key: DrawKey,
            ) -> Result<SelectedProfile, SelectionError> {
                match self {
                    $(::rama_core::combinators::$id::$param(source) => {
                        source.select_profile(request, seed, key)
                    })+
                }
            }
        }
    };
}

::rama_core::combinators::impl_either!(impl_profile_source_either);

/// What [`ProfileEmulateLayer`](super::ProfileEmulateLayer) does when no profile
/// matches the requested identity.
///
/// As a request extension it replaces the layer's configured fallback for that request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Extension)]
#[extension(tags(ua))]
pub enum ProfileSelectFallback {
    /// Do not relax the selector.
    #[default]
    Abort,
    /// Keep the client but accept any platform or device.
    SameClient,
    /// Try the same client on any platform first, then any profile at all.
    Any,
}

impl ProfileSelectFallback {
    /// Ever looser selectors to try, in order, after `selector` matched nothing.
    pub(super) fn relaxations(self, selector: &ProfileSelector) -> Vec<ProfileSelector> {
        let mut relaxed = Vec::new();
        if self == Self::Abort {
            return relaxed;
        }
        if selector.client.is_some() && (selector.platform.is_some() || selector.device.is_some()) {
            relaxed.push(ProfileSelector {
                client: selector.client.clone(),
                latest_versions: selector.latest_versions,
                ..ProfileSelector::default()
            });
        }
        if self == Self::Any {
            let any = ProfileSelector {
                latest_versions: selector.latest_versions,
                ..ProfileSelector::default()
            };
            if any != *selector {
                relaxed.push(any);
            }
        }
        relaxed
    }
}

/// Selection failures that a looser selector might resolve.
pub(super) fn is_no_match(error: &SelectionError) -> bool {
    matches!(
        error,
        SelectionError::MissingProfile
            | SelectionError::MissingFlow
            | SelectionError::MissingCapabilities(_)
    )
}
