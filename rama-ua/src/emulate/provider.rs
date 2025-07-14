use rama_core::Context;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    PlatformKind, UserAgentKind,
    profile::{UserAgentDatabase, UserAgentProfile, UserAgentRuntimeProfile},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Extra information about the selected user agent profile,
/// which isn't already injected. E.g. http and tls information
/// is already injected separately.
pub struct SelectedUserAgentProfile {
    /// The user agent header of the selected profile.
    pub user_agent_header: Option<Arc<str>>,

    /// The kind of [`crate::UserAgent`]
    pub ua_kind: UserAgentKind,
    /// The version of the [`crate::UserAgent`]
    pub ua_version: Option<usize>,
    /// The platform the [`crate::UserAgent`] is running on.
    pub platform: Option<PlatformKind>,

    /// Runtime (meta) info about the UA profile of the [`crate::UserAgent`].
    pub runtime: Option<Arc<UserAgentRuntimeProfile>>,
}

impl From<&UserAgentProfile> for SelectedUserAgentProfile {
    fn from(profile: &UserAgentProfile) -> Self {
        Self {
            user_agent_header: profile.ua_str().map(Into::into),
            ua_kind: profile.ua_kind,
            ua_version: profile.ua_version,
            platform: profile.platform,
            runtime: profile.runtime.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
/// Fallback strategy that can be injected into the context
/// to customise what a provider can be requested to do
/// in case the preconditions for UA selection were not fulfilled.
///
/// It is advised only fallback for pre-conditions and not
/// post-selection failure as the latter would be rather confusing.
///
/// For example if you request a Chromium profile you do not expect a Firefox one.
/// However if you do not give any filters it is fair to assume a random profile is desired,
/// given those all satisfy the abscence of filters.
pub enum UserAgentSelectFallback {
    #[default]
    /// Abort the request if no profile is found.
    Abort,
    /// Select a random profile if no profile is found.
    Random,
}

/// A trait for providing user agent profiles for emulation.
///
/// This trait is used to select a user agent profile based on the current context.
/// It's a core component of the user agent emulation system, allowing different
/// strategies for selecting which user agent profile to use for a request.
///
/// Rama provides several built-in implementations:
/// - [`()`]: Always returns `None`, effectively disabling user agent emulation
/// - [`UserAgentProfile`]: Always returns the same profile
/// - [`UserAgentDatabase`]: Selects a profile based on the [`UserAgent`] in the context,
///   or falls back to a random profile if configured with [`UserAgentSelectFallback::Random`]
/// - [`Option<P>`]: Delegates to the inner provider if `Some`, otherwise returns `None`
///
/// This trait is typically used by [`UserAgentEmulateService`] to select an appropriate
/// user agent profile for HTTP request emulation.
///
/// [`UserAgentProfile`]: crate::profile::UserAgentProfile
/// [`UserAgentDatabase`]: crate::profile::UserAgentDatabase
/// [`UserAgent`]: crate::UserAgent
/// [`UserAgentSelectFallback::Random`]: UserAgentSelectFallback::Random
/// [`UserAgentEmulateService`]: crate::emulate::UserAgentEmulateService
pub trait UserAgentProvider<State>: Send + Sync + 'static {
    /// Selects a user agent profile based on the current context.
    fn select_user_agent_profile(&self, ctx: &Context<State>) -> Option<&UserAgentProfile>;
}

impl<State> UserAgentProvider<State> for () {
    #[inline]
    fn select_user_agent_profile(&self, _ctx: &Context<State>) -> Option<&UserAgentProfile> {
        None
    }
}

impl<State> UserAgentProvider<State> for UserAgentProfile {
    #[inline]
    fn select_user_agent_profile(&self, _ctx: &Context<State>) -> Option<&UserAgentProfile> {
        Some(self)
    }
}

impl<State> UserAgentProvider<State> for UserAgentDatabase {
    #[inline]
    fn select_user_agent_profile(&self, ctx: &Context<State>) -> Option<&UserAgentProfile> {
        match (ctx.get(), ctx.get()) {
            (Some(agent), _) => self.get(agent),
            (None, Some(UserAgentSelectFallback::Random)) => self.rnd(),
            (None, None | Some(UserAgentSelectFallback::Abort)) => None,
        }
    }
}

impl<State, P> UserAgentProvider<State> for Option<P>
where
    P: UserAgentProvider<State>,
{
    #[inline]
    fn select_user_agent_profile(&self, ctx: &Context<State>) -> Option<&UserAgentProfile> {
        self.as_ref().and_then(|p| p.select_user_agent_profile(ctx))
    }
}

impl<State, P> UserAgentProvider<State> for Arc<P>
where
    P: UserAgentProvider<State>,
{
    #[inline]
    fn select_user_agent_profile(&self, ctx: &Context<State>) -> Option<&UserAgentProfile> {
        self.as_ref().select_user_agent_profile(ctx)
    }
}

impl<State, P> UserAgentProvider<State> for Box<P>
where
    P: UserAgentProvider<State>,
{
    #[inline]
    fn select_user_agent_profile(&self, ctx: &Context<State>) -> Option<&UserAgentProfile> {
        self.as_ref().select_user_agent_profile(ctx)
    }
}

macro_rules! impl_user_agent_provider_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<State, $($param),+> UserAgentProvider<State> for ::rama_core::combinators::$id<$($param),+>
        where
            $(
                $param: UserAgentProvider<State>,
            )+
        {
            fn select_user_agent_profile(
                &self,
                ctx: &Context<State>,
            ) -> Option<&UserAgentProfile> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(s) => s.select_user_agent_profile(ctx),
                    )+
                }
            }
        }
    };
}

::rama_core::combinators::impl_either!(impl_user_agent_provider_either);
