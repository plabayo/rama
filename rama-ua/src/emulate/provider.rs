use std::sync::Arc;

use rama_core::Context;

use crate::{UserAgentDatabase, UserAgentProfile};

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
    Abort,
    Random,
}

pub trait UserAgentProvider<State>: Send + Sync + 'static {
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
