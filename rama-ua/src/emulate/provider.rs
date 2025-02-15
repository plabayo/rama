use std::sync::Arc;

use rama_core::Context;

use crate::{UserAgentDatabase, UserAgentProfile};

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
        ctx.get().and_then(|agent| self.get(agent))
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
