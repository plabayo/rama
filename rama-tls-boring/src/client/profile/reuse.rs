//! Compare future pool requests before their connection-scoped compilation.

use rama_core::extensions::Extensions;
use rama_net::http::TargetHttpVersion;
use rama_tls::client::TlsConnectionReuse;
use rama_ua::profile::selection::variants::{
    ConnectionSelection, EmulationContext, ProfileConnectionReuse,
};

use super::{CompiledConnection, invalid};
use crate::client::BoringTlsClientConfigProvider;

#[derive(Debug)]
pub(in crate::client) struct CapturedReuse {
    caller: TlsConnectionReuse<BoringTlsClientConfigProvider>,
    context: EmulationContext,
}

pub(super) fn bind(
    mut compiled: CompiledConnection,
    request: &Extensions,
    selection: &ConnectionSelection,
) -> Result<CompiledConnection, rama_core::error::BoxError> {
    let Some(context) = EmulationContext::of(request) else {
        return Ok(compiled);
    };
    if context.selected.profile_id() != selection.profile
        || context
            .pins
            .connection
            .is_some_and(|pin| pin != selection.variant)
    {
        return Err(invalid(
            "captured TLS selection differs from its emulation context",
        ));
    }
    if let Some((_, pending)) = &mut compiled.tls
        && let Some(prepared) = pending.prepared.get_mut()
    {
        prepared.reuse = Some(Box::new(CapturedReuse {
            caller: TlsConnectionReuse::new(BoringTlsClientConfigProvider, request),
            context: context.clone(),
        }));
    }
    Ok(compiled)
}

impl CapturedReuse {
    pub(in crate::client) fn publish(
        self,
        connection: &Extensions,
        fallback: TlsConnectionReuse<BoringTlsClientConfigProvider>,
    ) {
        // The pool sees the caller's policy and selected profile before another
        // connection draw. Require both, including the actual negotiated protocol.
        // Without HTTP negotiation, retain the conservative wire-policy key.
        if let Some(version) = connection.get_ref::<TargetHttpVersion>() {
            self.caller.publish(connection);
            ProfileConnectionReuse::new(&self.context, version.0).publish(connection);
        } else {
            fallback.publish(connection);
        }
    }
}
