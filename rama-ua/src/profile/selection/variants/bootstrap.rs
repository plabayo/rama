//! Select the initial request recipe linked by a captured H3 connection.

use super::{SelectedProfile, SelectionError, connection_context_matches, scope_flow_matches};
use crate::profile::{
    capture::{
        http3::bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
    },
    format::canonical::{CanonicalDomain, ProfileDataError},
    model::identity::FlowKey,
    selection::{DrawKey, ProfileSeed},
};
use rama_core::extensions::Extension;
use rama_http::Version;

/// Select the connection's captured initial request, when it has one.
/// The application still supplies the method, destination, body and credentials;
/// this preference never sends a request or recovers discarded values.
#[derive(Debug, Default, Clone, Copy, Extension)]
#[extension(tags(ua))]
#[non_exhaustive]
pub struct ConnectionBootstrapRequest;

impl ConnectionBootstrapRequest {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SelectedProfile {
    /// Pin a caller-owned H3 operation to its connection's initial recipe.
    /// References must resolve within this profile, flow and connection context.
    pub fn for_connection_bootstrap(
        mut self,
        seed: ProfileSeed,
        connection_key: DrawKey,
    ) -> Result<Self, SelectionError> {
        let FlowKey::Http {
            version,
            method,
            connection,
            ..
        } = &self.flow
        else {
            return Err(ProfileDataError::Unsupported("initial request profile protocol").into());
        };
        if *version != Version::HTTP_3 {
            return Ok(self);
        }
        let selected = self.connection(connection, seed, connection_key)?;
        let joint = JointCapture::from_canonical(
            &selected.effective.capture,
            JointCaptureLimits::default(),
        )?;
        let Some(slot) = joint
            .slots
            .iter()
            .find(|slot| slot.kind == CapturedSlotKind::Http3Bootstrap)
        else {
            // Older static recipes can still prime a full/resumed connection.
            return Ok(self);
        };
        let bootstrap =
            H3BootstrapCapture::from_canonical(&slot.value, H3BootstrapLimits::default())?;
        if bootstrap.method != *method {
            return Err(ProfileDataError::Invalid(
                "captured bootstrap method differs from current request",
            )
            .into());
        }
        if self
            .pins
            .request
            .is_some_and(|pin| pin != bootstrap.request)
        {
            return Err(ProfileDataError::Invalid(
                "caller and captured bootstrap request pins conflict",
            )
            .into());
        }
        let flow = self.flow.canonical(super::MAXIMUM_IDENTITY_BYTES)?;
        let analysis = self
            .profile
            .captured
            .as_ref()
            .ok_or(SelectionError::MissingProfile)?;
        let present = analysis.scopes.iter().any(|scope| {
            scope.observations.domain == CanonicalDomain::Joint
                && scope_flow_matches(scope, &self.flow, flow.id)
                && connection_context_matches(
                    &scope.context.connection,
                    &selected.effective.context.connection,
                )
                && scope
                    .observations
                    .variants
                    .iter()
                    .any(|variant| variant.value.id == bootstrap.request)
        });
        if !present {
            return Err(SelectionError::IncompatiblePin(bootstrap.request));
        }
        self.pins.request = Some(bootstrap.request);
        Ok(self)
    }
}
