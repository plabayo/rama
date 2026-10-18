//! Select, admit and publish one connection's captured profile.
//!
//! Native state stays with its consuming connector. Only the admitted selection
//! and preservation report become connection facts for later request emulation.

use super::{PreparedConnectionComponents, compiler::CompiledConnectionProfile, h3_startup};
use crate::profile::{
    model::identity::{ConnectionContext, FlowKey},
    replay::h3_bootstrap::Insertions,
    replay::request::{
        H2ClientParameter, ProfilePreservationDifference, ProfilePreservationMode,
        ProfilePreservationReport, ProfileReplayError,
    },
    selection::{
        ProfileSeed,
        variants::{ConnectionSelection, EmulationContext, ProfileConnectionReuse},
    },
};
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, Extensions, ExtensionsRef},
};
use rama_http::{
    HeaderMap, Version,
    conn::H2ClientContextParams,
    proto::{h2::frame::EarlyFrame, h3::ClientSettingsProfile},
};
use std::sync::Arc;

/// Locally owned result of one connection draw and whole-profile admission.
#[derive(Debug)]
pub struct ConnectionPreparation {
    admission: ConnectionAdmission,
    components: PreparedConnectionComponents,
}

/// Selection bindings retained locally while decoded recipes move to consumers.
#[derive(Debug)]
pub(crate) struct ConnectionAdmission {
    selection: ConnectionSelection,
    // Selection happens before inner transport I/O. Retain only the remaining
    // draw inputs needed to reject a changed seed or connection scope afterward.
    seed: ProfileSeed,
    connection: ConnectionContext,
}

impl ConnectionPreparation {
    /// The connection variant that passed whole-profile admission.
    pub fn selection(&self) -> &ConnectionSelection {
        &self.admission.selection
    }

    pub(crate) fn into_parts(self) -> (ConnectionAdmission, PreparedConnectionComponents) {
        (self.admission, self.components)
    }

    /// Decode once and compile against the consumer's current input. Ordinary
    /// traffic returns `None` without drawing, decoding or invoking `compile`.
    pub fn prepare<C: CompiledConnectionProfile>(
        input: &impl ExtensionsRef,
        compile: impl FnOnce(
            &ConnectionSelection,
            &mut PreparedConnectionComponents,
            ProfilePreservationMode,
        ) -> Result<C, BoxError>,
    ) -> Result<Option<(Self, C)>, BoxError> {
        let Some(context) = EmulationContext::of(input.extensions()) else {
            return Ok(None);
        };
        let connection = input
            .extensions()
            .get_ref::<ConnectionContext>()
            .cloned()
            .unwrap_or_default();
        let selection =
            context
                .selected
                .connection(&connection, context.seed, context.connection_key)?;
        if context
            .pins
            .connection
            .is_some_and(|pin| pin != selection.variant)
        {
            return Err(BoxError::from_static_str(
                "connection pin differs from its selected profile",
            ));
        }
        let mode = input
            .extensions()
            .get_ref::<ProfilePreservationMode>()
            .copied()
            .unwrap_or_default();
        let (components, compiled) = selection
            .prepare_for_replay_with(mode, |components| compile(&selection, components, mode))?;
        Ok(Some((
            Self {
                admission: ConnectionAdmission {
                    selection,
                    seed: context.seed,
                    connection,
                },
                components,
            },
            compiled,
        )))
    }

    /// Apply admitted HTTP recipes before the HTTP connector reads them. Native
    /// TLS/QUIC configuration is deliberately absent from the request store.
    pub fn apply_http(&mut self, input: &impl ExtensionsRef) -> Result<(), BoxError> {
        let context = EmulationContext::of(input.extensions())
            .ok_or_else(|| BoxError::from_static_str("captured profile context is missing"))?;
        if let Some((bootstrap, sequence)) = self
            .components
            .h3_bootstrap
            .as_ref()
            .zip(self.components.h3_sequence.as_ref())
            .filter(|(_, sequence)| !sequence.encoder_instructions.is_empty())
        {
            if context.selected.pins().request != Some(bootstrap.request) {
                return Err(BoxError::from_static_str(
                    "initial QPACK request must be selected before connecting",
                ));
            }
            // Resolve the pin in this profile, flow and connection. Empty caller fields
            // are used only for recipe selection; current values remain request-owned.
            let initial = context.selected.request(
                &self.admission.selection,
                context.selected.flow(),
                &HeaderMap::new(),
                ProfilePreservationMode::BestEffort,
                context.seed,
                context.request_key,
            )?;
            let FlowKey::Http { method, .. } = context.selected.flow() else {
                return Err(BoxError::from_static_str(
                    "initial QPACK request requires an HTTP flow",
                ));
            };
            let insertions = Insertions::new(bootstrap, sequence, initial.variant, method)?;
            insertions.validate_request(&initial.effective.capture)?;
        }
        let startup = h3_startup::prepare(
            input.extensions(),
            self.components.h3_sequence.as_ref(),
            self.components.h3_bootstrap.as_ref(),
        )?;
        if let Some(settings) = self
            .components
            .h3_client_settings(&mut self.admission.selection.h3_settings_draw(context.seed))?
        {
            if input
                .extensions()
                .get_ref::<ClientSettingsProfile>()
                .is_some_and(|caller| caller != &settings)
            {
                return Err(BoxError::from_static_str(
                    "caller and selected HTTP/3 SETTINGS profiles conflict",
                ));
            }
            input.extensions().insert(settings);
        }
        if let Some(frames) = &self.components.h2_early_frames {
            let mode = input
                .extensions()
                .get_ref::<ProfilePreservationMode>()
                .copied()
                .unwrap_or_default();
            apply_profile_h2_replay(
                input,
                frames.clone(),
                mode,
                &mut self.components.preservation_report,
            )?;
        }
        if let Some(startup) = startup {
            startup.apply(input.extensions());
        }
        Ok(())
    }

    /// Validate the admitted selection again after an inner transport returns.
    /// A changed context must be rejected before any prepared native output.
    pub fn check_context<'a>(
        &self,
        input: &'a Extensions,
    ) -> Result<&'a EmulationContext, BoxError> {
        self.admission.check_context(input)
    }

    /// Publish the admitted selection and report. A negotiated HTTP version also
    /// validates protocol support and installs the profile's HTTP reuse witness.
    /// Other consumers must supply their own conservative transport reuse policy.
    pub fn publish(
        self,
        input: &Extensions,
        connection: &Extensions,
        version: Option<Version>,
    ) -> Result<(), BoxError> {
        let context = self.check_context(input)?;
        if let Some(version) = version {
            context.selected.validate_negotiated_protocol(version)?;
        }
        let report = match connection.get_ref::<ProfilePreservationReport>() {
            Some(inner) => self
                .components
                .preservation_report
                .followed_by(inner.clone()),
            None => self.components.preservation_report,
        };
        connection.insert(report);
        connection.insert(self.admission.selection);
        if let Some(version) = version {
            ProfileConnectionReuse::new(context, version).publish(connection);
        }
        Ok(())
    }
}

impl ConnectionAdmission {
    pub(crate) fn selection(&self) -> &ConnectionSelection {
        &self.selection
    }

    pub(crate) fn into_selection(self) -> ConnectionSelection {
        self.selection
    }

    pub(crate) fn check_context<'a>(
        &self,
        input: &'a Extensions,
    ) -> Result<&'a EmulationContext, BoxError> {
        let context = EmulationContext::of(input)
            .ok_or_else(|| BoxError::from_static_str("captured profile context is missing"))?;
        if context.selected.profile_id() != self.selection.profile
            || context.seed != self.seed
            || input
                .get_ref::<ConnectionContext>()
                .cloned()
                .unwrap_or_default()
                != self.connection
            || context.connection_key != self.selection.draw
            || context
                .pins
                .connection
                .is_some_and(|pin| pin != self.selection.variant)
        {
            return Err(BoxError::from_static_str(
                "connection context differs from its admitted selection",
            ));
        }
        Ok(context)
    }
}

#[derive(Debug, Clone, Extension)]
struct AppliedH2Replay(Arc<[EarlyFrame]>);

fn apply_profile_h2_replay(
    input: &impl ExtensionsRef,
    replay: Arc<[EarlyFrame]>,
    preservation: ProfilePreservationMode,
    report: &mut ProfilePreservationReport,
) -> Result<(), ProfileReplayError> {
    let mut params = input
        .extensions()
        .get_ref::<H2ClientContextParams>()
        .cloned()
        .unwrap_or_default();

    let installed_replay = input
        .extensions()
        .get_ref::<AppliedH2Replay>()
        .map(|applied| &applied.0)
        .zip(params.replay_early_frames.as_ref())
        .is_some_and(|(installed, current)| Arc::ptr_eq(installed, current));

    for parameter in h2_wire_parameters(&params) {
        // A repeated connection attempt may retain our previous replay input.
        // A caller replacement, even with equal contents, is still an override.
        if parameter == H2ClientParameter::ReplayEarlyFrames && installed_replay {
            continue;
        }
        if preservation == ProfilePreservationMode::Strict {
            return Err(ProfileReplayError::IncompatibleH2ClientParameter(parameter));
        }
        report.push(ProfilePreservationDifference::RetainedH2ClientParameter { parameter });
    }

    params.replay_early_frames = Some(replay.clone());
    input.extensions().insert(AppliedH2Replay(replay));
    input.extensions().insert(params);
    Ok(())
}

fn h2_wire_parameters(params: &H2ClientContextParams) -> impl Iterator<Item = H2ClientParameter> {
    [
        params
            .early_frames
            .is_some()
            .then_some(H2ClientParameter::EarlyFrames),
        params
            .replay_early_frames
            .is_some()
            .then_some(H2ClientParameter::ReplayEarlyFrames),
        params
            .init_stream_window_size
            .is_some()
            .then_some(H2ClientParameter::InitialStreamWindowSize),
        params
            .init_connection_window_size
            .is_some()
            .then_some(H2ClientParameter::InitialConnectionWindowSize),
        params
            .keep_alive_interval
            .is_some()
            .then_some(H2ClientParameter::KeepAliveInterval),
        params
            .keep_alive_timeout
            .is_some()
            .then_some(H2ClientParameter::KeepAliveTimeout),
        params
            .keep_alive_while_idle
            .is_some()
            .then_some(H2ClientParameter::KeepAliveWhileIdle),
        params
            .max_header_list_size
            .is_some()
            .then_some(H2ClientParameter::MaximumHeaderListSize),
        params
            .max_frame_size
            .is_some()
            .then_some(H2ClientParameter::MaximumFrameSize),
        params
            .max_concurrent_streams
            .is_some()
            .then_some(H2ClientParameter::MaximumConcurrentStreams),
        params
            .adaptive_window
            .is_some()
            .then_some(H2ClientParameter::AdaptiveWindow),
    ]
    .into_iter()
    .flatten()
}

#[cfg(test)]
mod tests;
