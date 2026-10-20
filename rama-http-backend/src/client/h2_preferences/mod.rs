//! Value identity for native H2 connection preferences, independent of UA profiles.

use std::{
    hash::{Hash, Hasher},
    mem::discriminant,
    sync::Arc,
    time::Duration,
};

use rama_core::extensions::Extensions;
use rama_http_types::{
    conn::H2ClientContextParams,
    proto::h2::{
        PseudoHeaderOrder,
        frame::{EarlyFrame, Settings},
    },
};

/// Retain existing immutable extension storage; checkout never encodes/copies frames.
#[derive(Clone, Debug)]
pub(super) struct H2WirePreferences {
    params: Option<Arc<H2ClientContextParams>>,
    fallback_order: Option<Arc<PseudoHeaderOrder>>,
}

#[derive(Debug, Default, PartialEq, Eq, Hash)]
struct Scalars {
    stream_window: Option<u32>,
    connection_window: Option<u32>,
    keep_alive_interval: Option<Duration>,
    keep_alive_timeout: Option<Duration>,
    keep_alive_while_idle: Option<bool>,
    max_header_list_size: Option<u32>,
    max_frame_size: Option<u32>,
    header_table_size: Option<u32>,
    max_concurrent_streams: Option<u32>,
    adaptive_window: Option<bool>,
}

impl H2WirePreferences {
    pub(super) fn from_extensions(extensions: &Extensions) -> Option<Self> {
        let params = extensions.get_arc::<H2ClientContextParams>();
        let fallback_order = if params
            .as_ref()
            .is_some_and(|params| params.headers_pseudo_order.is_some())
        {
            None
        } else {
            extensions.get_arc::<PseudoHeaderOrder>()
        };
        let mut preferences = Self {
            params,
            fallback_order,
        };
        if preferences.initial_settings().is_none()
            && preferences.frames().is_none()
            && preferences.scalars() == Scalars::default()
            && preferences
                .params
                .as_ref()
                .is_none_or(|params| params.headers_pseudo_order.is_none())
        {
            // Buffer/reset/admission-only controls do not change the wire policy.
            preferences.params = None;
        }
        (preferences.params.is_some() || preferences.fallback_order.is_some())
            .then_some(preferences)
    }

    fn scalars(&self) -> Scalars {
        let Some(params) = self.params.as_deref() else {
            return Scalars::default();
        };
        Scalars {
            stream_window: params.init_stream_window_size,
            connection_window: params.init_connection_window_size,
            keep_alive_interval: params.keep_alive_interval,
            keep_alive_timeout: params.keep_alive_timeout,
            keep_alive_while_idle: params.keep_alive_while_idle,
            max_header_list_size: params.max_header_list_size,
            max_frame_size: params.max_frame_size,
            header_table_size: params.header_table_size,
            max_concurrent_streams: params.max_concurrent_streams,
            adaptive_window: params.adaptive_window,
        }
    }

    fn initial_settings(&self) -> Option<&Settings> {
        self.params.as_deref()?.initial_settings.as_deref()
    }

    fn frames(&self) -> Option<&[EarlyFrame]> {
        let params = self.params.as_deref()?;
        params.replay_early_frames.as_deref().or_else(|| {
            params
                .early_frames
                .as_ref()
                .map(|capture| capture.as_slice())
        })
    }

    fn order(&self) -> Option<&PseudoHeaderOrder> {
        self.params
            .as_deref()
            .and_then(|params| params.headers_pseudo_order.as_ref())
            .or(self.fallback_order.as_deref())
    }
}

impl PartialEq for H2WirePreferences {
    fn eq(&self, other: &Self) -> bool {
        self.scalars() == other.scalars()
            && self.order() == other.order()
            && match (self.initial_settings(), other.initial_settings()) {
                (Some(left), Some(right)) => literal_settings_eq(left, right),
                (None, None) => true,
                _ => false,
            }
            && match (self.frames(), other.frames()) {
                (Some(left), Some(right)) => {
                    left.len() == right.len()
                        && left
                            .iter()
                            .zip(right)
                            .all(|(left, right)| match (left, right) {
                                (EarlyFrame::Settings(left), EarlyFrame::Settings(right)) => {
                                    settings_eq(left, right)
                                }
                                (EarlyFrame::Priority(left), EarlyFrame::Priority(right)) => {
                                    left == right
                                }
                                (
                                    EarlyFrame::WindowUpdate(left),
                                    EarlyFrame::WindowUpdate(right),
                                ) => left == right,
                                _ => false,
                            })
                }
                (None, None) => true,
                _ => false,
            }
    }
}

impl Eq for H2WirePreferences {}

impl Hash for H2WirePreferences {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scalars().hash(state);
        self.order().map(PseudoHeaderOrder::as_slice).hash(state);
        self.initial_settings().is_some().hash(state);
        if let Some(settings) = self.initial_settings() {
            hash_literal_settings(settings, state);
        }
        self.frames().is_some().hash(state);
        if let Some(frames) = self.frames() {
            frames.len().hash(state);
            for frame in frames {
                discriminant(frame).hash(state);
                match frame {
                    EarlyFrame::Settings(settings) => hash_settings(settings, state),
                    EarlyFrame::Priority(priority) => {
                        priority.stream_id.hash(state);
                        priority.dependency.dependency_id.hash(state);
                        priority.dependency.weight.hash(state);
                        priority.dependency.is_exclusive.hash(state);
                    }
                    EarlyFrame::WindowUpdate(update) => {
                        update.stream_id.hash(state);
                        update.size_increment.hash(state);
                    }
                }
            }
        }
    }
}

// Whole-frame overrides pass through to_literal at handshake. Observed entries
// therefore remain significant even when direct encoding would use semantic fields.
// Retain validation inputs too: an invalid/stale override must not reuse a valid one.
fn literal_settings_eq(left: &Settings, right: &Settings) -> bool {
    u8::from(left.flags) == u8::from(right.flags)
        && match (&left.observation, &right.observation) {
            (Some(left_observation), Some(right_observation)) => {
                left.config == right.config
                    && left.config.setting_order == right.config.setting_order
                    && left_observation.complete == right_observation.complete
                    && left_observation.entries == right_observation.entries
            }
            (None, None) => left.encoded_entries().eq(right.encoded_entries()),
            _ => false,
        }
}

fn hash_literal_settings<H: Hasher>(settings: &Settings, state: &mut H) {
    u8::from(settings.flags).hash(state);
    settings.observation.is_some().hash(state);
    if let Some(observation) = &settings.observation {
        settings.config.hash(state);
        settings.config.setting_order.is_some().hash(state);
        if let Some(order) = &settings.config.setting_order {
            order.len().hash(state);
            for id in order.iter() {
                id.hash(state);
            }
        }
        observation.complete.hash(state);
        observation.entries.hash(state);
    } else {
        hash_entries(settings, state);
    }
}

fn settings_eq(left: &Settings, right: &Settings) -> bool {
    u8::from(left.flags) == u8::from(right.flags)
        && left.encoded_entries().eq(right.encoded_entries())
}

fn hash_settings<H: Hasher>(settings: &Settings, state: &mut H) {
    u8::from(settings.flags).hash(state);
    hash_entries(settings, state);
}

fn hash_entries<H: Hasher>(settings: &Settings, state: &mut H) {
    let entries = settings.encoded_entries();
    entries.clone().count().hash(state);
    for entry in entries {
        entry.hash(state);
    }
}

#[cfg(test)]
mod tests;
