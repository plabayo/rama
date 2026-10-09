//! Opt-in observation with immutable, budgeted request snapshots.

use super::{connection::Shared, frame::FrameEvent};
use rama_core::extensions::Extension;
use rama_http_types::proto::h3::{
    Code, FrameHeader, Settings, StreamType,
    observation::{
        H3ObservationSnapshot, ObservationCompleteness, ObservationLimits, ObservedControlFrame,
        ObservedEncoderInstruction, ObservedSetting, ObservedUniStream,
    },
};
use std::{
    fmt,
    sync::{Arc, Weak},
};
use tokio::time::Instant;

/// Connection observer attached to captured HTTP/3 requests.
#[derive(Clone)]
pub struct H3Observer {
    shared: Weak<Shared>,
    unavailable: Arc<H3ObservationSnapshot>,
}
impl Extension for H3Observer {}
impl fmt::Debug for H3Observer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H3Observer").finish_non_exhaustive()
    }
}

/// A SETTINGS wait always reports its termination condition separately from its data.
#[derive(Debug, Clone)]
pub enum SettingsObservation {
    Received(Arc<H3ObservationSnapshot>),
    TimedOut(Arc<H3ObservationSnapshot>),
    Closed {
        snapshot: Arc<H3ObservationSnapshot>,
        error: Option<Code>,
    },
}

impl H3Observer {
    pub(crate) fn new(shared: &Arc<Shared>, unavailable: Arc<H3ObservationSnapshot>) -> Self {
        Self {
            shared: Arc::downgrade(shared),
            unavailable,
        }
    }

    /// Return immediately; old snapshots never change as later frames arrive.
    #[must_use]
    pub fn snapshot(&self) -> Arc<H3ObservationSnapshot> {
        self.shared
            .upgrade()
            .and_then(|s| s.observation_snapshot())
            .unwrap_or_else(|| self.unavailable.clone())
    }

    /// Wait only until this explicit consumer's deadline; ordinary requests do not wait.
    pub async fn settings(&self, deadline: Instant) -> SettingsObservation {
        match self.shared.upgrade() {
            Some(shared) => {
                shared
                    .observation_settings(deadline, &self.unavailable)
                    .await
            }
            None => SettingsObservation::Closed {
                snapshot: self.unavailable.clone(),
                error: None,
            },
        }
    }
}

pub(super) struct Recorder {
    limits: ObservationLimits,
    bytes: usize,
    value: H3ObservationSnapshot,
    pending: Option<FrameHeader>,
    current: Option<Arc<H3ObservationSnapshot>>,
    live: Vec<Weak<H3ObservationSnapshot>>,
    pub(super) unavailable: Arc<H3ObservationSnapshot>,
}

impl Recorder {
    pub(super) fn new(limits: ObservationLimits, local: &Settings) -> Self {
        let mut this = Self {
            limits,
            bytes: 0,
            value: H3ObservationSnapshot {
                completeness: ObservationCompleteness {
                    settings: false,
                    streams: true,
                    control: true,
                    qpack: true,
                    fields: true,
                    snapshot: true,
                },
                ..H3ObservationSnapshot::default()
            },
            pending: None,
            current: None,
            live: Vec::new(),
            unavailable: Arc::new(H3ObservationSnapshot::default()),
        };
        let bytes = local
            .entries()
            .len()
            .saturating_mul(size_of::<ObservedSetting>());
        if this.reserve(bytes) {
            this.value.local_settings = settings(local);
        } else {
            this.value.completeness.control = false;
        }
        this
    }

    fn reserve(&mut self, bytes: usize) -> bool {
        if bytes > self.limits.bytes.saturating_sub(self.bytes) {
            return false;
        }
        self.bytes += bytes;
        true
    }

    pub(super) fn changed(&mut self) {
        self.value.revision = self.value.revision.saturating_add(1);
    }

    pub(super) fn stream(&mut self, stream_id: u64, ty: StreamType) {
        self.changed();
        if self.value.streams.len() >= self.limits.streams
            || !self.reserve(size_of::<ObservedUniStream>())
        {
            self.value.completeness.streams = false;
            return;
        }
        self.value.streams.push(ObservedUniStream {
            sequence: self.value.revision,
            stream_id,
            stream_type: ty.value(),
            grease: ty.is_reserved(),
        });
    }

    pub(super) fn control(&mut self, event: &FrameEvent) {
        if let FrameEvent::Header(header) = event {
            self.pending = Some(*header);
            return;
        }
        let Some(header) = self.pending.take() else {
            return;
        };
        self.changed();
        let (element_id, value) = match event {
            FrameEvent::CancelPush(id) | FrameEvent::GoAway(id) | FrameEvent::MaxPushId(id) => {
                (Some(*id), &[][..])
            }
            FrameEvent::PriorityUpdate {
                element_id,
                field_value,
                ..
            } => (Some(*element_id), &field_value[..]),
            _ => (None, &[][..]),
        };
        if let FrameEvent::Settings(peer) = event {
            let charge = peer
                .entries()
                .len()
                .saturating_mul(size_of::<ObservedSetting>());
            if self.reserve(charge) {
                self.value.settings = Some(settings(peer));
                self.value.completeness.settings = true;
            }
        }
        if self.value.control.len() >= self.limits.events
            || !self.reserve(size_of::<ObservedControlFrame>().saturating_add(value.len()))
        {
            self.value.completeness.control = false;
            return;
        }
        self.value.control.push(ObservedControlFrame {
            sequence: self.value.revision,
            frame_type: header.ty.value(),
            length: header.len,
            element_id,
            value: value.to_vec(),
        });
    }

    pub(super) fn snapshot(
        &mut self,
        instructions: Option<(&[ObservedEncoderInstruction], bool)>,
        error: Option<Code>,
    ) -> Arc<H3ObservationSnapshot> {
        if let Some(current) = &self.current
            && current.revision == self.value.revision
            && current.connection_error == error.map(Code::value)
        {
            return current.clone();
        }
        self.current = None;
        self.live.retain(|snapshot| snapshot.strong_count() > 0);
        if self.live.len() >= self.limits.retained_snapshots {
            return self.unavailable.clone();
        }
        let mut value = self.value.clone();
        value.connection_error = error.map(Code::value);
        if let Some((instructions, complete)) = instructions {
            let available = self.limits.bytes.saturating_sub(self.bytes)
                / size_of::<ObservedEncoderInstruction>();
            let retained = instructions.len().min(available);
            value.encoder_instructions = instructions[..retained].to_vec();
            value.completeness.qpack = complete && retained == instructions.len();
        }
        let snapshot = Arc::new(value);
        self.live.push(Arc::downgrade(&snapshot));
        self.current = Some(snapshot.clone());
        snapshot
    }
}

fn settings(value: &Settings) -> Vec<ObservedSetting> {
    value
        .entries()
        .iter()
        .map(|setting| ObservedSetting {
            id: setting.id.value(),
            value: setting.value,
            grease: setting.id.is_reserved(),
        })
        .collect()
}
