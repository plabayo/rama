use crate::proto::h2::frame::{Frame, Priority, Settings, StreamId, WindowUpdate};
use rama_core::telemetry::tracing;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// A [`Frame`] which is sent often early before any data
pub enum EarlyFrame {
    Priority(Priority),
    Settings(Settings),
    WindowUpdate(WindowUpdate),
}

impl EarlyFrame {
    /// returns true if this early frame applies to a stream already created
    #[must_use]
    pub fn stream_created(&self, next_stream_id: StreamId) -> bool {
        match self {
            Self::Priority(priority) => next_stream_id > priority.stream_id,
            Self::Settings(_) => true,
            Self::WindowUpdate(window_update) => next_stream_id > window_update.stream_id,
        }
    }
}

impl<T> From<EarlyFrame> for Frame<T> {
    fn from(value: EarlyFrame) -> Self {
        match value {
            EarlyFrame::Priority(priority) => Self::Priority(priority),
            EarlyFrame::Settings(settings) => Self::Settings(settings),
            EarlyFrame::WindowUpdate(window_update) => Self::WindowUpdate(window_update),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EarlyFrameStreamContext {
    kind: EarlyFrameKind,
}

impl EarlyFrameStreamContext {
    #[must_use]
    pub fn new_nop() -> Self {
        Self {
            kind: EarlyFrameKind::Nop,
        }
    }

    #[must_use]
    pub fn new_recorder() -> Self {
        Self {
            kind: EarlyFrameKind::Recorder(EarlyFrameRecorder {
                recording: Some(Vec::with_capacity(8)),
                frozen: None,
            }),
        }
    }

    #[must_use]
    pub fn new_replayer(mut frames: Vec<EarlyFrame>) -> (Self, Option<Settings>) {
        frames.reverse();
        let settings = match frames.pop() {
            Some(frame) => match frame {
                EarlyFrame::Settings(settings) => Some(settings),
                EarlyFrame::Priority(_) | EarlyFrame::WindowUpdate(_) => {
                    frames.push(frame);
                    None
                }
            },
            None => {
                return (
                    Self {
                        kind: EarlyFrameKind::Nop,
                    },
                    None,
                );
            }
        };
        (
            Self {
                kind: EarlyFrameKind::Replayer(frames),
            },
            settings,
        )
    }
}

impl EarlyFrameStreamContext {
    pub fn record_priority_frame(&mut self, frame: &Priority) {
        tracing::trace!("record priority frame: {frame:?}");
        if let EarlyFrameKind::Recorder(ref mut recorder) = self.kind {
            recorder.record_priority_frame(frame);
        }
    }

    pub fn record_settings_frame(&mut self, frame: &Settings) {
        tracing::trace!("record settings frame: {frame:?}");
        if let EarlyFrameKind::Recorder(ref mut recorder) = self.kind {
            recorder.record_settings_frame(frame);
        }
    }

    pub fn record_windows_update_frame(&mut self, frame: WindowUpdate) {
        tracing::trace!("record windows update frame: {frame:?}");
        if let EarlyFrameKind::Recorder(ref mut recorder) = self.kind {
            recorder.record_windows_update_frame(frame);
        }
    }

    /// Does nothing in case the ctx is not a recorder.
    pub fn freeze_recorder(&mut self) -> Option<EarlyFrameCapture> {
        if let EarlyFrameKind::Recorder(ref mut recorder) = self.kind {
            tracing::trace!("freeze recorder");
            return recorder.freeze();
        }
        tracing::trace!("ctx::freeze_recorder: nop");
        None
    }

    pub fn replay_next_frame(&mut self, next_stream_id: Option<StreamId>) -> Option<EarlyFrame> {
        if let EarlyFrameKind::Replayer(ref mut v) = self.kind {
            if let Some(next_stream_id) = next_stream_id
                && !v
                    .last()
                    .map(|f| f.stream_created(next_stream_id))
                    .unwrap_or_default()
            {
                self.kind = EarlyFrameKind::Nop;
                tracing::trace!(
                    "stop replayer early, the scenario has changed, we are beyond the existing streams now"
                );
                return None;
            }

            let next = v.pop();
            if v.is_empty() {
                self.kind = EarlyFrameKind::Nop;
            }
            tracing::trace!("replay_next_frame: frame = {:?}", next);
            return next;
        }
        tracing::trace!("replay_next_frame: EOF");
        None
    }
}

#[derive(Debug, Default, Clone)]
enum EarlyFrameKind {
    Recorder(EarlyFrameRecorder),
    Replayer(Vec<EarlyFrame>),
    #[default]
    Nop,
}

#[derive(Debug, Clone)]
/// Can be used by an h2 backend to record early frames.
struct EarlyFrameRecorder {
    recording: Option<Vec<EarlyFrame>>,
    frozen: Option<Arc<Vec<EarlyFrame>>>,
}

#[derive(Debug, Clone)]
pub struct EarlyFrameCapture(Arc<Vec<EarlyFrame>>);

impl EarlyFrameCapture {
    #[must_use]
    pub fn as_slice(&self) -> &[EarlyFrame] {
        &self.0
    }

    pub fn iter(&self) -> impl Iterator<Item = &EarlyFrame> {
        self.0.iter()
    }
}

impl serde::Serialize for EarlyFrameCapture {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_slice().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EarlyFrameCapture {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = <Vec<EarlyFrame>>::deserialize(deserializer)?;
        Ok(Self(v.into()))
    }
}

impl EarlyFrameRecorder {
    const MAX_FRAMES: usize = 16;

    fn record_priority_frame(&mut self, frame: &Priority) {
        if let Some(ref mut c) = self.recording {
            c.push(EarlyFrame::Priority(frame.clone()));
            if c.len() >= Self::MAX_FRAMES {
                self.frozen = Some(self.recording.take().unwrap().into());
            }
        }
    }

    fn record_settings_frame(&mut self, frame: &Settings) {
        if let Some(ref mut c) = self.recording {
            c.push(EarlyFrame::Settings(frame.clone()));
            if c.len() >= Self::MAX_FRAMES {
                self.frozen = Some(self.recording.take().unwrap().into());
            }
        }
    }

    fn record_windows_update_frame(&mut self, frame: WindowUpdate) {
        if let Some(ref mut c) = self.recording {
            c.push(EarlyFrame::WindowUpdate(frame));
            if c.len() >= Self::MAX_FRAMES {
                self.frozen = Some(self.recording.take().unwrap().into());
            }
        }
    }

    fn freeze(&mut self) -> Option<EarlyFrameCapture> {
        if let Some(fc) = self.frozen.clone() {
            return Some(EarlyFrameCapture(fc));
        }

        let c = std::mem::take(&mut self.recording)?;
        if c.is_empty() {
            return None;
        }

        let fc = Arc::new(c);
        self.frozen = Some(fc.clone());
        Some(EarlyFrameCapture(fc))
    }
}
