use crate::proto::h2::frame::{Frame, Priority, Settings, WindowUpdate};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// A [`Frame`] which is sent often early before any data
pub enum EarlyFrame {
    Priority(Priority),
    Settings(Settings),
    WindowUpdate(WindowUpdate),
}

impl<T> From<EarlyFrame> for Frame<T> {
    fn from(value: EarlyFrame) -> Self {
        match value {
            EarlyFrame::Priority(priority) => Frame::Priority(priority),
            EarlyFrame::Settings(settings) => Frame::Settings(settings),
            EarlyFrame::WindowUpdate(window_update) => Frame::WindowUpdate(window_update),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EarlyFrameStreamContext {
    kind: EarlyFrameKind,
}

impl EarlyFrameStreamContext {
    pub fn new_nop() -> Self {
        Self {
            kind: EarlyFrameKind::Nop,
        }
    }

    pub fn new_recorder() -> Self {
        Self {
            kind: EarlyFrameKind::Recorder(EarlyFrameRecorder {
                recording: Some(Vec::with_capacity(8)),
                frozen: None,
            }),
        }
    }

    pub fn new_replayer(mut frames: Vec<EarlyFrame>) -> Self {
        frames.reverse();
        Self {
            kind: EarlyFrameKind::Replayer(frames),
        }
    }
}

impl EarlyFrameStreamContext {
    pub fn record_priority_frame(&mut self, frame: &Priority) {
        if let EarlyFrameKind::Recorder(ref mut recorder) = self.kind {
            recorder.record_priority_frame(frame);
        }
    }

    pub fn record_settings_frame(&mut self, frame: &Settings) {
        if let EarlyFrameKind::Recorder(ref mut recorder) = self.kind {
            recorder.record_settings_frame(frame);
        }
    }

    pub fn record_windows_update_frame(&mut self, frame: &WindowUpdate) {
        if let EarlyFrameKind::Recorder(ref mut recorder) = self.kind {
            recorder.record_windows_update_frame(frame);
        }
    }

    /// Does nothing in case the ctx is not a recorder.
    pub fn freeze_recorder(&mut self) -> Option<EarlyFrameCapture> {
        if let EarlyFrameKind::Recorder(ref mut recorder) = self.kind {
            return recorder.freeze();
        }
        None
    }

    pub fn replay_next_frame(&mut self) -> Option<EarlyFrame> {
        if let EarlyFrameKind::Replayer(ref mut v) = self.kind {
            let next = v.pop();
            if v.is_empty() {
                self.kind = EarlyFrameKind::Nop;
            }
            return next;
        }
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

    fn record_windows_update_frame(&mut self, frame: &WindowUpdate) {
        if let Some(ref mut c) = self.recording {
            c.push(EarlyFrame::WindowUpdate(*frame));
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
