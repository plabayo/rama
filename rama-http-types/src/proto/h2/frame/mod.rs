use crate::proto::h2::hpack::DecoderError;
use rama_core::bytes::Bytes;
use std::fmt;

mod data;
mod early_frame;
mod go_away;
mod head;
mod headers;
mod ping;
mod priority;
mod reason;
mod reset;
mod setting;
mod settings;
mod stream_id;
mod util;
mod window_update;

pub use self::data::Data;
pub use self::early_frame::{EarlyFrame, EarlyFrameCapture, EarlyFrameStreamContext};
pub use self::go_away::GoAway;
pub use self::head::{Head, Kind};
pub use self::headers::{
    Continuation, Headers, Pseudo, PushPromise, PushPromiseHeaderError, parse_u64,
};
pub use self::ping::Ping;
pub use self::priority::{Priority, StreamDependency};
pub use self::reason::Reason;
pub use self::reset::Reset;
pub use self::setting::{Setting, SettingId, SettingOrder, SettingsConfig};
pub use self::settings::Settings;
pub use self::stream_id::{StreamId, StreamIdOverflow};
pub use self::window_update::WindowUpdate;

// Re-export some constants

pub use self::settings::{
    DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_FRAME_SIZE, DEFAULT_SETTINGS_HEADER_TABLE_SIZE,
    MAX_MAX_FRAME_SIZE,
};

pub type FrameSize = u32;

pub const HEADER_LEN: usize = 9;

#[derive(Eq, PartialEq)]
pub enum Frame<T = Bytes> {
    Data(Data<T>),
    Headers(Headers),
    Priority(Priority),
    PushPromise(PushPromise),
    Settings(Settings),
    Ping(Ping),
    GoAway(GoAway),
    WindowUpdate(WindowUpdate),
    Reset(Reset),
}

impl<T> Frame<T> {
    pub fn map<F, U>(self, f: F) -> Frame<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Self::Data(frame) => frame.map(f).into(),
            Self::Headers(frame) => frame.into(),
            Self::Priority(frame) => frame.into(),
            Self::PushPromise(frame) => frame.into(),
            Self::Settings(frame) => frame.into(),
            Self::Ping(frame) => frame.into(),
            Self::GoAway(frame) => frame.into(),
            Self::WindowUpdate(frame) => frame.into(),
            Self::Reset(frame) => frame.into(),
        }
    }
}

impl<T> fmt::Debug for Frame<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Data(ref frame) => fmt::Debug::fmt(frame, fmt),
            Self::Headers(ref frame) => fmt::Debug::fmt(frame, fmt),
            Self::Priority(ref frame) => fmt::Debug::fmt(frame, fmt),
            Self::PushPromise(ref frame) => fmt::Debug::fmt(frame, fmt),
            Self::Settings(ref frame) => fmt::Debug::fmt(frame, fmt),
            Self::Ping(ref frame) => fmt::Debug::fmt(frame, fmt),
            Self::GoAway(ref frame) => fmt::Debug::fmt(frame, fmt),
            Self::WindowUpdate(ref frame) => fmt::Debug::fmt(frame, fmt),
            Self::Reset(ref frame) => fmt::Debug::fmt(frame, fmt),
        }
    }
}

/// Errors that can occur during parsing an HTTP/2 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A length value other than 8 was set on a PING message.
    BadFrameSize,

    /// The padding length was larger than the frame-header-specified
    /// length of the payload.
    TooMuchPadding,

    /// An invalid setting value was provided
    InvalidSettingValue,

    /// An invalid window update value
    InvalidWindowUpdateValue,

    /// The payload length specified by the frame header was not the
    /// value necessary for the specific frame type.
    InvalidPayloadLength,

    /// Received a payload with an ACK settings frame
    InvalidPayloadAckSettings,

    /// An invalid stream identifier was provided.
    ///
    /// This is returned if a SETTINGS or PING frame is received with a stream
    /// identifier other than zero.
    InvalidStreamId,

    /// A request or response is malformed.
    MalformedMessage,

    /// An invalid stream dependency ID was provided
    ///
    /// This is returned if a HEADERS or PRIORITY frame is received with an
    /// invalid stream identifier.
    InvalidDependencyId,

    /// Failed to perform HPACK decoding
    Hpack(DecoderError),
}
