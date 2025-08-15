//! [🚀 Datastar] support for rama.
//!
//! Datastar helps you build reactive web applications with the simplicity
//! of server-side rendering and the power of a full-stack SPA framework.
//!
//! It's the combination of a small js library which makes use of SSE among other utilities,
//! this module implements the event data types used from the server-side to send to the client,
//! which makes use of this JS library.
//!
//! You can join the discord server of [🚀 Datastar] at <https://discord.gg/sGfFuw9k>,
//! after which you can join [the #general-rust channel](https://discord.com/channels/1296224603642925098/1315397669954392146)
//! for any datastar specific help.
//!
//! Combining [🚀 Datastar] with 🦙 Rama (ラマ) provides a powerful foundation
//! for your web application—one that **empowers you to build and scale without limitations**.
//!
//! [🚀 Datastar]: https://data-star.dev/

mod enums;
pub use enums::{ElementPatchMode, EventType};

mod patch_elements;
pub use patch_elements::{PatchElements, PatchElementsReader};

pub mod execute_script;
pub use execute_script::ExecuteScript;

mod patch_signals;
pub use patch_signals::{PatchSignals, PatchSignalsReader};

use crate::sse::{Event, EventDataLineReader, EventDataMultiLineReader, EventDataRead};
use rama_core::telemetry::tracing;
use rama_error::{ErrorContext, OpaqueError};
use std::marker::PhantomData;

pub type DatastarEvent<T = String> = Event<EventData<T>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventData<T = String> {
    /// [`PatchElements`]: patches HTML elements into the DOM
    PatchElements(PatchElements),
    /// [`ExecuteScript`]: utility sugar for [`PatchElements`]
    /// specialized for adding js scripts. Required by datastar
    /// to be part of all datastar SDKs.
    ExecuteScript(ExecuteScript),
    /// [`RemoveFragments`]: patches signals into the signal store
    PatchSignals(PatchSignals<T>),
}

macro_rules! into_event_data {
    ($($t:ident),+ $(,)?) => {
        $(
            impl<T> From<$t> for EventData<T> {
                fn from(value: $t) -> Self {
                    EventData::$t(value)
                }
            }
        )+
    };
}

into_event_data! {
    PatchElements,
    ExecuteScript,
}

impl<T> From<PatchSignals<T>> for EventData<T> {
    fn from(value: PatchSignals<T>) -> Self {
        Self::PatchSignals(value)
    }
}

impl<T> EventData<T> {
    /// Consume `self` as [`PatchElements`],
    ///
    /// returning itself as an error if it is of a different type.
    pub fn into_patch_elements(self) -> Result<PatchElements, Self> {
        match self {
            Self::PatchElements(data) => Ok(data),
            Self::ExecuteScript(_) | Self::PatchSignals(_) => Err(self),
        }
    }

    /// Consume `self` as [`PatchSignals`].
    ///
    /// returning itself as an error if it is of a different type.
    pub fn into_patch_signals(self) -> Result<PatchSignals<T>, Self> {
        match self {
            Self::PatchElements(_) | Self::ExecuteScript(_) => Err(self),
            Self::PatchSignals(data) => Ok(data),
        }
    }

    /// Return the [`EventType`] for the current data
    pub fn event_type(&self) -> EventType {
        match self {
            Self::PatchElements(_) | Self::ExecuteScript(_) => EventType::PatchElements,
            Self::PatchSignals(_) => EventType::PatchSignals,
        }
    }

    /// Consume `self` as an [`Event`].
    pub fn into_sse_event(self) -> Event<Self> {
        let event_type = self.event_type();
        Event::new()
            .try_with_event(event_type.as_smol_str())
            .unwrap()
            .with_data(self)
    }
}

impl<T: crate::sse::EventDataWrite> crate::sse::EventDataWrite for EventData<T> {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        match self {
            Self::PatchElements(patch_elements) => patch_elements.write_data(w),
            Self::ExecuteScript(exec_script) => exec_script.write_data(w),
            Self::PatchSignals(patch_signals) => patch_signals.write_data(w),
        }
    }
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`RemoveSignals`].
#[derive(Debug)]
pub struct EventDataReader<T = String> {
    reader: EventDataMultiLineReader<String>,
    _phantom: PhantomData<fn() -> T>,
}

impl<T: EventDataRead> EventDataRead for EventData<T> {
    type Reader = EventDataReader<T>;

    fn line_reader() -> Self::Reader {
        EventDataReader {
            reader: Vec::<String>::line_reader(),
            _phantom: PhantomData,
        }
    }
}

impl<T: EventDataRead> EventDataLineReader for EventDataReader<T> {
    type Data = EventData<T>;

    fn read_line(&mut self, line: &str) -> Result<(), OpaqueError> {
        self.reader.read_line(line)
    }

    fn data(&mut self, event: Option<&str>) -> Result<Option<Self::Data>, OpaqueError> {
        let Some(lines) = self.reader.data(None)? else {
            return Ok(None);
        };

        let event_type: EventType = event
            .context("event type is required for event data")?
            .parse()
            .context("parse event type as datastar event type")?;

        match event_type {
            EventType::PatchElements => {
                let mut reader = PatchElements::line_reader();
                for line in lines {
                    reader
                        .read_line(&line)
                        .context("EventData: PatchElements: read line")?;
                }
                reader.data(event).map(|v| v.map(EventData::PatchElements))
            }
            EventType::PatchSignals => {
                let mut reader = PatchSignals::<T>::line_reader();
                for line in lines {
                    reader
                        .read_line(&line)
                        .context("EventData: PatchSignals: read line")?;
                }
                reader.data(event).map(|v| v.map(EventData::PatchSignals))
            }
            EventType::Unknown(event_type) => {
                tracing::trace!("ignore datastar event with unknown event type: {event_type}");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sse::EventDataWrite;

    use super::*;

    fn read_datastar_event_data(event: &str, input: &str) -> EventData {
        let mut reader = EventData::line_reader();
        for line in input.lines() {
            reader.read_line(line).unwrap();
        }
        reader.data(Some(event)).unwrap().unwrap()
    }

    #[test]
    fn test_serialize_deserialize_reflect() {
        let test_cases: Vec<EventData> = vec![
            PatchElements::new("<div>\nHello, world!\n</div>")
                .with_selector("#foo")
                .with_mode(ElementPatchMode::Append)
                .with_use_view_transition(true)
                .into(),
            PatchSignals::new(r##"{a:1,b:{"c":2}}"##.to_owned())
                .with_only_if_missing(true)
                .into(),
        ];

        for test_case in test_cases {
            let mut buf = Vec::new();
            test_case.write_data(&mut buf).unwrap();

            let input = String::from_utf8(buf).unwrap();
            let data = read_datastar_event_data(test_case.event_type().as_str(), &input);

            assert_eq!(test_case, data);
        }
    }
}
