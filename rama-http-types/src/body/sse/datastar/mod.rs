//! [🚀 data-\*] support for rama.
//!
//! Datastar helps you build reactive web applications with the simplicity
//! of server-side rendering and the power of a full-stack SPA framework.
//!
//! It's the combination of a small js library which makes use of SSE among other utilities,
//! this module implements the event data types used from the server-side to send to the client,
//! which makes use of this JS library.
//!
//! You can join the discord server of [🚀 data-\*] at <https://discord.gg/sGfFuw9k>,
//! after which you can join [the #general-rust channel](https://discord.com/channels/1296224603642925098/1315397669954392146)
//! for any datastar specific help.
//!
//! Combining [🚀 data-\*] with 🦙 Rama (ラマ) provides a powerful foundation
//! for your web application—one that **empowers you to build and scale without limitations**.
//!
//! [🚀 data-\*]: https://data-star.dev/

mod enums;
use std::marker::PhantomData;

pub use enums::{EventType, FragmentMergeMode};

mod merge_fragments;
pub use merge_fragments::{MergeFragments, MergeFragmentsReader};

mod remove_fragments;
use rama_error::{ErrorContext, OpaqueError};
pub use remove_fragments::{RemoveFragments, RemoveFragmentsReader};

mod merge_signals;
pub use merge_signals::{MergeSignals, MergeSignalsReader};

mod remove_signals;
pub use remove_signals::{RemoveSignals, RemoveSignalsReader};

mod execute_script;
pub use execute_script::{
    CrossOriginKind, ExecuteScript, ExecuteScriptReader, ReferrerPolicy, ScriptAttribute,
    ScriptType,
};

use crate::sse::{Event, EventDataLineReader, EventDataMultiLineReader, EventDataRead};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventData<T = String> {
    /// [`MergeFragments`] merges one or more fragments into the DOM.
    MergeFragments(MergeFragments),
    /// [`RemoveFragments`] sends a selector to the browser to remove HTML fragments from the DOM.
    RemoveFragments(RemoveFragments),
    /// [`MergeSignals`] sends one or more signals to the browser
    /// to be merged into the signals.
    MergeSignals(MergeSignals<T>),
    /// [`RemoveSignals`] sends signals to the browser to be removed from the signals.
    RemoveSignals(RemoveSignals),
    /// [`ExecuteScript`] executes JavaScript in the browser
    ExecuteScript(ExecuteScript),
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
    MergeFragments,
    RemoveFragments,
    RemoveSignals,
    ExecuteScript,
}

impl<T> From<MergeSignals<T>> for EventData<T> {
    fn from(value: MergeSignals<T>) -> Self {
        EventData::MergeSignals(value)
    }
}

impl<T> EventData<T> {
    /// Consume `self` as an [`Event`].
    pub fn into_sse_event(self) -> Event<EventData<T>> {
        let event_type = match self {
            EventData::MergeFragments(_) => EventType::MergeFragments,
            EventData::RemoveFragments(_) => EventType::RemoveFragments,
            EventData::MergeSignals(_) => EventType::MergeSignals,
            EventData::RemoveSignals(_) => EventType::RemoveSignals,
            EventData::ExecuteScript(_) => EventType::ExecuteScript,
        };
        Event::new()
            .try_with_event(event_type.as_smol_str())
            .unwrap()
            .with_data(self)
    }
}

impl<T: crate::sse::EventDataWrite> crate::sse::EventDataWrite for EventData<T> {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        match self {
            EventData::MergeFragments(merge_fragments) => merge_fragments.write_data(w),
            EventData::RemoveFragments(remove_fragments) => remove_fragments.write_data(w),
            EventData::MergeSignals(merge_signals) => merge_signals.write_data(w),
            EventData::RemoveSignals(remove_signals) => remove_signals.write_data(w),
            EventData::ExecuteScript(execute_script) => execute_script.write_data(w),
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
        let lines = match self.reader.data(None)? {
            Some(data) => data,
            None => return Ok(None),
        };

        let event_type: EventType = event
            .context("event type is required for event data")?
            .parse()
            .context("parse event type as datastar event type")?;

        match event_type {
            EventType::MergeFragments => {
                let mut reader = MergeFragments::line_reader();
                for line in lines {
                    reader
                        .read_line(&line)
                        .context("EventData: MergeFragments: read line")?;
                }
                reader.data(event).map(|v| v.map(EventData::MergeFragments))
            }
            EventType::MergeSignals => {
                let mut reader = MergeSignals::<T>::line_reader();
                for line in lines {
                    reader
                        .read_line(&line)
                        .context("EventData: MergeSignals: read line")?;
                }
                reader.data(event).map(|v| v.map(EventData::MergeSignals))
            }
            EventType::RemoveFragments => {
                let mut reader = RemoveFragments::line_reader();
                for line in lines {
                    reader
                        .read_line(&line)
                        .context("EventData: RemoveFragments: read line")?;
                }
                reader
                    .data(event)
                    .map(|v| v.map(EventData::RemoveFragments))
            }
            EventType::RemoveSignals => {
                let mut reader = RemoveSignals::line_reader();
                for line in lines {
                    reader
                        .read_line(&line)
                        .context("EventData: RemoveSignals: read line")?;
                }
                reader.data(event).map(|v| v.map(EventData::RemoveSignals))
            }
            EventType::ExecuteScript => {
                let mut reader = ExecuteScript::line_reader();
                for line in lines {
                    reader
                        .read_line(&line)
                        .context("EventData: ExecuteScript: read line")?;
                }
                reader.data(event).map(|v| v.map(EventData::ExecuteScript))
            }
            EventType::Unknown(event_type) => {
                tracing::trace!(%event_type, "ignore datastar event with unknown event type");
                Ok(None)
            }
        }
    }
}
