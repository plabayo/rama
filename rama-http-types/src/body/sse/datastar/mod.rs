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

mod consts;

use crate::sse::{Event, EventDataLineReader, EventDataMultiLineReader, EventDataRead};
use rama_core::telemetry::tracing;

pub type DatastarEvent<T = String> = Event<EventData<T>>;

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
    /// Consume `self` as [`MergeFragments`],
    ///
    /// returning itself as an error if it is of a different type.
    pub fn into_merge_fragments(self) -> Result<MergeFragments, Self> {
        match self {
            EventData::MergeFragments(data) => Ok(data),
            EventData::RemoveFragments(_) => Err(self),
            EventData::MergeSignals(_) => Err(self),
            EventData::RemoveSignals(_) => Err(self),
            EventData::ExecuteScript(_) => Err(self),
        }
    }

    /// Consume `self` as [`RemoveFragments`].
    ///
    /// returning itself as an error if it is of a different type.
    pub fn into_remove_fragments(self) -> Result<RemoveFragments, Self> {
        match self {
            EventData::MergeFragments(_) => Err(self),
            EventData::RemoveFragments(data) => Ok(data),
            EventData::MergeSignals(_) => Err(self),
            EventData::RemoveSignals(_) => Err(self),
            EventData::ExecuteScript(_) => Err(self),
        }
    }

    /// Consume `self` as [`MergeSignals`].
    ///
    /// returning itself as an error if it is of a different type.
    pub fn into_merge_signals(self) -> Result<MergeSignals<T>, Self> {
        match self {
            EventData::MergeFragments(_) => Err(self),
            EventData::RemoveFragments(_) => Err(self),
            EventData::MergeSignals(data) => Ok(data),
            EventData::RemoveSignals(_) => Err(self),
            EventData::ExecuteScript(_) => Err(self),
        }
    }

    /// Consume `self` as [`RemoveSignals`].
    ///
    /// returning itself as an error if it is of a different type.
    pub fn into_remove_signals(self) -> Result<RemoveSignals, Self> {
        match self {
            EventData::MergeFragments(_) => Err(self),
            EventData::RemoveFragments(_) => Err(self),
            EventData::MergeSignals(_) => Err(self),
            EventData::RemoveSignals(data) => Ok(data),
            EventData::ExecuteScript(_) => Err(self),
        }
    }

    /// Consume `self` as [`ExecuteScript`].
    ///
    /// returning itself as an error if it is of a different type.
    pub fn into_execute_script(self) -> Result<ExecuteScript, Self> {
        match self {
            EventData::MergeFragments(_) => Err(self),
            EventData::RemoveFragments(_) => Err(self),
            EventData::MergeSignals(_) => Err(self),
            EventData::RemoveSignals(_) => Err(self),
            EventData::ExecuteScript(data) => Ok(data),
        }
    }

    /// Return the [`EventType`] for the current data
    pub fn event_type(&self) -> EventType {
        match self {
            EventData::MergeFragments(_) => EventType::MergeFragments,
            EventData::RemoveFragments(_) => EventType::RemoveFragments,
            EventData::MergeSignals(_) => EventType::MergeSignals,
            EventData::RemoveSignals(_) => EventType::RemoveSignals,
            EventData::ExecuteScript(_) => EventType::ExecuteScript,
        }
    }

    /// Consume `self` as an [`Event`].
    pub fn into_sse_event(self) -> Event<EventData<T>> {
        let event_type = self.event_type();
        Event::new()
            .try_with_event(event_type.as_smol_str())
            .unwrap()
            .with_retry(consts::DEFAULT_DATASTAR_DURATION)
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
            ExecuteScript::new(
                r##"console.log('Hello, world!')\nconsole.log('A second greeting')"##,
            )
            .with_auto_remove(false)
            .with_attributes([
                ScriptAttribute::Type(ScriptType::Module),
                ScriptAttribute::Defer,
            ])
            .into(),
            ExecuteScript::new(
                r##"console.log('Hello, world!')\nconsole.log('A second greeting')"##,
            )
            .with_auto_remove(true)
            .with_attribute(ScriptAttribute::Async)
            .into(),
            MergeFragments::new("<div>\nHello, world!\n</div>")
                .with_selector("#foo")
                .with_merge_mode(FragmentMergeMode::Append)
                .with_use_view_transition(true)
                .into(),
            MergeSignals::new(r##"{a:1,b:{"c":2}}"##.to_owned())
                .with_only_if_missing(true)
                .into(),
            RemoveFragments::new("body > main > header > .foo#bar::first")
                .with_use_view_transition(true)
                .into(),
            RemoveSignals::new_multi(["foo.bar", "baz"]).into(),
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
