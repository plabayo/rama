mod event;
mod event_data;
mod event_stream;
mod parser;
mod utf8_stream;

#[doc(inline)]
pub use {
    event::{Event, EventBuildError},
    event_data::{EventDataRead, EventDataWrite, JsonEventData},
    event_stream::EventStream,
};

pub mod server;
