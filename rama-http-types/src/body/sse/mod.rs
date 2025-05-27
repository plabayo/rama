//! SSE support
//!
//! Some code in this repo is adapted from third party sources:
//! - Axum (see <https://github.com/plabayo/rama/blob/main/docs/thirdparty/fork/README.md#relative-forks>)
//! - <https://github.com/jpopesculian/eventsource-stream/tree/3d46f1c758f9ee4681e9da0427556d24c53f9c01>:
//!   - Licensed under MIT OR Apache-2.0, owned by Julian Popescu <jpopesculian@gmail.com>

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
