//! Async streaming readers for RSS 2.0 and Atom 1.0 feeds.
//!
//! The stream-first entry points are the strongly-typed [`Rss2FeedStream`],
//! [`AtomFeedStream`], and the format-agnostic [`FeedStream`] umbrella. The
//! header / channel metadata is read once at stream construction time (XML
//! puts it before any item / entry by spec) and the stream then yields one
//! item / entry at a time over the underlying byte source. Methods on the
//! stream let the caller borrow the header, `drain` into `(header, items)`,
//! or `collect` the lot into an in-memory feed — pick what fits the caller.
//!
//! The internal event-emitting functions (`*_event_stream` /
//! `Rss2ReadEvent` / `AtomReadEvent`) stay private; they are the engine the
//! strongly-typed wrappers sit on, not part of the public API.

mod atom1;
mod feed_stream;
mod rss2;

pub use atom1::AtomHeader;
pub use feed_stream::{AtomFeedStream, FeedStream, Rss2FeedStream};
pub use rss2::Rss2Channel;
