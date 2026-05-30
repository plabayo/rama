//! Async streaming readers for RSS 2.0 and Atom 1.0 feeds.
//!
//! The stream-first entry points are the strongly-typed [`Rss2FeedStream`],
//! [`AtomFeedStream`], and the format-agnostic [`FeedStream`] umbrella. The
//! channel / feed header is read once at stream construction time (XML puts
//! it before any item / entry by spec) and the stream then yields items /
//! entries one at a time over the underlying byte source. Methods on the
//! stream let the caller borrow the header, `drain` into `(header, items)`,
//! or `collect` the lot into an in-memory feed — pick what fits the caller.

mod atom;
mod feed_stream;
mod rss2;

pub use atom::{AtomFeedStream, AtomHeader};
pub use feed_stream::FeedStream;
pub use rss2::{Rss2Channel, Rss2FeedStream};
