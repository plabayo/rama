//! Streaming request or response body utilities for capturing selected JSON
//! values while forwarding the body unchanged.
//!
//! [`JsonCaptureBody`] is useful when middleware needs to observe or decode
//! small selected JSON values but still pass the full body downstream. It uses
//! [`rama_json::capture`] under the hood: unmatched input is processed as a
//! stream, while selected values are bounded by `max_capture_bytes`.

mod body;

pub use body::JsonCaptureBody;

#[cfg(test)]
mod tests;
