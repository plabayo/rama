//! Middleware that rewrites JSON response bodies on the fly, using
//! rama's streaming JSON rewriter ([`rama_json::rewrite`]).
//!
//! [`JsonRewriteLayer`] wraps a service and, for each response, checks the
//! `Content-Type`: an `application/json` or `application/*+json` body (that is
//! not content-encoded) is piped through a
//! [`JsonRewriter`](rama_json::rewrite::JsonRewriter) as it streams, applying
//! a handler to matched values; anything else is forwarded unchanged. Because
//! rewriting changes the body length, the layer drops the now-stale
//! `Content-Length`.
//!
//! The body adapter, [`JsonRewriteBody`], is also usable on its own - e.g.
//! composed with [`MapResponseBodyLayer`](crate::layer::map_response_body) -
//! when you already handle the header concerns yourself.
//!
//! ## Handlers
//!
//! The handler is any type implementing
//! [`JsonValueHandler`](rama_json::rewrite::JsonValueHandler). The layer
//! requires it to be `Clone` (it is cloned per response, so each response
//! rewrites with fresh handler state) and `Send`. A plain data struct fits
//! naturally, since the rewriter is owned and only touched through `&mut self`
//! while the body is polled.
//!
//! When the handler *accumulates* state, recover it once the body finishes
//! via [`JsonRewriteBody::on_end`].
//!
//! ## Encoding
//!
//! The rewriter sees raw bytes, so a compressed (`Content-Encoding`) body is
//! skipped. Place this layer *after* a decompression layer if you need to
//! rewrite compressed responses.

mod body;
mod service;

pub use body::JsonRewriteBody;
pub use service::{JsonRewrite, JsonRewriteLayer};

#[cfg(test)]
mod tests;
