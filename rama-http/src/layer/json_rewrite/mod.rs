//! Middleware that rewrites JSON request or response bodies on the fly, using
//! rama's streaming JSON rewriter ([`rama_json::rewrite`]).
//!
//! [`JsonRewriteLayer`] wraps a service and, for each response, checks the
//! `Content-Type`: an `application/json` or `application/*+json` body (that is
//! not content-encoded) is piped through a
//! [`JsonRewriter`](rama_json::rewrite::JsonRewriter) as it streams, applying
//! a handler to matched values; anything else is forwarded unchanged. Because
//! rewriting changes the body length, the layer drops the now-stale
//! `Content-Length`.
//! Handlers can replace or remove scalar values as well as whole object/array
//! subtrees.
//!
//! [`JsonRequestRewriteLayer`] does the same for request bodies before the
//! wrapped service sees the request.
//!
//! The body adapter, [`JsonRewriteBody`], is also usable on its own - e.g.
//! composed with [`MapResponseBodyLayer`](crate::layer::map_response_body) or
//! [`MapRequestBodyLayer`](crate::layer::map_request_body) -
//! when you already handle the header concerns yourself.
//!
//! ## Handlers
//!
//! The handler is any type implementing
//! [`JsonValueHandler`](rama_json::rewrite::JsonValueHandler). The layer
//! requires it to be `Clone` (it is cloned per body, so each request/response
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
//! rewrite compressed requests or responses.

mod body;
mod service;

pub use body::JsonRewriteBody;
pub use service::{JsonRequestRewrite, JsonRequestRewriteLayer, JsonRewrite, JsonRewriteLayer};

#[cfg(test)]
mod tests;
