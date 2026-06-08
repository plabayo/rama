//! Middleware that rewrites `text/html` response bodies on the fly, using
//! rama's streaming HTML rewriter ([`crate::protocols::html::rewrite`]).
//!
//! [`HtmlRewriteLayer`] wraps a service and, for each response, checks the
//! `Content-Type`: a `text/html` body (that is not content-encoded) is piped
//! through an [`HtmlRewriter`](crate::protocols::html::rewrite::HtmlRewriter)
//! as it streams, applying a handler to matched elements; anything else is
//! forwarded unchanged. Because rewriting changes the body length, the layer
//! drops the now-stale `Content-Length`.
//!
//! The body adapter, [`HtmlRewriteBody`], is also usable on its own — e.g.
//! composed with [`MapResponseBodyLayer`](crate::layer::map_response_body) —
//! when you already handle the header concerns yourself.
//!
//! ## Handlers
//!
//! The handler is any type implementing
//! [`ElementContentHandler`](crate::protocols::html::rewrite::ElementContentHandler).
//! The layer requires it to be `Clone` (it is cloned per response, so each
//! response rewrites with fresh handler state) and `Send`. A plain data
//! struct fits naturally — no `Rc<RefCell>` / `Arc<Mutex>` / `SyncWrapper`
//! ceremony, since the rewriter is owned and only touched through `&mut self`
//! while the body is polled.
//!
//! ## Encoding
//!
//! The rewriter sees raw bytes, so a compressed (`Content-Encoding`) body is
//! skipped. Place this layer *after* a decompression layer if you need to
//! rewrite compressed responses. Charset is assumed UTF-8 (the rewriter is
//! byte-faithful and does not decode entities).

mod body;
mod service;

pub use body::HtmlRewriteBody;
pub use service::{HtmlRewrite, HtmlRewriteLayer};

#[cfg(test)]
mod tests;
