//! A byte-faithful, low-allocation HTML tokenizer.
//!
//! The tokenizer scans HTML into a stream of [`StartTag`], [`EndTag`],
//! [`Text`], [`Comment`] and [`Doctype`] events delivered to a
//! [`TokenSink`]. It is the substrate for rama's streaming HTML rewriting:
//! token views borrow the input (no per-token allocation), and every byte
//! of the input belongs to exactly one token's `raw()` span, so an
//! unmodified pass re-serializes to byte-identical output.
//!
//! Unlike a DOM parser it builds no tree and decodes no character
//! references — text and attribute values are exposed as raw bytes.
//!
//! # Example
//!
//! ```
//! use rama_http::protocols::html::tokenizer::{StartTag, TokenSink, tokenize};
//!
//! #[derive(Default)]
//! struct LinkCollector(Vec<Vec<u8>>);
//!
//! impl TokenSink for LinkCollector {
//!     fn start_tag(&mut self, tag: &StartTag<'_>) {
//!         if tag.name() == b"a" {
//!             for attr in tag.attributes() {
//!                 if attr.name() == b"href" {
//!                     self.0.push(attr.value().to_vec());
//!                 }
//!             }
//!         }
//!     }
//! }
//!
//! let mut links = LinkCollector::default();
//! tokenize(br#"<p>see <a href="/x">x</a></p>"#, &mut links);
//! assert_eq!(links.0, vec![b"/x".to_vec()]);
//! ```
//!
//! ## Scope (current)
//!
//! This is the first slice: a single-pass tokenizer over a complete input.
//! Text-mode switching for `<script>` / `<style>` / `<textarea>` / … and
//! foreign-content (SVG/MathML) handling, plus chunked streaming, land in
//! later slices. The identity property already holds for all input.

mod machine;
mod name;
mod sink;
mod token;

#[cfg(test)]
mod tests;

pub use self::machine::{Tokenizer, tokenize};
pub use self::name::LocalNameHash;
pub use self::sink::TokenSink;
pub use self::token::{Attribute, Attributes, Comment, Doctype, EndTag, StartTag, Text};
