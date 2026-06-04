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
//! ## Scope (current)
//!
//! Single-pass over a complete input, with correct text-mode handling for
//! `<script>` / `<style>` / `<textarea>` / `<title>` / `<plaintext>` / ….
//! Foreign content (SVG/MathML CDATA + namespaces) and chunked streaming
//! land in later slices. The identity property holds for all input.

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
