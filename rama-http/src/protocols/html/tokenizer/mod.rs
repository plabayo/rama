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
//! It is resumable (`write` + `end`) and handles HTML text modes
//! (`<script>` / `<style>` / `<textarea>` / `<title>` / `<plaintext>` / …)
//! plus the SVG/MathML foreign-content context needed to distinguish real
//! CDATA from bogus comments. The identity property holds for all input.

mod context;
mod machine;
mod name;
mod sink;
mod token;

#[cfg(test)]
mod tests;

pub use self::context::ParsingAmbiguityError;
pub use self::machine::{Tokenizer, tokenize};
pub use self::name::LocalNameHash;
pub use self::sink::TokenSink;
pub use self::token::{Attribute, Attributes, Cdata, Comment, Doctype, EndTag, StartTag, Text};
