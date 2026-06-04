//! The sink that receives tokens from the [`Tokenizer`](super::Tokenizer).

use super::token::{Comment, Doctype, EndTag, StartTag, Text};

/// Receives token events as the tokenizer scans HTML.
///
/// Every method has a default no-op body, so a sink only overrides the
/// events it cares about. Token views borrow the input and are valid only
/// for the duration of the call.
pub trait TokenSink {
    /// Called for each start tag (`<a href="…">`, `<br/>`).
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        let _ = tag;
    }

    /// Called for each end tag (`</a>`).
    fn end_tag(&mut self, tag: &EndTag<'_>) {
        let _ = tag;
    }

    /// Called for each run of character data.
    fn text(&mut self, text: &Text<'_>) {
        let _ = text;
    }

    /// Called for each comment.
    fn comment(&mut self, comment: &Comment<'_>) {
        let _ = comment;
    }

    /// Called for each doctype declaration.
    fn doctype(&mut self, doctype: &Doctype<'_>) {
        let _ = doctype;
    }
}
