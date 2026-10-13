//! The sink that receives tokens from the [`Tokenizer`](super::Tokenizer).

use super::context::{ContextTracker, ParsingAmbiguityError, TextMode};
use super::name::LocalNameHash;
use super::token::{Cdata, Comment, Doctype, EndTag, StartTag, Text};

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

    /// Called for each CDATA section (only inside SVG/MathML foreign content).
    fn cdata(&mut self, cdata: &Cdata<'_>) {
        let _ = cdata;
    }

    /// Called for each doctype declaration.
    fn doctype(&mut self, doctype: &Doctype<'_>) {
        let _ = doctype;
    }
}

/// A token consumer that also answers the two questions only tree
/// construction can: which text mode a start tag switches to, and whether
/// `<![CDATA[` opens character data.
pub(crate) trait ParseSink {
    /// Whether `<![CDATA[` currently opens a CDATA section.
    fn cdata_allowed(&self) -> bool;

    /// The text mode the element of this start tag switches the tokenizer
    /// to, decided before the tag is consumed (it also serves the streaming
    /// look-ahead, so it must not depend on the tag being applied).
    fn text_mode(&mut self, hash: LocalNameHash, name: &[u8]) -> Option<TextMode>;

    /// Consumes a start tag.
    fn start_tag(&mut self, tag: &StartTag<'_>) -> Result<(), ParsingAmbiguityError>;

    /// Consumes an end tag; `closes_text` marks the end tag of a text-mode
    /// body, which the tokenizer found itself.
    fn end_tag(&mut self, tag: &EndTag<'_>, closes_text: bool);

    /// Consumes a run of character data.
    fn text(&mut self, text: &Text<'_>);

    /// Consumes a comment.
    fn comment(&mut self, comment: &Comment<'_>);

    /// Consumes a CDATA section.
    fn cdata(&mut self, cdata: &Cdata<'_>);

    /// Consumes a doctype.
    fn doctype(&mut self, doctype: &Doctype<'_>);

    /// Called once the tokens of `input` (the bytes all token spans of this
    /// pass point into) are emitted, before `input` is released.
    fn flush(&mut self, input: &[u8]);
}

/// A plain [`TokenSink`] driven by the tokenizer's own [`ContextTracker`].
pub(crate) struct Standalone<'a, S> {
    pub(crate) sink: &'a mut S,
    pub(crate) context: &'a mut ContextTracker,
}

impl<S: TokenSink> ParseSink for Standalone<'_, S> {
    fn cdata_allowed(&self) -> bool {
        self.context.cdata_allowed()
    }

    fn text_mode(&mut self, hash: LocalNameHash, name: &[u8]) -> Option<TextMode> {
        self.context.peek_text_mode(hash, name)
    }

    fn start_tag(&mut self, tag: &StartTag<'_>) -> Result<(), ParsingAmbiguityError> {
        self.sink.start_tag(tag);
        self.context.on_start_tag(tag)
    }

    fn end_tag(&mut self, tag: &EndTag<'_>, closes_text: bool) {
        self.sink.end_tag(tag);
        if !closes_text {
            self.context.on_end_tag(tag);
        }
    }

    fn text(&mut self, text: &Text<'_>) {
        self.sink.text(text);
    }

    fn comment(&mut self, comment: &Comment<'_>) {
        self.sink.comment(comment);
    }

    fn cdata(&mut self, cdata: &Cdata<'_>) {
        self.sink.cdata(cdata);
    }

    fn doctype(&mut self, doctype: &Doctype<'_>) {
        self.sink.doctype(doctype);
    }

    fn flush(&mut self, _input: &[u8]) {}
}
