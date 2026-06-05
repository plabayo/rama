//! Native CSS selector parsing and matching.
//!
//! This module provides a small, dependency-free CSS selector engine for
//! the subset of selectors that can be evaluated while *streaming* HTML
//! (no sibling lookahead, no full-document state). It is the foundation
//! for rama's streaming HTML parser/rewriter, but is also usable on its
//! own to match selectors against any tree that implements
//! [`SelectorSubject`] — including the in-memory [`Dom`] provided here.
//!
//! # Supported selectors
//!
//! | Pattern | Meaning |
//! | --- | --- |
//! | `*` | any element |
//! | `E` | an element of type `E` (ASCII case-insensitive) |
//! | `E.cls` | an `E` with class `cls` |
//! | `E#id` | an `E` with id `id` |
//! | `E[a]` | an `E` with an `a` attribute |
//! | `E[a=v]` | value exactly `v` |
//! | `E[a~=v]` | whitespace-separated list containing `v` |
//! | `E[a^=v]` `E[a$=v]` `E[a*=v]` | prefix / suffix / substring |
//! | `E[a\|=v]` | `v` or `v-` prefix |
//! | `E[a=v i]` / `E[a=v s]` | case-insensitive / case-sensitive value |
//! | `E:nth-child(An+B)` `E:first-child` | structural position |
//! | `E:nth-of-type(An+B)` `E:first-of-type` | structural position by type |
//! | `E:not(s)` | negation of a combinator-free compound `s` |
//! | `E F` / `E > F` | descendant / child combinator |
//! | `a, b, c` | selector list (matches if any matches) |
//!
//! Sibling combinators (`+`, `~`), `:has()`, `:is()`, `:where()`,
//! namespaces, pseudo-elements, and the non-streamable structural pseudos
//! (`:last-child`, `:only-child`, `:last-of-type`, `:only-of-type`,
//! `:nth-last-*`) are intentionally rejected with a [`SelectorError`].

pub(crate) mod ast;
mod display;
mod dom;
mod matcher;
mod parser;

#[cfg(test)]
mod tests;

pub use self::ast::Selector;
pub use self::dom::{Dom, Element, NodeId};
pub use self::matcher::SelectorSubject;

use std::fmt;

/// Error returned when parsing a CSS selector string fails, or when it
/// uses a construct outside the streaming-safe [supported subset](self).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelectorError {
    /// The selector string was empty.
    EmptySelector,
    /// An unexpected character/token was encountered.
    UnexpectedToken,
    /// The selector ended while more input was expected.
    UnexpectedEnd,
    /// A combinator was not followed by a compound selector (e.g. `div >`).
    DanglingCombinator,
    /// An attribute selector was missing its attribute name (e.g. `[=x]`).
    MissingAttributeName,
    /// An unexpected token inside an attribute selector.
    UnexpectedTokenInAttribute,
    /// A sibling combinator (`+` or `~`) was used; not supported while
    /// streaming.
    UnsupportedCombinator(char),
    /// An unsupported pseudo-class or pseudo-element was used.
    UnsupportedPseudoClass,
    /// A selector used an explicit namespace (e.g. `svg|rect`).
    NamespacedSelector,
    /// A `:not()` had no argument.
    EmptyNegation,
    /// An `An+B` micro-syntax value was malformed.
    InvalidNth,
}

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySelector => f.write_str("empty selector"),
            Self::UnexpectedToken => f.write_str("unexpected token in selector"),
            Self::UnexpectedEnd => f.write_str("unexpected end of selector"),
            Self::DanglingCombinator => f.write_str("dangling combinator in selector"),
            Self::MissingAttributeName => {
                f.write_str("missing attribute name in attribute selector")
            }
            Self::UnexpectedTokenInAttribute => {
                f.write_str("unexpected token in attribute selector")
            }
            Self::UnsupportedCombinator(c) => {
                write!(f, "unsupported combinator `{c}` in selector")
            }
            Self::UnsupportedPseudoClass => {
                f.write_str("unsupported pseudo-class or pseudo-element in selector")
            }
            Self::NamespacedSelector => {
                f.write_str("selectors with explicit namespaces are not supported")
            }
            Self::EmptyNegation => f.write_str("empty `:not()` in selector"),
            Self::InvalidNth => f.write_str("invalid `An+B` value in selector"),
        }
    }
}

impl std::error::Error for SelectorError {}
