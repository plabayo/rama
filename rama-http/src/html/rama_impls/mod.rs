//! [`super::IntoHtml`] impls for the string and collection types that
//! the rest of the rama ecosystem hands around — `ArcStr`, `Substr`,
//! `NonEmptyStr`, `SmolStr`, `SmallVec`, `NonEmptySmallVec`. Without
//! these, users would have to round-trip through `&str` / `String` to
//! splice such values into a template.

mod collections;
mod strings;
