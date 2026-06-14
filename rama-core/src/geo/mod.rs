//! Geographic identity types shared across rama.
//!
//! Continents, countries, languages, scripts and [`Locale`]s, modelled as
//! closed, code-keyed enums with an `Unknown` escape hatch. The public surface
//! is std-only (no third-party types), and each enum has a borrowing, [`Copy`]
//! `*Ref` counterpart for zero-copy use.
//!
//! These types are intended for reuse beyond IP geolocation — e.g. a typed
//! `Accept-Language` header or proxy location metadata.

mod builder;

mod continent;
mod country;
mod language;
mod locale;

pub use continent::{Continent, ContinentRef};
pub use country::{Country, CountryRef};
pub use language::{Language, LanguageRef, Script, ScriptRef};
pub use locale::Locale;
