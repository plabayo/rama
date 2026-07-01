//! Tri-state optional port — distinguishes "no `:port` suffix" from
//! "empty `:` with no digits" from "explicit port number".

use core::fmt;

/// The port component of an authority — tri-state.
///
/// RFC 3986 §3.2.3 `port = *DIGIT` permits the `Empty` form on the wire
/// (`example.com:`). Most consumers treat it the same as `Unset` for
/// dialing purposes (see [`as_u16`](Self::as_u16)); preserving the
/// distinction keeps the wire bytes round-trippable through owned
/// address types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum OptPort {
    /// No `:port` suffix on the wire (`example.com/path`).
    #[default]
    Unset,
    /// `:` present, no digits (`example.com:/path`).
    Empty,
    /// Explicit port number (`example.com:8080/path`).
    Set(u16),
}

impl OptPort {
    /// Returns the port number, or `None` for both `Unset` and `Empty`.
    /// Use this when the wire distinction between "no colon" and
    /// "empty colon" doesn't matter — e.g. dialing.
    #[must_use]
    #[inline]
    pub const fn as_u16(self) -> Option<u16> {
        match self {
            Self::Set(n) => Some(n),
            Self::Unset | Self::Empty => None,
        }
    }

    /// `true` for `Empty` and `Set` — the wire had a `:` after host.
    #[must_use]
    #[inline]
    pub const fn is_explicit(self) -> bool {
        !matches!(self, Self::Unset)
    }

    /// `true` only for `Empty` — `:` present with no digits.
    #[must_use]
    #[inline]
    pub const fn is_empty(self) -> bool {
        matches!(self, Self::Empty)
    }

    /// `true` for `Unset` — no `:` after host.
    #[must_use]
    #[inline]
    pub const fn is_unset(self) -> bool {
        matches!(self, Self::Unset)
    }
}

impl From<u16> for OptPort {
    #[inline]
    fn from(n: u16) -> Self {
        Self::Set(n)
    }
}

impl From<Option<u16>> for OptPort {
    #[inline]
    fn from(opt: Option<u16>) -> Self {
        match opt {
            Some(n) => Self::Set(n),
            None => Self::Unset,
        }
    }
}

impl From<OptPort> for Option<u16> {
    /// Maps `Set(n) → Some(n)`; both `Unset` and `Empty` map to `None`.
    /// The reverse direction can't recover `Empty`.
    #[inline]
    fn from(p: OptPort) -> Self {
        p.as_u16()
    }
}

impl fmt::Display for OptPort {
    /// `Unset` renders nothing; `Empty` renders `:`; `Set(n)` renders
    /// `:n`. Suitable for direct concatenation after a host.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unset => Ok(()),
            Self::Empty => f.write_str(":"),
            Self::Set(n) => write!(f, ":{n}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_u16_collapses_unset_and_empty() {
        assert_eq!(OptPort::Unset.as_u16(), None);
        assert_eq!(OptPort::Empty.as_u16(), None);
        assert_eq!(OptPort::Set(8080).as_u16(), Some(8080));
    }

    #[test]
    fn distinct_under_eq_hash_ord() {
        use crate::test_hash::hash;

        assert_ne!(OptPort::Unset, OptPort::Empty);
        assert_ne!(OptPort::Unset, OptPort::Set(0));
        assert_ne!(OptPort::Empty, OptPort::Set(0));

        assert_ne!(hash(&OptPort::Unset), hash(&OptPort::Empty));

        assert!(OptPort::Unset < OptPort::Empty);
        assert!(OptPort::Empty < OptPort::Set(0));
        assert!(OptPort::Set(0) < OptPort::Set(1));
    }

    #[test]
    fn display_matches_wire_form() {
        assert_eq!(OptPort::Unset.to_string(), "");
        assert_eq!(OptPort::Empty.to_string(), ":");
        assert_eq!(OptPort::Set(8080).to_string(), ":8080");
    }

    #[test]
    fn from_conversions() {
        assert_eq!(OptPort::from(8080u16), OptPort::Set(8080));
        assert_eq!(OptPort::from(None::<u16>), OptPort::Unset);
        assert_eq!(OptPort::from(Some(8080u16)), OptPort::Set(8080));

        let back: Option<u16> = OptPort::Empty.into();
        assert_eq!(back, None);
    }
}
