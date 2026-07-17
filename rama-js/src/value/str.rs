use std::borrow::{Borrow, Cow};
use std::fmt;
use std::ops::Deref;

use rama_utils::str::smol_str::SmolStr;

/// A cheap, immutable string used for values crossing the js boundary.
///
/// Short strings are stored inline, longer ones behind a
/// reference count, making [`JsStr`] `O(1)` to clone either way.
/// It dereferences to [`str`] for all read-only usage.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JsStr(SmolStr);

impl JsStr {
    /// Create a new [`JsStr`] from anything string-like.
    pub fn new(s: impl AsRef<str>) -> Self {
        Self(SmolStr::new(s))
    }

    /// Create a new [`JsStr`] from a static string, without allocating.
    #[must_use]
    pub const fn new_static(s: &'static str) -> Self {
        Self(SmolStr::new_static(s))
    }

    /// View this [`JsStr`] as a [`str`].
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Deref for JsStr {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for JsStr {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for JsStr {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for JsStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for JsStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl From<&str> for JsStr {
    fn from(s: &str) -> Self {
        Self(SmolStr::new(s))
    }
}

impl From<&String> for JsStr {
    fn from(s: &String) -> Self {
        Self(SmolStr::new(s))
    }
}

impl From<String> for JsStr {
    fn from(s: String) -> Self {
        Self(SmolStr::from(s))
    }
}

impl From<Cow<'_, str>> for JsStr {
    fn from(s: Cow<'_, str>) -> Self {
        match s {
            Cow::Borrowed(s) => s.into(),
            Cow::Owned(s) => s.into(),
        }
    }
}

impl From<char> for JsStr {
    fn from(c: char) -> Self {
        Self(SmolStr::from(c.encode_utf8(&mut [0u8; 4]) as &str))
    }
}

impl From<JsStr> for String {
    fn from(s: JsStr) -> Self {
        s.0.into()
    }
}

impl PartialEq<str> for JsStr {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<JsStr> for str {
    fn eq(&self, other: &JsStr) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<&str> for JsStr {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<JsStr> for &str {
    fn eq(&self, other: &JsStr) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<String> for JsStr {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<JsStr> for String {
    fn eq(&self, other: &JsStr) -> bool {
        self.as_str() == other.as_str()
    }
}
