use std::fmt;

use crate::engine::NamespaceEntry;
use crate::func::JsFn;
use crate::value::{JsStr, JsValue};

/// A global host object: a named bag of host functions and values,
/// exposed to scripts as a single global object via
/// [`JsRuntimeBuilder::with_global`][crate::JsRuntimeBuilder::with_global].
#[derive(Default)]
pub struct JsNamespace {
    entries: Vec<(JsStr, NamespaceEntry)>,
}

struct EntryDebug<'a>(&'a NamespaceEntry);

impl fmt::Debug for EntryDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            NamespaceEntry::Value(value) => fmt::Debug::fmt(value, f),
            NamespaceEntry::Fn(_) => f.write_str("fn"),
        }
    }
}

impl fmt::Debug for JsNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                self.entries
                    .iter()
                    .map(|(name, entry)| (name, EntryDebug(entry))),
            )
            .finish()
    }
}

impl JsNamespace {
    /// Add a host function as a property of this namespace.
    #[must_use]
    pub fn with_fn<A, F: JsFn<A>>(mut self, name: impl Into<JsStr>, f: F) -> Self {
        self.set_fn(name, f);
        self
    }

    /// Add a host function as a property of this namespace.
    pub fn set_fn<A, F: JsFn<A>>(&mut self, name: impl Into<JsStr>, f: F) -> &mut Self {
        self.entries
            .push((name.into(), NamespaceEntry::Fn(f.into_raw_host_fn())));
        self
    }

    /// Add a value as a property of this namespace.
    #[must_use]
    pub fn with_value(mut self, name: impl Into<JsStr>, value: impl Into<JsValue>) -> Self {
        self.set_value(name, value);
        self
    }

    /// Add a value as a property of this namespace.
    pub fn set_value(&mut self, name: impl Into<JsStr>, value: impl Into<JsValue>) -> &mut Self {
        self.entries
            .push((name.into(), NamespaceEntry::Value(value.into())));
        self
    }

    pub(crate) fn into_entries(self) -> Vec<(JsStr, NamespaceEntry)> {
        self.entries
    }
}
