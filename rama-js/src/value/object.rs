use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::Arc;

use ahash::{HashMap, HashMapExt as _};

use super::{JsStr, JsValue};

/// An immutable, insertion-ordered snapshot of a js object.
///
/// Keys are unique: constructing one from entries with duplicate keys
/// collapses them like a js object literal (first position, last value).
///
/// The backing storage is shared, making clones `O(1)`, and all
/// conversions out of it are pull-based: nothing beyond the initial
/// boundary snapshot is computed unless you ask for it. The concrete
/// representation is private so it can evolve (e.g. become lazier)
/// without breaking changes.
#[derive(Clone, PartialEq)]
pub struct JsObject(Arc<[(JsStr, JsValue)]>);

impl JsObject {
    /// The number of properties in this object.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if this object has no properties.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The value of the property with the given key, if any.
    #[must_use]
    pub fn get(&self, key: impl AsRef<str>) -> Option<&JsValue> {
        let key = key.as_ref();
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Returns `true` if this object has a property with the given key.
    #[must_use]
    pub fn contains_key(&self, key: impl AsRef<str>) -> bool {
        self.get(key).is_some()
    }

    /// Iterate over the property keys of this object, in insertion order.
    pub fn keys(&self) -> impl Iterator<Item = &JsStr> {
        self.0.iter().map(|(k, _)| k)
    }

    /// Iterate over the property values of this object, in insertion order.
    pub fn values(&self) -> impl Iterator<Item = &JsValue> {
        self.0.iter().map(|(_, v)| v)
    }

    /// Iterate over the properties of this object, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&JsStr, &JsValue)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    pub(crate) fn get_index(&self, index: usize) -> Option<(&JsStr, &JsValue)> {
        self.0.get(index).map(|(key, value)| (key, value))
    }
}

impl Default for JsObject {
    fn default() -> Self {
        Self(Arc::from([]))
    }
}

impl fmt::Debug for JsObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(k, v)| (k, v)))
            .finish()
    }
}

impl<K: Into<JsStr>, V: Into<JsValue>> FromIterator<(K, V)> for JsObject {
    /// Duplicate keys collapse like a js object literal:
    /// the first occurrence keeps its position, the last value wins.
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut entries: Vec<(JsStr, JsValue)> = Vec::new();
        let mut seen: HashMap<JsStr, usize> = HashMap::new();
        for (key, value) in iter {
            let (key, value) = (key.into(), value.into());
            match seen.entry(key.clone()) {
                Entry::Vacant(slot) => {
                    slot.insert(entries.len());
                    entries.push((key, value));
                }
                Entry::Occupied(slot) => entries[*slot.get()].1 = value,
            }
        }
        Self(entries.into())
    }
}

impl<K: Into<JsStr>, V: Into<JsValue>> From<Vec<(K, V)>> for JsObject {
    fn from(entries: Vec<(K, V)>) -> Self {
        entries.into_iter().collect()
    }
}

impl<'a> IntoIterator for &'a JsObject {
    type Item = (&'a JsStr, &'a JsValue);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (JsStr, JsValue)>,
        fn(&'a (JsStr, JsValue)) -> (&'a JsStr, &'a JsValue),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().map(|(k, v)| (k, v))
    }
}
