use std::fmt;
use std::sync::Arc;

use super::JsValue;

/// An immutable snapshot of a js array.
///
/// The backing storage is shared, making clones `O(1)`.
/// The concrete representation is private so it can
/// evolve (e.g. become lazier) without breaking changes.
#[derive(Clone, PartialEq)]
pub struct JsArray(Arc<[JsValue]>);

impl JsArray {
    /// The number of elements in this array.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if this array has no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The element at the given index, if any.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&JsValue> {
        self.0.get(index)
    }

    /// Iterate over the elements of this array.
    pub fn iter(&self) -> std::slice::Iter<'_, JsValue> {
        self.0.iter()
    }

    /// View this array as a slice of values.
    #[must_use]
    pub fn as_slice(&self) -> &[JsValue] {
        &self.0
    }

    /// Copy this array into an owned `Vec` (elements clone `O(1)`).
    #[must_use]
    pub fn to_vec(&self) -> Vec<JsValue> {
        self.0.to_vec()
    }
}

impl Default for JsArray {
    fn default() -> Self {
        Self(Arc::from([]))
    }
}

impl fmt::Debug for JsArray {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl<T: Into<JsValue>> From<Vec<T>> for JsArray {
    fn from(values: Vec<T>) -> Self {
        values.into_iter().collect()
    }
}

impl<T: Into<JsValue>, const N: usize> From<[T; N]> for JsArray {
    fn from(values: [T; N]) -> Self {
        values.into_iter().collect()
    }
}

impl<T: Into<JsValue>> FromIterator<T> for JsArray {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

impl<'a> IntoIterator for &'a JsArray {
    type Item = &'a JsValue;
    type IntoIter = std::slice::Iter<'a, JsValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
