//! Original order and case tracking for h1 tracking...
//!
//! If somebody reads this that designs protocols please
//! ensure that your protocol in no way can have deterministic
//! ordering or makes use of capitals... *sigh* what a painful design mistake

use super::{Http1HeaderName, IntoHttp1HeaderName};

#[derive(Debug, Clone)]
// Keeps track of the order and casing
// of the inserted header names, usually used in combination
// with [`crate::proto::h1::Http1HeaderMap`].
pub struct OriginalHttp1Headers {
    /// ordered by insert order
    ordered_headers: Vec<Http1HeaderName>,
}

impl OriginalHttp1Headers {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ordered_headers: Vec::new(),
        }
    }

    pub fn push(&mut self, name: Http1HeaderName) {
        self.ordered_headers.push(name);
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.ordered_headers.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ordered_headers.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Http1HeaderName> {
        self.ordered_headers.iter()
    }
}

impl OriginalHttp1Headers {
    #[inline]
    #[must_use]
    pub fn with_capacity(size: usize) -> Self {
        Self {
            ordered_headers: Vec::with_capacity(size),
        }
    }
}

impl Default for OriginalHttp1Headers {
    #[inline]
    fn default() -> Self {
        Self::with_capacity(12)
    }
}

impl IntoIterator for OriginalHttp1Headers {
    type Item = Http1HeaderName;
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            headers_iter: self.ordered_headers.into_iter(),
        }
    }
}

impl<N: IntoHttp1HeaderName> FromIterator<N> for OriginalHttp1Headers {
    fn from_iter<T: IntoIterator<Item = N>>(iter: T) -> Self {
        Self {
            ordered_headers: iter
                .into_iter()
                .map(|it| it.into_http1_header_name())
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct IntoIter {
    headers_iter: std::vec::IntoIter<Http1HeaderName>,
}

impl Iterator for IntoIter {
    type Item = Http1HeaderName;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.headers_iter.next()
    }
}
