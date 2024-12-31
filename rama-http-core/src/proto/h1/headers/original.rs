use super::Http1HeaderName;

#[derive(Debug, Clone)]
pub(crate) struct OriginalHttp1Headers {
    /// ordered by insert order
    ordered_headers: Vec<Http1HeaderName>,
}

impl OriginalHttp1Headers {
    pub(super) fn push(&mut self, name: Http1HeaderName) {
        self.ordered_headers.push(name);
    }
}

impl OriginalHttp1Headers {
    #[inline]
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

#[derive(Debug)]
pub(crate) struct IntoIter {
    headers_iter: std::vec::IntoIter<Http1HeaderName>,
}

impl Iterator for IntoIter {
    type Item = Http1HeaderName;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.headers_iter.next()
    }
}
