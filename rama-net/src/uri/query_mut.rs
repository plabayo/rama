//! RAII guard for incremental query mutation.
//!
//! Created by [`Uri::query_mut`](super::Uri::query_mut). Holds the
//! Owned representation of the URI and lets callers push pairs (or
//! bare keys), pop the last pair as an owned [`QueryPair`], or drain
//! all pairs.

use rama_core::bytes::{Bytes, BytesMut};

use super::component_input::IntoUriComponent;
use super::encode;
use super::owned::OwnedUriRef;
use super::query::{Query, QueryPair};

/// Mutable view of a [`Uri`](super::Uri)'s query component.
///
/// Pushes append to the existing query, auto-encoding bytes outside the
/// pair grammar. The first push promotes a `None` query to `Some(empty)`
/// (i.e. adds a `?` to the wire form). Drop releases the borrow.
pub struct QueryMut<'a> {
    owned: &'a mut OwnedUriRef,
}

impl<'a> QueryMut<'a> {
    #[inline]
    pub(crate) fn new(owned: &'a mut OwnedUriRef) -> Self {
        Self { owned }
    }

    /// Append a `name=value` pair. Both `name` and `value` are
    /// percent-encoded under the pair policy (encode `&`, `=`, `+`,
    /// `%`, and everything outside `pchar`).
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters"
    )]
    pub fn push_pair(
        &mut self,
        name: impl IntoUriComponent,
        value: impl IntoUriComponent,
    ) -> &mut Self {
        let buf = self.buf_for_append();
        encode::extend_encoded_pair(buf, &name);
        buf.extend_from_slice(b"=");
        encode::extend_encoded_pair(buf, &value);
        self
    }

    /// Append a bare key (no `=`). Same encoding policy as
    /// [`push_pair`](Self::push_pair).
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters"
    )]
    pub fn push_key(&mut self, name: impl IntoUriComponent) -> &mut Self {
        let buf = self.buf_for_append();
        encode::extend_encoded_pair(buf, &name);
        self
    }

    /// Remove and return the last pair as an owned [`QueryPair`]. Returns
    /// `None` when the query is empty or absent.
    ///
    /// The pair's bytes are sliced into a refcounted [`Bytes`] from the
    /// underlying query buffer — no copy.
    pub fn pop(&mut self) -> Option<QueryPair> {
        loop {
            let q = self.owned.query.as_mut()?;
            if q.bytes.is_empty() {
                return None;
            }
            let pair_bytes = match memchr::memrchr(b'&', &q.bytes) {
                Some(i) => {
                    // Split [..i] | [i..]. The tail starts with `&`; trim it.
                    let mut tail = q.bytes.split_off(i);
                    let _amp = tail.split_to(1);
                    tail
                }
                None => std::mem::take(&mut q.bytes),
            };
            if pair_bytes.is_empty() {
                // Trailing `&` with nothing after — skip and try again.
                continue;
            }
            return Some(QueryPair::from_raw(pair_bytes.freeze()));
        }
    }

    /// Empty the query content and return an iterator yielding the
    /// removed pairs as owned [`QueryPair`]s.
    ///
    /// The query stays `Some(empty)` after this — the `?` remains on
    /// the wire. Call [`Uri::unset_query`](super::Uri::unset_query) to
    /// remove the `?` entirely.
    pub fn drain(&mut self) -> Drain {
        let bytes = match self.owned.query.as_mut() {
            Some(q) => std::mem::take(&mut q.bytes).freeze(),
            None => Bytes::new(),
        };
        Drain { bytes, offset: 0 }
    }

    /// Ensure the query is `Some(_)` and return `&mut BytesMut` for the
    /// underlying buffer. Inserts `&` if the existing buffer is
    /// non-empty so the next pair appends correctly.
    fn buf_for_append(&mut self) -> &mut BytesMut {
        let q = self.owned.query.get_or_insert_with(|| Query {
            bytes: BytesMut::new(),
        });
        if !q.bytes.is_empty() {
            q.bytes.extend_from_slice(b"&");
        }
        &mut q.bytes
    }
}

impl std::fmt::Debug for QueryMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let query = self
            .owned
            .query
            .as_ref()
            // Safety: parser invariant — query bytes are valid UTF-8.
            .map(|q| unsafe { std::str::from_utf8_unchecked(&q.bytes) });
        f.debug_struct("QueryMut").field("query", &query).finish()
    }
}

/// Iterator yielding owned [`QueryPair`]s drained from a [`QueryMut`].
/// Created by [`QueryMut::drain`].
#[derive(Debug, Clone)]
pub struct Drain {
    bytes: Bytes,
    offset: usize,
}

impl Iterator for Drain {
    type Item = QueryPair;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.offset >= self.bytes.len() {
                return None;
            }
            // Find next `&` from current offset.
            let remaining = &self.bytes[self.offset..];
            let (start, end) = match memchr::memchr(b'&', remaining) {
                Some(i) => (self.offset, self.offset + i),
                None => (self.offset, self.bytes.len()),
            };
            self.offset = end + 1; // skip past `&` (or one-past-end if no `&`)

            if start == end {
                // Empty fragment (`&&`, leading/trailing `&`) — skip.
                continue;
            }

            let fragment = self.bytes.slice(start..end);
            return Some(QueryPair::from_raw(fragment));
        }
    }
}

impl std::iter::FusedIterator for Drain {}
