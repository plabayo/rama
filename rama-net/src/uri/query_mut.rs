//! RAII guard for incremental query mutation.
//!
//! Created by [`Uri::query_mut`](super::Uri::query_mut). Holds the
//! Owned representation of the URI and lets callers push pairs (or
//! bare keys), pop the last pair as an owned [`QueryPair`], drain
//! all pairs, or remove / replace / retain pairs by name.

use super::component_input::IntoUriComponent;
use super::encode;
use super::owned::OwnedUriRef;
use super::query::{Query, QueryPair, QueryPairRef, QueryRef, form_decode_bytes};

use rama_core::bytes::{Bytes, BytesMut};

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
                None => core::mem::take(&mut q.bytes),
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
            Some(q) => core::mem::take(&mut q.bytes).freeze(),
            None => Bytes::new(),
        };
        Drain { bytes, offset: 0 }
    }

    /// Keep only the pairs for which `keep` returns `true`, preserving
    /// their order and raw bytes. Empty `&`-fragments (`&&`, leading /
    /// trailing `&`) are dropped as part of the rebuild.
    ///
    /// Like [`drain`](Self::drain), the query stays `Some(_)` (the `?`
    /// remains on the wire) even when every pair is removed.
    pub fn retain(&mut self, mut keep: impl FnMut(QueryPairRef<'_>) -> bool) -> &mut Self {
        let Some(q) = self.owned.query.as_mut() else {
            return self;
        };
        let old = core::mem::take(&mut q.bytes);
        let mut new = BytesMut::with_capacity(old.len());
        for pair in QueryRef::new(&old).pairs() {
            if keep(pair) {
                if !new.is_empty() {
                    new.extend_from_slice(b"&");
                }
                new.extend_from_slice(pair.raw_bytes());
            }
        }
        q.bytes = new;
        self
    }

    /// Remove every pair whose form-decoded name equals `name` (bare keys
    /// included). Returns the number of pairs removed.
    ///
    /// `name` is component text, compared form-decoded on both sides —
    /// see [`QueryRef::first_value`](super::QueryRef::first_value) for the
    /// matching rules.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows the input"
    )]
    pub fn remove(&mut self, name: impl IntoUriComponent) -> usize {
        let name = name.as_uri_component_bytes();
        let pattern = form_decode_bytes(&name).into_owned();
        let mut removed = 0;
        self.retain(|pair| {
            let matches = *form_decode_bytes(pair.name_bytes()) == *pattern;
            removed += usize::from(matches);
            !matches
        });
        removed
    }

    /// Replace-or-append: remove every pair named `name` (form-decoded
    /// comparison, see [`remove`](Self::remove)), then append `name=value`
    /// under the [`push_pair`](Self::push_pair) encoding policy. The pair
    /// always ends up last, regardless of where the old ones sat.
    pub fn set_pair(
        &mut self,
        name: impl IntoUriComponent,
        value: impl IntoUriComponent,
    ) -> &mut Self {
        self.remove(&*name.as_uri_component_bytes());
        self.push_pair(name, value)
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

impl core::fmt::Debug for QueryMut<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let query = self
            .owned
            .query
            .as_ref()
            // Safety: parser invariant — query bytes are valid UTF-8.
            .map(|q| unsafe { core::str::from_utf8_unchecked(&q.bytes) });
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

impl core::iter::FusedIterator for Drain {}
