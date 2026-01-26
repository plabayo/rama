use rama_http_types::HeaderName;

pub(crate) use self::as_encoding_agnostic_metadata_key::AsEncodingAgnosticMetadataKey;
pub(crate) use self::as_metadata_key::AsMetadataKey;
pub(crate) use self::into_metadata_key::IntoMetadataKey;

use super::encoding::{Ascii, Binary, ValueEncoding};
use super::key::{InvalidMetadataKey, MetadataKey};
use super::value::MetadataValue;

use std::marker::PhantomData;

/// A set of gRPC custom metadata entries.
#[derive(Clone, Debug, Default)]
pub struct MetadataMap {
    headers: rama_http_types::HeaderMap,
}

impl AsRef<rama_http_types::HeaderMap> for MetadataMap {
    fn as_ref(&self) -> &rama_http_types::HeaderMap {
        &self.headers
    }
}

impl AsMut<rama_http_types::HeaderMap> for MetadataMap {
    fn as_mut(&mut self) -> &mut rama_http_types::HeaderMap {
        &mut self.headers
    }
}

/// `MetadataMap` entry iterator.
///
/// Yields `KeyAndValueRef` values. The same header name may be yielded
/// more than once if it has more than one associated value.
#[derive(Debug)]
pub struct Iter<'a> {
    inner: rama_http_types::header::Iter<'a, rama_http_types::header::HeaderValue>,
}

/// Reference to a key and an associated value in a `MetadataMap`. It can point
/// to either an ascii or a binary ("*-bin") key.
#[derive(Debug)]
pub enum KeyAndValueRef<'a> {
    /// An ascii metadata key and value.
    Ascii(&'a MetadataKey<Ascii>, &'a MetadataValue<Ascii>),
    /// A binary metadata key and value.
    Binary(&'a MetadataKey<Binary>, &'a MetadataValue<Binary>),
}

/// Reference to a key and an associated value in a `MetadataMap`. It can point
/// to either an ascii or a binary ("*-bin") key.
#[derive(Debug)]
pub enum KeyAndMutValueRef<'a> {
    /// An ascii metadata key and value.
    Ascii(&'a MetadataKey<Ascii>, &'a mut MetadataValue<Ascii>),
    /// A binary metadata key and value.
    Binary(&'a MetadataKey<Binary>, &'a mut MetadataValue<Binary>),
}

/// `MetadataMap` entry iterator.
///
/// Yields `(&MetadataKey, &mut value)` tuples. The same header name may be yielded
/// more than once if it has more than one associated value.
#[derive(Debug)]
pub struct IterMut<'a> {
    inner: rama_http_types::header::IterMut<'a, rama_http_types::header::HeaderValue>,
}

/// A drain iterator of all values associated with a single metadata key.
#[derive(Debug)]
pub struct ValueDrain<'a, VE: ValueEncoding> {
    inner: rama_http_types::header::ValueDrain<'a, rama_http_types::header::HeaderValue>,
    phantom: PhantomData<VE>,
}

/// An iterator over `MetadataMap` keys.
///
/// Yields `KeyRef` values. Each header name is yielded only once, even if it
/// has more than one associated value.
#[derive(Debug)]
pub struct Keys<'a> {
    inner: rama_http_types::header::Keys<'a, rama_http_types::header::HeaderValue>,
}

/// Reference to a key in a `MetadataMap`. It can point
/// to either an ascii or a binary ("*-bin") key.
#[derive(Debug)]
pub enum KeyRef<'a> {
    /// An ascii metadata key and value.
    Ascii(&'a MetadataKey<Ascii>),
    /// A binary metadata key and value.
    Binary(&'a MetadataKey<Binary>),
}

/// `MetadataMap` value iterator.
///
/// Yields `ValueRef` values. Each value contained in the `MetadataMap` will be
/// yielded.
#[derive(Debug)]
pub struct Values<'a> {
    // Need to use rama_http_types::header::Iter and not rama_http_types::header::Values to be able
    // to know if a value is binary or not.
    inner: rama_http_types::header::Iter<'a, rama_http_types::header::HeaderValue>,
}

/// Reference to a value in a `MetadataMap`. It can point
/// to either an ascii or a binary ("*-bin" key) value.
#[derive(Debug)]
pub enum ValueRef<'a> {
    /// An ascii metadata key and value.
    Ascii(&'a MetadataValue<Ascii>),
    /// A binary metadata key and value.
    Binary(&'a MetadataValue<Binary>),
}

/// `MetadataMap` value iterator.
///
/// Each value contained in the `MetadataMap` will be yielded.
#[derive(Debug)]
pub struct ValuesMut<'a> {
    // Need to use rama_http_types::header::IterMut and not rama_http_types::header::ValuesMut to be
    // able to know if a value is binary or not.
    inner: rama_http_types::header::IterMut<'a, rama_http_types::header::HeaderValue>,
}

/// Reference to a value in a `MetadataMap`. It can point
/// to either an ascii or a binary ("*-bin" key) value.
#[derive(Debug)]
pub enum ValueRefMut<'a> {
    /// An ascii metadata key and value.
    Ascii(&'a mut MetadataValue<Ascii>),
    /// A binary metadata key and value.
    Binary(&'a mut MetadataValue<Binary>),
}

/// An iterator of all values associated with a single metadata key.
#[derive(Debug)]
pub struct ValueIter<'a, VE: ValueEncoding> {
    inner: Option<rama_http_types::header::ValueIter<'a, rama_http_types::header::HeaderValue>>,
    phantom: PhantomData<VE>,
}

/// An iterator of all values associated with a single metadata key.
#[derive(Debug)]
pub struct ValueIterMut<'a, VE: ValueEncoding> {
    inner: rama_http_types::header::ValueIterMut<'a, rama_http_types::header::HeaderValue>,
    phantom: PhantomData<VE>,
}

/// A view to all values stored in a single entry.
///
/// This struct is returned by `MetadataMap::get_all` and
/// `MetadataMap::get_all_bin`.
#[derive(Debug)]
pub struct GetAll<'a, VE: ValueEncoding> {
    inner: Option<rama_http_types::header::GetAll<'a, rama_http_types::header::HeaderValue>>,
    phantom: PhantomData<VE>,
}

/// A view into a single location in a `MetadataMap`, which may be vacant or
/// occupied.
#[derive(Debug)]
pub enum Entry<'a, VE: ValueEncoding> {
    /// An occupied entry
    Occupied(OccupiedEntry<'a, VE>),

    /// A vacant entry
    Vacant(VacantEntry<'a, VE>),
}

/// A view into a single empty location in a `MetadataMap`.
///
/// This struct is returned as part of the `Entry` enum.
#[derive(Debug)]
pub struct VacantEntry<'a, VE: ValueEncoding> {
    inner: rama_http_types::header::VacantEntry<'a, rama_http_types::header::HeaderValue>,
    phantom: PhantomData<VE>,
}

/// A view into a single occupied location in a `MetadataMap`.
///
/// This struct is returned as part of the `Entry` enum.
#[derive(Debug)]
pub struct OccupiedEntry<'a, VE: ValueEncoding> {
    inner: rama_http_types::header::OccupiedEntry<'a, rama_http_types::header::HeaderValue>,
    phantom: PhantomData<VE>,
}

pub(crate) const GRPC_TIMEOUT_HEADER: &str = "grpc-timeout";

// ===== impl MetadataMap =====

impl MetadataMap {
    // Headers reserved by the gRPC protocol.
    pub(crate) const GRPC_RESERVED_HEADERS: [HeaderName; 5] = [
        HeaderName::from_static("te"),
        HeaderName::from_static("content-type"),
        HeaderName::from_static("grpc-message"),
        HeaderName::from_static("grpc-message-type"),
        HeaderName::from_static("grpc-status"),
    ];

    /// Create an empty `MetadataMap`.
    ///
    /// The map will be created without any capacity. This function will not
    /// allocate.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Convert an HTTP HeaderMap to a MetadataMap
    #[must_use]
    pub fn from_headers(headers: rama_http_types::HeaderMap) -> Self {
        Self { headers }
    }

    /// Convert a MetadataMap into a HTTP HeaderMap
    #[must_use]
    pub fn into_headers(self) -> rama_http_types::HeaderMap {
        self.headers
    }

    pub(crate) fn into_sanitized_headers(mut self) -> rama_http_types::HeaderMap {
        for r in &Self::GRPC_RESERVED_HEADERS {
            self.headers.remove(r);
        }
        self.headers
    }

    /// Create an empty `MetadataMap` with the specified capacity.
    ///
    /// The returned map will allocate internal storage in order to hold about
    /// `capacity` elements without reallocating. However, this is a "best
    /// effort" as there are usage patterns that could cause additional
    /// allocations before `capacity` metadata entries are stored in the map.
    ///
    /// More capacity than requested may be allocated.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            headers: rama_http_types::HeaderMap::with_capacity(capacity),
        }
    }

    /// Returns the number of metadata entries (ascii and binary) stored in the
    /// map.
    ///
    /// This number represents the total number of **values** stored in the map.
    /// This number can be greater than or equal to the number of **keys**
    /// stored given that a single key may have more than one associated value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns the number of keys (ascii and binary) stored in the map.
    ///
    /// This number will be less than or equal to `len()` as each key may have
    /// more than one associated value.
    #[must_use]
    pub fn keys_len(&self) -> usize {
        self.headers.keys_len()
    }

    /// Returns true if the map contains no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Clears the map, removing all key-value pairs. Keeps the allocated memory
    /// for reuse.
    pub fn clear(&mut self) {
        self.headers.clear();
    }

    /// Returns the number of custom metadata entries the map can hold without
    /// reallocating.
    ///
    /// This number is an approximation as certain usage patterns could cause
    /// additional allocations before the returned capacity is filled.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.headers.capacity()
    }

    /// Reserves capacity for at least `additional` more custom metadata to be
    /// inserted into the `MetadataMap`.
    ///
    /// The metadata map may reserve more space to avoid frequent reallocations.
    /// Like with `with_capacity`, this will be a "best effort" to avoid
    /// allocations until `additional` more custom metadata is inserted. Certain
    /// usage patterns could cause additional allocations before the number is
    /// reached.
    ///
    /// # Panics
    ///
    /// Panics if the new allocation size overflows `usize`.
    pub fn reserve(&mut self, additional: usize) {
        self.headers.reserve(additional);
    }

    /// Returns a reference to the value associated with the key. This method
    /// is for ascii metadata entries (those whose names don't end with
    /// "-bin"). For binary entries, use get_bin.
    ///
    /// If there are multiple values associated with the key, then the first one
    /// is returned. Use `get_all` to get all values associated with a given
    /// key. Returns `None` if there are no values associated with the key.
    pub fn get<K>(&self, key: K) -> Option<&MetadataValue<Ascii>>
    where
        K: AsMetadataKey<Ascii>,
    {
        key.get(self)
    }

    /// Like get, but for Binary keys (for example "trace-proto-bin").
    pub fn get_bin<K>(&self, key: K) -> Option<&MetadataValue<Binary>>
    where
        K: AsMetadataKey<Binary>,
    {
        key.get(self)
    }

    /// Returns a mutable reference to the value associated with the key. This
    /// method is for ascii metadata entries (those whose names don't end with
    /// "-bin"). For binary entries, use get_mut_bin.
    ///
    /// If there are multiple values associated with the key, then the first one
    /// is returned. Use `entry` to get all values associated with a given
    /// key. Returns `None` if there are no values associated with the key.
    pub fn get_mut<K>(&mut self, key: K) -> Option<&mut MetadataValue<Ascii>>
    where
        K: AsMetadataKey<Ascii>,
    {
        key.get_mut(self)
    }

    /// Like get_mut, but for Binary keys (for example "trace-proto-bin").
    pub fn get_bin_mut<K>(&mut self, key: K) -> Option<&mut MetadataValue<Binary>>
    where
        K: AsMetadataKey<Binary>,
    {
        key.get_mut(self)
    }

    /// Returns a view of all values associated with a key. This method is for
    /// ascii metadata entries (those whose names don't end with "-bin"). For
    /// binary entries, use get_all_bin.
    ///
    /// The returned view does not incur any allocations and allows iterating
    /// the values associated with the key.  See [`GetAll`] for more details.
    /// Returns `None` if there are no values associated with the key.
    ///
    /// [`GetAll`]: struct.GetAll.html
    pub fn get_all<K>(&self, key: K) -> GetAll<'_, Ascii>
    where
        K: AsMetadataKey<Ascii>,
    {
        GetAll {
            inner: key.get_all(self),
            phantom: PhantomData,
        }
    }

    /// Like get_all, but for Binary keys (for example "trace-proto-bin").
    pub fn get_all_bin<K>(&self, key: K) -> GetAll<'_, Binary>
    where
        K: AsMetadataKey<Binary>,
    {
        GetAll {
            inner: key.get_all(self),
            phantom: PhantomData,
        }
    }

    /// Returns true if the map contains a value for the specified key. This
    /// method works for both ascii and binary entries.
    #[inline(always)]
    pub fn contains_key<K>(&self, key: &K) -> bool
    where
        K: AsEncodingAgnosticMetadataKey,
    {
        key.contains_key(self)
    }

    /// An iterator visiting all key-value pairs (both ascii and binary).
    ///
    /// The iteration order is arbitrary, but consistent across platforms for
    /// the same crate version. Each key will be yielded once per associated
    /// value. So, if a key has 3 associated values, it will be yielded 3 times.
    #[must_use]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.headers.iter(),
        }
    }

    /// An iterator visiting all key-value pairs, with mutable value references.
    ///
    /// The iterator order is arbitrary, but consistent across platforms for the
    /// same crate version. Each key will be yielded once per associated value,
    /// so if a key has 3 associated values, it will be yielded 3 times.
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut {
            inner: self.headers.iter_mut(),
        }
    }

    /// An iterator visiting all keys.
    ///
    /// The iteration order is arbitrary, but consistent across platforms for
    /// the same crate version. Each key will be yielded only once even if it
    /// has multiple associated values.
    #[must_use]
    pub fn keys(&self) -> Keys<'_> {
        Keys {
            inner: self.headers.keys(),
        }
    }

    /// An iterator visiting all values (both ascii and binary).
    ///
    /// The iteration order is arbitrary, but consistent across platforms for
    /// the same crate version.
    #[must_use]
    pub fn values(&self) -> Values<'_> {
        Values {
            inner: self.headers.iter(),
        }
    }

    /// An iterator visiting all values mutably.
    ///
    /// The iteration order is arbitrary, but consistent across platforms for
    /// the same crate version.
    pub fn values_mut(&mut self) -> ValuesMut<'_> {
        ValuesMut {
            inner: self.headers.iter_mut(),
        }
    }

    /// Gets the given ascii key's corresponding entry in the map for in-place
    /// manipulation. For binary keys, use `entry_bin`.
    pub fn entry<K>(&mut self, key: K) -> Result<Entry<'_, Ascii>, InvalidMetadataKey>
    where
        K: AsMetadataKey<Ascii>,
    {
        self.generic_entry::<Ascii, K>(key)
    }

    /// Gets the given Binary key's corresponding entry in the map for in-place
    /// manipulation.
    pub fn entry_bin<K>(&mut self, key: K) -> Result<Entry<'_, Binary>, InvalidMetadataKey>
    where
        K: AsMetadataKey<Binary>,
    {
        self.generic_entry::<Binary, K>(key)
    }

    fn generic_entry<VE: ValueEncoding, K>(
        &mut self,
        key: K,
    ) -> Result<Entry<'_, VE>, InvalidMetadataKey>
    where
        K: AsMetadataKey<VE>,
    {
        match key.entry(self) {
            Ok(entry) => Ok(match entry {
                rama_http_types::header::Entry::Occupied(e) => Entry::Occupied(OccupiedEntry {
                    inner: e,
                    phantom: PhantomData,
                }),
                rama_http_types::header::Entry::Vacant(e) => Entry::Vacant(VacantEntry {
                    inner: e,
                    phantom: PhantomData,
                }),
            }),
            Err(err) => Err(err),
        }
    }

    /// Inserts an ascii key-value pair into the map. To insert a binary entry,
    /// use `insert_bin`.
    ///
    /// This method panics when the given key is a string and it cannot be
    /// converted to a `MetadataKey<Ascii>`.
    ///
    /// If the map did not previously have this key present, then `None` is
    /// returned.
    ///
    /// If the map did have this key present, the new value is associated with
    /// the key and all previous values are removed. **Note** that only a single
    /// one of the previous values is returned. If there are multiple values
    /// that have been previously associated with the key, then the first one is
    /// returned. See `insert_mult` on `OccupiedEntry` for an API that returns
    /// all values.
    ///
    /// The key is not updated, though; this matters for types that can be `==`
    /// without being identical.
    pub fn insert<K>(&mut self, key: K, val: MetadataValue<Ascii>) -> Option<MetadataValue<Ascii>>
    where
        K: IntoMetadataKey<Ascii>,
    {
        key.insert(self, val)
    }

    /// Like insert, but for Binary keys (for example "trace-proto-bin").
    ///
    /// This method panics when the given key is a string and it cannot be
    /// converted to a `MetadataKey<Binary>`.
    pub fn insert_bin<K>(
        &mut self,
        key: K,
        val: MetadataValue<Binary>,
    ) -> Option<MetadataValue<Binary>>
    where
        K: IntoMetadataKey<Binary>,
    {
        key.insert(self, val)
    }

    /// Inserts an ascii key-value pair into the map. To insert a binary entry,
    /// use `append_bin`.
    ///
    /// This method panics when the given key is a string and it cannot be
    /// converted to a `MetadataKey<Ascii>`.
    ///
    /// If the map did not previously have this key present, then `false` is
    /// returned.
    ///
    /// If the map did have this key present, the new value is pushed to the end
    /// of the list of values currently associated with the key. The key is not
    /// updated, though; this matters for types that can be `==` without being
    /// identical.
    pub fn append<K>(&mut self, key: K, value: MetadataValue<Ascii>) -> bool
    where
        K: IntoMetadataKey<Ascii>,
    {
        key.append(self, value)
    }

    /// Like append, but for binary keys (for example "trace-proto-bin").
    ///
    /// This method panics when the given key is a string and it cannot be
    /// converted to a `MetadataKey<Binary>`.
    pub fn append_bin<K>(&mut self, key: K, value: MetadataValue<Binary>) -> bool
    where
        K: IntoMetadataKey<Binary>,
    {
        key.append(self, value)
    }

    /// Removes an ascii key from the map, returning the value associated with
    /// the key. To remove a binary key, use `remove_bin`.
    ///
    /// Returns `None` if the map does not contain the key. If there are
    /// multiple values associated with the key, then the first one is returned.
    /// See `remove_entry_mult` on `OccupiedEntry` for an API that yields all
    /// values.
    pub fn remove<K>(&mut self, key: K) -> Option<MetadataValue<Ascii>>
    where
        K: AsMetadataKey<Ascii>,
    {
        key.remove(self)
    }

    /// Like remove, but for Binary keys (for example "trace-proto-bin").
    pub fn remove_bin<K>(&mut self, key: K) -> Option<MetadataValue<Binary>>
    where
        K: AsMetadataKey<Binary>,
    {
        key.remove(self)
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.headers.extend(other.headers);
    }
}

// ===== impl Iter =====

impl<'a> Iterator for Iter<'a> {
    type Item = KeyAndValueRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| {
            let (name, value) = item;
            if Ascii::is_valid_key(name.as_str()) {
                KeyAndValueRef::Ascii(
                    MetadataKey::unchecked_from_header_name_ref(name),
                    MetadataValue::unchecked_from_header_value_ref(value),
                )
            } else {
                KeyAndValueRef::Binary(
                    MetadataKey::unchecked_from_header_name_ref(name),
                    MetadataValue::unchecked_from_header_value_ref(value),
                )
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

// ===== impl IterMut =====

impl<'a> Iterator for IterMut<'a> {
    type Item = KeyAndMutValueRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| {
            let (name, value) = item;
            if Ascii::is_valid_key(name.as_str()) {
                KeyAndMutValueRef::Ascii(
                    MetadataKey::unchecked_from_header_name_ref(name),
                    MetadataValue::unchecked_from_mut_header_value_ref(value),
                )
            } else {
                KeyAndMutValueRef::Binary(
                    MetadataKey::unchecked_from_header_name_ref(name),
                    MetadataValue::unchecked_from_mut_header_value_ref(value),
                )
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

// ===== impl ValueDrain =====

impl<VE: ValueEncoding> Iterator for ValueDrain<'_, VE> {
    type Item = MetadataValue<VE>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(MetadataValue::unchecked_from_header_value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

// ===== impl Keys =====

impl<'a> Iterator for Keys<'a> {
    type Item = KeyRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|key| {
            if Ascii::is_valid_key(key.as_str()) {
                KeyRef::Ascii(MetadataKey::unchecked_from_header_name_ref(key))
            } else {
                KeyRef::Binary(MetadataKey::unchecked_from_header_name_ref(key))
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for Keys<'_> {}

// ===== impl Values ====

impl<'a> Iterator for Values<'a> {
    type Item = ValueRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| {
            let (name, value) = item;
            if Ascii::is_valid_key(name.as_str()) {
                ValueRef::Ascii(MetadataValue::unchecked_from_header_value_ref(value))
            } else {
                ValueRef::Binary(MetadataValue::unchecked_from_header_value_ref(value))
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

// ===== impl Values ====

impl<'a> Iterator for ValuesMut<'a> {
    type Item = ValueRefMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| {
            let (name, value) = item;
            if Ascii::is_valid_key(name.as_str()) {
                ValueRefMut::Ascii(MetadataValue::unchecked_from_mut_header_value_ref(value))
            } else {
                ValueRefMut::Binary(MetadataValue::unchecked_from_mut_header_value_ref(value))
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

// ===== impl ValueIter =====

impl<'a, VE: ValueEncoding> Iterator for ValueIter<'a, VE>
where
    VE: 'a,
{
    type Item = &'a MetadataValue<VE>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            Some(ref mut inner) => inner
                .next()
                .map(MetadataValue::unchecked_from_header_value_ref),
            None => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.inner {
            Some(ref inner) => inner.size_hint(),
            None => (0, Some(0)),
        }
    }
}

impl<'a, VE: ValueEncoding> DoubleEndedIterator for ValueIter<'a, VE>
where
    VE: 'a,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.inner {
            Some(ref mut inner) => inner
                .next_back()
                .map(MetadataValue::unchecked_from_header_value_ref),
            None => None,
        }
    }
}

// ===== impl ValueIterMut =====

impl<'a, VE: ValueEncoding> Iterator for ValueIterMut<'a, VE>
where
    VE: 'a,
{
    type Item = &'a mut MetadataValue<VE>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(MetadataValue::unchecked_from_mut_header_value_ref)
    }
}

impl<'a, VE: ValueEncoding> DoubleEndedIterator for ValueIterMut<'a, VE>
where
    VE: 'a,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner
            .next_back()
            .map(MetadataValue::unchecked_from_mut_header_value_ref)
    }
}

// ===== impl Entry =====

impl<'a, VE: ValueEncoding> Entry<'a, VE> {
    /// Ensures a value is in the entry by inserting the default if empty.
    ///
    /// Returns a mutable reference to the **first** value in the entry.
    pub fn or_insert(self, default: MetadataValue<VE>) -> &'a mut MetadataValue<VE> {
        use self::Entry::{Occupied, Vacant};

        match self {
            Occupied(e) => e.into_mut(),
            Vacant(e) => e.insert(default),
        }
    }

    /// Ensures a value is in the entry by inserting the result of the default
    /// function if empty.
    ///
    /// The default function is not called if the entry exists in the map.
    /// Returns a mutable reference to the **first** value in the entry.
    pub fn or_insert_with<F: FnOnce() -> MetadataValue<VE>>(
        self,
        default: F,
    ) -> &'a mut MetadataValue<VE> {
        use self::Entry::{Occupied, Vacant};

        match self {
            Occupied(e) => e.into_mut(),
            Vacant(e) => e.insert(default()),
        }
    }

    /// Returns a reference to the entry's key
    pub fn key(&self) -> &MetadataKey<VE> {
        use self::Entry::{Occupied, Vacant};

        MetadataKey::unchecked_from_header_name_ref(match *self {
            Vacant(ref e) => e.inner.key(),
            Occupied(ref e) => e.inner.key(),
        })
    }
}

// ===== impl VacantEntry =====

impl<'a, VE: ValueEncoding> VacantEntry<'a, VE> {
    /// Returns a reference to the entry's key
    pub fn key(&self) -> &MetadataKey<VE> {
        MetadataKey::unchecked_from_header_name_ref(self.inner.key())
    }

    /// Take ownership of the key
    pub fn into_key(self) -> MetadataKey<VE> {
        MetadataKey::unchecked_from_header_name(self.inner.into_key())
    }

    /// Insert the value into the entry.
    ///
    /// The value will be associated with this entry's key. A mutable reference
    /// to the inserted value will be returned.
    pub fn insert(self, value: MetadataValue<VE>) -> &'a mut MetadataValue<VE> {
        MetadataValue::unchecked_from_mut_header_value_ref(self.inner.insert(value.inner))
    }

    /// Insert the value into the entry.
    ///
    /// The value will be associated with this entry's key. The new
    /// `OccupiedEntry` is returned, allowing for further manipulation.
    pub fn insert_entry(self, value: MetadataValue<VE>) -> OccupiedEntry<'a, Ascii> {
        OccupiedEntry {
            inner: self.inner.insert_entry(value.inner),
            phantom: PhantomData,
        }
    }
}

// ===== impl OccupiedEntry =====

impl<'a, VE: ValueEncoding> OccupiedEntry<'a, VE> {
    /// Returns a reference to the entry's key.
    #[must_use]
    pub fn key(&self) -> &MetadataKey<VE> {
        MetadataKey::unchecked_from_header_name_ref(self.inner.key())
    }

    /// Get a reference to the first value in the entry.
    ///
    /// Values are stored in insertion order.
    ///
    /// # Panics
    ///
    /// `get` panics if there are no values associated with the entry.
    #[must_use]
    pub fn get(&self) -> &MetadataValue<VE> {
        MetadataValue::unchecked_from_header_value_ref(self.inner.get())
    }

    /// Get a mutable reference to the first value in the entry.
    ///
    /// Values are stored in insertion order.
    ///
    /// # Panics
    ///
    /// `get_mut` panics if there are no values associated with the entry.
    pub fn get_mut(&mut self) -> &mut MetadataValue<VE> {
        MetadataValue::unchecked_from_mut_header_value_ref(self.inner.get_mut())
    }

    /// Converts the `OccupiedEntry` into a mutable reference to the **first**
    /// value.
    ///
    /// The lifetime of the returned reference is bound to the original map.
    ///
    /// # Panics
    ///
    /// `into_mut` panics if there are no values associated with the entry.
    #[must_use]
    pub fn into_mut(self) -> &'a mut MetadataValue<VE> {
        MetadataValue::unchecked_from_mut_header_value_ref(self.inner.into_mut())
    }

    /// Sets the value of the entry.
    ///
    /// All previous values associated with the entry are removed and the first
    /// one is returned. See `insert_mult` for an API that returns all values.
    pub fn insert(&mut self, value: MetadataValue<VE>) -> MetadataValue<VE> {
        let header_value = self.inner.insert(value.inner);
        MetadataValue::unchecked_from_header_value(header_value)
    }

    /// Sets the value of the entry.
    ///
    /// This function does the same as `insert` except it returns an iterator
    /// that yields all values previously associated with the key.
    pub fn insert_mult(&mut self, value: MetadataValue<VE>) -> ValueDrain<'_, VE> {
        ValueDrain {
            inner: self.inner.insert_mult(value.inner),
            phantom: PhantomData,
        }
    }

    /// Insert the value into the entry.
    ///
    /// The new value is appended to the end of the entry's value list. All
    /// previous values associated with the entry are retained.
    pub fn append(&mut self, value: MetadataValue<VE>) {
        self.inner.append(value.inner)
    }

    /// Remove the entry from the map.
    ///
    /// All values associated with the entry are removed and the first one is
    /// returned. See `remove_entry_mult` for an API that returns all values.
    #[must_use]
    pub fn remove(self) -> MetadataValue<VE> {
        let value = self.inner.remove();
        MetadataValue::unchecked_from_header_value(value)
    }

    /// Remove the entry from the map.
    ///
    /// The key and all values associated with the entry are removed and the
    /// first one is returned. See `remove_entry_mult` for an API that returns
    /// all values.
    #[must_use]
    pub fn remove_entry(self) -> (MetadataKey<VE>, MetadataValue<VE>) {
        let (name, value) = self.inner.remove_entry();
        (
            MetadataKey::unchecked_from_header_name(name),
            MetadataValue::unchecked_from_header_value(value),
        )
    }

    /// Remove the entry from the map.
    ///
    /// The key and all values associated with the entry are removed and
    /// returned.
    #[must_use]
    pub fn remove_entry_mult(self) -> (MetadataKey<VE>, ValueDrain<'a, VE>) {
        let (name, value_drain) = self.inner.remove_entry_mult();
        (
            MetadataKey::unchecked_from_header_name(name),
            ValueDrain {
                inner: value_drain,
                phantom: PhantomData,
            },
        )
    }

    /// Returns an iterator visiting all values associated with the entry.
    ///
    /// Values are iterated in insertion order.
    #[must_use]
    pub fn iter(&self) -> ValueIter<'_, VE> {
        ValueIter {
            inner: Some(self.inner.iter()),
            phantom: PhantomData,
        }
    }

    /// Returns an iterator mutably visiting all values associated with the
    /// entry.
    ///
    /// Values are iterated in insertion order.
    pub fn iter_mut(&mut self) -> ValueIterMut<'_, VE> {
        ValueIterMut {
            inner: self.inner.iter_mut(),
            phantom: PhantomData,
        }
    }
}

impl<'a, VE: ValueEncoding> IntoIterator for OccupiedEntry<'a, VE>
where
    VE: 'a,
{
    type Item = &'a mut MetadataValue<VE>;
    type IntoIter = ValueIterMut<'a, VE>;

    fn into_iter(self) -> ValueIterMut<'a, VE> {
        ValueIterMut {
            inner: self.inner.into_iter(),
            phantom: PhantomData,
        }
    }
}

impl<'a, 'b: 'a, VE: ValueEncoding> IntoIterator for &'b OccupiedEntry<'a, VE> {
    type Item = &'a MetadataValue<VE>;
    type IntoIter = ValueIter<'a, VE>;

    fn into_iter(self) -> ValueIter<'a, VE> {
        self.iter()
    }
}

impl<'a, 'b: 'a, VE: ValueEncoding> IntoIterator for &'b mut OccupiedEntry<'a, VE> {
    type Item = &'a mut MetadataValue<VE>;
    type IntoIter = ValueIterMut<'a, VE>;

    fn into_iter(self) -> ValueIterMut<'a, VE> {
        self.iter_mut()
    }
}

// ===== impl GetAll =====

impl<'a, VE: ValueEncoding> GetAll<'a, VE> {
    /// Returns an iterator visiting all values associated with the entry.
    ///
    /// Values are iterated in insertion order.
    #[must_use]
    pub fn iter(&self) -> ValueIter<'a, VE> {
        ValueIter {
            inner: self.inner.as_ref().map(|inner| inner.iter()),
            phantom: PhantomData,
        }
    }
}

impl<VE: ValueEncoding> PartialEq for GetAll<'_, VE> {
    fn eq(&self, other: &Self) -> bool {
        self.inner.iter().eq(other.inner.iter())
    }
}

impl<'a, VE: ValueEncoding> IntoIterator for GetAll<'a, VE>
where
    VE: 'a,
{
    type Item = &'a MetadataValue<VE>;
    type IntoIter = ValueIter<'a, VE>;

    fn into_iter(self) -> ValueIter<'a, VE> {
        ValueIter {
            inner: self.inner.map(|inner| inner.into_iter()),
            phantom: PhantomData,
        }
    }
}

impl<'a, 'b: 'a, VE: ValueEncoding> IntoIterator for &'b GetAll<'a, VE> {
    type Item = &'a MetadataValue<VE>;
    type IntoIter = ValueIter<'a, VE>;

    fn into_iter(self) -> ValueIter<'a, VE> {
        ValueIter {
            inner: self.inner.as_ref().map(|inner| inner.into_iter()),
            phantom: PhantomData,
        }
    }
}

// ===== impl IntoMetadataKey / AsMetadataKey =====

mod into_metadata_key {
    use super::{MetadataMap, MetadataValue, ValueEncoding};
    use crate::metadata::key::MetadataKey;

    /// A marker trait used to identify values that can be used as insert keys
    /// to a `MetadataMap`.
    pub trait IntoMetadataKey<VE: ValueEncoding>: Sealed<VE> {}

    // All methods are on this pub(super) trait, instead of `IntoMetadataKey`,
    // so that they aren't publicly exposed to the world.
    //
    // Being on the `IntoMetadataKey` trait would mean users could call
    // `"host".insert(&mut map, "localhost")`.
    //
    // Ultimately, this allows us to adjust the signatures of these methods
    // without breaking any external crate.
    pub trait Sealed<VE: ValueEncoding> {
        #[doc(hidden)]
        fn insert(self, map: &mut MetadataMap, val: MetadataValue<VE>)
        -> Option<MetadataValue<VE>>;

        #[doc(hidden)]
        fn append(self, map: &mut MetadataMap, val: MetadataValue<VE>) -> bool;
    }

    // ==== impls ====

    impl<VE: ValueEncoding> Sealed<VE> for MetadataKey<VE> {
        #[doc(hidden)]
        #[inline]
        fn insert(
            self,
            map: &mut MetadataMap,
            val: MetadataValue<VE>,
        ) -> Option<MetadataValue<VE>> {
            map.headers
                .insert(self.inner, val.inner)
                .map(MetadataValue::unchecked_from_header_value)
        }

        #[doc(hidden)]
        #[inline]
        fn append(self, map: &mut MetadataMap, val: MetadataValue<VE>) -> bool {
            map.headers.append(self.inner, val.inner)
        }
    }

    impl<VE: ValueEncoding> IntoMetadataKey<VE> for MetadataKey<VE> {}

    impl<VE: ValueEncoding> Sealed<VE> for &MetadataKey<VE> {
        #[doc(hidden)]
        #[inline]
        fn insert(
            self,
            map: &mut MetadataMap,
            val: MetadataValue<VE>,
        ) -> Option<MetadataValue<VE>> {
            map.headers
                .insert(&self.inner, val.inner)
                .map(MetadataValue::unchecked_from_header_value)
        }
        #[doc(hidden)]
        #[inline]
        fn append(self, map: &mut MetadataMap, val: MetadataValue<VE>) -> bool {
            map.headers.append(&self.inner, val.inner)
        }
    }

    impl<VE: ValueEncoding> IntoMetadataKey<VE> for &MetadataKey<VE> {}

    impl<VE: ValueEncoding> Sealed<VE> for &'static str {
        #[doc(hidden)]
        #[inline]
        fn insert(
            self,
            map: &mut MetadataMap,
            val: MetadataValue<VE>,
        ) -> Option<MetadataValue<VE>> {
            // Perform name validation
            let key = MetadataKey::<VE>::from_static(self);

            map.headers
                .insert(key.inner, val.inner)
                .map(MetadataValue::unchecked_from_header_value)
        }
        #[doc(hidden)]
        #[inline]
        fn append(self, map: &mut MetadataMap, val: MetadataValue<VE>) -> bool {
            // Perform name validation
            let key = MetadataKey::<VE>::from_static(self);

            map.headers.append(key.inner, val.inner)
        }
    }

    impl<VE: ValueEncoding> IntoMetadataKey<VE> for &'static str {}
}

mod as_metadata_key {
    use super::{MetadataMap, MetadataValue, ValueEncoding};
    use crate::metadata::key::{InvalidMetadataKey, MetadataKey};
    use rama_http_types::header::{Entry, GetAll, HeaderValue};

    /// A marker trait used to identify values that can be used as search keys
    /// to a `MetadataMap`.
    pub trait AsMetadataKey<VE: ValueEncoding>: Sealed<VE> {}

    // All methods are on this pub(super) trait, instead of `AsMetadataKey`,
    // so that they aren't publicly exposed to the world.
    //
    // Being on the `AsMetadataKey` trait would mean users could call
    // `"host".find(&map)`.
    //
    // Ultimately, this allows us to adjust the signatures of these methods
    // without breaking any external crate.
    pub trait Sealed<VE: ValueEncoding> {
        #[doc(hidden)]
        fn get(self, map: &MetadataMap) -> Option<&MetadataValue<VE>>;

        #[doc(hidden)]
        fn get_mut(self, map: &mut MetadataMap) -> Option<&mut MetadataValue<VE>>;

        #[doc(hidden)]
        fn get_all(self, map: &MetadataMap) -> Option<GetAll<'_, HeaderValue>>;

        #[doc(hidden)]
        fn entry(self, map: &mut MetadataMap)
        -> Result<Entry<'_, HeaderValue>, InvalidMetadataKey>;

        #[doc(hidden)]
        fn remove(self, map: &mut MetadataMap) -> Option<MetadataValue<VE>>;
    }

    // ==== impls ====

    impl<VE: ValueEncoding> Sealed<VE> for MetadataKey<VE> {
        #[doc(hidden)]
        #[inline]
        fn get(self, map: &MetadataMap) -> Option<&MetadataValue<VE>> {
            map.headers
                .get(self.inner)
                .map(MetadataValue::unchecked_from_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_mut(self, map: &mut MetadataMap) -> Option<&mut MetadataValue<VE>> {
            map.headers
                .get_mut(self.inner)
                .map(MetadataValue::unchecked_from_mut_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_all(self, map: &MetadataMap) -> Option<GetAll<'_, HeaderValue>> {
            Some(map.headers.get_all(self.inner))
        }

        #[doc(hidden)]
        #[inline]
        fn entry(
            self,
            map: &mut MetadataMap,
        ) -> Result<Entry<'_, HeaderValue>, InvalidMetadataKey> {
            Ok(map.headers.entry(self.inner))
        }

        #[doc(hidden)]
        #[inline]
        fn remove(self, map: &mut MetadataMap) -> Option<MetadataValue<VE>> {
            map.headers
                .remove(self.inner)
                .map(MetadataValue::unchecked_from_header_value)
        }
    }

    impl<VE: ValueEncoding> AsMetadataKey<VE> for MetadataKey<VE> {}

    impl<VE: ValueEncoding> Sealed<VE> for &MetadataKey<VE> {
        #[doc(hidden)]
        #[inline]
        fn get(self, map: &MetadataMap) -> Option<&MetadataValue<VE>> {
            map.headers
                .get(&self.inner)
                .map(MetadataValue::unchecked_from_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_mut(self, map: &mut MetadataMap) -> Option<&mut MetadataValue<VE>> {
            map.headers
                .get_mut(&self.inner)
                .map(MetadataValue::unchecked_from_mut_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_all(self, map: &MetadataMap) -> Option<GetAll<'_, HeaderValue>> {
            Some(map.headers.get_all(&self.inner))
        }

        #[doc(hidden)]
        #[inline]
        fn entry(
            self,
            map: &mut MetadataMap,
        ) -> Result<Entry<'_, HeaderValue>, InvalidMetadataKey> {
            Ok(map.headers.entry(&self.inner))
        }

        #[doc(hidden)]
        #[inline]
        fn remove(self, map: &mut MetadataMap) -> Option<MetadataValue<VE>> {
            map.headers
                .remove(&self.inner)
                .map(MetadataValue::unchecked_from_header_value)
        }
    }

    impl<VE: ValueEncoding> AsMetadataKey<VE> for &MetadataKey<VE> {}

    impl<VE: ValueEncoding> Sealed<VE> for &str {
        #[doc(hidden)]
        #[inline]
        fn get(self, map: &MetadataMap) -> Option<&MetadataValue<VE>> {
            if !VE::is_valid_key(self) {
                return None;
            }
            map.headers
                .get(self)
                .map(MetadataValue::unchecked_from_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_mut(self, map: &mut MetadataMap) -> Option<&mut MetadataValue<VE>> {
            if !VE::is_valid_key(self) {
                return None;
            }
            map.headers
                .get_mut(self)
                .map(MetadataValue::unchecked_from_mut_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_all(self, map: &MetadataMap) -> Option<GetAll<'_, HeaderValue>> {
            if !VE::is_valid_key(self) {
                return None;
            }
            Some(map.headers.get_all(self))
        }

        #[doc(hidden)]
        #[inline]
        fn entry(
            self,
            map: &mut MetadataMap,
        ) -> Result<Entry<'_, HeaderValue>, InvalidMetadataKey> {
            if !VE::is_valid_key(self) {
                return Err(InvalidMetadataKey::new());
            }

            let key = rama_http_types::header::HeaderName::from_bytes(self.as_bytes())
                .map_err(|_| InvalidMetadataKey::new())?;
            let entry = map.headers.entry(key);
            Ok(entry)
        }

        #[doc(hidden)]
        #[inline]
        fn remove(self, map: &mut MetadataMap) -> Option<MetadataValue<VE>> {
            if !VE::is_valid_key(self) {
                return None;
            }
            map.headers
                .remove(self)
                .map(MetadataValue::unchecked_from_header_value)
        }
    }

    impl<VE: ValueEncoding> AsMetadataKey<VE> for &str {}

    impl<VE: ValueEncoding> Sealed<VE> for String {
        #[doc(hidden)]
        #[inline]
        fn get(self, map: &MetadataMap) -> Option<&MetadataValue<VE>> {
            if !VE::is_valid_key(self.as_str()) {
                return None;
            }
            map.headers
                .get(self.as_str())
                .map(MetadataValue::unchecked_from_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_mut(self, map: &mut MetadataMap) -> Option<&mut MetadataValue<VE>> {
            if !VE::is_valid_key(self.as_str()) {
                return None;
            }
            map.headers
                .get_mut(self.as_str())
                .map(MetadataValue::unchecked_from_mut_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_all(self, map: &MetadataMap) -> Option<GetAll<'_, HeaderValue>> {
            if !VE::is_valid_key(self.as_str()) {
                return None;
            }
            Some(map.headers.get_all(self.as_str()))
        }

        #[doc(hidden)]
        #[inline]
        fn entry(
            self,
            map: &mut MetadataMap,
        ) -> Result<Entry<'_, HeaderValue>, InvalidMetadataKey> {
            if !VE::is_valid_key(self.as_str()) {
                return Err(InvalidMetadataKey::new());
            }

            let key = rama_http_types::header::HeaderName::from_bytes(self.as_bytes())
                .map_err(|_| InvalidMetadataKey::new())?;
            Ok(map.headers.entry(key))
        }

        #[doc(hidden)]
        #[inline]
        fn remove(self, map: &mut MetadataMap) -> Option<MetadataValue<VE>> {
            if !VE::is_valid_key(self.as_str()) {
                return None;
            }
            map.headers
                .remove(self.as_str())
                .map(MetadataValue::unchecked_from_header_value)
        }
    }

    impl<VE: ValueEncoding> AsMetadataKey<VE> for String {}

    impl<VE: ValueEncoding> Sealed<VE> for &String {
        #[doc(hidden)]
        #[inline]
        fn get(self, map: &MetadataMap) -> Option<&MetadataValue<VE>> {
            if !VE::is_valid_key(self) {
                return None;
            }
            map.headers
                .get(self.as_str())
                .map(MetadataValue::unchecked_from_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_mut(self, map: &mut MetadataMap) -> Option<&mut MetadataValue<VE>> {
            if !VE::is_valid_key(self) {
                return None;
            }
            map.headers
                .get_mut(self.as_str())
                .map(MetadataValue::unchecked_from_mut_header_value_ref)
        }

        #[doc(hidden)]
        #[inline]
        fn get_all(self, map: &MetadataMap) -> Option<GetAll<'_, HeaderValue>> {
            if !VE::is_valid_key(self) {
                return None;
            }
            Some(map.headers.get_all(self.as_str()))
        }

        #[doc(hidden)]
        #[inline]
        fn entry(
            self,
            map: &mut MetadataMap,
        ) -> Result<Entry<'_, HeaderValue>, InvalidMetadataKey> {
            if !VE::is_valid_key(self) {
                return Err(InvalidMetadataKey::new());
            }

            let key = rama_http_types::header::HeaderName::from_bytes(self.as_bytes())
                .map_err(|_| InvalidMetadataKey::new())?;
            Ok(map.headers.entry(key))
        }

        #[doc(hidden)]
        #[inline]
        fn remove(self, map: &mut MetadataMap) -> Option<MetadataValue<VE>> {
            if !VE::is_valid_key(self) {
                return None;
            }
            map.headers
                .remove(self.as_str())
                .map(MetadataValue::unchecked_from_header_value)
        }
    }

    impl<VE: ValueEncoding> AsMetadataKey<VE> for &String {}
}

mod as_encoding_agnostic_metadata_key {
    use super::{MetadataMap, ValueEncoding};
    use crate::metadata::key::MetadataKey;

    /// A marker trait used to identify values that can be used as search keys
    /// to a `MetadataMap`, for operations that don't expose the actual value.
    pub trait AsEncodingAgnosticMetadataKey: Sealed {}

    // All methods are on this pub(super) trait, instead of
    // `AsEncodingAgnosticMetadataKey`, so that they aren't publicly exposed to
    // the world.
    //
    // Being on the `AsEncodingAgnosticMetadataKey` trait would mean users could
    // call `"host".contains_key(&map)`.
    //
    // Ultimately, this allows us to adjust the signatures of these methods
    // without breaking any external crate.
    pub trait Sealed {
        #[doc(hidden)]
        fn contains_key(&self, map: &MetadataMap) -> bool;
    }

    // ==== impls ====

    impl<VE: ValueEncoding> Sealed for MetadataKey<VE> {
        #[doc(hidden)]
        #[inline]
        fn contains_key(&self, map: &MetadataMap) -> bool {
            map.headers.contains_key(&self.inner)
        }
    }

    impl<VE: ValueEncoding> AsEncodingAgnosticMetadataKey for MetadataKey<VE> {}

    impl<VE: ValueEncoding> Sealed for &MetadataKey<VE> {
        #[doc(hidden)]
        #[inline]
        fn contains_key(&self, map: &MetadataMap) -> bool {
            map.headers.contains_key(&self.inner)
        }
    }

    impl<VE: ValueEncoding> AsEncodingAgnosticMetadataKey for &MetadataKey<VE> {}

    impl Sealed for &str {
        #[doc(hidden)]
        #[inline]
        fn contains_key(&self, map: &MetadataMap) -> bool {
            map.headers.contains_key(*self)
        }
    }

    impl AsEncodingAgnosticMetadataKey for &str {}

    impl Sealed for String {
        #[doc(hidden)]
        #[inline]
        fn contains_key(&self, map: &MetadataMap) -> bool {
            map.headers.contains_key(self.as_str())
        }
    }

    impl AsEncodingAgnosticMetadataKey for String {}

    impl Sealed for &String {
        #[doc(hidden)]
        #[inline]
        fn contains_key(&self, map: &MetadataMap) -> bool {
            map.headers.contains_key(self.as_str())
        }
    }

    impl AsEncodingAgnosticMetadataKey for &String {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_headers_takes_http_headers() {
        let mut http_map = rama_http_types::HeaderMap::new();
        http_map.insert("x-host", "example.com".parse().unwrap());

        let map = MetadataMap::from_headers(http_map);

        assert_eq!(map.get("x-host").unwrap(), "example.com");
    }

    #[test]
    fn test_to_headers_encoding() {
        use crate::Status;
        let special_char_message = "Beyond 100% ascii \t\n\r🌶️💉💧🐮🍺";
        let s1 = Status::unknown(special_char_message);

        assert_eq!(s1.message(), special_char_message);

        let s1_map = s1.to_header_map().unwrap();
        let s2 = Status::from_header_map(&s1_map).unwrap();

        assert_eq!(s1.message(), s2.message());

        assert!(
            s1_map
                .get("grpc-message")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("Beyond%20100%25%20ascii"),
            "Percent sign or other character isn't encoded as desired: {:?}",
            s1_map.get("grpc-message")
        );
    }

    #[test]
    fn test_iter_categorizes_ascii_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.append_bin(
            "x-word-bin",
            MetadataValue::try_from_bytes(b"goodbye").unwrap(),
        );
        map.insert_bin(
            "x-number-bin",
            MetadataValue::try_from_bytes(b"123").unwrap(),
        );

        let mut found_x_word = false;
        for key_and_value in map.iter() {
            if let KeyAndValueRef::Ascii(key, _value) = key_and_value {
                if key.as_str() == "x-word" {
                    found_x_word = true;
                } else {
                    panic!("Unexpected key");
                }
            }
        }
        assert!(found_x_word);
    }

    #[test]
    fn test_iter_categorizes_binary_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.append_bin(
            "x-word-bin",
            MetadataValue::try_from_bytes(b"goodbye").unwrap(),
        );

        let mut found_x_word_bin = false;
        for key_and_value in map.iter() {
            if let KeyAndValueRef::Binary(key, _value) = key_and_value {
                if key.as_str() == "x-word-bin" {
                    found_x_word_bin = true;
                } else {
                    panic!("Unexpected key");
                }
            }
        }
        assert!(found_x_word_bin);
    }

    #[test]
    fn test_iter_mut_categorizes_ascii_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.append_bin(
            "x-word-bin",
            MetadataValue::try_from_bytes(b"goodbye").unwrap(),
        );
        map.insert_bin(
            "x-number-bin",
            MetadataValue::try_from_bytes(b"123").unwrap(),
        );

        let mut found_x_word = false;
        for key_and_value in map.iter_mut() {
            if let KeyAndMutValueRef::Ascii(key, _value) = key_and_value {
                if key.as_str() == "x-word" {
                    found_x_word = true;
                } else {
                    panic!("Unexpected key");
                }
            }
        }
        assert!(found_x_word);
    }

    #[test]
    fn test_iter_mut_categorizes_binary_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.append_bin(
            "x-word-bin",
            MetadataValue::try_from_bytes(b"goodbye").unwrap(),
        );

        let mut found_x_word_bin = false;
        for key_and_value in map.iter_mut() {
            if let KeyAndMutValueRef::Binary(key, _value) = key_and_value {
                if key.as_str() == "x-word-bin" {
                    found_x_word_bin = true;
                } else {
                    panic!("Unexpected key");
                }
            }
        }
        assert!(found_x_word_bin);
    }

    #[test]
    fn test_keys_categorizes_ascii_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.append_bin(
            "x-word-bin",
            MetadataValue::try_from_bytes(b"goodbye").unwrap(),
        );
        map.insert_bin(
            "x-number-bin",
            MetadataValue::try_from_bytes(b"123").unwrap(),
        );

        let mut found_x_word = false;
        for key in map.keys() {
            if let KeyRef::Ascii(key) = key {
                if key.as_str() == "x-word" {
                    found_x_word = true;
                } else {
                    panic!("Unexpected key");
                }
            }
        }
        assert!(found_x_word);
    }

    #[test]
    fn test_keys_categorizes_binary_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.insert_bin(
            "x-number-bin",
            MetadataValue::try_from_bytes(b"123").unwrap(),
        );

        let mut found_x_number_bin = false;
        for key in map.keys() {
            if let KeyRef::Binary(key) = key {
                if key.as_str() == "x-number-bin" {
                    found_x_number_bin = true;
                } else {
                    panic!("Unexpected key");
                }
            }
        }
        assert!(found_x_number_bin);
    }

    #[test]
    fn test_values_categorizes_ascii_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.append_bin(
            "x-word-bin",
            MetadataValue::try_from_bytes(b"goodbye").unwrap(),
        );
        map.insert_bin(
            "x-number-bin",
            MetadataValue::try_from_bytes(b"123").unwrap(),
        );

        let mut found_x_word = false;
        for value in map.values() {
            if let ValueRef::Ascii(value) = value {
                if *value == "hello" {
                    found_x_word = true;
                } else {
                    panic!("Unexpected key");
                }
            }
        }
        assert!(found_x_word);
    }

    #[test]
    fn test_values_categorizes_binary_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.append_bin(
            "x-word-bin",
            MetadataValue::try_from_bytes(b"goodbye").unwrap(),
        );

        let mut found_x_word_bin = false;
        for value_ref in map.values() {
            if let ValueRef::Binary(value) = value_ref {
                assert_eq!(*value, "goodbye");
                found_x_word_bin = true;
            }
        }
        assert!(found_x_word_bin);
    }

    #[test]
    fn test_values_mut_categorizes_ascii_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.append_bin(
            "x-word-bin",
            MetadataValue::try_from_bytes(b"goodbye").unwrap(),
        );
        map.insert_bin(
            "x-number-bin",
            MetadataValue::try_from_bytes(b"123").unwrap(),
        );

        let mut found_x_word = false;
        for value_ref in map.values_mut() {
            if let ValueRefMut::Ascii(value) = value_ref {
                assert_eq!(*value, "hello");
                found_x_word = true;
            }
        }
        assert!(found_x_word);
    }

    #[test]
    fn test_values_mut_categorizes_binary_entries() {
        let mut map = MetadataMap::new();

        map.insert("x-word", "hello".parse().unwrap());
        map.append_bin(
            "x-word-bin",
            MetadataValue::try_from_bytes(b"goodbye").unwrap(),
        );

        let mut found_x_word_bin = false;
        for value in map.values_mut() {
            if let ValueRefMut::Binary(value) = value {
                assert_eq!(*value, "goodbye");
                found_x_word_bin = true;
            }
        }
        assert!(found_x_word_bin);
    }

    #[allow(dead_code)]
    fn value_drain_is_send_sync() {
        fn is_send_sync<T: Send + Sync>() {}

        is_send_sync::<Iter<'_>>();
        is_send_sync::<IterMut<'_>>();

        is_send_sync::<ValueDrain<'_, Ascii>>();
        is_send_sync::<ValueDrain<'_, Binary>>();

        is_send_sync::<ValueIterMut<'_, Ascii>>();
        is_send_sync::<ValueIterMut<'_, Binary>>();
    }
}
