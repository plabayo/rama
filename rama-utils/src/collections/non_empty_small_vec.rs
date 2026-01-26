use serde::{
    Deserialize, Serialize,
    de::Error,
    ser::{SerializeSeq, Serializer},
};
use smallvec::SmallVec;

use std::convert::TryFrom;
use std::iter;
use std::mem;
use std::{cmp::Ordering, num::NonZeroUsize};

/// Like the `vec!` macro, but enforces at least one argument. A nice short-hand
/// for constructing [`NonEmptySmallVec`] values.
#[macro_export]
#[doc(hidden)]
macro_rules! __non_empty_smallvec {
    ($h:expr, $( $x:expr ),* $(,)?) => {{
        let tail = $crate::collections::smallvec::smallvec![$($x),*];
        $crate::collections::NonEmptySmallVec { head: $h, tail }
    }};
    ($h:expr, $( $x:expr ),* ; _) => {{
        let tail = $crate::collections::smallvec::smallvec![$($x),*];
        const N: usize = $crate::macros::count!($($x)*);
        $crate::collections::NonEmptySmallVec::<N, _> { head: $h, tail }
    }};
    ($h:expr, $( $x:expr ),* ; $N:literal) => {{
        let tail = $crate::collections::smallvec::smallvec![$($x),*];
        $crate::collections::NonEmptySmallVec::<$N, _> { head: $h, tail }
    }};
    ($h:expr) => {
        $crate::collections::NonEmptySmallVec {
            head: $h,
            tail: $crate::collections::smallvec::smallvec![],
        }
    };
    ($h:expr; _) => {
        $crate::collections::NonEmptySmallVec {
            head: $h,
            tail: $crate::collections::smallvec::SmallVec::<[_; 0]>::new(),
        }
    };
}

/// A Non-empty stack vector which can grow to the heap.
///
/// See [`crate::collections::NonEmptyVec`] for more inforamtion,
/// as it's identical to it except that we make use of a [`SmallVec`]
/// instead of a [`Vec`] for tail storage.
///
/// Note that the total storage is N+1, as N is the size of the tail,
/// but there's also the head.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NonEmptySmallVec<const N: usize, T> {
    pub head: T,
    pub tail: SmallVec<[T; N]>,
}

impl<const N: usize, T: Serialize> Serialize for NonEmptySmallVec<N, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for e in self {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

impl<'de, const N: usize, T: Deserialize<'de>> Deserialize<'de> for NonEmptySmallVec<N, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <SmallVec<[T; N]>>::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
}

/// Iterator for [`NonEmptySmallVec`].
pub struct NonEmptySmallVecIter<'a, T> {
    head: Option<&'a T>,
    tail: &'a [T],
}

impl<'a, T> Iterator for NonEmptySmallVecIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(value) = self.head.take() {
            Some(value)
        } else if let Some((first, rest)) = self.tail.split_first() {
            self.tail = rest;
            Some(first)
        } else {
            None
        }
    }
}

impl<T> DoubleEndedIterator for NonEmptySmallVecIter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if let Some((last, rest)) = self.tail.split_last() {
            self.tail = rest;
            Some(last)
        } else if let Some(first_value) = self.head.take() {
            Some(first_value)
        } else {
            None
        }
    }
}

impl<T> ExactSizeIterator for NonEmptySmallVecIter<'_, T> {
    fn len(&self) -> usize {
        self.tail.len() + self.head.map_or(0, |_| 1)
    }
}

impl<T> std::iter::FusedIterator for NonEmptySmallVecIter<'_, T> {}

impl<const N: usize, T> NonEmptySmallVec<N, T> {
    /// Alias for [`NonEmptySmallVec::singleton`].
    pub fn new(e: T) -> Self {
        Self::singleton(e)
    }

    /// Converts from `&NonEmptySmallVec<N, T>` to `NonEmptySmallVec<N, &T>`.
    pub fn as_ref(&self) -> NonEmptySmallVec<N, &T> {
        NonEmptySmallVec {
            head: &self.head,
            tail: self.tail.iter().collect(),
        }
    }

    /// Attempt to convert an iterator into a `NonEmptySmallVec` vector.
    /// Returns `None` if the iterator was empty.
    pub fn collect<I>(iter: I) -> Option<Self>
    where
        I: IntoIterator<Item = T>,
    {
        let mut iter = iter.into_iter();
        let head = iter.next()?;
        Some(Self {
            head,
            tail: iter.collect(),
        })
    }

    /// Create a new non-empty list with an initial element.
    pub fn singleton(head: T) -> Self {
        Self {
            head,
            tail: SmallVec::new(),
        }
    }

    /// Always returns false.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Get the first element. Never fails.
    pub const fn first(&self) -> &T {
        &self.head
    }

    /// Get the mutable reference to the first element. Never fails.
    pub fn first_mut(&mut self) -> &mut T {
        &mut self.head
    }

    /// Get the possibly-empty tail of the list.
    pub fn tail(&self) -> &[T] {
        &self.tail
    }

    /// Push an element to the end of the list.
    pub fn push(&mut self, e: T) {
        self.tail.push(e)
    }

    /// Pop an element from the end of the list.
    pub fn pop(&mut self) -> Option<T> {
        self.tail.pop()
    }

    /// Inserts an element at position index within the vector, shifting all elements after it to the right.
    ///
    /// # Panics
    ///
    /// Panics if index > len.
    pub fn insert(&mut self, index: usize, element: T) {
        let len = self.len();
        assert!(index <= len);

        if index == 0 {
            let head = mem::replace(&mut self.head, element);
            self.tail.insert(0, head);
        } else {
            self.tail.insert(index - 1, element);
        }
    }

    /// Get the length of the list.
    pub fn len(&self) -> usize {
        self.tail.len() + 1
    }

    /// Gets the length of the list as a NonZeroUsize.
    pub fn len_nonzero(&self) -> NonZeroUsize {
        unsafe { NonZeroUsize::new_unchecked(self.tail.len().saturating_add(1)) }
    }

    /// Get the capacity of the list.
    pub fn capacity(&self) -> NonZeroUsize {
        NonZeroUsize::MIN.saturating_add(self.tail.capacity())
    }

    /// Get the last element. Never fails.
    pub fn last(&self) -> &T {
        match self.tail.last() {
            None => &self.head,
            Some(e) => e,
        }
    }

    /// Get the last element mutably.
    pub fn last_mut(&mut self) -> &mut T {
        match self.tail.last_mut() {
            None => &mut self.head,
            Some(e) => e,
        }
    }

    /// Check whether an element is contained in the list.
    pub fn contains(&self, x: &T) -> bool
    where
        T: PartialEq,
    {
        self.iter().any(|e| e == x)
    }

    /// Get an element by index.
    pub fn get(&self, index: usize) -> Option<&T> {
        if index == 0 {
            Some(&self.head)
        } else {
            self.tail.get(index - 1)
        }
    }

    /// Get an element by index, mutably.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index == 0 {
            Some(&mut self.head)
        } else {
            self.tail.get_mut(index - 1)
        }
    }

    /// Truncate the list to a certain size. Must be greater than `0`.
    pub fn truncate(&mut self, len: NonZeroUsize) {
        self.tail.truncate(len.get() - 1);
    }

    pub fn iter(&self) -> NonEmptySmallVecIter<'_, T> {
        NonEmptySmallVecIter {
            head: Some(&self.head),
            tail: &self.tail,
        }
    }

    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut T> + '_ {
        iter::once(&mut self.head).chain(self.tail.iter_mut())
    }

    /// Often we have a `Vec` (or slice `&[T]`) but want to ensure that it is `NonEmptySmallVec` before
    /// proceeding with a computation. Using `from_slice` will give us a proof
    /// that we have a `NonEmptySmallVec` in the `Some` branch, otherwise it allows
    /// the caller to handle the `None` case.
    pub fn from_slice(slice: &[T]) -> Option<Self>
    where
        T: Clone,
    {
        slice.split_first().map(|(h, t)| Self {
            head: h.clone(),
            tail: t.into(),
        })
    }

    /// Often we have a `Vec` (or slice `&[T]`) but want to ensure that it is `NonEmptySmallVec` before
    /// proceeding with a computation. Using `from_smallvec` will give us a proof
    /// that we have a `NonEmptySmallVec` in the `Some` branch, otherwise it allows
    /// the caller to handle the `None` case.
    ///
    /// This version will consume the `Vec` you pass in. If you would rather pass the data as a
    /// slice then use `NonEmptySmallVec::from_slice`.
    #[must_use]
    pub fn from_smallvec(mut vec: SmallVec<[T; N]>) -> Option<Self> {
        if vec.is_empty() {
            None
        } else {
            let head = vec.remove(0);
            Some(Self { head, tail: vec })
        }
    }

    /// Deconstruct a `NonEmptySmallVec` into its head and tail.
    /// This operation never fails since we are guaranteed
    /// to have a head element.
    pub fn split_first(&self) -> (&T, &[T]) {
        (&self.head, &self.tail)
    }

    /// Deconstruct a `NonEmptySmallVec` into its first, last, and
    /// middle elements, in that order.
    ///
    /// If there is only one element then last is `None`.
    pub fn split(&self) -> (&T, &[T], Option<&T>) {
        match self.tail.split_last() {
            None => (&self.head, &[], None),
            Some((last, middle)) => (&self.head, middle, Some(last)),
        }
    }

    /// Append a `Vec` to the tail of the `NonEmptySmallVec`.
    pub fn append(&mut self, other: &mut SmallVec<[T; N]>) {
        self.tail.append(other)
    }

    /// A structure preserving `map`. This is useful for when
    /// we wish to keep the `NonEmptySmallVec` structure guaranteeing
    /// that there is at least one element. Otherwise, we can
    /// use `non_empty_smallvec.iter().map(f)`.
    pub fn map<U, F>(self, mut f: F) -> NonEmptySmallVec<N, U>
    where
        F: FnMut(T) -> U,
    {
        NonEmptySmallVec {
            head: f(self.head),
            tail: self.tail.into_iter().map(f).collect(),
        }
    }

    /// A structure preserving, fallible mapping function.
    pub fn try_map<E, U, F>(self, mut f: F) -> Result<NonEmptySmallVec<N, U>, E>
    where
        F: FnMut(T) -> Result<U, E>,
    {
        Ok(NonEmptySmallVec {
            head: f(self.head)?,
            tail: self.tail.into_iter().map(f).collect::<Result<_, _>>()?,
        })
    }

    /// When we have a function that goes from some `T` to a `NonEmptySmallVec<U>`,
    /// we may want to apply it to a `NonEmptySmallVec<T>` but keep the structure flat.
    /// This is where `flat_map` shines.
    pub fn flat_map<U, F>(self, mut f: F) -> NonEmptySmallVec<N, U>
    where
        F: FnMut(T) -> NonEmptySmallVec<N, U>,
    {
        let mut heads = f(self.head);
        let mut tails = self
            .tail
            .into_iter()
            .flat_map(|t| f(t).into_iter())
            .collect();
        heads.append(&mut tails);
        heads
    }

    /// Flatten nested `NonEmptySmallVec`s into a single one.
    pub fn flatten(full: NonEmptySmallVec<N, Self>) -> Self {
        full.flat_map(|n| n)
    }

    /// Binary searches this sorted non-empty vector for a given element.
    ///
    /// If the value is found then Result::Ok is returned, containing the index of the matching element.
    /// If there are multiple matches, then any one of the matches could be returned.
    ///
    /// If the value is not found then Result::Err is returned, containing the index where a
    /// matching element could be inserted while maintaining sorted order.
    pub fn binary_search(&self, x: &T) -> Result<usize, usize>
    where
        T: Ord,
    {
        self.binary_search_by(|p| p.cmp(x))
    }

    /// Binary searches this sorted non-empty with a comparator function.
    ///
    /// The comparator function should implement an order consistent with the sort order of the underlying slice,
    /// returning an order code that indicates whether its argument is Less, Equal or Greater the desired target.
    ///
    /// If the value is found then Result::Ok is returned, containing the index of the matching element.
    /// If there are multiple matches, then any one of the matches could be returned.
    /// If the value is not found then Result::Err is returned, containing the index where a matching element could be
    /// inserted while maintaining sorted order.
    pub fn binary_search_by<'a, F>(&'a self, mut f: F) -> Result<usize, usize>
    where
        F: FnMut(&'a T) -> Ordering,
    {
        match f(&self.head) {
            Ordering::Equal => Ok(0),
            Ordering::Greater => Err(0),
            Ordering::Less => self
                .tail
                .binary_search_by(f)
                .map(|index| index + 1)
                .map_err(|index| index + 1),
        }
    }

    /// Binary searches this sorted non-empty vector with a key extraction function.
    ///
    /// Assumes that the vector is sorted by the key.
    ///
    /// If the value is found then Result::Ok is returned, containing the index of the matching element. If there are multiple matches,
    /// then any one of the matches could be returned. If the value is not found then Result::Err is returned,
    /// containing the index where a matching element could be inserted while maintaining sorted order.
    pub fn binary_search_by_key<'a, B, F>(&'a self, b: &B, mut f: F) -> Result<usize, usize>
    where
        B: Ord,
        F: FnMut(&'a T) -> B,
    {
        self.binary_search_by(|k| f(k).cmp(b))
    }

    /// Returns the maximum element in the non-empty vector.
    ///
    /// This will return the first item in the vector if the tail is empty.
    pub fn maximum(&self) -> &T
    where
        T: Ord,
    {
        self.maximum_by(|i, j| i.cmp(j))
    }

    /// Returns the minimum element in the non-empty vector.
    ///
    /// This will return the first item in the vector if the tail is empty.
    pub fn minimum(&self) -> &T
    where
        T: Ord,
    {
        self.minimum_by(|i, j| i.cmp(j))
    }

    /// Returns the element that gives the maximum value with respect to the specified comparison function.
    ///
    /// This will return the first item in the vector if the tail is empty.
    pub fn maximum_by<F>(&self, mut compare: F) -> &T
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        let mut max = &self.head;
        for i in self.tail.iter() {
            max = match compare(max, i) {
                Ordering::Equal | Ordering::Greater => max,
                Ordering::Less => i,
            };
        }
        max
    }

    /// Returns the element that gives the minimum value with respect to the specified comparison function.
    ///
    /// This will return the first item in the vector if the tail is empty.
    pub fn minimum_by<F>(&self, mut compare: F) -> &T
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        self.maximum_by(|a, b| compare(a, b).reverse())
    }

    /// Returns the element that gives the maximum value with respect to the specified function.
    ///
    /// This will return the first item in the vector if the tail is empty.
    pub fn maximum_by_key<U, F>(&self, mut f: F) -> &T
    where
        U: Ord,
        F: FnMut(&T) -> U,
    {
        self.maximum_by(|i, j| f(i).cmp(&f(j)))
    }

    /// Returns the element that gives the minimum value with respect to the specified function.
    ///
    /// This will return the first item in the vector if the tail is empty.
    pub fn minimum_by_key<U, F>(&self, mut f: F) -> &T
    where
        U: Ord,
        F: FnMut(&T) -> U,
    {
        self.minimum_by(|i, j| f(i).cmp(&f(j)))
    }

    /// Sorts the [`NonEmptySmallVec`].
    ///
    /// The implementation uses [`slice::sort`](slice::sort) for the tail and then checks where the
    /// head belongs. If the head is already the smallest element, this should be as fast as sorting a
    /// slice. However, if the head needs to be inserted, then it incurs extra cost for removing
    /// the new head from the tail and adding the old head at the correct index.
    pub fn sort(&mut self)
    where
        T: Ord,
    {
        self.tail.sort();
        let index = self.tail.partition_point(|x| x < &self.head);
        if index != 0 {
            let new_head = self.tail.remove(0);
            let head = mem::replace(&mut self.head, new_head);
            self.tail.insert(index - 1, head);
        }
    }

    /// Sorts the [`NonEmptySmallVec`] with a comparator function.
    ///
    /// The implementation uses [`slice::sort_by`](slice::sort_by) for the tail and then checks where
    /// the head belongs. If the head is already the smallest element, this should be as fast as sorting
    /// a slice. However, if the head needs to be inserted, then it incurs extra cost for removing the
    /// new head from the tail and adding the old head at the correct index.
    pub fn sort_by<F>(&mut self, mut compare: F)
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        self.tail.sort_by(&mut compare);

        let index = self
            .tail
            .partition_point(|x| compare(x, &self.head) == Ordering::Less);
        if index != 0 {
            let new_head = self.tail.remove(0);
            let head = mem::replace(&mut self.head, new_head);
            self.tail.insert(index - 1, head);
        }
    }

    /// Sorts the [`NonEmptySmallVec`] with a key extraction function.
    pub fn sort_by_key<K, F>(&mut self, mut f: F)
    where
        F: FnMut(&T) -> K,
        K: Ord,
    {
        self.tail.sort_by_key(&mut f);

        let head_key = f(&self.head);
        let index = self.tail.partition_point(|x| f(x) < head_key);
        if index != 0 {
            let new_head = self.tail.remove(0);
            let head = mem::replace(&mut self.head, new_head);
            self.tail.insert(index - 1, head);
        }
    }

    /// Sorts the [`NonEmptySmallVec`] with a key extraction function, caching the keys.
    ///
    /// The implementation uses [`slice::sort_by_cached_key`](slice::sort_by_cached_key)
    /// for the tail and then determines where the head belongs using the cached head key.
    pub fn sort_by_cached_key<K, F>(&mut self, mut f: F)
    where
        F: FnMut(&T) -> K,
        K: Ord,
    {
        self.tail.sort_by_cached_key(&mut f);

        let head_key = f(&self.head);
        let index = self.tail.partition_point(|x| f(x) < head_key);

        if index != 0 {
            let new_head = self.tail.remove(0);
            let head = mem::replace(&mut self.head, new_head);
            self.tail.insert(index - 1, head);
        }
    }
}

impl<const N: usize, T: Default> Default for NonEmptySmallVec<N, T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<const N: usize, T> From<NonEmptySmallVec<N, T>> for SmallVec<[T; N]> {
    /// Turns a non-empty list into a Vec.
    fn from(non_empty_smallvec: NonEmptySmallVec<N, T>) -> Self {
        let NonEmptySmallVec { head, mut tail } = non_empty_smallvec;
        tail.insert(0, head);
        tail
    }
}

impl<const N: usize, T> From<NonEmptySmallVec<N, T>> for (T, SmallVec<[T; N]>) {
    /// Turns a non-empty list into a SmallVec.
    fn from(non_empty_smallvec: NonEmptySmallVec<N, T>) -> (T, SmallVec<[T; N]>) {
        (non_empty_smallvec.head, non_empty_smallvec.tail)
    }
}

impl<const N: usize, T> From<(T, SmallVec<[T; N]>)> for NonEmptySmallVec<N, T> {
    /// Turns a pair of an element and a Vec into
    /// a NonEmptySmallVec.
    fn from((head, tail): (T, SmallVec<[T; N]>)) -> Self {
        Self { head, tail }
    }
}

impl<const N: usize, T> IntoIterator for NonEmptySmallVec<N, T> {
    type Item = T;
    type IntoIter = iter::Chain<iter::Once<T>, smallvec::IntoIter<[Self::Item; N]>>;

    fn into_iter(self) -> Self::IntoIter {
        iter::once(self.head).chain(self.tail)
    }
}

impl<'a, const N: usize, T> IntoIterator for &'a NonEmptySmallVec<N, T> {
    type Item = &'a T;
    type IntoIter = iter::Chain<iter::Once<&'a T>, std::slice::Iter<'a, T>>;

    fn into_iter(self) -> Self::IntoIter {
        iter::once(&self.head).chain(self.tail.iter())
    }
}

impl<const N: usize, T> std::ops::Index<usize> for NonEmptySmallVec<N, T> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        if index > 0 {
            &self.tail[index - 1]
        } else {
            &self.head
        }
    }
}

impl<const N: usize, T> std::ops::IndexMut<usize> for NonEmptySmallVec<N, T> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        if index > 0 {
            &mut self.tail[index - 1]
        } else {
            &mut self.head
        }
    }
}

impl<const N: usize, A> Extend<A> for NonEmptySmallVec<N, A> {
    fn extend<T: IntoIterator<Item = A>>(&mut self, iter: T) {
        self.tail.extend(iter)
    }
}

impl<const N: usize, T> TryFrom<SmallVec<[T; N]>> for NonEmptySmallVec<N, T> {
    type Error = NonEmptySmallVecEmptyError;

    fn try_from(vec: SmallVec<[T; N]>) -> Result<Self, Self::Error> {
        Self::from_smallvec(vec).ok_or(NonEmptySmallVecEmptyError)
    }
}

crate::macros::error::static_str_error! {
    #[doc = "empty value cannot be turned into a NonEmptySmallVec"]
    pub struct NonEmptySmallVecEmptyError;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collections::non_empty_smallvec;
    use smallvec::smallvec;

    #[test]
    fn test_from_conversion() {
        let result: NonEmptySmallVec<4, _> = NonEmptySmallVec::from((1, smallvec![2, 3, 4, 5]));
        let expected: NonEmptySmallVec<4, _> = NonEmptySmallVec {
            head: 1,
            tail: smallvec![2, 3, 4, 5],
        };
        assert_eq!(result, expected);
    }

    #[test]
    fn test_into_iter() {
        let non_empty_smallvec: NonEmptySmallVec<3, _> =
            NonEmptySmallVec::from((0, smallvec![1, 2, 3]));
        for (i, n) in non_empty_smallvec.into_iter().enumerate() {
            assert_eq!(i as i32, n);
        }
    }

    #[test]
    fn test_iter_syntax() {
        let non_empty_smallvec: NonEmptySmallVec<3, _> =
            NonEmptySmallVec::from((0, smallvec![1, 2, 3]));
        for n in &non_empty_smallvec {
            let _ = *n; // Prove that we're dealing with references.
        }
        for _ in non_empty_smallvec {}
    }

    #[test]
    fn test_iter_both_directions() {
        let mut non_empty_smallvec: NonEmptySmallVec<3, _> =
            NonEmptySmallVec::from((0, smallvec![1, 2, 3]));
        assert_eq!(
            non_empty_smallvec.iter().cloned().collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(
            non_empty_smallvec.iter().rev().cloned().collect::<Vec<_>>(),
            [3, 2, 1, 0]
        );
        assert_eq!(
            non_empty_smallvec.iter_mut().rev().collect::<Vec<_>>(),
            [&mut 3, &mut 2, &mut 1, &mut 0]
        );
    }

    #[test]
    fn test_iter_both_directions_at_once() {
        let non_empty_smallvec: NonEmptySmallVec<3, _> =
            NonEmptySmallVec::from((0, smallvec![1, 2, 3]));
        let mut i = non_empty_smallvec.iter();
        assert_eq!(i.next(), Some(&0));
        assert_eq!(i.next_back(), Some(&3));
        assert_eq!(i.next(), Some(&1));
        assert_eq!(i.next_back(), Some(&2));
        assert_eq!(i.next(), None);
        assert_eq!(i.next_back(), None);
    }

    #[test]
    fn test_mutate_head() {
        let mut non_empty: NonEmptySmallVec<0, _> = NonEmptySmallVec::new(42);
        non_empty.head += 1;
        assert_eq!(non_empty.head, 43);

        let mut non_empty: NonEmptySmallVec<3, _> = NonEmptySmallVec::from((1, smallvec![4, 2, 3]));
        non_empty.head *= 42;
        assert_eq!(non_empty.head, 42);
    }

    #[test]
    fn test_to_nonempty() {
        use std::iter::{empty, once};

        assert_eq!(NonEmptySmallVec::<0, ()>::collect(empty()), None);
        assert_eq!(
            NonEmptySmallVec::<0, ()>::collect(once(())),
            Some(NonEmptySmallVec::new(()))
        );
        assert_eq!(
            NonEmptySmallVec::<1, u8>::collect(once(1).chain(once(2))),
            Some(non_empty_smallvec!(1, 2))
        );
    }

    #[test]
    fn test_try_map() {
        assert_eq!(
            non_empty_smallvec!(1, 2, 3, 4; 4).try_map(Ok::<_, String>),
            Ok(non_empty_smallvec!(1, 2, 3, 4; 4))
        );
        assert_eq!(
            non_empty_smallvec!(1, 2, 3, 4; 4).try_map(|i| if i % 2 == 0 {
                Ok(i)
            } else {
                Err("not even")
            }),
            Err("not even")
        );
    }

    #[test]
    fn test_nontrivial_minimum_by_key() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct Position {
            x: i32,
            y: i32,
        }
        impl Position {
            pub(super) fn distance_squared(self, other: Self) -> u32 {
                let dx = self.x - other.x;
                let dy = self.y - other.y;
                (dx * dx + dy * dy) as u32
            }
        }
        let positions = non_empty_smallvec![
            Position { x: 1, y: 1 },
            Position { x: 0, y: 0 },
            Position { x: 3, y: 4 }
            ; _
        ];
        let target = Position { x: 1, y: 2 };
        let closest = positions.minimum_by_key(|position| position.distance_squared(target));
        assert_eq!(closest, &Position { x: 1, y: 1 });
    }

    #[test]
    fn test_sort() {
        let mut numbers = non_empty_smallvec![1; _];
        numbers.sort();
        assert_eq!(numbers, non_empty_smallvec![1; _]);

        let mut numbers = non_empty_smallvec![2, 1, 3; _];
        numbers.sort();
        assert_eq!(numbers, non_empty_smallvec![1, 2, 3; _]);

        let mut numbers = non_empty_smallvec![1, 3, 2; _];
        numbers.sort();
        assert_eq!(numbers, non_empty_smallvec![1, 2, 3; _]);

        let mut numbers = non_empty_smallvec![3, 2, 1; _];
        numbers.sort();
        assert_eq!(numbers, non_empty_smallvec![1, 2, 3; _]);
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct SimpleSerializable(pub i32);

    #[test]
    fn test_simple_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        // Given
        let mut non_empty = NonEmptySmallVec::new(SimpleSerializable(42));
        non_empty.push(SimpleSerializable(777));

        // When
        let res = serde_json::from_str::<'_, NonEmptySmallVec<8, SimpleSerializable>>(
            &serde_json::to_string(&non_empty)?,
        )?;

        // Then
        assert_eq!(res, non_empty);

        Ok(())
    }

    #[test]
    fn test_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let ne = non_empty_smallvec![1, 2, 3, 4, 5; _];
        let ve: SmallVec<[_; 5]> = smallvec![1, 2, 3, 4, 5];

        assert_eq!(serde_json::to_string(&ne)?, serde_json::to_string(&ve)?);

        Ok(())
    }
}
