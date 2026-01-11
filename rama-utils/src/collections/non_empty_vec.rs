// > Fork of <https://github.com/cloudhead/non_empty_vec>.
// >
// > License and version information can be found at
// > <https://github.com/plabayo/rama/tree/main/docs/thirdparty/fork>.

use serde::{
    Deserialize, Serialize,
    ser::{SerializeSeq, Serializer},
};

use std::convert::TryFrom;
use std::iter;
use std::mem;
use std::vec::{self, Vec};
use std::{cmp::Ordering, num::NonZeroUsize};

/// Like the `vec!` macro, but enforces at least one argument. A nice short-hand
/// for constructing [`NonEmptyVec`] values.
///
/// ```
/// use rama_utils::collections::{NonEmptyVec, non_empty_vec};
///
/// let v = non_empty_vec![1, 2, 3];
/// assert_eq!(v, NonEmptyVec { head: 1, tail: vec![2, 3]});
///
/// let v = non_empty_vec![1];
/// assert_eq!(v, NonEmptyVec::new(1));
///
/// // Accepts trailing commas
/// let v = non_empty_vec![1,];
/// assert_eq!(v, NonEmptyVec::new(1));
///
/// // Doesn't compile!
/// // let v = non_empty_vec![];
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! __non_empty_vec {
    ($h:expr, $( $x:expr ),* $(,)?) => {{
        let tail = $crate::collections::__macro_support::vec![$($x),*];
        $crate::collections::NonEmptyVec { head: $h, tail }
    }};
    ($h:expr) => {
        $crate::collections::NonEmptyVec {
            head: $h,
            tail: $crate::collections::__macro_support::vec![],
        }
    };
}

/// A Non-empty growable vector.
///
/// Non-emptiness can be a powerful guarantee. If your main use of `Vec` is as
/// an `Iterator`, then you may not need to distinguish on emptiness. But there
/// are indeed times when the `Vec` you receive as as function argument needs to
/// be non-empty or your function can't proceed. Similarly, there are times when
/// the `Vec` you return to a calling user needs to promise it actually contains
/// something.
///
/// With `NonEmptyVec`, you're freed from the boilerplate of constantly needing to
/// check `is_empty()` or pattern matching before proceeding, or erroring if you
/// can't. So overall, code, type signatures, and logic become cleaner.
///
/// Consider that unlike `Vec`, [`NonEmptyVec::first`] and [`NonEmptyVec::last`] don't
/// return in `Option`, they always succeed.
///
/// # Examples
///
/// The simplest way to construct a [`NonEmptyVec`] is via the [`non_empty_vec`] macro:
///
/// ```
/// use rama_utils::collections::{NonEmptyVec, non_empty_vec};
///
/// let l: NonEmptyVec<u32> = non_empty_vec![1, 2, 3];
/// assert_eq!(l.head, 1);
/// ```
///
/// Unlike the familiar `vec!` macro, `non_empty_vec!` requires at least one element:
///
/// ```
/// use rama_utils::collections::non_empty_vec;
///
/// let l = non_empty_vec![1];
///
/// // Doesn't compile!
/// // let l = non_empty_vec![];
/// ```
///
/// Like `Vec`, you can also construct a [`NonEmptyVec`]
/// the old fashioned way with [`NonEmptyVec::new`].
///
/// # Caveats
///
/// Since `NonEmptyVec` must have a least one element, it is not possible to
/// implement the [`FromIterator`] trait for it. We can't know, in general, if
/// any given [`Iterator`] actually contains something.
///
/// [`non_empty_vec`]: super::non_empty_vec
#[derive(Deserialize)]
#[serde(try_from = "Vec<T>")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NonEmptyVec<T> {
    pub head: T,
    pub tail: Vec<T>,
}

// Nb. `Serialize` is implemented manually, as serde's `into` container attribute
// requires a `T: Clone` bound which we'd like to avoid.
impl<T> Serialize for NonEmptyVec<T>
where
    T: Serialize,
{
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

/// Iterator for [`NonEmptyVec`].
pub struct NonEmptyVecIter<'a, T> {
    head: Option<&'a T>,
    tail: &'a [T],
}

impl<'a, T> Iterator for NonEmptyVecIter<'a, T> {
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

impl<T> DoubleEndedIterator for NonEmptyVecIter<'_, T> {
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

impl<T> ExactSizeIterator for NonEmptyVecIter<'_, T> {
    fn len(&self) -> usize {
        self.tail.len() + self.head.map_or(0, |_| 1)
    }
}

impl<T> std::iter::FusedIterator for NonEmptyVecIter<'_, T> {}

impl<T> NonEmptyVec<T> {
    /// Alias for [`NonEmptyVec::singleton`].
    pub const fn new(e: T) -> Self {
        Self::singleton(e)
    }

    /// Converts from `&NonEmptyVec<T>` to `NonEmptyVec<&T>`.
    pub fn as_ref(&self) -> NonEmptyVec<&T> {
        NonEmptyVec {
            head: &self.head,
            tail: self.tail.iter().collect(),
        }
    }

    /// Attempt to convert an iterator into a `NonEmptyVec` vector.
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
    pub const fn singleton(head: T) -> Self {
        Self {
            head,
            tail: Vec::new(),
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
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let mut non_empty = NonEmptyVec::new(42);
    /// let head = non_empty.first_mut();
    /// *head += 1;
    /// assert_eq!(non_empty.first(), &43);
    ///
    /// let mut non_empty = NonEmptyVec::from((1, vec![4, 2, 3]));
    /// let head = non_empty.first_mut();
    /// *head *= 42;
    /// assert_eq!(non_empty.first(), &42);
    /// ```
    pub fn first_mut(&mut self) -> &mut T {
        &mut self.head
    }

    /// Get the possibly-empty tail of the list.
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::new(42);
    /// assert_eq!(non_empty.tail(), &[]);
    ///
    /// let non_empty = NonEmptyVec::from((1, vec![4, 2, 3]));
    /// assert_eq!(non_empty.tail(), &[4, 2, 3]);
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let mut non_empty = NonEmptyVec::from((1, vec![2, 3]));
    /// non_empty.insert(1, 4);
    /// assert_eq!(non_empty, NonEmptyVec::from((1, vec![4, 2, 3])));
    /// non_empty.insert(4, 5);
    /// assert_eq!(non_empty, NonEmptyVec::from((1, vec![4, 2, 3, 5])));
    /// non_empty.insert(0, 42);
    /// assert_eq!(non_empty, NonEmptyVec::from((42, vec![1, 4, 2, 3, 5])));
    /// ```
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
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let mut l = NonEmptyVec::from((42, vec![36, 58]));
    ///
    /// assert!(l.contains(&42));
    /// assert!(!l.contains(&101));
    /// ```
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

    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let mut l = NonEmptyVec::from((42, vec![36, 58]));
    ///
    /// let mut l_iter = l.iter();
    ///
    /// assert_eq!(l_iter.len(), 3);
    /// assert_eq!(l_iter.next(), Some(&42));
    /// assert_eq!(l_iter.next(), Some(&36));
    /// assert_eq!(l_iter.next(), Some(&58));
    /// assert_eq!(l_iter.next(), None);
    /// ```
    pub fn iter(&self) -> NonEmptyVecIter<'_, T> {
        NonEmptyVecIter {
            head: Some(&self.head),
            tail: &self.tail,
        }
    }

    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let mut l = NonEmptyVec::new(42);
    /// l.push(36);
    /// l.push(58);
    ///
    /// for i in l.iter_mut() {
    ///     *i *= 10;
    /// }
    ///
    /// let mut l_iter = l.iter();
    ///
    /// assert_eq!(l_iter.next(), Some(&420));
    /// assert_eq!(l_iter.next(), Some(&360));
    /// assert_eq!(l_iter.next(), Some(&580));
    /// assert_eq!(l_iter.next(), None);
    /// ```
    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut T> + '_ {
        iter::once(&mut self.head).chain(self.tail.iter_mut())
    }

    /// Often we have a `Vec` (or slice `&[T]`) but want to ensure that it is `NonEmptyVec` before
    /// proceeding with a computation. Using `from_slice` will give us a proof
    /// that we have a `NonEmptyVec` in the `Some` branch, otherwise it allows
    /// the caller to handle the `None` case.
    ///
    /// # Example Use
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty_vec = NonEmptyVec::from_slice(&[1, 2, 3, 4, 5]);
    /// assert_eq!(non_empty_vec, Some(NonEmptyVec::from((1, vec![2, 3, 4, 5]))));
    ///
    /// let empty_vec: Option<NonEmptyVec<&u32>> = NonEmptyVec::from_slice(&[]);
    /// assert!(empty_vec.is_none());
    /// ```
    pub fn from_slice(slice: &[T]) -> Option<Self>
    where
        T: Clone,
    {
        slice.split_first().map(|(h, t)| Self {
            head: h.clone(),
            tail: t.into(),
        })
    }

    /// Often we have a `Vec` (or slice `&[T]`) but want to ensure that it is `NonEmptyVec` before
    /// proceeding with a computation. Using `from_vec` will give us a proof
    /// that we have a `NonEmptyVec` in the `Some` branch, otherwise it allows
    /// the caller to handle the `None` case.
    ///
    /// This version will consume the `Vec` you pass in. If you would rather pass the data as a
    /// slice then use `NonEmptyVec::from_slice`.
    ///
    /// # Example Use
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty_vec = NonEmptyVec::from_vec(vec![1, 2, 3, 4, 5]);
    /// assert_eq!(non_empty_vec, Some(NonEmptyVec::from((1, vec![2, 3, 4, 5]))));
    ///
    /// let empty_vec: Option<NonEmptyVec<&u32>> = NonEmptyVec::from_vec(vec![]);
    /// assert!(empty_vec.is_none());
    /// ```
    #[must_use]
    pub fn from_vec(mut vec: Vec<T>) -> Option<Self> {
        if vec.is_empty() {
            None
        } else {
            let head = vec.remove(0);
            Some(Self { head, tail: vec })
        }
    }

    /// Deconstruct a `NonEmptyVec` into its head and tail.
    /// This operation never fails since we are guaranteed
    /// to have a head element.
    ///
    /// # Example Use
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let mut non_empty = NonEmptyVec::from((1, vec![2, 3, 4, 5]));
    ///
    /// // Guaranteed to have the head and we also get the tail.
    /// assert_eq!(non_empty.split_first(), (&1, &[2, 3, 4, 5][..]));
    ///
    /// let non_empty = NonEmptyVec::new(1);
    ///
    /// // Guaranteed to have the head element.
    /// assert_eq!(non_empty.split_first(), (&1, &[][..]));
    /// ```
    pub fn split_first(&self) -> (&T, &[T]) {
        (&self.head, &self.tail)
    }

    /// Deconstruct a `NonEmptyVec` into its first, last, and
    /// middle elements, in that order.
    ///
    /// If there is only one element then last is `None`.
    ///
    /// # Example Use
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let mut non_empty = NonEmptyVec::from((1, vec![2, 3, 4, 5]));
    ///
    /// // When there are two or more elements, the last element is represented
    /// // as a `Some`. Elements preceding it, except for the first, are returned
    /// // in the middle.
    /// assert_eq!(non_empty.split(), (&1, &[2, 3, 4][..], Some(&5)));
    ///
    /// let non_empty = NonEmptyVec::new(1);
    ///
    /// // The last element is `None` when there's only one element.
    /// assert_eq!(non_empty.split(), (&1, &[][..], None));
    /// ```
    pub fn split(&self) -> (&T, &[T], Option<&T>) {
        match self.tail.split_last() {
            None => (&self.head, &[], None),
            Some((last, middle)) => (&self.head, middle, Some(last)),
        }
    }

    /// Append a `Vec` to the tail of the `NonEmptyVec`.
    ///
    /// # Example Use
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let mut non_empty = NonEmptyVec::new(1);
    /// let mut vec = vec![2, 3, 4, 5];
    /// non_empty.append(&mut vec);
    ///
    /// let mut expected = NonEmptyVec::from((1, vec![2, 3, 4, 5]));
    ///
    /// assert_eq!(non_empty, expected);
    /// ```
    pub fn append(&mut self, other: &mut Vec<T>) {
        self.tail.append(other)
    }

    /// A structure preserving `map`. This is useful for when
    /// we wish to keep the `NonEmptyVec` structure guaranteeing
    /// that there is at least one element. Otherwise, we can
    /// use `non_empty_vec.iter().map(f)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::from((1, vec![2, 3, 4, 5]));
    ///
    /// let squares = non_empty.map(|i| i * i);
    ///
    /// let expected = NonEmptyVec::from((1, vec![4, 9, 16, 25]));
    ///
    /// assert_eq!(squares, expected);
    /// ```
    pub fn map<U, F>(self, mut f: F) -> NonEmptyVec<U>
    where
        F: FnMut(T) -> U,
    {
        NonEmptyVec {
            head: f(self.head),
            tail: self.tail.into_iter().map(f).collect(),
        }
    }

    /// A structure preserving, fallible mapping function.
    pub fn try_map<E, U, F>(self, mut f: F) -> Result<NonEmptyVec<U>, E>
    where
        F: FnMut(T) -> Result<U, E>,
    {
        Ok(NonEmptyVec {
            head: f(self.head)?,
            tail: self.tail.into_iter().map(f).collect::<Result<_, _>>()?,
        })
    }

    /// When we have a function that goes from some `T` to a `NonEmptyVec<U>`,
    /// we may want to apply it to a `NonEmptyVec<T>` but keep the structure flat.
    /// This is where `flat_map` shines.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::from((1, vec![2, 3, 4, 5]));
    ///
    /// let windows = non_empty.flat_map(|i| {
    ///     let mut next = NonEmptyVec::new(i + 5);
    ///     next.push(i + 6);
    ///     next
    /// });
    ///
    /// let expected = NonEmptyVec::from((6, vec![7, 7, 8, 8, 9, 9, 10, 10, 11]));
    ///
    /// assert_eq!(windows, expected);
    /// ```
    pub fn flat_map<U, F>(self, mut f: F) -> NonEmptyVec<U>
    where
        F: FnMut(T) -> NonEmptyVec<U>,
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

    /// Flatten nested `NonEmptyVec`s into a single one.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::from((
    ///     NonEmptyVec::from((1, vec![2, 3])),
    ///     vec![NonEmptyVec::from((4, vec![5]))],
    /// ));
    ///
    /// let expected = NonEmptyVec::from((1, vec![2, 3, 4, 5]));
    ///
    /// assert_eq!(NonEmptyVec::flatten(non_empty), expected);
    /// ```
    pub fn flatten(full: NonEmptyVec<Self>) -> Self {
        full.flat_map(|n| n)
    }

    /// Binary searches this sorted non-empty vector for a given element.
    ///
    /// If the value is found then Result::Ok is returned, containing the index of the matching element.
    /// If there are multiple matches, then any one of the matches could be returned.
    ///
    /// If the value is not found then Result::Err is returned, containing the index where a
    /// matching element could be inserted while maintaining sorted order.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::from((0, vec![1, 1, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55]));
    /// assert_eq!(non_empty.binary_search(&0),   Ok(0));
    /// assert_eq!(non_empty.binary_search(&13),  Ok(9));
    /// assert_eq!(non_empty.binary_search(&4),   Err(7));
    /// assert_eq!(non_empty.binary_search(&100), Err(13));
    /// let r = non_empty.binary_search(&1);
    /// assert!(match r { Ok(1..=4) => true, _ => false, });
    /// ```
    ///
    /// If you want to insert an item to a sorted non-empty vector, while maintaining sort order:
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let mut non_empty = NonEmptyVec::from((0, vec![1, 1, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55]));
    /// let num = 42;
    /// let idx = non_empty.binary_search(&num).unwrap_or_else(|x| x);
    /// non_empty.insert(idx, num);
    /// assert_eq!(non_empty, NonEmptyVec::from((0, vec![1, 1, 1, 1, 2, 3, 5, 8, 13, 21, 34, 42, 55])));
    /// ```
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
    ///
    /// # Examples
    ///
    /// Looks up a series of four elements. The first is found, with a uniquely determined
    /// position; the second and third are not found; the fourth could match any position in `[1,4]`.
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::from((0, vec![1, 1, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55]));
    /// let seek = 0;
    /// assert_eq!(non_empty.binary_search_by(|probe| probe.cmp(&seek)), Ok(0));
    /// let seek = 13;
    /// assert_eq!(non_empty.binary_search_by(|probe| probe.cmp(&seek)), Ok(9));
    /// let seek = 4;
    /// assert_eq!(non_empty.binary_search_by(|probe| probe.cmp(&seek)), Err(7));
    /// let seek = 100;
    /// assert_eq!(non_empty.binary_search_by(|probe| probe.cmp(&seek)), Err(13));
    /// let seek = 1;
    /// let r = non_empty.binary_search_by(|probe| probe.cmp(&seek));
    /// assert!(match r { Ok(1..=4) => true, _ => false, });
    /// ```
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
    ///
    /// # Examples
    ///
    /// Looks up a series of four elements in a non-empty vector of pairs sorted by their second elements.
    /// The first is found, with a uniquely determined position; the second and third are not found;
    /// the fourth could match any position in [1, 4].
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::from((
    ///     (0, 0),
    ///     vec![(2, 1), (4, 1), (5, 1), (3, 1),
    ///          (1, 2), (2, 3), (4, 5), (5, 8), (3, 13),
    ///          (1, 21), (2, 34), (4, 55)]
    /// ));
    ///
    /// assert_eq!(non_empty.binary_search_by_key(&0, |&(a,b)| b),  Ok(0));
    /// assert_eq!(non_empty.binary_search_by_key(&13, |&(a,b)| b),  Ok(9));
    /// assert_eq!(non_empty.binary_search_by_key(&4, |&(a,b)| b),   Err(7));
    /// assert_eq!(non_empty.binary_search_by_key(&100, |&(a,b)| b), Err(13));
    /// let r = non_empty.binary_search_by_key(&1, |&(a,b)| b);
    /// assert!(match r { Ok(1..=4) => true, _ => false, });
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::new(42);
    /// assert_eq!(non_empty.maximum(), &42);
    ///
    /// let non_empty = NonEmptyVec::from((1, vec![-34, 42, 76, 4, 5]));
    /// assert_eq!(non_empty.maximum(), &76);
    /// ```
    pub fn maximum(&self) -> &T
    where
        T: Ord,
    {
        self.maximum_by(|i, j| i.cmp(j))
    }

    /// Returns the minimum element in the non-empty vector.
    ///
    /// This will return the first item in the vector if the tail is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::new(42);
    /// assert_eq!(non_empty.minimum(), &42);
    ///
    /// let non_empty = NonEmptyVec::from((1, vec![-34, 42, 76, 4, 5]));
    /// assert_eq!(non_empty.minimum(), &-34);
    /// ```
    pub fn minimum(&self) -> &T
    where
        T: Ord,
    {
        self.minimum_by(|i, j| i.cmp(j))
    }

    /// Returns the element that gives the maximum value with respect to the specified comparison function.
    ///
    /// This will return the first item in the vector if the tail is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::new((0, 42));
    /// assert_eq!(non_empty.maximum_by(|(k, _), (l, _)| k.cmp(l)), &(0, 42));
    ///
    /// let non_empty = NonEmptyVec::from(((2, 1), vec![(2, -34), (4, 42), (0, 76), (1, 4), (3, 5)]));
    /// assert_eq!(non_empty.maximum_by(|(k, _), (l, _)| k.cmp(l)), &(4, 42));
    /// ```
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
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::new((0, 42));
    /// assert_eq!(non_empty.minimum_by(|(k, _), (l, _)| k.cmp(l)), &(0, 42));
    ///
    /// let non_empty = NonEmptyVec::from(((2, 1), vec![(2, -34), (4, 42), (0, 76), (1, 4), (3, 5)]));
    /// assert_eq!(non_empty.minimum_by(|(k, _), (l, _)| k.cmp(l)), &(0, 76));
    /// ```
    pub fn minimum_by<F>(&self, mut compare: F) -> &T
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        self.maximum_by(|a, b| compare(a, b).reverse())
    }

    /// Returns the element that gives the maximum value with respect to the specified function.
    ///
    /// This will return the first item in the vector if the tail is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::new((0, 42));
    /// assert_eq!(non_empty.maximum_by_key(|(k, _)| *k), &(0, 42));
    ///
    /// let non_empty = NonEmptyVec::from(((2, 1), vec![(2, -34), (4, 42), (0, 76), (1, 4), (3, 5)]));
    /// assert_eq!(non_empty.maximum_by_key(|(k, _)| *k), &(4, 42));
    /// assert_eq!(non_empty.maximum_by_key(|(k, _)| -k), &(0, 76));
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::new((0, 42));
    /// assert_eq!(non_empty.minimum_by_key(|(k, _)| *k), &(0, 42));
    ///
    /// let non_empty = NonEmptyVec::from(((2, 1), vec![(2, -34), (4, 42), (0, 76), (1, 4), (3, 5)]));
    /// assert_eq!(non_empty.minimum_by_key(|(k, _)| *k), &(0, 76));
    /// assert_eq!(non_empty.minimum_by_key(|(k, _)| -k), &(4, 42));
    /// ```
    pub fn minimum_by_key<U, F>(&self, mut f: F) -> &T
    where
        U: Ord,
        F: FnMut(&T) -> U,
    {
        self.minimum_by(|i, j| f(i).cmp(&f(j)))
    }

    /// Sorts the [`NonEmptyVec`].
    ///
    /// The implementation uses [`slice::sort`](slice::sort) for the tail and then checks where the
    /// head belongs. If the head is already the smallest element, this should be as fast as sorting a
    /// slice. However, if the head needs to be inserted, then it incurs extra cost for removing
    /// the new head from the tail and adding the old head at the correct index.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::non_empty_vec;
    ///
    /// let mut non_empty = non_empty_vec![-5, 4, 1, -3, 2];
    ///
    /// non_empty.sort();
    /// assert!(non_empty == non_empty_vec![-5, -3, 1, 2, 4]);
    /// ```
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

    /// Sorts the [`NonEmptyVec`] with a comparator function.
    ///
    /// The implementation uses [`slice::sort_by`](slice::sort_by) for the tail and then checks where
    /// the head belongs. If the head is already the smallest element, this should be as fast as sorting
    /// a slice. However, if the head needs to be inserted, then it incurs extra cost for removing the
    /// new head from the tail and adding the old head at the correct index.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::non_empty_vec;
    ///
    /// let mut non_empty = non_empty_vec![-5, 4, 1, -3, 2];
    ///
    /// non_empty.sort_by(|a, b| a.cmp(b));
    /// assert!(non_empty == non_empty_vec![-5, -3, 1, 2, 4]);
    /// ```
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

    /// Sorts the [`NonEmptyVec`] with a key extraction function.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::non_empty_vec;
    ///
    /// let mut non_empty = non_empty_vec!["bbb", "a", "cccc"];
    ///
    /// non_empty.sort_by_key(|s| s.len());
    /// assert!(non_empty == non_empty_vec!["a", "bbb", "cccc"]);
    /// ```
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

    /// Sorts the [`NonEmptyVec`] with a key extraction function, caching the keys.
    ///
    /// The implementation uses [`slice::sort_by_cached_key`](slice::sort_by_cached_key)
    /// for the tail and then determines where the head belongs using the cached head key.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::non_empty_vec;
    ///
    /// let mut non_empty = non_empty_vec!["bbb", "a", "cccc"];
    ///
    /// non_empty.sort_by_cached_key(|s| s.len());
    /// assert!(non_empty == non_empty_vec!["a", "bbb", "cccc"]);
    /// ```
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

impl<T: Default> Default for NonEmptyVec<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> From<NonEmptyVec<T>> for Vec<T> {
    /// Turns a non-empty list into a Vec.
    fn from(non_empty_vec: NonEmptyVec<T>) -> Self {
        iter::once(non_empty_vec.head)
            .chain(non_empty_vec.tail)
            .collect()
    }
}

impl<T> From<NonEmptyVec<T>> for (T, Vec<T>) {
    /// Turns a non-empty list into a Vec.
    fn from(non_empty_vec: NonEmptyVec<T>) -> (T, Vec<T>) {
        (non_empty_vec.head, non_empty_vec.tail)
    }
}

impl<T> From<(T, Vec<T>)> for NonEmptyVec<T> {
    /// Turns a pair of an element and a Vec into
    /// a NonEmptyVec.
    fn from((head, tail): (T, Vec<T>)) -> Self {
        Self { head, tail }
    }
}

impl<T> IntoIterator for NonEmptyVec<T> {
    type Item = T;
    type IntoIter = iter::Chain<iter::Once<T>, vec::IntoIter<Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        iter::once(self.head).chain(self.tail)
    }
}

impl<'a, T> IntoIterator for &'a NonEmptyVec<T> {
    type Item = &'a T;
    type IntoIter = iter::Chain<iter::Once<&'a T>, std::slice::Iter<'a, T>>;

    fn into_iter(self) -> Self::IntoIter {
        iter::once(&self.head).chain(self.tail.iter())
    }
}

impl<T> std::ops::Index<usize> for NonEmptyVec<T> {
    type Output = T;

    /// ```
    /// use rama_utils::collections::NonEmptyVec;
    ///
    /// let non_empty = NonEmptyVec::from((1, vec![2, 3, 4, 5]));
    ///
    /// assert_eq!(non_empty[0], 1);
    /// assert_eq!(non_empty[1], 2);
    /// assert_eq!(non_empty[3], 4);
    /// ```
    fn index(&self, index: usize) -> &T {
        if index > 0 {
            &self.tail[index - 1]
        } else {
            &self.head
        }
    }
}

impl<T> std::ops::IndexMut<usize> for NonEmptyVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        if index > 0 {
            &mut self.tail[index - 1]
        } else {
            &mut self.head
        }
    }
}

impl<A> Extend<A> for NonEmptyVec<A> {
    fn extend<T: IntoIterator<Item = A>>(&mut self, iter: T) {
        self.tail.extend(iter)
    }
}

impl<T> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = NonEmptyVecEmptyError;

    fn try_from(vec: Vec<T>) -> Result<Self, Self::Error> {
        Self::from_vec(vec).ok_or(NonEmptyVecEmptyError)
    }
}

crate::macros::error::static_str_error! {
    #[doc = "empty value cannot be turned into a NonEmptyVec"]
    pub struct NonEmptyVecEmptyError;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collections::non_empty_vec;
    use std::string::String;

    #[test]
    fn test_from_conversion() {
        let result = NonEmptyVec::from((1, vec![2, 3, 4, 5]));
        let expected = NonEmptyVec {
            head: 1,
            tail: vec![2, 3, 4, 5],
        };
        assert_eq!(result, expected);
    }

    #[test]
    fn test_into_iter() {
        let non_empty_vec = NonEmptyVec::from((0, vec![1, 2, 3]));
        for (i, n) in non_empty_vec.into_iter().enumerate() {
            assert_eq!(i as i32, n);
        }
    }

    #[test]
    fn test_iter_syntax() {
        let non_empty_vec = NonEmptyVec::from((0, vec![1, 2, 3]));
        for n in &non_empty_vec {
            let _ = *n; // Prove that we're dealing with references.
        }
        for _ in non_empty_vec {}
    }

    #[test]
    fn test_iter_both_directions() {
        let mut non_empty_vec = NonEmptyVec::from((0, vec![1, 2, 3]));
        assert_eq!(
            non_empty_vec.iter().cloned().collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(
            non_empty_vec.iter().rev().cloned().collect::<Vec<_>>(),
            [3, 2, 1, 0]
        );
        assert_eq!(
            non_empty_vec.iter_mut().rev().collect::<Vec<_>>(),
            [&mut 3, &mut 2, &mut 1, &mut 0]
        );
    }

    #[test]
    fn test_iter_both_directions_at_once() {
        let non_empty_vec = NonEmptyVec::from((0, vec![1, 2, 3]));
        let mut i = non_empty_vec.iter();
        assert_eq!(i.next(), Some(&0));
        assert_eq!(i.next_back(), Some(&3));
        assert_eq!(i.next(), Some(&1));
        assert_eq!(i.next_back(), Some(&2));
        assert_eq!(i.next(), None);
        assert_eq!(i.next_back(), None);
    }

    #[test]
    fn test_mutate_head() {
        let mut non_empty = NonEmptyVec::new(42);
        non_empty.head += 1;
        assert_eq!(non_empty.head, 43);

        let mut non_empty = NonEmptyVec::from((1, vec![4, 2, 3]));
        non_empty.head *= 42;
        assert_eq!(non_empty.head, 42);
    }

    #[test]
    fn test_to_nonempty() {
        use std::iter::{empty, once};

        assert_eq!(NonEmptyVec::<()>::collect(empty()), None);
        assert_eq!(
            NonEmptyVec::<()>::collect(once(())),
            Some(NonEmptyVec::new(()))
        );
        assert_eq!(
            NonEmptyVec::<u8>::collect(once(1).chain(once(2))),
            Some(non_empty_vec!(1, 2))
        );
    }

    #[test]
    fn test_try_map() {
        assert_eq!(
            non_empty_vec!(1, 2, 3, 4).try_map(Ok::<_, String>),
            Ok(non_empty_vec!(1, 2, 3, 4))
        );
        assert_eq!(
            non_empty_vec!(1, 2, 3, 4).try_map(|i| if i % 2 == 0 {
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
        let positions = non_empty_vec![
            Position { x: 1, y: 1 },
            Position { x: 0, y: 0 },
            Position { x: 3, y: 4 }
        ];
        let target = Position { x: 1, y: 2 };
        let closest = positions.minimum_by_key(|position| position.distance_squared(target));
        assert_eq!(closest, &Position { x: 1, y: 1 });
    }

    #[test]
    fn test_sort() {
        let mut numbers = non_empty_vec![1];
        numbers.sort();
        assert_eq!(numbers, non_empty_vec![1]);

        let mut numbers = non_empty_vec![2, 1, 3];
        numbers.sort();
        assert_eq!(numbers, non_empty_vec![1, 2, 3]);

        let mut numbers = non_empty_vec![1, 3, 2];
        numbers.sort();
        assert_eq!(numbers, non_empty_vec![1, 2, 3]);

        let mut numbers = non_empty_vec![3, 2, 1];
        numbers.sort();
        assert_eq!(numbers, non_empty_vec![1, 2, 3]);
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct SimpleSerializable(pub i32);

    #[test]
    fn test_simple_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        // Given
        let mut non_empty = NonEmptyVec::new(SimpleSerializable(42));
        non_empty.push(SimpleSerializable(777));

        // When
        let res = serde_json::from_str::<'_, NonEmptyVec<SimpleSerializable>>(
            &serde_json::to_string(&non_empty)?,
        )?;

        // Then
        assert_eq!(res, non_empty);

        Ok(())
    }

    #[test]
    fn test_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let ne = non_empty_vec![1, 2, 3, 4, 5];
        let ve = vec![1, 2, 3, 4, 5];

        assert_eq!(serde_json::to_string(&ne)?, serde_json::to_string(&ve)?);

        Ok(())
    }
}
