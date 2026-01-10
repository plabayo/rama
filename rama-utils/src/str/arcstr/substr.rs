#![allow(
    // We follow libstd's lead and prefer to define both.
    clippy::partialeq_ne_impl,
    // This is a really annoying clippy lint, since it's required for so many cases...
    clippy::cast_ptr_alignment,
    // For macros
    clippy::redundant_slicing,
)]

use std::ops::{Range, RangeBounds};

use super::ArcStr;

type Idx = usize;

#[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
compile_error!(
    "Non-32/64-bit pointers not supported right now due to insufficient \
    testing on a platform like that. Please file a issue with the \
    `rama` project so we can talk about your use case if this is \
    important to you."
);

/// A low-cost string type representing a view into an [`ArcStr`].
///
/// Conceptually this is `(ArcStr, Range<usize>)` with ergonomic helpers. In
/// implementation, the only difference between it and that is that the index
/// type is `u32` unless the `substr-usize-indices` feature is enabled, which
/// makes them use `usize`.
///
/// # Examples
///
/// ```
/// use rama_utils::str::arcstr::{ArcStr, Substr};
/// let parent = ArcStr::from("foo   bar");
/// // The main way to create a Substr is with `ArcStr::substr`.
/// let substr: Substr = parent.substr(3..);
/// assert_eq!(substr, "   bar");
/// // You can use `try_substr_using` to try to turn a function which is
/// // `&str => &str` into a function over `Substr => Substr`.
/// // See also `substr_from`, `try_substr_{from,using}`, and
/// // the functions with the same name on `ArcStr`.
/// let trimmed = substr.try_substr_using(str::trim).unwrap();
/// assert_eq!(trimmed, "bar");
/// ```
///
/// # Caveats
///
/// The main caveat is the bit about index types. The index type is u32 by
/// default. You can turn on `substr-usize-indices` if you desire though. The
/// feature doesn't change the public API at all, just makes it able to handle
/// enormous strings without panicking. This seems very niche to me, though.
#[derive(Clone)]
#[repr(C)] // We mentioned ArcStr being good at FFI at some point so why not
pub struct Substr(ArcStr, Idx, Idx);

#[inline]
#[cfg(target_pointer_width = "64")]
#[allow(clippy::let_unit_value)]
const fn to_idx_const(i: usize) -> Idx {
    const DUMMY: [(); 1] = [()];
    let _ = DUMMY[i >> 32];
    i as Idx
}
#[inline]
#[cfg(not(target_pointer_width = "64"))]
const fn to_idx_const(i: usize) -> Idx {
    i as Idx
}

#[inline]
#[cfg(target_pointer_width = "64")]
fn to_idx(i: usize) -> Idx {
    if i > 0xffff_ffff {
        index_overflow(i);
    }
    i as Idx
}

#[inline]
#[cfg(not(target_pointer_width = "64"))]
fn to_idx(i: usize) -> Idx {
    i as Idx
}

#[cold]
#[inline(never)]
#[cfg(target_pointer_width = "64")]
fn index_overflow(i: usize) -> ! {
    panic!(
        "The index {i} is too large for arcstr::Substr (enable the `substr-usize-indices` feature in `arcstr` if you need this)"
    );
}
#[cold]
#[inline(never)]
fn bad_substr_idx(s: &ArcStr, i: usize, e: usize) -> ! {
    assert!(i <= e, "Bad substr range: start {i} must be <= end {e}");
    let max = if cfg!(target_pointer_width = "64",) {
        u32::MAX as usize
    } else {
        usize::MAX
    };
    let len = s.len().min(max);
    assert!(
        e <= len,
        "Bad substr range: end {e} must be <= string length/index max size {len}"
    );
    assert!(
        s.is_char_boundary(i) && s.is_char_boundary(e),
        "Bad substr range: start and end must be on char boundaries"
    );
    unreachable!(
        "[arcstr bug]: should have failed one of the above tests: \
                  please report me. debugging info: b={}, e={}, l={}, max={:#x}",
        i,
        e,
        s.len(),
        max
    );
}

impl Substr {
    /// Construct an empty substr.
    ///
    /// # Examples
    /// ```
    /// # use rama_utils::str::arcstr::Substr;
    /// let s = Substr::new();
    /// assert_eq!(s, "");
    /// ```
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self(ArcStr::new(), 0, 0)
    }

    /// Construct a Substr over the entire ArcStr.
    ///
    /// This is also provided as `Substr::from(some_arcstr)`, and can be
    /// accomplished with `a.substr(..)`, `a.into_substr(..)`, ...
    ///
    /// # Examples
    /// ```
    /// # use rama_utils::str::arcstr::{Substr, ArcStr};
    /// let s = Substr::full(ArcStr::from("foo"));
    /// assert_eq!(s, "foo");
    /// assert_eq!(s.range(), 0..3);
    /// ```
    #[inline]
    #[must_use]
    pub fn full(a: ArcStr) -> Self {
        let l = to_idx(a.len());
        Self(a, 0, l)
    }

    #[inline]
    pub(crate) fn from_parts(a: &ArcStr, range: impl RangeBounds<usize>) -> Self {
        use core::ops::Bound;
        let begin = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n + 1,
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(&n) => n + 1,
            Bound::Excluded(&n) => n,
            Bound::Unbounded => a.len(),
        };
        let _ = &a.as_str()[begin..end];

        Self(ArcStr::clone(a), to_idx(begin), to_idx(end))
    }

    /// Extract a substr of this substr.
    ///
    /// If the result would be empty, a new strong reference to our parent is
    /// not created.
    ///
    /// # Examples
    /// ```
    /// # use rama_utils::str::arcstr::{Substr, arcstr};
    /// let s: Substr = arcstr!("foobarbaz").substr(3..);
    /// assert_eq!(s.as_str(), "barbaz");
    ///
    /// let s2 = s.substr(1..5);
    /// assert_eq!(s2, "arba");
    /// ```
    /// # Panics
    /// If any of the following are untrue, we panic
    /// - `range.start() <= range.end()`
    /// - `range.end() <= self.len()`
    /// - `self.is_char_boundary(start) && self.is_char_boundary(end)`
    /// - These can be conveniently verified in advance using
    ///   `self.get(start..end).is_some()` if needed.
    #[inline]
    #[must_use]
    pub fn substr(&self, range: impl RangeBounds<usize>) -> Self {
        use core::ops::Bound;
        let my_end = self.2;

        let begin = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n + 1,
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(&n) => n + 1,
            Bound::Excluded(&n) => n,
            Bound::Unbounded => self.len(),
        };
        let new_begin = self.1 + begin;
        let new_end = self.1 + end;
        // let _ = &self.0.as_str()[new_begin..new_end];
        if begin > end
            || end > my_end
            || !self.0.is_char_boundary(new_begin)
            || !self.0.is_char_boundary(new_end)
        {
            bad_substr_idx(&self.0, new_begin, new_end);
        }
        debug_assert!(self.0.get(new_begin..new_end).is_some());

        Self(ArcStr::clone(&self.0), new_begin as Idx, new_end as Idx)
    }

    /// Extract a string slice containing our data.
    ///
    /// Note: This is an equivalent to our `Deref` implementation, but can be
    /// more readable than `&*s` in the cases where a manual invocation of
    /// `Deref` would be required.
    ///
    /// # Examples
    /// ```
    /// # use rama_utils::str::arcstr::{Substr, arcstr};
    /// let s: Substr = arcstr!("foobar").substr(3..);
    /// assert_eq!(s.as_str(), "bar");
    /// ```
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        self
    }

    /// Returns the length of this `Substr` in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::{ArcStr, Substr};
    /// let a: Substr = ArcStr::from("foo").substr(1..);
    /// assert_eq!(a.len(), 2);
    /// ```
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        debug_assert!(self.2 >= self.1);
        self.2 - self.1
    }

    /// Returns true if this `Substr` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::{Substr, arcstr};
    /// assert!(arcstr!("abc").substr(3..).is_empty());
    /// assert!(!arcstr!("abc").substr(2..).is_empty());
    /// assert!(Substr::new().is_empty());
    /// ```
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.2 == self.1
    }

    /// Convert us to a `std::string::String`.
    ///
    /// This is provided as an inherent method to avoid needing to route through
    /// the `Display` machinery, but is equivalent to `ToString::to_string`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::{Substr, arcstr};
    /// let s: Substr = arcstr!("12345").substr(1..4);
    /// assert_eq!(s.to_string(), "234");
    /// ```
    #[inline]
    #[allow(clippy::inherent_to_string_shadow_display)]
    #[must_use]
    pub fn to_string(&self) -> std::string::String {
        self.as_str().to_owned()
    }

    /// Unchecked function to construct a [`Substr`] from an [`ArcStr`] and a
    /// byte range. Direct usage of this function is largely discouraged in
    /// favor of [`ArcStr::substr`].
    ///
    /// This is unsafe because currently `ArcStr` cannot provide a `&str` in a
    /// `const fn`. If that changes then we will likely deprecate this function,
    /// and provide a `pub const fn from_parts` with equivalent functionality.
    ///
    /// In the distant future, it would be nice if this accepted other kinds of
    /// ranges too.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::{ArcStr, Substr, arcstr};
    /// const FOOBAR: ArcStr = arcstr!("foobar");
    /// const OBA: Substr = unsafe { Substr::from_parts_unchecked(FOOBAR, 2..5) };
    /// assert_eq!(OBA, "oba");
    /// ```
    // TODO: can I do a compile_fail test that only is a failure under a certain feature?
    ///
    /// # Safety
    /// You promise that `range` is in bounds for `s`, and that the start and
    /// end are both on character boundaries. Note that we do check that the
    /// `usize` indices fit into `u32` if thats our configured index type, so
    /// `_unchecked` is not *entirely* a lie.
    ///
    /// # Panics
    /// If the `substr-usize-indices` is not enabled, and the target arch is
    /// 64-bit, and the usizes do not fit in 32 bits, then we panic with a
    /// (possibly strange-looking) index-out-of-bounds error in order to force
    /// compilation failure.
    #[inline]
    #[must_use]
    pub const unsafe fn from_parts_unchecked(s: ArcStr, range: Range<usize>) -> Self {
        Self(s, to_idx_const(range.start), to_idx_const(range.end))
    }

    /// Returns `true` if the two `Substr`s have identical parents, and are
    /// covering the same range.
    ///
    /// Note that the "identical"ness of parents is determined by
    /// [`ArcStr::ptr_eq`], which can have surprising/nondeterministic results
    /// when used on `const` `ArcStr`s. It is guaranteed that `Substr::clone()`s
    /// will be `shallow_eq` eachother, however.
    ///
    /// This should generally only be used as an optimization, or a debugging
    /// aide. Additionally, it is already used in the implementation of
    /// `PartialEq`, so optimizing a comparison by performing it first is
    /// generally unnecessary.
    ///
    /// # Examples
    /// ```
    /// # use rama_utils::str::arcstr::{ArcStr, Substr};
    /// let parent = ArcStr::from("foooo");
    /// let sub1 = parent.substr(1..3);
    /// let sub2 = parent.substr(1..3);
    /// assert!(Substr::shallow_eq(&sub1, &sub2));
    /// // Same parent *and* contents, but over a different range: not `shallow_eq`.
    /// let not_same = parent.substr(3..);
    /// assert!(!Substr::shallow_eq(&sub1, &not_same));
    /// ```
    #[inline]
    #[must_use]
    pub fn shallow_eq(this: &Self, o: &Self) -> bool {
        ArcStr::ptr_eq(&this.0, &o.0) && (this.1 == o.1) && (this.2 == o.2)
    }

    /// Returns the ArcStr this is a substring of.
    ///
    /// Note that the exact pointer value of this can be somewhat
    /// nondeterministic when used with `const` `ArcStr`s. For example
    ///
    /// ```rust,ignore
    /// use rama_utils::str::arcstr::{ArcStr, arcstr};
    /// const FOO: ArcStr = arcstr!("foo");
    /// // This is non-deterministic, as all references to a given
    /// // const are not required to point to the same value.
    /// ArcStr::ptr_eq(FOO.substr(..).parent(), &FOO);
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let parent = ArcStr::from("abc def");
    /// let child = parent.substr(2..5);
    /// assert!(ArcStr::ptr_eq(&parent, child.parent()));
    ///
    /// let child = parent.substr(..);
    /// assert_eq!(child.range(), 0..7);
    /// ```
    #[inline]
    #[must_use]
    pub fn parent(&self) -> &ArcStr {
        &self.0
    }

    /// Returns the range of bytes we occupy inside our parent.
    ///
    /// This range is always guaranteed to:
    ///
    /// - Have an end >= start.
    /// - Have both start and end be less than or equal to `self.parent().len()`
    /// - Have both start and end be on meet `self.parent().is_char_boundary(b)`
    ///
    /// To put another way, it's always sound to do
    /// `s.parent().get_unchecked(s.range())`.
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let parent = ArcStr::from("abc def");
    /// let child = parent.substr(2..5);
    /// assert_eq!(child.range(), 2..5);
    ///
    /// let child = parent.substr(..);
    /// assert_eq!(child.range(), 0..7);
    /// ```
    #[inline]
    #[must_use]
    pub fn range(&self) -> Range<usize> {
        self.1..self.2
    }

    /// If possible, returns a [`Substr`] of self over the given `&str`.
    ///
    /// It is not rare to end up with a `&str` which holds a view into a
    /// `ArcStr`'s backing data. A common case is when using functionality that
    /// takes and returns `&str` and are entirely unaware of `arcstr`, for
    /// example: `str::trim()`.
    ///
    /// This function allows you to reconstruct a [`Substr`] from a `&str` which
    /// is a view into this [`Substr`]'s backing string. Note that we accept the
    /// empty string as input, in which case we return the same value as
    /// [`Substr::new`] (For clarity, this no longer holds a reference to
    /// `self.parent()`).
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::Substr;
    /// let text = Substr::from("   abc");
    /// let trimmed = text.trim();
    /// let substr: Option<Substr> = text.try_substr_from(trimmed);
    /// assert_eq!(substr.unwrap(), "abc");
    /// // `&str`s not derived from `self` will return None.
    /// let not_substr = text.try_substr_from("abc");
    /// assert!(not_substr.is_none());
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `substr` is a view into our memory but is >= `u32::MAX` bytes
    /// away from our start, on a 64-bit machine, when `substr-usize-indices` is
    /// not enabled.
    #[must_use]
    pub fn try_substr_from(&self, substr: &str) -> Option<Self> {
        if substr.is_empty() {
            return Some(Self::new());
        }
        let parent_ptr = self.0.as_ptr() as usize;
        let self_start = parent_ptr + self.1;
        let self_end = parent_ptr + self.2;

        let substr_start = substr.as_ptr() as usize;
        let substr_end = substr_start + substr.len();
        if substr_start < self_start || substr_end > self_end {
            return None;
        }

        let index = substr_start - self_start;
        let end = index + substr.len();
        Some(self.substr(index..end))
    }
    /// Compute a derived `&str` a function of `&str` => `&str`, and produce a
    /// Substr of the result if possible.
    ///
    /// The function may return either a derived string, or any empty string.
    ///
    /// This function is mainly a wrapper around [`Substr::try_substr_from`]. If
    /// you're coming to `arcstr` from the `shared_string` crate, this is the
    /// moral equivalent of the `slice_with` function.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::Substr;
    /// let text = Substr::from("   abc");
    /// let trimmed: Option<Substr> = text.try_substr_using(str::trim);
    /// assert_eq!(trimmed.unwrap(), "abc");
    /// let other = text.try_substr_using(|_s| "different string!");
    /// assert_eq!(other, None);
    /// // As a special case, this is allowed.
    /// let empty = text.try_substr_using(|_s| "");
    /// assert_eq!(empty.unwrap(), "");
    /// ```
    pub fn try_substr_using(&self, f: impl FnOnce(&str) -> &str) -> Option<Self> {
        self.try_substr_from(f(self.as_str()))
    }
}

impl From<ArcStr> for Substr {
    #[inline]
    fn from(a: ArcStr) -> Self {
        Self::full(a)
    }
}

impl From<&ArcStr> for Substr {
    #[inline]
    fn from(a: &ArcStr) -> Self {
        Self::full(a.clone())
    }
}

impl core::ops::Deref for Substr {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        debug_assert!(self.0.get(self.1..self.2).is_some());
        unsafe { self.0.get_unchecked(self.1..self.2) }
    }
}

impl PartialEq for Substr {
    #[inline]
    fn eq(&self, o: &Self) -> bool {
        Self::shallow_eq(self, o) || PartialEq::eq(self.as_str(), o.as_str())
    }
    #[inline]
    fn ne(&self, o: &Self) -> bool {
        !Self::shallow_eq(self, o) && PartialEq::ne(self.as_str(), o.as_str())
    }
}

impl PartialEq<ArcStr> for Substr {
    #[inline]
    fn eq(&self, o: &ArcStr) -> bool {
        (ArcStr::ptr_eq(&self.0, o) && (self.1 == 0) && (self.2 == o.len()))
            || PartialEq::eq(self.as_str(), o.as_str())
    }
    #[inline]
    fn ne(&self, o: &ArcStr) -> bool {
        (!ArcStr::ptr_eq(&self.0, o) || (self.1 != 0) || (self.2 != o.len()))
            && PartialEq::ne(self.as_str(), o.as_str())
    }
}
impl PartialEq<Substr> for ArcStr {
    #[inline]
    fn eq(&self, o: &Substr) -> bool {
        PartialEq::eq(o, self)
    }
    #[inline]
    fn ne(&self, o: &Substr) -> bool {
        PartialEq::ne(o, self)
    }
}

impl Eq for Substr {}

impl PartialOrd for Substr {
    #[inline]
    #[allow(clippy::non_canonical_partial_ord_impl)]
    fn partial_cmp(&self, s: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(s))
    }
}

impl Ord for Substr {
    #[inline]
    fn cmp(&self, s: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(s.as_str())
    }
}

impl core::hash::Hash for Substr {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) {
        self.as_str().hash(h)
    }
}

impl core::fmt::Debug for Substr {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl core::fmt::Display for Substr {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self.as_str(), f)
    }
}

impl Default for Substr {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! impl_from_via_arcstr {
    ($($SrcTy:ty),+) => {$(
        impl From<$SrcTy> for Substr {
            #[inline]
            fn from(v: $SrcTy) -> Self {
                Self::full(ArcStr::from(v))
            }
        }
    )+};
}
impl_from_via_arcstr![
    &str,
    &mut str,
    std::string::String,
    &std::string::String,
    std::boxed::Box<str>,
    std::rc::Rc<str>,
    std::sync::Arc<str>,
    std::borrow::Cow<'_, str>
];

impl<'a> From<&'a Substr> for std::borrow::Cow<'a, str> {
    #[inline]
    fn from(s: &'a Substr) -> Self {
        std::borrow::Cow::Borrowed(s)
    }
}

impl<'a> From<Substr> for std::borrow::Cow<'a, str> {
    #[inline]
    fn from(s: Substr) -> Self {
        if let Some(st) = ArcStr::as_static(&s.0) {
            debug_assert!(st.get(s.range()).is_some());
            std::borrow::Cow::Borrowed(unsafe { st.get_unchecked(s.range()) })
        } else {
            std::borrow::Cow::Owned(s.to_string())
        }
    }
}

macro_rules! impl_peq {
    (@one $a:ty, $b:ty) => {
        #[allow(clippy::extra_unused_lifetimes)]
        impl<'a> PartialEq<$b> for $a {
            #[inline]
            fn eq(&self, s: &$b) -> bool {
                PartialEq::eq(&self[..], &s[..])
            }
            #[inline]
            fn ne(&self, s: &$b) -> bool {
                PartialEq::ne(&self[..], &s[..])
            }
        }
    };
    ($(($a:ty, $b:ty),)+) => {$(
        impl_peq!(@one $a, $b);
        impl_peq!(@one $b, $a);
    )+};
}

impl_peq! {
    (Substr, str),
    (Substr, &'a str),
    (Substr, std::string::String),
    (Substr, std::borrow::Cow<'a, str>),
    (Substr, std::boxed::Box<str>),
    (Substr, std::sync::Arc<str>),
    (Substr, std::rc::Rc<str>),
}

macro_rules! impl_index {
    ($($IdxT:ty,)*) => {$(
        impl core::ops::Index<$IdxT> for Substr {
            type Output = str;
            #[inline]
            fn index(&self, i: $IdxT) -> &Self::Output {
                &self.as_str()[i]
            }
        }
    )*};
}

impl_index! {
    core::ops::RangeFull,
    core::ops::Range<usize>,
    core::ops::RangeFrom<usize>,
    core::ops::RangeTo<usize>,
    core::ops::RangeInclusive<usize>,
    core::ops::RangeToInclusive<usize>,
}

impl AsRef<str> for Substr {
    #[inline]
    fn as_ref(&self) -> &str {
        self
    }
}

impl AsRef<[u8]> for Substr {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::borrow::Borrow<str> for Substr {
    #[inline]
    fn borrow(&self) -> &str {
        self
    }
}

impl core::str::FromStr for Substr {
    type Err = core::convert::Infallible;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(ArcStr::from(s)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    #[should_panic]
    #[cfg(not(miri))] // XXX does miri still hate unwinding?
    #[cfg(target_pointer_width = "64")]
    fn test_from_parts_unchecked_err() {
        let s = crate::str::arcstr::arcstr!("foo");
        // Note: this is actually a violation of the safety requirement of
        // from_parts_unchecked (the indices are illegal), but I can't get an
        // ArcStr that's big enough, and I'm the author so I know it's fine
        // because we hit the panic case.
        let _u = unsafe { Substr::from_parts_unchecked(s, 0x1_0000_0000usize..0x1_0000_0001) };
    }
    #[test]
    fn test_from_parts_unchecked_valid() {
        let s = crate::str::arcstr::arcstr!("foobar");
        let u = unsafe { Substr::from_parts_unchecked(s, 2..5) };
        assert_eq!(&*u, "oba");
    }
}
