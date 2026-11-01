#![expect(
    // We follow libstd's lead and prefer to define both.
    clippy::partialeq_ne_impl,
    // Vendored from upstream `arcstr`: matches stdlib panicking conventions
    // (capacity overflow, layout failure) and uses inner `#[allow]` attributes
    // in the upstream-idiomatic style.
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::allow_attributes,
    reason = "vendored from upstream arcstr; preserve upstream idioms"
)]
use core::alloc::Layout;
use core::mem::{MaybeUninit, align_of, size_of};
use core::ptr::NonNull;
#[cfg(not(all(loom, test)))]
pub(crate) use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(all(loom, test))]
pub(crate) use loom::sync::atomic::{AtomicUsize, Ordering};
use smol_str::SmolStr;

use crate::std::borrow::Cow;
use crate::std::borrow::ToOwned as _;
use crate::std::boxed::Box;
use crate::std::string::String;

use super::Substr;

/// A better atomically-reference counted string type.
///
/// ## Benefits of `ArcStr` over `Arc<str>`
///
/// - It's possible to create a const `ArcStr` from a literal via the
///   [`arcstr!`][crate::str::arcstr::arcstr] macro. This is probably the killer
///   feature, to be honest.
///
///   These "static" `ArcStr`s are zero cost, take no heap allocation, and don't
///   even need to perform atomic reads/writes when being cloned or dropped (nor
///   at any other time).
///
///   They even get stored in the read-only memory of your executable, which can
///   be beneficial for performance and memory usage. (In theory your linker may
///   even dedupe these for you, but usually not)
///
/// - `ArcStr`s from `arcstr!` can be turned into `&'static str` safely
///   at any time using [`ArcStr::as_static`]. (This returns an Option, which is
///   `None` if the `ArcStr` was not static)
///
/// - This should be unsurprising given the literal functionality, but
///   [`ArcStr::new`] is able to be a `const` function.
///
/// - `ArcStr` is thin, e.g. only a single pointer. Great for cases where you
///   want to keep the data structure lightweight or need to do some FFI stuff
///   with it.
///
/// - `ArcStr` is totally immutable. No need to lose sleep because you're afraid
///   of code which thinks it has a right to mutate your `Arc`s just because it
///   holds the only reference...
///
/// - Lower reference counting operations are lower overhead because we don't
///   support `Weak` references. This can be a drawback for some use cases, but
///   improves performance for the common case of no-weak-refs.
///
/// ## What does "zero-cost literals" mean?
///
/// In a few places I call the literal arcstrs "zero-cost". No overhead most
/// accesses accesses (aside from stuff like `as_static` which obviously
/// requires it). and it imposes a extra branch in both `clone` and `drop`.
///
/// This branch in `clone`/`drop` is not on the result of an atomic load, and is
/// just a normal memory read. This is actually what allows literal/static
/// `ArcStr`s to avoid needing to perform any atomic operations in those
/// functions, which seems likely more than cover the cost.
///
/// (Additionally, it's almost certain that in the future we'll be able to
/// reduce the synchronization required for atomic instructions. This is due to
/// our guarantee of immutability and lack of support for `Weak`.)
///
/// # Usage
///
/// ## As a `const`
///
/// The big unique feature of `ArcStr` is the ability to create static/const
/// `ArcStr`s. (See [the macro](crate::str::arcstr::arcstr) docs or the [feature
/// overview][feats]
///
/// [feats]: index.html#feature-overview
///
/// ```
/// # use rama_utils::str::arcstr::{ArcStr, arcstr};
/// const WOW: ArcStr = arcstr!("cool robot!");
/// assert_eq!(WOW, "cool robot!");
/// ```
///
/// ## As a `str`
///
/// (This is not unique to `ArcStr`, but is a frequent source of confusion I've
/// seen): `ArcStr` implements `Deref<Target = str>`, and so all functions and
/// methods from `str` work on it, even though we don't expose them on `ArcStr`
/// directly.
///
/// ```
/// # use rama_utils::str::arcstr::ArcStr;
/// let s = ArcStr::from("something");
/// // These go through `Deref`, so they work even though
/// // there is no `ArcStr::eq_ignore_ascii_case` function
/// assert!(s.eq_ignore_ascii_case("SOMETHING"));
/// ```
///
/// Additionally, `&ArcStr` can be passed to any function which accepts `&str`.
/// For example:
///
/// ```
/// # use rama_utils::str::arcstr::ArcStr;
/// fn accepts_str(s: &str) {
///    # _ = s;
///     // s...
/// }
///
/// let test_str: ArcStr = "test".into();
/// // This works even though `&test_str` is normally an `&ArcStr`
/// accepts_str(&test_str);
///
/// // Of course, this works for functionality from the standard library as well.
/// let test_but_loud = ArcStr::from("TEST");
/// assert!(test_str.eq_ignore_ascii_case(&test_but_loud));
/// ```
#[repr(transparent)]
pub struct ArcStr(
    // Safety invariant: the pointer points to an inner of one of two forms
    // (see `ThinInner` for the count protocol):
    // - static: a `'static StaticArcStrInner<[u8; N]>` whose `len_flag` is
    //   `encode_len(N)` (flag set), whose `count_flag` is `STATIC_COUNT_VALUE`
    //   and whose `data` is valid UTF-8; it is only ever read;
    // - heap: a live global-allocator allocation of
    //   `Layout::from_size_align(len + OFFSET_DATA, 8)` that starts with a
    //   `ThinInner` whose `len_flag` is `(false, len)` and is never written
    //   after allocation, followed by `len` bytes of valid UTF-8 that are never
    //   written after allocation either. This handle owns one unit of the
    //   count, or the count flag is set and the allocation is never freed.
    NonNull<ThinInner>,
);

// SAFETY: an `ArcStr` gives access to immutable bytes (the data and `len_flag`
// are never written after the inner is shared) and to `count_flag`, which is
// only accessed atomically. The allocation is freed only after the acquire
// edge in `Drop` (see `ThinInner`), so every other handle's use of it, on any
// thread, happens-before the free. Nothing in it is tied to a thread.
unsafe impl Sync for ArcStr {}
// SAFETY: see the `Sync` impl; dropping or cloning on another thread uses the
// same atomic count protocol.
unsafe impl Send for ArcStr {}

impl ArcStr {
    /// Construct a new empty string.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let s = ArcStr::new();
    /// assert_eq!(s, "");
    /// ```
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        EMPTY
    }

    /// Attempt to copy the provided string into a newly allocated `ArcStr`, but
    /// return `None` if we cannot allocate the required memory.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    ///
    /// # fn do_stuff_with(s: ArcStr) {}
    ///
    /// let some_big_str = "please pretend this is a very long string";
    /// if let Some(s) = ArcStr::try_alloc(some_big_str) {
    ///     do_stuff_with(s);
    /// } else {
    ///     // Complain about allocation failure, somehow.
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn try_alloc(copy_from: &str) -> Option<Self> {
        if let Ok(inner) = ThinInner::try_allocate(copy_from) {
            // Field invariant: by `try_allocate`'s safety-usable invariant.
            Some(Self(inner))
        } else {
            None
        }
    }

    /// Attempt to allocate memory for an [`ArcStr`] of length `n`, and use the
    /// provided callback to fully initialize the provided buffer with valid
    /// UTF-8 text.
    ///
    /// This function returns `None` if memory allocation fails, see
    /// [`ArcStr::init_with_unchecked`] for a version which calls
    /// [`handle_alloc_error`](std::alloc::handle_alloc_error).
    ///
    /// # Safety
    ///
    /// The caller must ensure that `initializer`, if it returns, has written
    /// valid UTF-8 to all `n` bytes of the buffer it is given. If it unwinds,
    /// the allocation is leaked and nothing else is required.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// # use core::mem::MaybeUninit;
    /// // SAFETY: the closure writes `b'a'` (ASCII) to every byte.
    /// let arcstr = unsafe {
    ///     ArcStr::try_init_with_unchecked(10, |s: &mut [MaybeUninit<u8>]| {
    ///         s.fill(MaybeUninit::new(b'a'));
    ///     }).unwrap()
    /// };
    /// assert_eq!(arcstr, "aaaaaaaaaa")
    /// ```
    #[inline]
    pub unsafe fn try_init_with_unchecked<F>(n: usize, initializer: F) -> Option<Self>
    where
        F: FnOnce(&mut [MaybeUninit<u8>]),
    {
        if let Ok(inner) =
            // SAFETY: `try_allocate_with` requires `initializer` to write valid
            // UTF-8 to all `n` bytes when it returns: this function's `# Safety`
            // places exactly that obligation on our caller.
            unsafe { ThinInner::try_allocate_with(n, AllocInit::Uninit, initializer) }
        {
            // Field invariant: by `try_allocate_with`'s postcondition.
            Some(Self(inner))
        } else {
            None
        }
    }

    /// Allocate memory for an [`ArcStr`] of length `n`, and use the provided
    /// callback to fully initialize the provided buffer with valid UTF-8 text.
    ///
    /// This function calls
    /// [`handle_alloc_error`](std::alloc::handle_alloc_error) if memory
    /// allocation fails, see [`ArcStr::try_init_with_unchecked`] for a version
    /// which returns `None`
    ///
    /// # Safety
    ///
    /// Same as [`ArcStr::try_init_with_unchecked`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// # use core::mem::MaybeUninit;
    /// // SAFETY: the closure writes `b'a'` (ASCII) to every byte.
    /// let arcstr = unsafe {
    ///     ArcStr::init_with_unchecked(10, |s: &mut [MaybeUninit<u8>]| {
    ///         s.fill(MaybeUninit::new(b'a'));
    ///     })
    /// };
    /// assert_eq!(arcstr, "aaaaaaaaaa")
    /// ```
    #[inline]
    pub unsafe fn init_with_unchecked<F>(n: usize, initializer: F) -> Self
    where
        F: FnOnce(&mut [MaybeUninit<u8>]),
    {
        // SAFETY: `try_allocate_with` requires `initializer` to write valid
        // UTF-8 to all `n` bytes when it returns: this function's `# Safety`
        // places exactly that obligation on our caller.
        match unsafe { ThinInner::try_allocate_with(n, AllocInit::Uninit, initializer) } {
            // Field invariant: by `try_allocate_with`'s postcondition.
            Ok(inner) => Self(inner),
            Err(None) => panic!("capacity overflow"),
            Err(Some(layout)) => crate::std::alloc::handle_alloc_error(layout),
        }
    }

    /// Attempt to allocate memory for an [`ArcStr`] of length `n`, and use the
    /// provided callback to initialize the provided (initially-zeroed) buffer
    /// with valid UTF-8 text.
    ///
    /// Note: This function is provided with a zeroed buffer, and performs UTF-8
    /// validation after calling the initializer. While both of these are fast
    /// operations, some high-performance use cases will be better off using
    /// [`ArcStr::try_init_with_unchecked`] as the building block.
    ///
    /// # Errors
    /// The provided `initializer` callback must initialize the provided buffer
    /// with valid UTF-8 text, or a UTF-8 error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    ///
    /// let s = ArcStr::init_with(5, |slice| {
    ///     slice
    ///         .iter_mut()
    ///         .zip(b'0'..b'5')
    ///         .for_each(|(db, sb)| *db = sb);
    /// }).unwrap();
    /// assert_eq!(s, "01234");
    /// ```
    #[inline]
    pub fn init_with<F>(n: usize, initializer: F) -> Result<Self, core::str::Utf8Error>
    where
        F: FnOnce(&mut [u8]),
    {
        let mut failed = None::<core::str::Utf8Error>;
        let wrapper = |zeroed_slice: &mut [MaybeUninit<u8>]| {
            let len = zeroed_slice.len();
            // SAFETY: `from_raw_parts_mut` needs a non-null pointer, aligned
            // for `u8`, to `len` initialized bytes in one allocation, with no
            // other access for the slice's lifetime and `len <= isize::MAX`.
            // It is the same range as `zeroed_slice` (a valid `&mut` slice),
            // which `zeroed_slice` gives up for the new slice's lifetime, and
            // `AllocInit::Zero` makes `try_allocate_with` hand it over zeroed
            // (its postcondition), so every byte is an initialized `u8`.
            let slice = unsafe {
                core::slice::from_raw_parts_mut(zeroed_slice.as_mut_ptr().cast::<u8>(), len)
            };
            initializer(slice);
            if let Err(e) = core::str::from_utf8(slice) {
                failed = Some(e);
                // All zero bytes are valid UTF-8: the `ArcStr` built below to
                // free the allocation then holds its field invariant.
                slice.fill(0);
            }
        };
        // SAFETY: `wrapper` returns only after all `n` bytes are valid UTF-8:
        // checked by `from_utf8`, or reset to zero bytes when that fails.
        match unsafe { ThinInner::try_allocate_with(n, AllocInit::Zero, wrapper) } {
            Ok(inner) => {
                // Field invariant: by `try_allocate_with`'s postcondition.
                // Built on error too, so its drop frees the allocation.
                let this = Self(inner);
                if let Some(e) = failed {
                    Err(e)
                } else {
                    Ok(this)
                }
            }
            Err(None) => panic!("capacity overflow"),
            Err(Some(layout)) => crate::std::alloc::handle_alloc_error(layout),
        }
    }

    /// Extract a string slice containing our data.
    ///
    /// Note: This is an equivalent to our `Deref` implementation, but can be
    /// more readable than `&*s` in the cases where a manual invocation of
    /// `Deref` would be required.
    ///
    /// # Examples
    // TODO: find a better example where `&*` would have been required.
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let s = ArcStr::from("abc");
    /// assert_eq!(s.as_str(), "abc");
    /// ```
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        self
    }

    /// Returns the length of this `ArcStr` in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let a = ArcStr::from("foo");
    /// assert_eq!(a.len(), 3);
    /// ```
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.get_inner_len_flag().uint_part()
    }

    #[inline]
    fn get_inner_len_flag(&self) -> PackedFlagUint {
        // SAFETY: `self.0` holds the `ArcStr` field invariant, which is
        // `get_len_flag`'s precondition.
        unsafe { ThinInner::get_len_flag(self.0.as_ptr()) }
    }

    /// Returns true if this `ArcStr` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// assert!(!ArcStr::from("foo").is_empty());
    /// assert!(ArcStr::new().is_empty());
    /// ```
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Convert us to a `core::string::String`.
    ///
    /// This is provided as an inherent method to avoid needing to route through
    /// the `Display` machinery, but is equivalent to `ToString::to_string`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let s = ArcStr::from("abc");
    /// assert_eq!(s.to_string(), "abc");
    /// ```
    #[inline]
    #[allow(clippy::inherent_to_string_shadow_display)]
    #[must_use]
    pub fn to_string(&self) -> String {
        self.as_str().to_owned()
    }

    /// Extract a byte slice containing the string's data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let foobar = ArcStr::from("foobar");
    /// assert_eq!(foobar.as_bytes(), b"foobar");
    /// ```
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: by `bytes_ptr`'s safety-usable invariant the pointer is
        // non-null, aligned (for `u8`) and covers `self.len()` initialized
        // bytes inside the inner's allocation (so at most `isize::MAX`). Those
        // bytes are never written, and the allocation stays live while `self`
        // is borrowed (field invariant: `self` owns a count or the inner is
        // never freed), which outlives the returned slice.
        unsafe { &*Self::bytes_ptr(self) }
    }

    /// Return the raw pointer this `ArcStr` wraps, for advanced use cases.
    ///
    /// Note that in addition to the `NonNull` constraint expressed in the type
    /// signature, we also guarantee the pointer has an alignment of at least 8
    /// bytes, even on platforms where a lower alignment would be acceptable.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let s = ArcStr::from("abcd");
    /// let p = ArcStr::into_raw(s);
    /// // Some time later...
    /// // SAFETY: `p` comes from one `into_raw` call and is used once.
    /// let s = unsafe { ArcStr::from_raw(p) };
    /// assert_eq!(s, "abcd");
    /// ```
    #[inline]
    #[must_use]
    pub fn into_raw(this: Self) -> NonNull<()> {
        let p = this.0;
        #[allow(clippy::mem_forget)]
        core::mem::forget(this);
        p.cast()
    }

    /// The opposite version of [`Self::into_raw`]. Still intended only for
    /// advanced use cases.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` was returned by [`ArcStr::into_raw`],
    /// and that `from_raw` is called at most once for each `into_raw` call
    /// that returned it: the returned `ArcStr` takes over the handle that
    /// `into_raw` consumed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let s = ArcStr::from("abcd");
    /// let p = ArcStr::into_raw(s);
    /// // Some time later...
    /// // SAFETY: `p` comes from one `into_raw` call and is used once.
    /// let s = unsafe { ArcStr::from_raw(p) };
    /// assert_eq!(s, "abcd");
    /// ```
    #[inline]
    #[must_use]
    pub unsafe fn from_raw(ptr: NonNull<()>) -> Self {
        // Field invariant: by the `# Safety` contract `ptr` is the pointer of
        // a handle that `into_raw` consumed without dropping, and no other
        // `from_raw` call took that handle over.
        Self(ptr.cast())
    }

    /// Returns true if the two `ArcStr`s point to the same allocation.
    ///
    /// Note that functions like `PartialEq` check this already, so there's
    /// no performance benefit to doing something like `ArcStr::ptr_eq(&a1, &a2) || (a1 == a2)`.
    ///
    /// Caveat: `const`s aren't guaranteed to only occur in an executable a
    /// single time, and so this may be non-deterministic for `ArcStr` defined
    /// in a `const` with [`arcstr!`][crate::str::arcstr::arcstr], unless one
    /// was created by a `clone()` on the other.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::{ArcStr, arcstr};
    ///
    /// let foobar = ArcStr::from("foobar");
    /// let same_foobar = foobar.clone();
    /// let other_foobar = ArcStr::from("foobar");
    /// assert!(ArcStr::ptr_eq(&foobar, &same_foobar));
    /// assert!(!ArcStr::ptr_eq(&foobar, &other_foobar));
    ///
    /// const YET_AGAIN_A_DIFFERENT_FOOBAR: ArcStr = arcstr!("foobar");
    /// let strange_new_foobar = YET_AGAIN_A_DIFFERENT_FOOBAR.clone();
    /// let wild_blue_foobar = strange_new_foobar.clone();
    /// assert!(ArcStr::ptr_eq(&strange_new_foobar, &wild_blue_foobar));
    /// ```
    #[inline]
    #[must_use]
    pub fn ptr_eq(lhs: &Self, rhs: &Self) -> bool {
        core::ptr::eq(lhs.0.as_ptr(), rhs.0.as_ptr())
    }

    /// Returns the number of references that exist to this `ArcStr`. If this is
    /// a static `ArcStr` (For example, one from
    /// [`arcstr!`][crate::str::arcstr::arcstr]), returns `None`.
    ///
    /// Despite the difference in return type, this is named to match the method
    /// from the stdlib's Arc:
    /// [`Arc::strong_count`][std::sync::Arc::strong_count].
    ///
    /// If you aren't sure how to handle static `ArcStr` in the context of this
    /// return value, `ArcStr::strong_count(&s).unwrap_or(usize::MAX)` is
    /// frequently reasonable.
    ///
    /// # Races
    ///
    /// Another thread can change the strong count at any time, including
    /// potentially between calling this method and acting on the result.
    ///
    /// It never changes from `None` to `Some`. It changes from `Some` to
    /// `None` once [`ArcStr::leak`] is called on any handle of this string.
    ///
    /// # Examples
    ///
    /// ### Dynamic ArcStr
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let foobar = ArcStr::from("foobar");
    /// assert_eq!(Some(1), ArcStr::strong_count(&foobar));
    /// let also_foobar = ArcStr::clone(&foobar);
    /// assert_eq!(Some(2), ArcStr::strong_count(&foobar));
    /// assert_eq!(Some(2), ArcStr::strong_count(&also_foobar));
    /// ```
    ///
    /// ### Static ArcStr
    /// ```
    /// # use rama_utils::str::arcstr::{ArcStr, arcstr};
    /// let baz = arcstr!("baz");
    /// assert_eq!(None, ArcStr::strong_count(&baz));
    /// // Similarly:
    /// assert_eq!(None, ArcStr::strong_count(&ArcStr::default()));
    /// ```
    #[inline]
    #[must_use]
    pub fn strong_count(this: &Self) -> Option<usize> {
        let cf = Self::load_count_flag(this, Ordering::Acquire)?;
        if cf.flag_part() {
            None
        } else {
            Some(cf.uint_part())
        }
    }

    /// The count of `this`'s heap inner.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `this` points to a heap inner, which holds
    /// when [`Self::has_static_lenflag`] returns false for it.
    #[inline]
    unsafe fn count_flag(this: &Self) -> &AtomicUsize {
        // SAFETY: the reference is in bounds, aligned (8, the allocation's
        // alignment) and points to the `AtomicUsize` written at allocation,
        // because `this` points to a heap inner (precondition) and that inner
        // stays live while `this` is borrowed (field invariant). Every other
        // access to it goes through shared `&AtomicUsize` references only.
        unsafe { &(*this.0.as_ptr()).count_flag }
    }

    #[inline]
    fn load_count_flag(this: &Self, ord_if_needed: Ordering) -> Option<PackedFlagUint> {
        if Self::has_static_lenflag(this) {
            None
        } else {
            // SAFETY: the len flag is clear, so `this` points to a heap inner.
            let count = unsafe { Self::count_flag(this) };
            Some(PackedFlagUint::from_encoded(count.load(ord_if_needed)))
        }
    }

    /// Convert the `ArcStr` into a "static" `ArcStr`, even if it was originally
    /// created from runtime values. The `&'static str` is returned.
    ///
    /// This is useful if you want to use [`ArcStr::as_static`] or
    /// [`ArcStr::is_static`] on a value only known at runtime.
    ///
    /// If the `ArcStr` is already static, then this is a noop.
    ///
    /// # Caveats
    /// Calling this function on an ArcStr will cause us to never free it, thus
    /// leaking it's memory. Doing this excessively can lead to problems.
    ///
    /// # Examples
    /// ```no_run
    /// # // This isn't run because it needs a leakcheck suppression,
    /// # // which I can't seem to make work in CI (no symbols for
    /// # // doctests?). Instead, we test this in tests/arc_str.rs
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let s = ArcStr::from("foobar");
    /// assert!(!ArcStr::is_static(&s));
    /// assert!(ArcStr::as_static(&s).is_none());
    ///
    /// let leaked: &'static str = s.leak();
    /// assert_eq!(leaked, s);
    /// assert!(ArcStr::is_static(&s));
    /// assert_eq!(ArcStr::as_static(&s), Some("foobar"));
    /// ```
    #[inline]
    #[must_use]
    pub fn leak(&self) -> &'static str {
        if !Self::is_static(self) {
            // SAFETY: `is_static` returned false, so the len flag is clear and
            // `self` points to a heap inner.
            let count = unsafe { Self::count_flag(self) };
            // An atomic read-modify-write, never a plain write: other threads
            // may access this inner through other handles, or this one.
            count.fetch_or(PackedFlagUint::TRUE_ZERO.encoded_value(), Ordering::Release);
        }
        debug_assert!(Self::is_static(self));
        // SAFETY: `self` is static: its len flag was set, or its count flag
        // was set by the `fetch_or` above or earlier, and a set count flag is
        // never cleared (see `ThinInner`).
        unsafe { Self::to_static_unchecked(self) }
    }

    /// # Safety
    ///
    /// The caller must ensure that `this` is static, which holds once
    /// [`Self::is_static`] returned true for it.
    ///
    /// The returned string is valid for `'static`: a static inner is
    /// `'static`, and a heap inner with the count flag set is never freed
    /// (see `ThinInner`); its bytes are never written.
    #[inline]
    unsafe fn to_static_unchecked(this: &Self) -> &'static str {
        // SAFETY: by the safety-usable invariants of `str_ptr` and
        // `bytes_ptr`, the pointer is non-null, aligned (for `u8`) and covers
        // exactly the `len` initialized data bytes, valid UTF-8, in one
        // allocation. Those bytes are never written and, `this` being static
        // (precondition), never freed, so a shared `'static` reference to
        // them is valid.
        unsafe { &*Self::str_ptr(this) }
    }

    /// # Safety-usable invariant
    ///
    /// Returns a slice pointer with address `this.0 + OFFSET_DATA`, length
    /// metadata `this.len()` and the provenance of `this.0`: it covers exactly
    /// the data bytes of `this`'s inner, which are non-null, inside the
    /// inner's allocation, initialized and valid UTF-8.
    #[inline]
    fn bytes_ptr(this: &Self) -> *const [u8] {
        let len = this.get_inner_len_flag().uint_part();
        // SAFETY: `add` needs the result to stay in bounds of the allocation
        // `this.0` points into. Both inner forms (field invariant) are an
        // allocation of at least `OFFSET_DATA + len` bytes starting at
        // `this.0`, so `OFFSET_DATA` is in bounds (or one past the end when
        // `len == 0`). The data bytes start there for both forms (layout
        // asserts below).
        let data = unsafe { this.0.as_ptr().cast::<u8>().add(OFFSET_DATA) };
        core::ptr::slice_from_raw_parts(data, len)
    }

    /// # Safety-usable invariant
    ///
    /// Returns [`Self::bytes_ptr`]'s pointer cast to `*const str`: the same
    /// address, provenance and length metadata (in bytes).
    #[inline]
    fn str_ptr(this: &Self) -> *const str {
        Self::bytes_ptr(this) as *const str
    }

    /// Returns true if `this` is a "static" ArcStr. For example, if it was
    /// created from a call to [`arcstr!`][crate::str::arcstr::arcstr]),
    /// returned by `ArcStr::new`, etc.
    ///
    /// Static `ArcStr`s can be converted to `&'static str` for free using
    /// [`ArcStr::as_static`], without leaking memory — they're static constants
    /// in the program (somewhere).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::{ArcStr, arcstr};
    /// const STATIC: ArcStr = arcstr!("Electricity!");
    /// assert!(ArcStr::is_static(&STATIC));
    ///
    /// let still_static = arcstr!("Shocking!");
    /// assert!(ArcStr::is_static(&still_static));
    /// assert!(
    ///     ArcStr::is_static(&still_static.clone()),
    ///     "Cloned statics are still static"
    /// );
    ///
    /// let nonstatic = ArcStr::from("Grounded...");
    /// assert!(!ArcStr::is_static(&nonstatic));
    /// ```
    ///
    /// # Safety-usable invariant
    ///
    /// Returns true only if `this` points to a static inner, or to a heap
    /// inner whose count flag is set (it then stays set).
    #[inline]
    #[must_use]
    pub fn is_static(this: &Self) -> bool {
        // We align this to 16 bytes and keep the `is_static` flags in the same
        // place. In theory this means that if `cfg(target_feature = "avx")`
        // (where aligned 16byte loads are atomic), the compiler *could*
        // implement this function using the equivalent of:
        // ```
        // let vec = _mm_load_si128(self.0.as_ptr().cast());
        // let mask = _mm_movemask_pd(_mm_srli_epi64(vac, 63));
        // mask != 0
        // ```
        // and that's all; one load, no branching. (I don't think it *does*, but
        // I haven't checked so I'll be optimistic and keep the `#[repr(align)]`
        // -- hey, maybe the CPU can peephole-optimize it).
        //
        // That said, unless I did it in asm, *I* can't implement it that way,
        // since Rust's semantics don't allow me to make that change
        // optimization on my own (that load isn't considered atomic, for
        // example).
        Self::load_count_flag(this, Ordering::Relaxed).is_none_or(|cf| cf.flag_part())
    }

    /// This is true for any `ArcStr` that has been static from the time when it
    /// was created. It's cheaper than checking the count flag.
    ///
    /// # Safety-usable invariant
    ///
    /// Returns true exactly when `this` points to a static inner (field
    /// invariant: the len flag is set only there).
    #[inline]
    fn has_static_lenflag(this: &Self) -> bool {
        this.get_inner_len_flag().flag_part()
    }

    /// Returns true if `this` is a "static"/`"literal"` ArcStr. For example, if
    /// it was created from a call to [`arcstr!`][crate::str::arcstr::arcstr]), returned by
    /// `ArcStr::new`, etc.
    ///
    /// Static `ArcStr`s can be converted to `&'static str` for free using
    /// [`ArcStr::as_static`], without leaking memory — they're static constants
    /// in the program (somewhere).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::{ArcStr, arcstr};
    /// const STATIC: ArcStr = arcstr!("Electricity!");
    /// assert_eq!(ArcStr::as_static(&STATIC), Some("Electricity!"));
    ///
    /// // Note that they don't have to be consts, just made using `arcstr!`:
    /// let still_static = arcstr!("Shocking!");
    /// assert_eq!(ArcStr::as_static(&still_static), Some("Shocking!"));
    /// // Cloning a static still produces a static.
    /// assert_eq!(ArcStr::as_static(&still_static.clone()), Some("Shocking!"));
    ///
    /// // But it won't work for strings from other sources.
    /// let nonstatic = ArcStr::from("Grounded...");
    /// assert_eq!(ArcStr::as_static(&nonstatic), None);
    /// ```
    #[inline]
    #[must_use]
    pub fn as_static(this: &Self) -> Option<&'static str> {
        if Self::is_static(this) {
            // SAFETY: `is_static` returned true.
            Some(unsafe { Self::to_static_unchecked(this) })
        } else {
            None
        }
    }

    // Not public API. Exists so the `arcstr!` macro can call it.
    //
    /// # Safety
    ///
    /// The caller must ensure that `inner.data` is valid UTF-8.
    ///
    /// # Panics
    ///
    /// If `inner.len_flag` is not `encode_len(N)` or `inner.count_flag` is
    /// not [`STATIC_COUNT_VALUE`]; in a `const` this fails compilation.
    #[inline]
    #[doc(hidden)]
    #[must_use]
    pub const unsafe fn _private_new_from_static_data<const N: usize>(
        inner: &'static StaticArcStrInner<[u8; N]>,
    ) -> Self {
        assert!(
            matches!(StaticArcStrInner::<[u8; N]>::encode_len(N), Some(v) if v == inner.len_flag),
            "static ArcStr: len_flag must be encode_len(N)"
        );
        assert!(
            inner.count_flag == STATIC_COUNT_VALUE,
            "static ArcStr: count_flag must be STATIC_COUNT_VALUE"
        );
        // Field invariant (static form): `inner` is a `'static`
        // `StaticArcStrInner<[u8; N]>` behind a shared reference (so only
        // read), its tags are checked above, its data is valid UTF-8 by the
        // `# Safety` contract, and `repr(C, align(8))` plus the layout asserts
        // below give it the `ThinInner` header layout.
        Self(NonNull::from_ref(inner).cast::<ThinInner>())
    }

    /// Returns a substr of `self` over the given range.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::{ArcStr, Substr};
    ///
    /// let a = ArcStr::from("abcde");
    /// let b: Substr = a.substr(2..);
    ///
    /// assert_eq!(b, "cde");
    /// ```
    ///
    /// # Panics
    /// If any of the following are untrue, we panic
    /// - `range.start() <= range.end()`
    /// - `range.end() <= self.len()`
    /// - `self.is_char_boundary(start) && self.is_char_boundary(end)`
    /// - These can be conveniently verified in advance using
    ///   `self.get(start..end).is_some()` if needed.
    #[inline]
    pub fn substr(&self, range: impl core::ops::RangeBounds<usize>) -> Substr {
        Substr::from_parts(self, range)
    }

    /// Returns a [`Substr`] of self over the given `&str`.
    ///
    /// It is not rare to end up with a `&str` which holds a view into a
    /// `ArcStr`'s backing data. A common case is when using functionality that
    /// takes and returns `&str` and are entirely unaware of `arcstr`, for
    /// example: `str::trim()`.
    ///
    /// This function allows you to reconstruct a [`Substr`] from a `&str` which
    /// is a view into this `ArcStr`'s backing string.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::{ArcStr, Substr};
    /// let text = ArcStr::from("   abc");
    /// let trimmed = text.trim();
    /// let substr: Substr = text.substr_from(trimmed);
    /// assert_eq!(substr, "abc");
    /// // for illustration
    /// assert!(ArcStr::ptr_eq(substr.parent(), &text));
    /// assert_eq!(substr.range(), 3..6);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `substr` isn't a view into our memory.
    ///
    /// Also panics if `substr` is a view into our memory but is >= `u32::MAX`
    /// bytes away from our start, if we're a 64-bit machine and
    /// `substr-usize-indices` is not enabled.
    #[must_use]
    pub fn substr_from(&self, substr: &str) -> Substr {
        if substr.is_empty() {
            return Substr::new();
        }

        let self_start = self.as_ptr() as usize;
        let self_end = self_start + self.len();

        let substr_start = substr.as_ptr() as usize;
        let substr_end = substr_start + substr.len();
        if substr_start < self_start || substr_end > self_end {
            out_of_range(self, &substr);
        }

        let index = substr_start - self_start;
        let end = index + substr.len();
        self.substr(index..end)
    }

    /// If possible, returns a [`Substr`] of self over the
    /// given `&str`.
    ///
    /// This is a fallible version of [`ArcStr::substr_from`].
    ///
    /// It is not rare to end up with a `&str` which holds a view into a
    /// `ArcStr`'s backing data. A common case is when using functionality that
    /// takes and returns `&str` and are entirely unaware of `arcstr`, for
    /// example: `str::trim()`.
    ///
    /// This function allows you to reconstruct a [`Substr`] from a `&str` which
    /// is a view into this `ArcStr`'s backing string.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::{ArcStr, Substr};
    /// let text = ArcStr::from("   abc");
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
    /// away from our start, if we're a 64-bit machine and
    /// `substr-usize-indices` is not enabled.
    #[must_use]
    pub fn try_substr_from(&self, substr: &str) -> Option<Substr> {
        if substr.is_empty() {
            return Some(Substr::new());
        }

        let self_start = self.as_ptr() as usize;
        let self_end = self_start + self.len();

        let substr_start = substr.as_ptr() as usize;
        let substr_end = substr_start + substr.len();
        if substr_start < self_start || substr_end > self_end {
            return None;
        }

        let index = substr_start - self_start;
        let end = index + substr.len();
        debug_assert!(self.get(index..end).is_some());
        Some(self.substr(index..end))
    }

    /// Compute a derived `&str` a function of `&str` =>
    /// `&str`, and produce a Substr of the result if possible.
    ///
    /// The function may return either a derived string, or any empty string.
    ///
    /// This function is mainly a wrapper around [`ArcStr::try_substr_from`]. If
    /// you're coming to `arcstr` from the `shared_string` crate, this is the
    /// moral equivalent of the `slice_with` function.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::{ArcStr, Substr};
    /// let text = ArcStr::from("   abc");
    /// let trimmed: Option<Substr> = text.try_substr_using(str::trim);
    /// assert_eq!(trimmed.unwrap(), "abc");
    /// let other = text.try_substr_using(|_s| "different string!");
    /// assert_eq!(other, None);
    /// // As a special case, this is allowed.
    /// let empty = text.try_substr_using(|_s| "");
    /// assert_eq!(empty.unwrap(), "");
    /// ```
    pub fn try_substr_using(&self, f: impl FnOnce(&str) -> &str) -> Option<Substr> {
        self.try_substr_from(f(self.as_str()))
    }

    /// Compute a derived `&str` a function of `&str` =>
    /// `&str`, and produce a Substr of the result.
    ///
    /// The function may return either a derived string, or any empty string.
    /// Returning anything else will result in a panic.
    ///
    /// This function is mainly a wrapper around [`ArcStr::try_substr_from`]. If
    /// you're coming to `arcstr` from the `shared_string` crate, this is the
    /// likely closest to the `slice_with_unchecked` function, but this panics
    /// instead of UB on dodginess.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::{ArcStr, Substr};
    /// let text = ArcStr::from("   abc");
    /// let trimmed: Substr = text.substr_using(str::trim);
    /// assert_eq!(trimmed, "abc");
    /// // As a special case, this is allowed.
    /// let empty = text.substr_using(|_s| "");
    /// assert_eq!(empty, "");
    /// ```
    pub fn substr_using(&self, f: impl FnOnce(&str) -> &str) -> Substr {
        self.substr_from(f(self.as_str()))
    }

    /// Creates an `ArcStr` by repeating the source string `n` times
    ///
    /// # Errors
    ///
    /// This function returns `None` if the capacity overflows or allocation
    /// fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::str::arcstr::ArcStr;
    ///
    /// let source = "A";
    /// let repeated = ArcStr::try_repeat(source, 10);
    /// assert_eq!(repeated.unwrap(), "AAAAAAAAAA");
    /// ```
    #[must_use]
    pub fn try_repeat(source: &str, n: usize) -> Option<Self> {
        // If the source string is empty or the user asked for zero repetitions,
        // return an empty string
        if source.is_empty() || n == 0 {
            return Some(Self::new());
        }

        // Calculate the capacity for the allocated string
        let capacity = source.len().checked_mul(n)?;
        // Copy `source` into the allocated string `n` times.
        let fill = |buf: &mut [MaybeUninit<u8>]| {
            for chunk in buf.chunks_exact_mut(source.len()) {
                chunk.write_copy_of_slice(source.as_bytes());
            }
        };
        // SAFETY: the buffer has `capacity = source.len() * n` bytes, so
        // `chunks_exact_mut` splits it into `n` chunks with no remainder and
        // `fill` writes a copy of `source` to each: when it returns all bytes
        // hold `n` copies of a `&str`, which is valid UTF-8.
        let inner =
            unsafe { ThinInner::try_allocate_with(capacity, AllocInit::Uninit, fill) }.ok()?;

        // Field invariant: by `try_allocate_with`'s postcondition.
        Some(Self(inner))
    }
}

#[cold]
#[inline(never)]
fn out_of_range(arc: &ArcStr, substr: &&str) -> ! {
    let arc_start = arc.as_ptr();
    let arc_end = arc_start.wrapping_add(arc.len());
    let substr_start = substr.as_ptr();
    let substr_end = substr_start.wrapping_add(substr.len());
    panic!(
        "ArcStr over ({arc_start:p}..{arc_end:p}) does not contain substr over ({substr_start:p}..{substr_end:p})",
    );
}

impl Clone for ArcStr {
    #[inline]
    fn clone(&self) -> Self {
        if !Self::is_static(self) {
            // SAFETY: `is_static` returned false, so the len flag is clear and
            // `self` points to a heap inner.
            let count = unsafe { Self::count_flag(self) };
            // From libstd's impl:
            //
            // > Using a relaxed ordering is alright here, as knowledge of the
            // > original reference prevents other threads from erroneously deleting
            // > the object.
            //
            // See: https://doc.rust-lang.org/src/alloc/sync.rs.html#1073
            let n = PackedFlagUint::from_encoded(
                count.fetch_add(PackedFlagUint::FALSE_ONE.encoded_value(), Ordering::Relaxed),
            );
            // Refcount saturation: once a clone sees a count above `RC_MAX`,
            // it sets the flag, which makes the inner static: from then on
            // `Clone` and `Drop` return early and the inner is never freed.
            //
            // The count never wraps past `UINT_PART_MAX` (a wrap would let a
            // drop free a live inner): an increment that returns more than
            // `RC_MAX` is undone right after the flag is set or seen set, so
            // the count stays below `RC_MAX + 2` plus one per thread between
            // its `fetch_add` and `fetch_sub`. The headroom `UINT_PART_MAX -
            // RC_MAX` (2^62, or 2^30 on 32-bit) exceeds the number of threads
            // that can run at once, each with its own stack in the address
            // space. With the flag set the count no longer decides anything,
            // so undoing is harmless.
            if n.uint_part() > RC_MAX {
                if !n.flag_part() {
                    count.fetch_or(PackedFlagUint::TRUE_ZERO.encoded_value(), Ordering::Release);
                    tracing::error!(
                        rc = n.uint_part(),
                        rc_max = RC_MAX,
                        "ArcStr refcount saturated; transitioning to static (leaking backing storage) instead of aborting",
                    );
                }
                count.fetch_sub(PackedFlagUint::FALSE_ONE.encoded_value(), Ordering::Relaxed);
            }
        }
        // Field invariant: a static inner is shared freely; for a heap inner
        // the `fetch_add` above took one more unit of the count for the new
        // handle, or the count flag is set (and stays set: never freed).
        Self(self.0)
    }
}
const RC_MAX: usize = PackedFlagUint::UINT_PART_MAX / 2;

impl Drop for ArcStr {
    #[inline]
    fn drop(&mut self) {
        if Self::is_static(self) {
            return;
        }
        let enc = {
            // SAFETY: `is_static` returned false, so the len flag is clear and
            // `self` points to a heap inner.
            let count = unsafe { Self::count_flag(self) };
            let enc = PackedFlagUint::from_encoded(
                count.fetch_sub(PackedFlagUint::FALSE_ONE.encoded_value(), Ordering::Release),
            );
            if enc == PackedFlagUint::FALSE_ONE {
                // Acquire edge: this load reads the value of the `fetch_sub`
                // above, which is in the release sequence of every other
                // handle's `Release` `fetch_sub`, so all their uses of the
                // inner happen-before the free below.
                _ = count.load(Ordering::Acquire);
            }
            enc
        };
        if enc == PackedFlagUint::FALSE_ONE {
            // SAFETY: `destroy_cold` needs a heap inner that no handle or
            // reference uses afterwards, with every earlier use
            // happening-before. The `fetch_sub` returned a count of 1 with the
            // flag clear, so `self` held the last unit, no other handle exists
            // and none can be made; no `&'static str` exists as the flag was
            // never set; `count` is out of scope; the acquire load above gives
            // the happens-before edge.
            unsafe { ThinInner::destroy_cold(self.0.as_ptr()) }
        }
    }
}
// An `ArcStr` points to a `ThinInner` header, or to a `StaticArcStrInner<[u8;
// N]>` with the same header layout (asserted below) whose `count_flag` is a
// plain `usize`, possibly in read-only memory. The `len_flag` flag tells them
// apart: set exactly for a static inner. So `count_flag` is accessed (always
// atomically, through `&AtomicUsize`) only after reading the len flag as clear,
// and no `&ThinInner` to a whole inner is ever made.
//
// Count protocol of a heap inner (`count_flag`, a `PackedFlagUint`):
// - the uint part counts the handles that own a unit of it;
// - the flag part, once set (`ArcStr::leak`, or refcount saturation in
//   `Clone`), is never cleared: every later access is a load, `fetch_or`, or a
//   `fetch_add`/`fetch_sub` of `FALSE_ONE`, which leaves bit 0 unchanged;
// - the inner is freed only by the `Drop` whose `fetch_sub` returned exactly
//   `FALSE_ONE` (count 1, flag clear), after an acquire edge; so an inner with
//   the flag set is never freed.
#[repr(C, align(8))]
struct ThinInner {
    // Both of these are `PackedFlagUint`s that store `is_static` as the flag.
    //
    // The reason it's not just stored in len is because an ArcStr may become
    // static after creation (via `ArcStr::leak`) and we don't need to do an
    // atomic load to access the length (and not only because it would mess with
    // optimization).
    //
    // The reason it's not just stored in the count is because it may be UB to
    // do atomic loads from read-only memory. This is also the reason it's not
    // stored in a separate atomic, and why doing an atomic load to access the
    // length wouldn't be acceptable even if compilers were really good.
    len_flag: PackedFlagUint,
    count_flag: AtomicUsize,
    data: [u8; 0],
}

const OFFSET_LENFLAGS: usize = 0;
const OFFSET_COUNTFLAGS: usize = size_of::<PackedFlagUint>();
const OFFSET_DATA: usize = OFFSET_COUNTFLAGS + size_of::<AtomicUsize>();

// Not public API, exists for macros.
#[repr(C, align(8))]
#[doc(hidden)]
pub struct StaticArcStrInner<Buf> {
    pub len_flag: usize,
    pub count_flag: usize,
    pub data: Buf,
}

#[doc(hidden)]
pub const STATIC_COUNT_VALUE: usize = PackedFlagUint::new_raw(true, 1).encoded_value();

impl<Buf> StaticArcStrInner<Buf> {
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub const fn encode_len(v: usize) -> Option<usize> {
        match PackedFlagUint::new(true, v) {
            Some(v) => Some(v.encoded_value()),
            None => None,
        }
    }
}

const _: () = assert!(core::mem::offset_of!(ThinInner, len_flag) == OFFSET_LENFLAGS);
const _: () = assert!(core::mem::offset_of!(ThinInner, count_flag) == OFFSET_COUNTFLAGS);
const _: () = assert!(core::mem::offset_of!(ThinInner, data) == OFFSET_DATA);
const _: () =
    assert!(core::mem::offset_of!(StaticArcStrInner<[u8; 1]>, len_flag) == OFFSET_LENFLAGS);
const _: () =
    assert!(core::mem::offset_of!(StaticArcStrInner<[u8; 1]>, count_flag) == OFFSET_COUNTFLAGS);
const _: () = assert!(core::mem::offset_of!(StaticArcStrInner<[u8; 1]>, data) == OFFSET_DATA);

const _: [(); size_of::<StaticArcStrInner<[u8; 0]>>()] = [(); 2 * size_of::<usize>()];
const _: [(); align_of::<StaticArcStrInner<[u8; 0]>>()] = [(); 8];

const _: [(); size_of::<StaticArcStrInner<[u8; 2 * size_of::<usize>()]>>()] =
    [(); 4 * size_of::<usize>()];
const _: [(); align_of::<StaticArcStrInner<[u8; 2 * size_of::<usize>()]>>()] = [(); 8];

const _: [(); size_of::<ThinInner>()] = [(); 2 * size_of::<usize>()];
const _: [(); align_of::<ThinInner>()] = [(); 8];

const _: [(); align_of::<AtomicUsize>()] = [(); align_of::<usize>()];
const _: [(); align_of::<AtomicUsize>()] = [(); size_of::<usize>()];
const _: [(); size_of::<AtomicUsize>()] = [(); size_of::<usize>()];

const _: [(); align_of::<PackedFlagUint>()] = [(); align_of::<usize>()];
const _: [(); size_of::<PackedFlagUint>()] = [(); size_of::<usize>()];

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct PackedFlagUint(usize);
impl PackedFlagUint {
    const UINT_PART_MAX: usize = (1 << (usize::BITS - 1)) - 1;
    /// Encodes `false` as the flag and `1` as the uint. Used for a few things,
    /// such as the amount we `fetch_add` by for refcounting, and so on.
    const FALSE_ONE: Self = Self::new_raw(false, 1);
    /// Only the flag bit: what `fetch_or` sets to make an inner static.
    const TRUE_ZERO: Self = Self::new_raw(true, 0);

    #[inline]
    const fn new(flag_part: bool, uint_part: usize) -> Option<Self> {
        if uint_part > Self::UINT_PART_MAX {
            None
        } else {
            Some(Self::new_raw(flag_part, uint_part))
        }
    }

    #[inline(always)]
    const fn new_raw(flag_part: bool, uint_part: usize) -> Self {
        Self(flag_part as usize | (uint_part << 1))
    }

    #[inline(always)]
    const fn uint_part(self) -> usize {
        self.0 >> 1
    }

    #[inline(always)]
    const fn flag_part(self) -> bool {
        (self.0 & 1) != 0
    }

    #[inline(always)]
    const fn from_encoded(v: usize) -> Self {
        Self(v)
    }

    #[inline(always)]
    const fn encoded_value(self) -> usize {
        self.0
    }
}

const EMPTY: ArcStr = super::arcstr!("");

impl ThinInner {
    /// [`ThinInner::try_allocate`], diverging on failure.
    ///
    /// # Safety-usable invariant
    ///
    /// Returns `try_allocate`'s `Ok` pointer unchanged, with its guarantees:
    /// the heap form of the `ArcStr` field invariant with `len ==
    /// data.len()` and a count of 1 that the caller owns.
    #[inline]
    fn allocate(data: &str) -> NonNull<Self> {
        match Self::try_allocate(data) {
            Ok(v) => v,
            Err(None) => alloc_overflow(),
            Err(Some(layout)) => crate::std::alloc::handle_alloc_error(layout),
        }
    }

    /// Allocates a `ThinInner` where the data segment is uninitialized or
    /// zeroed.
    ///
    /// Returns `Err(Some(layout))` if we failed to allocate that layout, and
    /// `Err(None)` for integer overflow when computing layout
    ///
    /// # Safety-usable invariant
    ///
    /// On `Ok(p)`, `p` is the only pointer to a fresh global-allocator
    /// allocation of `Layout::from_size_align(capacity + OFFSET_DATA, 8)`
    /// (a valid layout), which starts with a `ThinInner` whose `len_flag` is
    /// `(false, capacity)` and whose `count_flag` is `(false, 1)`. The
    /// `capacity` data bytes after it are uninitialized for
    /// `AllocInit::Uninit` and zero for `AllocInit::Zero`.
    fn try_allocate_maybe_uninit(
        capacity: usize,
        init_how: AllocInit,
    ) -> Result<NonNull<Self>, Option<Layout>> {
        const ALIGN: usize = align_of::<ThinInner>();

        let size = capacity.checked_add(OFFSET_DATA).ok_or(None)?;
        let layout = Layout::from_size_align(size, ALIGN).ok().ok_or(None)?;
        // `size <= isize::MAX` (checked by `Layout`) so `capacity` fits.
        let len_flag = PackedFlagUint::new(false, capacity).ok_or(None)?;

        #[expect(
            clippy::cast_ptr_alignment,
            reason = "`layout` has `ALIGN`, the alignment of `ThinInner`"
        )]
        let ptr = match init_how {
            // SAFETY: `alloc` needs a layout of non-zero size: it is at least
            // `OFFSET_DATA` bytes.
            AllocInit::Uninit => unsafe { crate::std::alloc::alloc(layout) },
            // SAFETY: as for `alloc` above.
            AllocInit::Zero => unsafe { crate::std::alloc::alloc_zeroed(layout) },
        }
        .cast::<Self>();
        let Some(ptr) = NonNull::new(ptr) else {
            return Err(Some(layout));
        };

        let header = Self {
            len_flag,
            count_flag: AtomicUsize::new(PackedFlagUint::FALSE_ONE.encoded_value()),
            data: [],
        };
        // SAFETY: `write` needs `ptr` valid for writes of a `ThinInner` and
        // aligned. The allocation has alignment 8 = `align_of::<ThinInner>()`
        // and at least `OFFSET_DATA = size_of::<ThinInner>()` bytes, and no
        // other pointer to it exists yet.
        unsafe { ptr.write(header) };
        Ok(ptr)
    }

    /// Allocates an inner holding a copy of `data`, as
    /// [`ThinInner::try_allocate_maybe_uninit`] does.
    ///
    /// # Safety-usable invariant
    ///
    /// On `Ok(p)`, `p` satisfies the heap form of the `ArcStr` field
    /// invariant with `len == data.len()` and a count of 1 that the caller
    /// owns.
    #[inline]
    fn try_allocate(data: &str) -> Result<NonNull<Self>, Option<Layout>> {
        let copy = |uninit_slice: &mut [MaybeUninit<u8>]| {
            uninit_slice.write_copy_of_slice(data.as_bytes());
        };
        // SAFETY: `write_copy_of_slice` writes all bytes of the buffer, or
        // panics if its length is not `data.len()`, so when `copy` returns the
        // buffer holds a copy of the `&str` `data`, which is valid UTF-8.
        unsafe { Self::try_allocate_with(data.len(), AllocInit::Uninit, copy) }
    }

    /// Allocates an inner of `len` data bytes and calls `initializer` with
    /// them (zeroed for `AllocInit::Zero`, else uninitialized).
    ///
    /// # Safety
    ///
    /// The caller must ensure that `initializer`, if it returns, has written
    /// valid UTF-8 to all `len` bytes of the buffer it is given.
    ///
    /// On `Ok(p)`, `p` satisfies the heap form of the `ArcStr` field invariant
    /// with a count of 1 that the caller owns. If `initializer` unwinds, the
    /// allocation is leaked.
    #[inline]
    unsafe fn try_allocate_with(
        len: usize,
        init_style: AllocInit,
        initializer: impl FnOnce(&mut [MaybeUninit<u8>]),
    ) -> Result<NonNull<Self>, Option<Layout>> {
        let this = Self::try_allocate_maybe_uninit(len, init_style)?;
        // SAFETY: `this` points to an allocation of `OFFSET_DATA + len` bytes
        // (by `try_allocate_maybe_uninit`'s safety-usable invariant), which
        // is `data_ptr`'s precondition.
        let data = unsafe { Self::data_ptr(this) };
        // SAFETY: `from_raw_parts_mut` needs a non-null pointer aligned for
        // `MaybeUninit<u8>` (align 1) to `len` values in one allocation, no
        // other access for the slice's lifetime, and `len <= isize::MAX`.
        // `data` is `this + OFFSET_DATA` (`data_ptr`'s postcondition), the
        // start of the `len` data bytes of the fresh `OFFSET_DATA + len`
        // allocation (non-null, in bounds, `len + OFFSET_DATA <= isize::MAX`
        // by the `Layout` check), and nothing else holds a pointer to it yet
        // (`this` is not used while `buf` lives). Any
        // bytes are a valid `MaybeUninit<u8>`; with `AllocInit::Zero` they are
        // zero (`alloc_zeroed`).
        let buf = unsafe { core::slice::from_raw_parts_mut(data.cast::<MaybeUninit<u8>>(), len) };
        initializer(buf);
        Ok(this)
    }

    /// # Safety
    ///
    /// The caller must ensure that `this` points to an allocation of at least
    /// `OFFSET_DATA` bytes starting at `this`.
    ///
    /// Returns `this + OFFSET_DATA` with the provenance of `this`: the first
    /// data byte of the inner (one past the end of the allocation when it
    /// has exactly `OFFSET_DATA` bytes).
    #[inline]
    unsafe fn data_ptr(this: NonNull<Self>) -> *mut u8 {
        // SAFETY: `add` needs the result in bounds (or one past the end) of the
        // allocation `this` points into, which the precondition gives.
        unsafe { this.as_ptr().cast::<u8>().add(OFFSET_DATA) }
    }

    /// # Safety
    ///
    /// The caller must ensure that `p` holds the `ArcStr` field invariant for
    /// the duration of the call.
    #[inline]
    unsafe fn get_len_flag(p: *const Self) -> PackedFlagUint {
        // SAFETY: `read` needs `p` (offset `OFFSET_LENFLAGS == 0`) valid for
        // reads of a `PackedFlagUint` and aligned, pointing to an initialized
        // value. Both inner forms start with an initialized 8-aligned `usize`
        // `len_flag` (`PackedFlagUint` is a transparent `usize`), and it is
        // never written while any handle exists, so this plain read cannot
        // race.
        unsafe { p.cast::<PackedFlagUint>().read() }
    }

    /// Frees a heap inner.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `p` points to a heap inner (`ArcStr`
    /// field invariant), that every earlier use of it happens-before this
    /// call, and that nothing uses it afterwards.
    #[cold]
    unsafe fn destroy_cold(p: *mut Self) {
        // SAFETY: a heap inner holds the `ArcStr` field invariant until it is
        // freed, which happens below.
        let lf = unsafe { Self::get_len_flag(p) };
        debug_assert!(!lf.flag_part());
        // `len_flag` was `(false, capacity)` at allocation and never written
        // since, so this is the layout it was allocated with, which
        // `Layout::from_size_align` accepted then.
        let layout = Layout::from_size_align(lf.uint_part() + OFFSET_DATA, align_of::<Self>());
        debug_assert!(layout.is_ok());
        let Ok(layout) = layout else {
            return;
        };
        // SAFETY: `dealloc` needs `p` allocated by the global allocator with
        // `layout`: a heap inner is allocated with
        // `Layout::from_size_align(len + OFFSET_DATA, 8)` (field invariant) and
        // `len` is the uint part read above. The caller guarantees no later
        // use and that earlier uses happen-before.
        unsafe { crate::std::alloc::dealloc(p.cast::<u8>(), layout) };
    }
}

#[derive(Clone, Copy, PartialEq)]
enum AllocInit {
    Uninit,
    Zero,
}

#[inline(never)]
#[cold]
fn alloc_overflow() -> ! {
    panic!("overflow during Layout computation")
}

impl From<&str> for ArcStr {
    #[inline]
    fn from(s: &str) -> Self {
        if s.is_empty() {
            Self::new()
        } else {
            // Field invariant: by `allocate`'s safety-usable invariant; this
            // handle takes over the count of 1.
            Self(ThinInner::allocate(s))
        }
    }
}

impl TryFrom<&[u8]> for ArcStr {
    type Error = core::str::Utf8Error;

    #[inline(always)]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let s = core::str::from_utf8(value)?;
        Ok(s.into())
    }
}

impl TryFrom<crate::std::vec::Vec<u8>> for ArcStr {
    type Error = crate::std::string::FromUtf8Error;

    #[inline(always)]
    fn try_from(value: crate::std::vec::Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(value)?;
        Ok(s.into())
    }
}

impl TryFrom<&crate::std::vec::Vec<u8>> for ArcStr {
    type Error = core::str::Utf8Error;

    #[inline(always)]
    fn try_from(value: &crate::std::vec::Vec<u8>) -> Result<Self, Self::Error> {
        let s = core::str::from_utf8(value)?;
        Ok(s.into())
    }
}

impl From<SmolStr> for ArcStr {
    #[inline(always)]
    fn from(s: SmolStr) -> Self {
        Self::from(s.as_str())
    }
}

impl From<&SmolStr> for ArcStr {
    #[inline(always)]
    fn from(s: &SmolStr) -> Self {
        Self::from(s.as_str())
    }
}

impl core::ops::Deref for ArcStr {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        // SAFETY: `from_utf8_unchecked` needs valid UTF-8: `as_bytes` returns
        // the data bytes, valid UTF-8 by the field invariant.
        unsafe { core::str::from_utf8_unchecked(self.as_bytes()) }
    }
}

impl Default for ArcStr {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl From<String> for ArcStr {
    #[inline]
    fn from(v: String) -> Self {
        v.as_str().into()
    }
}

impl From<&mut str> for ArcStr {
    #[inline]
    fn from(s: &mut str) -> Self {
        let s: &str = s;
        Self::from(s)
    }
}

impl From<Box<str>> for ArcStr {
    #[inline]
    fn from(s: Box<str>) -> Self {
        Self::from(&s[..])
    }
}
impl From<ArcStr> for Box<str> {
    #[inline]
    fn from(s: ArcStr) -> Self {
        s.as_str().into()
    }
}
impl From<ArcStr> for crate::std::rc::Rc<str> {
    #[inline]
    fn from(s: ArcStr) -> Self {
        s.as_str().into()
    }
}
impl From<ArcStr> for crate::std::Arc<str> {
    #[inline]
    fn from(s: ArcStr) -> Self {
        s.as_str().into()
    }
}
impl From<crate::std::rc::Rc<str>> for ArcStr {
    #[inline]
    fn from(s: crate::std::rc::Rc<str>) -> Self {
        Self::from(&*s)
    }
}
impl From<crate::std::Arc<str>> for ArcStr {
    #[inline]
    fn from(s: crate::std::Arc<str>) -> Self {
        Self::from(&*s)
    }
}
impl<'a> From<Cow<'a, str>> for ArcStr {
    #[inline]
    fn from(s: Cow<'a, str>) -> Self {
        Self::from(&*s)
    }
}
impl<'a> From<&'a ArcStr> for Cow<'a, str> {
    #[inline]
    fn from(s: &'a ArcStr) -> Self {
        Cow::Borrowed(s)
    }
}

impl<'a> From<ArcStr> for Cow<'a, str> {
    #[inline]
    fn from(s: ArcStr) -> Self {
        if let Some(st) = ArcStr::as_static(&s) {
            Cow::Borrowed(st)
        } else {
            Cow::Owned(s.to_string())
        }
    }
}

impl From<&String> for ArcStr {
    #[inline]
    fn from(s: &String) -> Self {
        Self::from(s.as_str())
    }
}
impl From<&Self> for ArcStr {
    #[inline]
    fn from(s: &Self) -> Self {
        s.clone()
    }
}

impl core::fmt::Debug for ArcStr {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl core::fmt::Display for ArcStr {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self.as_str(), f)
    }
}

impl PartialEq for ArcStr {
    #[inline]
    fn eq(&self, o: &Self) -> bool {
        Self::ptr_eq(self, o) || PartialEq::eq(self.as_str(), o.as_str())
    }
    #[inline]
    fn ne(&self, o: &Self) -> bool {
        !Self::ptr_eq(self, o) && PartialEq::ne(self.as_str(), o.as_str())
    }
}

impl Eq for ArcStr {}

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
    (ArcStr, str),
    (ArcStr, &'a str),
    (ArcStr, String),
    (ArcStr, Cow<'a, str>),
    (ArcStr, Box<str>),
    (ArcStr, crate::std::Arc<str>),
    (ArcStr, crate::std::rc::Rc<str>),
    (ArcStr, crate::std::Arc<String>),
    (ArcStr, crate::std::rc::Rc<String>),
}

impl PartialOrd for ArcStr {
    #[inline]
    #[allow(clippy::non_canonical_partial_ord_impl)]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArcStr {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl core::hash::Hash for ArcStr {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) {
        self.as_str().hash(h)
    }
}

macro_rules! impl_index {
    ($($IdxT:ty,)*) => {$(
        impl core::ops::Index<$IdxT> for ArcStr {
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

impl AsRef<str> for ArcStr {
    #[inline]
    fn as_ref(&self) -> &str {
        self
    }
}

impl AsRef<[u8]> for ArcStr {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::borrow::Borrow<str> for ArcStr {
    #[inline]
    fn borrow(&self) -> &str {
        self
    }
}

impl core::str::FromStr for ArcStr {
    type Err = core::convert::Infallible;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    // Heap handles count with loom atomics, usable only inside `loom::model`.
    #[cfg(not(loom))]
    use core::sync::atomic::AtomicPtr;

    /// Keep leaked strings reachable, so Miri's leak check accepts them.
    #[cfg(not(loom))]
    static LEAKED_IN_RACE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    #[cfg(not(loom))]
    static LEAKED_OUTLIVING: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

    #[test]
    #[cfg(not(loom))]
    fn leak_races_clone_and_len_on_a_shared_handle() {
        // `leak` on a handle that is the only owner of its count, while other
        // threads clone and read through the same handle: Miri reports a data
        // race if `leak` writes the header non-atomically.
        let a = ArcStr::from("hello world");
        std::thread::scope(|s| {
            s.spawn(|| {
                let leaked = a.leak();
                LEAKED_IN_RACE.store(
                    leaked.as_ptr().cast_mut(),
                    core::sync::atomic::Ordering::Relaxed,
                );
                assert_eq!(leaked, "hello world");
            });
            s.spawn(|| {
                let c = a.clone();
                assert_eq!(c.len(), 11);
            });
            s.spawn(|| {
                assert_eq!(a.len(), 11);
                assert_eq!(a.as_str(), "hello world");
            });
        });
        assert!(ArcStr::is_static(&a));
        assert_eq!(ArcStr::strong_count(&a), None);
    }

    #[test]
    #[cfg(not(loom))]
    fn leaked_str_outlives_every_handle() {
        let a = ArcStr::from(std::format!("{}-{}", "left", "right"));
        let b = a.clone();
        let leaked = a.leak();
        LEAKED_OUTLIVING.store(
            leaked.as_ptr().cast_mut(),
            core::sync::atomic::Ordering::Relaxed,
        );
        drop(a);
        drop(b);
        assert_eq!(leaked, "left-right");
    }

    #[test]
    #[cfg(not(loom))]
    fn empty_heap_allocations_are_valid() {
        let s = ArcStr::init_with(0, |_| {}).unwrap();
        assert_eq!(s, "");
        let s = ArcStr::try_alloc("").unwrap();
        assert_eq!(s, "");
    }

    #[test]
    #[cfg(not(loom))]
    fn init_with_invalid_utf8_frees_its_allocation() {
        let err = ArcStr::init_with(3, |buf| buf.copy_from_slice(b"a\xffb"));
        err.unwrap_err();
    }

    fn sasi_layout_check<Buf>() {
        assert!(align_of::<StaticArcStrInner<Buf>>() >= 8);
        assert_eq!(
            core::mem::offset_of!(StaticArcStrInner<Buf>, count_flag),
            OFFSET_COUNTFLAGS
        );
        assert_eq!(
            core::mem::offset_of!(StaticArcStrInner<Buf>, len_flag),
            OFFSET_LENFLAGS
        );
        assert_eq!(
            core::mem::offset_of!(StaticArcStrInner<Buf>, data),
            OFFSET_DATA
        );
        assert_eq!(
            core::mem::offset_of!(ThinInner, count_flag),
            core::mem::offset_of!(StaticArcStrInner::<Buf>, count_flag),
        );
        assert_eq!(
            core::mem::offset_of!(ThinInner, len_flag),
            core::mem::offset_of!(StaticArcStrInner::<Buf>, len_flag),
        );
        assert_eq!(
            core::mem::offset_of!(ThinInner, data),
            core::mem::offset_of!(StaticArcStrInner::<Buf>, data),
        );
    }

    #[test]
    fn verify_type_pun_offsets_sasi_big_bufs() {
        assert_eq!(
            core::mem::offset_of!(ThinInner, count_flag),
            OFFSET_COUNTFLAGS,
        );
        assert_eq!(core::mem::offset_of!(ThinInner, len_flag), OFFSET_LENFLAGS);
        assert_eq!(core::mem::offset_of!(ThinInner, data), OFFSET_DATA);

        assert!(align_of::<ThinInner>() >= 8);

        sasi_layout_check::<[u8; 0]>();
        sasi_layout_check::<[u8; 1]>();
        sasi_layout_check::<[u8; 2]>();
        sasi_layout_check::<[u8; 3]>();
        sasi_layout_check::<[u8; 4]>();
        sasi_layout_check::<[u8; 5]>();
        sasi_layout_check::<[u8; 15]>();
        sasi_layout_check::<[u8; 16]>();
        sasi_layout_check::<[u8; 64]>();
        sasi_layout_check::<[u8; 128]>();
        sasi_layout_check::<[u8; 1024]>();
        sasi_layout_check::<[u8; 4095]>();
        sasi_layout_check::<[u8; 4096]>();
    }
}

#[cfg(all(test, loom))]
mod loomtest {
    use super::ArcStr;
    use loom::sync::Arc;
    use loom::thread;
    #[test]
    fn cloning_threads() {
        loom::model(|| {
            let a = ArcStr::from("abcdefgh");
            let addr = a.as_ptr() as usize;

            let a1 = Arc::new(a);
            let a2 = a1.clone();

            let t1 = thread::spawn(move || {
                let b: ArcStr = (*a1).clone();
                assert_eq!(b.as_ptr() as usize, addr);
            });
            let t2 = thread::spawn(move || {
                let b: ArcStr = (*a2).clone();
                assert_eq!(b.as_ptr() as usize, addr);
            });

            t1.join().unwrap();
            t2.join().unwrap();
        });
    }
    #[test]
    fn drop_timing() {
        loom::model(|| {
            let a1 = std::vec![
                ArcStr::from("s1"),
                ArcStr::from("s2"),
                ArcStr::from("s3"),
                ArcStr::from("s4"),
            ];
            let a2 = a1.clone();

            let t1 = thread::spawn(move || {
                let mut a1 = a1;
                while let Some(s) = a1.pop() {
                    assert!(s.starts_with("s"));
                }
            });
            let t2 = thread::spawn(move || {
                let mut a2 = a2;
                while let Some(s) = a2.pop() {
                    assert!(s.starts_with("s"));
                }
            });

            t1.join().unwrap();
            t2.join().unwrap();
        });
    }

    #[test]
    fn leak_drop() {
        loom::model(|| {
            let a1 = ArcStr::from("foo");
            let a2 = a1.clone();

            let t1 = thread::spawn(move || {
                drop(a1);
            });
            let t2 = thread::spawn(move || a2.leak());
            t1.join().unwrap();
            let leaked: &'static str = t2.join().unwrap();
            assert_eq!(leaked, "foo");
        });
    }
}
