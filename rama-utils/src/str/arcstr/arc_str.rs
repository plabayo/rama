#![allow(
// We follow libstd's lead and prefer to define both.
    clippy::partialeq_ne_impl,
// This is a really annoying clippy lint, since it's required for so many cases...
    clippy::cast_ptr_alignment,
// For macros
    clippy::redundant_slicing,
)]
#[cfg(all(loom, test))]
pub(crate) use loom::sync::atomic::{AtomicUsize, Ordering};
use smol_str::SmolStr;
use std::alloc::Layout;
use std::mem::{MaybeUninit, align_of, size_of};
use std::ptr::NonNull;
#[cfg(not(all(loom, test)))]
pub(crate) use std::sync::atomic::{AtomicUsize, Ordering};

use std::borrow::Cow;
use std::boxed::Box;
use std::string::String;

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
///    # let _ = s;
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
pub struct ArcStr(NonNull<ThinInner>);

unsafe impl Sync for ArcStr {}
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
        if let Ok(inner) = ThinInner::try_allocate(copy_from, false) {
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
    /// The provided `initializer` callback must fully initialize the provided
    /// buffer with valid UTF-8 text.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// # use std::mem::MaybeUninit;
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
            // SAFETY: contract requests callee to ensure buffer is fully initialized
            unsafe { ThinInner::try_allocate_with(n, false, AllocInit::Uninit, initializer) }
        {
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
    /// The provided `initializer` callback must fully initialize the provided
    /// buffer with valid UTF-8 text.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// # use std::mem::MaybeUninit;
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
        // SAFETY: contract requests callee to ensure buffer is fully initialized
        match unsafe { ThinInner::try_allocate_with(n, false, AllocInit::Uninit, initializer) } {
            Ok(inner) => Self(inner),
            Err(None) => panic!("capacity overflow"),
            Err(Some(layout)) => std::alloc::handle_alloc_error(layout),
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
    pub fn init_with<F>(n: usize, initializer: F) -> Result<Self, std::str::Utf8Error>
    where
        F: FnOnce(&mut [u8]),
    {
        let mut failed = None::<std::str::Utf8Error>;
        let wrapper = |zeroed_slice: &mut [MaybeUninit<u8>]| {
            debug_assert_eq!(n, zeroed_slice.len());
            // Safety: we pass `AllocInit::Zero`, so this is actually initialized
            let slice = unsafe {
                std::slice::from_raw_parts_mut(zeroed_slice.as_mut_ptr().cast::<u8>(), n)
            };
            initializer(slice);
            if let Err(e) = std::str::from_utf8(slice) {
                failed = Some(e);
            }
        };
        match unsafe { ThinInner::try_allocate_with(n, false, AllocInit::Zero, wrapper) } {
            Ok(inner) => {
                // Ensure we clean up the allocation even on error.
                let this = Self(inner);
                if let Some(e) = failed {
                    Err(e)
                } else {
                    Ok(this)
                }
            }
            Err(None) => panic!("capacity overflow"),
            Err(Some(layout)) => std::alloc::handle_alloc_error(layout),
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

    /// Convert us to a `std::string::String`.
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
        let len = self.len();
        let p = self.0.as_ptr();
        unsafe {
            let data = p.cast::<u8>().add(OFFSET_DATA);
            debug_assert_eq!(std::ptr::addr_of!((*p).data).cast::<u8>(), data);
            std::slice::from_raw_parts(data, len)
        }
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
    /// let s = unsafe { ArcStr::from_raw(p) };
    /// assert_eq!(s, "abcd");
    /// ```
    #[inline]
    #[must_use]
    pub fn into_raw(this: Self) -> NonNull<()> {
        let p = this.0;
        #[allow(clippy::mem_forget)]
        std::mem::forget(this);
        p.cast()
    }

    /// The opposite version of [`Self::into_raw`]. Still intended only for
    /// advanced use cases.
    ///
    /// # Safety
    ///
    /// This function must be used on a valid pointer returned from
    /// [`ArcStr::into_raw`]. Additionally, you must ensure that a given `ArcStr`
    /// instance is only dropped once.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rama_utils::str::arcstr::ArcStr;
    /// let s = ArcStr::from("abcd");
    /// let p = ArcStr::into_raw(s);
    /// // Some time later...
    /// let s = unsafe { ArcStr::from_raw(p) };
    /// assert_eq!(s, "abcd");
    /// ```
    #[inline]
    #[must_use]
    pub unsafe fn from_raw(ptr: NonNull<()>) -> Self {
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
        std::ptr::eq(lhs.0.as_ptr(), rhs.0.as_ptr())
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
    /// # Safety
    ///
    /// This method by itself is safe, but using it correctly requires extra
    /// care. Another thread can change the strong count at any time, including
    /// potentially between calling this method and acting on the result.
    ///
    /// However, it may never change from `None` to `Some` or from `Some` to
    /// `None` for a given `ArcStr` — whether or not it is static is determined
    /// at construction, and never changes.
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

    /// Safety: Unsafe to use `this` is stored in static memory (check
    /// `Self::has_static_lenflag`)
    #[inline]
    unsafe fn load_count_flag_raw(this: &Self, ord_if_needed: Ordering) -> PackedFlagUint {
        PackedFlagUint::from_encoded(unsafe { (*this.0.as_ptr()).count_flag.load(ord_if_needed) })
    }

    #[inline]
    fn load_count_flag(this: &Self, ord_if_needed: Ordering) -> Option<PackedFlagUint> {
        if Self::has_static_lenflag(this) {
            None
        } else {
            let count_and_flag = PackedFlagUint::from_encoded(unsafe {
                (*this.0.as_ptr()).count_flag.load(ord_if_needed)
            });
            Some(count_and_flag)
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
        if Self::has_static_lenflag(self) {
            return unsafe { Self::to_static_unchecked(self) };
        }
        let is_static_count = unsafe {
            // Not sure about ordering, maybe relaxed would be fine.
            Self::load_count_flag_raw(self, Ordering::Acquire)
        };
        if is_static_count.flag_part() {
            return unsafe { Self::to_static_unchecked(self) };
        }
        unsafe { Self::become_static(self, is_static_count.uint_part() == 1) };
        debug_assert!(Self::is_static(self));
        unsafe { Self::to_static_unchecked(self) }
    }

    unsafe fn become_static(this: &Self, is_unique: bool) {
        if is_unique {
            // SAFETY: inner pointer is per contract always valid
            unsafe {
                std::ptr::addr_of_mut!((*this.0.as_ptr()).count_flag).write(AtomicUsize::new(
                    PackedFlagUint::new_raw(true, 1).encoded_value(),
                ));
            }
            // SAFETY: inner pointer is per contract always valid
            let lenp = unsafe { std::ptr::addr_of_mut!((*this.0.as_ptr()).len_flag) };
            // SAFETY: packed flag is per contract always valid,
            // so reading is fine
            debug_assert!(!unsafe { lenp.read() }.flag_part());
            // SAFETY: packed flag is per contract always valid,
            // so reading & writing is fine
            unsafe { lenp.write(lenp.read().with_flag(true)) };
        } else {
            let flag_bit = PackedFlagUint::new_raw(true, 0).encoded_value();
            // SAFETY: inner pointer is per contract always valid
            let atomic_count_flag = unsafe { &*std::ptr::addr_of!((*this.0.as_ptr()).count_flag) };
            atomic_count_flag.fetch_or(flag_bit, Ordering::Release);
        }
    }

    #[inline]
    unsafe fn to_static_unchecked(this: &Self) -> &'static str {
        // SAFETY: by mutual contract this operation is fine
        unsafe { &*Self::str_ptr(this) }
    }

    #[inline]
    fn bytes_ptr(this: &Self) -> *const [u8] {
        let len = this.get_inner_len_flag().uint_part();
        unsafe {
            let p: *const ThinInner = this.0.as_ptr();
            let data = p.cast::<u8>().add(OFFSET_DATA);
            debug_assert_eq!(std::ptr::addr_of!((*p).data).cast::<u8>(), data,);
            std::ptr::slice_from_raw_parts(data, len)
        }
    }

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
        this.get_inner_len_flag().flag_part()
            || unsafe { Self::load_count_flag_raw(this, Ordering::Relaxed).flag_part() }
    }

    /// This is true for any `ArcStr` that has been static from the time when it
    /// was created. It's cheaper than `has_static_rcflag`.
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
            // We know static strings live forever, so they can have a static lifetime.
            Some(unsafe { &*(this.as_str() as *const str) })
        } else {
            None
        }
    }

    // Not public API. Exists so the `arcstr!` macro can call it.
    #[inline]
    #[doc(hidden)]
    pub const unsafe fn _private_new_from_static_data<B>(
        ptr: &'static StaticArcStrInner<B>,
    ) -> Self {
        // SAFETY: ThisInner's contract upholds the needed guarantees
        Self(unsafe { NonNull::new_unchecked(ptr as *const _ as *mut ThinInner) })
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
    pub fn substr(&self, range: impl std::ops::RangeBounds<usize>) -> Substr {
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
        let inner =
            ThinInner::try_allocate_maybe_uninit(capacity, false, AllocInit::Uninit).ok()?;

        unsafe {
            let mut data_ptr = ThinInner::data_ptr(inner);
            let data_end = data_ptr.add(capacity);

            // Copy `source` into the allocated string `n` times
            while data_ptr < data_end {
                std::ptr::copy_nonoverlapping(source.as_ptr(), data_ptr, source.len());
                data_ptr = data_ptr.add(source.len());
            }
        }

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
            // From libstd's impl:
            //
            // > Using a relaxed ordering is alright here, as knowledge of the
            // > original reference prevents other threads from erroneously deleting
            // > the object.
            //
            // See: https://doc.rust-lang.org/src/alloc/sync.rs.html#1073
            let n: PackedFlagUint = PackedFlagUint::from_encoded(unsafe {
                let step = PackedFlagUint::FALSE_ONE.encoded_value();
                (*self.0.as_ptr())
                    .count_flag
                    .fetch_add(step, Ordering::Relaxed)
            });
            // Protect against aggressive leaking of Arcs causing us to
            // overflow. Technically, we could probably transition it to static
            // here, but I haven't thought it through.
            if n.uint_part() > RC_MAX && !n.flag_part() {
                let val = PackedFlagUint::new_raw(true, 0).encoded_value();
                unsafe {
                    (*self.0.as_ptr())
                        .count_flag
                        .fetch_or(val, Ordering::Release)
                };
                // abort();
            }
        }
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
        unsafe {
            let this = self.0.as_ptr();
            let enc = PackedFlagUint::from_encoded(
                (*this)
                    .count_flag
                    .fetch_sub(PackedFlagUint::FALSE_ONE.encoded_value(), Ordering::Release),
            );
            // Note: `enc == PackedFlagUint::FALSE_ONE`
            if enc == PackedFlagUint::FALSE_ONE {
                let _ = (*this).count_flag.load(Ordering::Acquire);
                ThinInner::destroy_cold(this)
            }
        }
    }
}
// Caveat on the `static`/`strong` fields: "is_static" indicates if we're
// located in static data (as with empty string). is_static being false meanse
// we are a normal arc-ed string.
//
// While `ArcStr` claims to hold a pointer to a `ThinInner`, for the static case
// we actually are using a pointer to a `StaticArcStrInner<[u8; N]>`. These have
// almost identical layouts, except the static contains a explicit trailing
// array, and does not have a `AtomicUsize` The issue is: We kind of want the
// static ones to not have any interior mutability, so that `const`s can use
// them, and so that they may be stored in read-only memory.
//
// We do this by keeping a flag in `len_flag` flag to indicate which case we're
// in, and maintaining the invariant that if we're a `StaticArcStrInner` **we
// may never access `.strong` in any way or produce a `&ThinInner` pointing to
// our data**.
//
// This is more subtle than you might think, sinc AFAIK we're not legally
// allowed to create an `&ThinInner` until we're 100% sure it's nonstatic, and
// prior to determining it, we are forced to work from entirely behind a raw
// pointer...
//
// That said, a bit of this hoop jumping might be not required in the future,
// but for now what we're doing works and is apparently sound:
// https://github.com/rust-lang/unsafe-code-guidelines/issues/246
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

    #[inline(always)]
    #[must_use]
    const fn with_flag(self, v: bool) -> Self {
        Self(v as usize | self.0)
    }
}

const EMPTY: ArcStr = super::arcstr!("");

impl ThinInner {
    #[inline]
    fn allocate(data: &str, initially_static: bool) -> NonNull<Self> {
        match Self::try_allocate(data, initially_static) {
            Ok(v) => v,
            Err(None) => alloc_overflow(),
            Err(Some(layout)) => std::alloc::handle_alloc_error(layout),
        }
    }

    #[inline]
    fn data_ptr(this: NonNull<Self>) -> *mut u8 {
        unsafe { this.as_ptr().cast::<u8>().add(OFFSET_DATA) }
    }

    /// Allocates a `ThinInner` where the data segment is uninitialized or
    /// zeroed.
    ///
    /// Returns `Err(Some(layout))` if we failed to allocate that layout, and
    /// `Err(None)` for integer overflow when computing layout
    fn try_allocate_maybe_uninit(
        capacity: usize,
        initially_static: bool,
        init_how: AllocInit,
    ) -> Result<NonNull<Self>, Option<Layout>> {
        const ALIGN: usize = align_of::<ThinInner>();

        debug_assert_ne!(capacity, 0);
        if capacity >= (isize::MAX as usize) - (OFFSET_DATA + ALIGN) {
            return Err(None);
        }

        debug_assert!(Layout::from_size_align(capacity + OFFSET_DATA, ALIGN).is_ok());
        let layout = unsafe { Layout::from_size_align_unchecked(capacity + OFFSET_DATA, ALIGN) };
        let ptr = match init_how {
            AllocInit::Uninit => unsafe { std::alloc::alloc(layout) as *mut Self },
            AllocInit::Zero => unsafe { std::alloc::alloc_zeroed(layout) as *mut Self },
        };
        if ptr.is_null() {
            return Err(Some(layout));
        }

        // we actually already checked this above...
        debug_assert!(PackedFlagUint::new(initially_static, capacity).is_some());

        let len_flag = PackedFlagUint::new_raw(initially_static, capacity);
        debug_assert_eq!(len_flag.uint_part(), capacity);
        debug_assert_eq!(len_flag.flag_part(), initially_static);

        unsafe {
            std::ptr::addr_of_mut!((*ptr).len_flag).write(len_flag);

            let initial_count_flag = PackedFlagUint::new_raw(initially_static, 1);
            let count_flag: AtomicUsize = AtomicUsize::new(initial_count_flag.encoded_value());
            std::ptr::addr_of_mut!((*ptr).count_flag).write(count_flag);

            debug_assert_eq!(
                (ptr as *const u8).wrapping_add(OFFSET_DATA),
                (*ptr).data.as_ptr(),
            );

            Ok(NonNull::new_unchecked(ptr))
        }
    }

    // returns `Err(Some(l))` if we failed to allocate that layout, and
    // `Err(None)` for integer overflow when computing layout.
    #[inline]
    fn try_allocate(data: &str, initially_static: bool) -> Result<NonNull<Self>, Option<Layout>> {
        // Safety: we initialize the whole buffer by copying `data` into it.
        unsafe {
            // Allocate a enough space to hold the given string
            Self::try_allocate_with(
                data.len(),
                initially_static,
                AllocInit::Uninit,
                // Copy the given string into the allocation
                |uninit_slice| {
                    debug_assert_eq!(uninit_slice.len(), data.len());
                    std::ptr::copy_nonoverlapping(
                        data.as_ptr(),
                        uninit_slice.as_mut_ptr().cast::<u8>(),
                        data.len(),
                    )
                },
            )
        }
    }

    /// Safety: caller must fully initialize the provided buffer with valid
    /// UTF-8 in the `initializer` function (well, you at least need to handle
    /// it before giving it back to the user).
    #[inline]
    unsafe fn try_allocate_with(
        len: usize,
        initially_static: bool,
        init_style: AllocInit,
        initializer: impl FnOnce(&mut [std::mem::MaybeUninit<u8>]),
    ) -> Result<NonNull<Self>, Option<Layout>> {
        // Allocate a enough space to hold the given string
        let this = Self::try_allocate_maybe_uninit(len, initially_static, init_style)?;

        // SAFETY: initialised above
        initializer(unsafe {
            std::slice::from_raw_parts_mut(Self::data_ptr(this).cast::<MaybeUninit<u8>>(), len)
        });

        Ok(this)
    }

    #[inline]
    unsafe fn get_len_flag(p: *const Self) -> PackedFlagUint {
        debug_assert_eq!(OFFSET_LENFLAGS, 0);
        // SAFETY: valid by mutual conract of ThisInner and the callee
        unsafe { *p.cast() }
    }

    #[cold]
    unsafe fn destroy_cold(p: *mut Self) {
        // SAFETY: valid by mutual conract of ThisInner and the callee
        let lf = unsafe { Self::get_len_flag(p) };
        let (is_static, len) = (lf.flag_part(), lf.uint_part());
        debug_assert!(!is_static);
        let layout = {
            let size = len + OFFSET_DATA;
            let align = align_of::<Self>();
            // SAFETY: valid by mutual conract of ThisInner and the callee
            unsafe { Layout::from_size_align_unchecked(size, align) }
        };
        // SAFETY: valid by mutual conract of ThisInner and the callee
        unsafe { std::alloc::dealloc(p as *mut _, layout) };
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
            Self(ThinInner::allocate(s, false))
        }
    }
}

impl TryFrom<&[u8]> for ArcStr {
    type Error = std::str::Utf8Error;

    #[inline(always)]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(value)?;
        Ok(s.into())
    }
}

impl TryFrom<Vec<u8>> for ArcStr {
    type Error = std::string::FromUtf8Error;

    #[inline(always)]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(value)?;
        Ok(s.into())
    }
}

impl TryFrom<&Vec<u8>> for ArcStr {
    type Error = std::str::Utf8Error;

    #[inline(always)]
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(value)?;
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

impl std::ops::Deref for ArcStr {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.as_bytes()) }
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
impl From<ArcStr> for std::rc::Rc<str> {
    #[inline]
    fn from(s: ArcStr) -> Self {
        s.as_str().into()
    }
}
impl From<ArcStr> for std::sync::Arc<str> {
    #[inline]
    fn from(s: ArcStr) -> Self {
        s.as_str().into()
    }
}
impl From<std::rc::Rc<str>> for ArcStr {
    #[inline]
    fn from(s: std::rc::Rc<str>) -> Self {
        Self::from(&*s)
    }
}
impl From<std::sync::Arc<str>> for ArcStr {
    #[inline]
    fn from(s: std::sync::Arc<str>) -> Self {
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

impl std::fmt::Debug for ArcStr {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl std::fmt::Display for ArcStr {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.as_str(), f)
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
    (ArcStr, std::sync::Arc<str>),
    (ArcStr, std::rc::Rc<str>),
    (ArcStr, std::sync::Arc<String>),
    (ArcStr, std::rc::Rc<String>),
}

impl PartialOrd for ArcStr {
    #[inline]
    #[allow(clippy::non_canonical_partial_ord_impl)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArcStr {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl std::hash::Hash for ArcStr {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        self.as_str().hash(h)
    }
}

macro_rules! impl_index {
    ($($IdxT:ty,)*) => {$(
        impl std::ops::Index<$IdxT> for ArcStr {
            type Output = str;
            #[inline]
            fn index(&self, i: $IdxT) -> &Self::Output {
                &self.as_str()[i]
            }
        }
    )*};
}

impl_index! {
    std::ops::RangeFull,
    std::ops::Range<usize>,
    std::ops::RangeFrom<usize>,
    std::ops::RangeTo<usize>,
    std::ops::RangeInclusive<usize>,
    std::ops::RangeToInclusive<usize>,
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

impl std::borrow::Borrow<str> for ArcStr {
    #[inline]
    fn borrow(&self) -> &str {
        self
    }
}

impl std::str::FromStr for ArcStr {
    type Err = std::convert::Infallible;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn sasi_layout_check<Buf>() {
        assert!(align_of::<StaticArcStrInner<Buf>>() >= 8);
        assert_eq!(
            std::mem::offset_of!(StaticArcStrInner<Buf>, count_flag),
            OFFSET_COUNTFLAGS
        );
        assert_eq!(
            std::mem::offset_of!(StaticArcStrInner<Buf>, len_flag),
            OFFSET_LENFLAGS
        );
        assert_eq!(
            std::mem::offset_of!(StaticArcStrInner<Buf>, data),
            OFFSET_DATA
        );
        assert_eq!(
            std::mem::offset_of!(ThinInner, count_flag),
            std::mem::offset_of!(StaticArcStrInner::<Buf>, count_flag),
        );
        assert_eq!(
            std::mem::offset_of!(ThinInner, len_flag),
            std::mem::offset_of!(StaticArcStrInner::<Buf>, len_flag),
        );
        assert_eq!(
            std::mem::offset_of!(ThinInner, data),
            std::mem::offset_of!(StaticArcStrInner::<Buf>, data),
        );
    }

    #[test]
    fn verify_type_pun_offsets_sasi_big_bufs() {
        assert_eq!(
            std::mem::offset_of!(ThinInner, count_flag),
            OFFSET_COUNTFLAGS,
        );
        assert_eq!(std::mem::offset_of!(ThinInner, len_flag), OFFSET_LENFLAGS);
        assert_eq!(std::mem::offset_of!(ThinInner, data), OFFSET_DATA);

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
