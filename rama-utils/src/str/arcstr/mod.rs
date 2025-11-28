//! # Better reference counted strings
//!
//! > Fork of <https://github.com/thomcc/arcstr/>
//! >
//! > License and version information can be found at
//! > <https://github.com/plabayo/rama/tree/main/docs/thirdparty/fork>.
//!
//! This crate defines [`ArcStr`], a type similar to `Arc<str>`, but with a
//! number of new features and functionality. There's a list of
//! [benefits][benefits] in the `ArcStr` documentation comment which covers some
//! of the reasons you might want to use it over other alternatives.
//!
//! Additionally, if the `substr` feature is enabled (and it is by default), we
//! provide a [`Substr`] type which is essentially a `(ArcStr, Range<usize>)`
//! with better ergonomics and more functionality, which represents a shared
//! slice of a "parent" `ArcStr` (note that in reality, `u32` is used for the
//! index type, but this is not exposed in the API, and can be transparently
//! changed via a cargo feature).
//!
//! [benefits]: struct.ArcStr.html#benefits-of-arcstr-over-arcstr
//!
//! ## Feature overview
//!
//! A quick tour of the distinguishing features:
//!
//! ```
//! use rama_utils::str::arcstr::{ArcStr, arcstr};
//!
//! // Works in const:
//! const MY_ARCSTR: ArcStr = arcstr!("amazing constant");
//! assert_eq!(MY_ARCSTR, "amazing constant");
//!
//! // `arcstr!` input can come from `include_str!` too:
//! # // We have to fake it here, but this has test coverage and such.
//! # const _: &str = stringify!{
//! const MY_ARCSTR: ArcStr = arcstr!(include_str!("my-best-files.txt"));
//! # };
//! ```
//!
//! Or, you can define the literals in normal expressions. Note that these
//! literals are essentially ["Zero Cost"][zero-cost]. Specifically, below we
//! not only avoid allocating any heap memory to instantiate `wow` or any of
//! the clones, we also don't have to perform any atomic reads or writes.
//!
//! [zero-cost]: struct.ArcStr.html#what-does-zero-cost-literals-mean
//!
//! ```
//! use rama_utils::str::arcstr::{ArcStr, arcstr};
//!
//! let wow: ArcStr = arcstr!("Wow!");
//! assert_eq!("Wow!", wow);
//! // This line is probably not something you want to do regularly,
//! // but causes no extra allocations, nor performs any atomic reads
//! // nor writes.
//! let wowzers = wow.clone().clone().clone().clone();
//!
//! // At some point in the future, we can get a `&'static str` out of one
//! // of the literal `ArcStr`s too. Note that this returns `None` for
//! // a dynamically allocated `ArcStr`:
//! let static_str: Option<&'static str> = ArcStr::as_static(&wowzers);
//! assert_eq!(static_str, Some("Wow!"));
//! ```
//!
//! Of course, this is in addition to the typical functionality you might find in a
//! non-borrowed string type (with the caveat that there is explicitly no way to
//! mutate `ArcStr`).

#[macro_use]
mod mac;
mod arc_str;
mod impl_serde;
pub use arc_str::ArcStr;

mod substr;
pub use substr::Substr;

#[doc(inline)]
pub use crate::__arcstr as arcstr;

#[doc(inline)]
pub use crate::__format_arcstr as format_arcstr;

#[doc(inline)]
pub use crate::__substr as substr;

// Not public API, exists for macros
#[doc(hidden)]
pub mod _private {
    // Not part of public API. Transmutes a `*const u8` to a `&[u8; N]`.
    //
    // As of writing this, it's unstable to directly deref a raw pointer in
    // const code. We can get around this by transmuting (using the
    // const-transmute union trick) to transmute from `*const u8` to `&[u8; N]`,
    // and the dereferencing that.
    //
    // ... I'm a little surprised that this is allowed, but in general I do
    // remember a motivation behind stabilizing transmute in `const fn` was that
    // the union trick existed as a workaround.
    //
    // Anyway, this trick is courtesy of rodrimati1992 (that means you have to
    // blame them if it blows up :p).
    #[repr(C)]
    pub union ConstPtrDeref<Arr: Copy + 'static> {
        pub p: *const u8,
        pub a: &'static Arr,
    }

    pub use super::arc_str::{STATIC_COUNT_VALUE, StaticArcStrInner};
    pub use ::const_format::formatcp;
    pub use std::primitive::{str, u8};
}
