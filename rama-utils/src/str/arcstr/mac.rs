/// Create a const [`ArcStr`](crate::str::arcstr::ArcStr) from a string literal. The
/// resulting `ArcStr` require no heap allocation, can be freely cloned and used
/// interchangeably with `ArcStr`s from the heap, and are effectively "free".
///
/// The main downside is that it's a macro. Eventually it may be doable as a
/// `const fn`, which would be cleaner, but for now the drawbacks to this are
/// not overwhelming, and the functionality it provides is very useful.
///
/// # Usage
///
/// ```
/// # use rama_utils::str::arcstr::{ArcStr, arcstr};
/// // Works in const:
/// const MY_ARCSTR: ArcStr = arcstr!("testing testing");
/// assert_eq!(MY_ARCSTR, "testing testing");
///
/// // Or, just in normal expressions.
/// assert_eq!("Wow!", arcstr!("Wow!"));
/// ```
///
/// Another motivating use case is bundled files:
///
/// ```rust,ignore
/// use rama_utils::str::arcstr::{ArcStr, arcstr};
/// const VERY_IMPORTANT_FILE: ArcStr =
///     arcstr!(include_str!("./very-important.txt"));
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! __arcstr {
    ($text:expr $(,)?) => {{
        // Note: extra scope to reduce the size of what's in `$text`'s scope
        // (note that consts in macros dont have hygene the way let does).
        const __ARC_STR_TEXT: &$crate::str::arcstr::_private::str = $text;
        {
            #[allow(clippy::declare_interior_mutable_const)]
            const __ARC_STR_SI: &$crate::str::arcstr::_private::StaticArcStrInner<[$crate::str::arcstr::_private::u8; __ARC_STR_TEXT.len()]> = unsafe {
                &$crate::str::arcstr::_private::StaticArcStrInner {
                    len_flag: match $crate::str::arcstr::_private::StaticArcStrInner::<[$crate::str::arcstr::_private::u8; __ARC_STR_TEXT.len()]>::encode_len(__ARC_STR_TEXT.len()) {
                        Some(len) => len,
                        None => panic!("impossibly long length")
                    },
                    count_flag: $crate::str::arcstr::_private::STATIC_COUNT_VALUE,
                    // See comment for `_private::ConstPtrDeref` for what the hell's
                    // going on here.
                    data: *$crate::str::arcstr::_private::ConstPtrDeref::<[$crate::str::arcstr::_private::u8; __ARC_STR_TEXT.len()]> {
                        p: __ARC_STR_TEXT.as_ptr(),
                    }
                    .a,
                    // data: __ARC_STR_TEXT.as_ptr().cast::<[$crate::str::arcstr::_private::u8; __ARC_STR_TEXT.len()]>().read(),
                }
            };
            #[allow(clippy::declare_interior_mutable_const)]
            const __ARC_STR_FINAL: $crate::str::arcstr::ArcStr = unsafe { $crate::str::arcstr::ArcStr::_private_new_from_static_data(__ARC_STR_SI) };
            __ARC_STR_FINAL
        }
    }};
}

/// Constant format a string and create an arcstr from it with 0 memory overhead.
///
/// # Example
///
/// ```
/// use rama_utils::str::arcstr::format_arcstr;
/// let arcstr = format_arcstr!("testing {}", 123usize);
/// assert_eq!(arcstr, "testing 123");
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! __format_arcstr {
    ($format_string:expr $( $(, $expr:expr )+ )? $(,)? ) => {
        $crate::str::arcstr::arcstr!(
            $crate::str::arcstr::_private::formatcp!(
                $format_string $( $(, $expr )+ )?
            )
        )
    };
}

/// Create a `const` [`Substr`][crate::str::arcstr::Substr].
///
/// This is a wrapper that initializes a `Substr` over the entire contents of a
/// `const` [`ArcStr`](crate::str::arcstr::ArcStr) made using [arcstr!](crate::str::arcstr::arcstr).
///
/// As with `arcstr::literal`, these require no heap allocation, can be freely
/// cloned and used interchangeably with `ArcStr`s from the heap, and are
/// effectively "free".
///
/// The main use case here is in applications where `Substr` is a much more
/// common string type than `ArcStr`.
///
/// # Examples
///
/// ```
/// use rama_utils::str::arcstr::{Substr, substr};
/// // Works in const:
/// const EXAMPLE_SUBSTR: Substr = substr!("testing testing");
/// assert_eq!(EXAMPLE_SUBSTR, "testing testing");
///
/// // Or, just in normal expressions.
/// assert_eq!("Wow!", substr!("Wow!"));
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! __substr {
    ($text:expr $(,)?) => {{
        const __S: &$crate::str::arcstr::_private::str = $text;
        {
            const PARENT: $crate::str::arcstr::ArcStr = $crate::str::arcstr::arcstr!(__S);
            const SUBSTR: $crate::str::arcstr::Substr =
                unsafe { $crate::str::arcstr::Substr::from_parts_unchecked(PARENT, 0..__S.len()) };
            SUBSTR
        }
    }};
}

#[cfg(test)]
mod test {
    use crate::str::arcstr::{arcstr, substr};

    #[cfg(not(loom))]
    use crate::str::arcstr::format_arcstr;

    #[test]
    fn ensure_no_import() {
        let v = arcstr!("foo");
        assert_eq!(v, "foo");
        {
            let substr = substr!("bar");
            assert_eq!(substr, "bar");
        }
        // Loom doesn't like it if you do things outside `loom::model`, AFAICT.
        // These calls produce error messages from inside `libstd` about
        // accessing thread_locals that haven't been initialized.
        #[cfg(not(loom))]
        {
            let test = format_arcstr!("foo");
            assert_eq!(test, "foo");

            const NUMBER: usize = 123;
            let test2 = format_arcstr!("foo {NUMBER}");
            assert_eq!(test2, "foo 123");

            let test3 = format_arcstr!("foo {}", 123usize);
            assert_eq!(test3, "foo 123");
        }
    }
}
