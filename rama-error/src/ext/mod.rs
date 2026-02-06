use std::fmt;

mod backtrace;
mod context;

use crate::BoxError;

/// Extends the `Result` and `Option` types with methods for adding context to errors.
///
/// See the [module level documentation](crate) for more information.
pub trait ErrorContext: private::SealedErrorContext {
    /// The resulting contexct type after adding context to the contained error.
    type Context;

    /// Return a err variant for [`Self::Context`] as [`BoxError`].
    fn into_box_error(self) -> Self::Context;

    /// Add context to the contained error.
    fn context<M>(self, value: M) -> Self::Context
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static;

    /// Add context to the contained error,
    /// using [`fmt::Debug`] as `[fmt::Display`].
    fn context_debug<M>(self, value: M) -> Self::Context
    where
        M: fmt::Debug + Send + Sync + 'static;

    /// Add keyed context to the contained error.
    fn context_field<M>(self, key: &'static str, value: M) -> Self::Context
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static;

    /// Same as [`Self::context_field`] but using a string-like value,
    /// this is useful in case you need to pass a string slice which is borrowed
    /// and thus cannot be passed as part of 'static error.
    fn context_str_field<M>(self, key: &'static str, value: M) -> Self::Context
    where
        M: Into<String>;

    /// Add keyed context to the contained error
    /// using [`fmt::Debug`] as `[fmt::Display`].
    fn context_debug_field<M>(self, key: &'static str, value: M) -> Self::Context
    where
        M: fmt::Debug + Send + Sync + 'static;

    /// Lazily add a context to the contained error, if it exists.
    fn with_context<C, F>(self, cb: F) -> Self::Context
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C;

    /// Lazily add a context to the contained error, if it exists.
    /// using [`fmt::Debug`] as `[fmt::Display`].
    fn with_context_debug<C, F>(self, cb: F) -> Self::Context
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C;

    /// Lazily add keyed context to the contained error, if it exists.
    fn with_context_field<C, F>(self, key: &'static str, cb: F) -> Self::Context
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C;

    /// Same as [`Self::with_context_field`] but using a string-like value,
    /// this is useful in case you need to pass a string slice which is borrowed
    /// and thus cannot be passed as part of 'static error.
    fn with_context_str_field<C, F>(self, key: &'static str, cb: F) -> Self::Context
    where
        C: Into<String>,
        F: FnOnce() -> C;

    /// Lazily add keyed context to the contained error, if it exists
    /// using [`fmt::Debug`] as `[fmt::Display`].
    fn with_context_debug_field<C, F>(self, key: &'static str, cb: F) -> Self::Context
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<T, E: Into<BoxError>> ErrorContext for Result<T, E> {
    type Context = Result<T, BoxError>;

    #[inline(always)]
    fn into_box_error(self) -> Self::Context {
        self.map_err(Into::into)
    }

    #[inline(always)]
    fn context<M>(self, value: M) -> Self::Context
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|error| error.context(value))
    }

    #[inline(always)]
    fn context_debug<M>(self, value: M) -> Self::Context
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.map_err(|error| error.context_debug(value))
    }

    #[inline(always)]
    fn context_field<M>(self, key: &'static str, value: M) -> Self::Context
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|error| error.context_field(key, value))
    }

    #[inline(always)]
    fn context_str_field<M>(self, key: &'static str, value: M) -> Self::Context
    where
        M: Into<String>,
    {
        self.map_err(|error| error.context_str_field(key, value))
    }

    #[inline(always)]
    fn context_debug_field<M>(self, key: &'static str, value: M) -> Self::Context
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.map_err(|error| error.context_debug_field(key, value))
    }

    #[inline(always)]
    fn with_context<C, F>(self, cb: F) -> Self::Context
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|error| error.with_context(cb))
    }

    #[inline(always)]
    fn with_context_debug<C, F>(self, cb: F) -> Self::Context
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|error| error.with_context_debug(cb))
    }

    #[inline(always)]
    fn with_context_field<C, F>(self, key: &'static str, cb: F) -> Self::Context
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|error| error.with_context_field(key, cb))
    }

    #[inline(always)]
    fn with_context_str_field<C, F>(self, key: &'static str, cb: F) -> Self::Context
    where
        C: Into<String>,
        F: FnOnce() -> C,
    {
        self.map_err(|error| error.with_context_str_field(key, cb))
    }

    #[inline(always)]
    fn with_context_debug_field<C, F>(self, key: &'static str, cb: F) -> Self::Context
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|error| error.with_context_debug_field(key, cb))
    }
}

impl<T> ErrorContext for Option<T> {
    type Context = Result<T, BoxError>;

    fn into_box_error(self) -> Self::Context {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None")
                .context_debug_field("type", std::any::type_name::<Self>())),
        }
    }

    fn context<M>(self, value: M) -> Self::Context
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None")
                .context_debug_field("type", std::any::type_name::<Self>())
                .context(value)),
        }
    }

    fn context_debug<M>(self, value: M) -> Self::Context
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None")
                .context_debug_field("type", std::any::type_name::<Self>())
                .context_debug(value)),
        }
    }

    fn context_field<M>(self, key: &'static str, value: M) -> Self::Context
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None")
                .context_debug_field("type", std::any::type_name::<Self>())
                .context_field(key, value)),
        }
    }

    fn context_str_field<M>(self, key: &'static str, value: M) -> Self::Context
    where
        M: Into<String>,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None")
                .context_debug_field("type", std::any::type_name::<Self>())
                .context_str_field(key, value)),
        }
    }

    fn context_debug_field<M>(self, key: &'static str, value: M) -> Self::Context
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None")
                .context_debug_field("type", std::any::type_name::<Self>())
                .context_debug_field(key, value)),
        }
    }

    fn with_context<C, F>(self, cb: F) -> Self::Context
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None")
                .context_debug_field("type", std::any::type_name::<Self>())
                .with_context(cb)),
        }
    }

    fn with_context_debug<C, F>(self, cb: F) -> Self::Context
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None")
                .context_debug_field("type", std::any::type_name::<Self>())
                .with_context_debug(cb)),
        }
    }

    fn with_context_field<C, F>(self, key: &'static str, cb: F) -> Self::Context
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None")
                .context_debug_field("type", std::any::type_name::<Self>())
                .with_context_field(key, cb)),
        }
    }

    fn with_context_str_field<C, F>(self, key: &'static str, cb: F) -> Self::Context
    where
        C: Into<String>,
        F: FnOnce() -> C,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None").with_context_str_field(key, cb)),
        }
    }

    fn with_context_debug_field<C, F>(self, key: &'static str, cb: F) -> Self::Context
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(BoxError::from("Option is None").with_context_debug_field(key, cb)),
        }
    }
}

/// Extends the `Error` type with methods for working with errors.
///
/// See the [module level documentation](crate) for more information.
pub trait ErrorExt: private::SealedErrorExt {
    /// Return self as [`BoxError`] without additional context.
    fn into_box_error(self) -> BoxError;

    /// Wrap the error in a context.
    fn context<M>(self, value: M) -> BoxError
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static;

    /// Wrap the error in a context,
    /// using [`fmt::Debug`] as `[fmt::Display`].
    fn context_debug<M>(self, value: M) -> BoxError
    where
        M: fmt::Debug + Send + Sync + 'static;

    /// Wrap the error in a keyed context.
    fn context_field<M>(self, key: &'static str, value: M) -> BoxError
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static;

    /// Same as [`Self::context_field`] but using a string-like value,
    /// this is useful in case you need to pass a string slice which is borrowed
    /// and thus cannot be passed as part of 'static error.
    fn context_str_field<M>(self, key: &'static str, value: M) -> BoxError
    where
        M: Into<String>;

    /// Wrap the error in a keyed context,
    /// using [`fmt::Debug`] as `[fmt::Display`].
    fn context_debug_field<M>(self, key: &'static str, value: M) -> BoxError
    where
        M: fmt::Debug + Send + Sync + 'static;

    /// Lazily wrap the error with a context.
    fn with_context<C, F>(self, cb: F) -> BoxError
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C;

    /// Lazily wrap the error with a context,
    /// using [`fmt::Debug`] as `[fmt::Display`].
    fn with_context_debug<C, F>(self, cb: F) -> BoxError
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C;

    /// Lazily wrap the error with keyed context.
    fn with_context_field<C, F>(self, key: &'static str, cb: F) -> BoxError
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C;

    /// Same as [`Self::with_context_field`] but using a string-like value,
    /// this is useful in case you need to pass a string slice which is borrowed
    /// and thus cannot be passed as part of 'static error.
    fn with_context_str_field<C, F>(self, key: &'static str, cb: F) -> BoxError
    where
        C: Into<String>,
        F: FnOnce() -> C;

    /// Lazily wrap the error with keyed context
    /// using [`fmt::Debug`] as `[fmt::Display`].
    fn with_context_debug_field<C, F>(self, key: &'static str, cb: F) -> BoxError
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C;

    /// Add a [`Backtrace`][std::backtrace::Backtrace] to the error.
    fn backtrace(self) -> BoxError;
}

impl<Error: Into<BoxError>> ErrorExt for Error {
    #[inline(always)]
    fn into_box_error(self) -> BoxError {
        self.into()
    }

    fn context<M>(self, value: M) -> BoxError
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        let mut err = self.into();

        if let Some(existing) = err.downcast_mut::<self::context::ErrorWithContext>() {
            existing.insert_value(value);
            return err;
        }

        let mut wrapped = self::context::ErrorWithContext::new(err);
        wrapped.insert_value(value);
        Box::new(wrapped)
    }

    #[inline(always)]
    fn context_debug<M>(self, value: M) -> BoxError
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.context(self::context::DebugContextValue(value))
    }

    fn context_field<M>(self, key: &'static str, value: M) -> BoxError
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        let mut err = self.into();

        if let Some(existing) = err.downcast_mut::<self::context::ErrorWithContext>() {
            existing.insert_key_value(key, value);
            return err;
        }

        let mut wrapped = self::context::ErrorWithContext::new(err);
        wrapped.insert_key_value(key, value);
        Box::new(wrapped)
    }

    fn context_str_field<M>(self, key: &'static str, value: M) -> BoxError
    where
        M: Into<String>,
    {
        let mut err = self.into();

        if let Some(existing) = err.downcast_mut::<self::context::ErrorWithContext>() {
            existing.insert_key_value_str(key, value);
            return err;
        }

        let mut wrapped = self::context::ErrorWithContext::new(err);
        wrapped.insert_key_value_str(key, value);
        Box::new(wrapped)
    }

    #[inline(always)]
    fn context_debug_field<M>(self, key: &'static str, value: M) -> BoxError
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.context_field(key, self::context::DebugContextValue(value))
    }

    #[inline(always)]
    fn with_context<C, F>(self, cb: F) -> BoxError
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context(cb())
    }

    #[inline(always)]
    fn with_context_debug<C, F>(self, cb: F) -> BoxError
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context(self::context::DebugContextValue(cb()))
    }

    #[inline(always)]
    fn with_context_field<C, F>(self, key: &'static str, cb: F) -> BoxError
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context_field(key, cb())
    }

    #[inline(always)]
    fn with_context_str_field<C, F>(self, key: &'static str, cb: F) -> BoxError
    where
        C: Into<String>,
        F: FnOnce() -> C,
    {
        self.context_str_field(key, cb())
    }

    #[inline(always)]
    fn with_context_debug_field<C, F>(self, key: &'static str, cb: F) -> BoxError
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context_field(key, self::context::DebugContextValue(cb()))
    }

    fn backtrace(self) -> BoxError {
        let source = self.into();
        Box::new(self::backtrace::ErrorWithBacktrace::new(source))
    }
}

mod private {
    pub trait SealedErrorContext {}

    impl<T, E> SealedErrorContext for Result<T, E> where E: Into<crate::BoxError> {}
    impl<T> SealedErrorContext for Option<T> {}

    pub trait SealedErrorExt {}

    impl<Error: Into<crate::BoxError>> SealedErrorExt for Error {}
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::StdError;

    use std::{cell::Cell, io};

    fn io_err(msg: &'static str) -> io::Error {
        io::Error::other(msg)
    }

    #[test]
    fn result_context_adds_context_to_error() {
        let res: Result<(), io::Error> = Err(io_err("boom"));

        let err = res.context("ctx").unwrap_err();
        let s = format!("{err}");

        assert!(s.starts_with("boom"), "got: {s:?}");
        assert!(s.contains(" | "), "got: {s:?}");
        assert!(s.contains(r#""ctx""#), "got: {s:?}");
    }

    #[test]
    fn result_context_field_adds_keyed_context_to_error() {
        let res: Result<(), io::Error> = Err(io_err("boom"));

        let err = res.context_field("path", "/a,b/c").unwrap_err();
        let s = format!("{err}");

        assert!(s.starts_with("boom"), "got: {s:?}");
        assert!(s.contains(r#"path="/a,b/c""#), "got: {s:?}");
    }

    #[test]
    fn result_with_context_is_lazy_and_called_once() {
        let res: Result<(), io::Error> = Err(io_err("boom"));

        let calls = Cell::new(0);
        let err = res
            .with_context(|| {
                calls.set(calls.get() + 1);
                "lazy"
            })
            .unwrap_err();

        assert_eq!(calls.get(), 1);

        let s = format!("{err}");
        assert!(s.contains(r#""lazy""#), "got: {s:?}");
    }

    #[test]
    fn result_with_context_field_is_lazy_and_called_once() {
        let res: Result<(), io::Error> = Err(io_err("boom"));

        let calls = Cell::new(0);
        let err = res
            .with_context_field("k", || {
                calls.set(calls.get() + 1);
                "v"
            })
            .unwrap_err();

        assert_eq!(calls.get(), 1);

        let s = format!("{err}");
        assert!(s.contains(r#"k="v""#), "got: {s:?}");
    }

    #[test]
    fn option_context_none_returns_error_with_context() {
        let opt: Option<i32> = None;

        let err = opt.context("missing").unwrap_err();
        let s = format!("{err}");

        assert!(s.starts_with("Option is None"), "got: {s:?}");
        assert!(s.contains(r#""missing""#), "got: {s:?}");
    }

    #[test]
    fn option_context_field_none_returns_error_with_keyed_context() {
        let opt: Option<i32> = None;

        let err = opt.context_field("user_id", 42).unwrap_err();
        let s = format!("{err}");

        assert!(s.starts_with("Option is None"), "got: {s:?}");
        assert!(s.contains(r#"user_id="42""#), "got: {s:?}");
    }

    #[test]
    fn option_with_context_none_is_lazy_and_called_once() {
        let opt: Option<i32> = None;

        let calls = Cell::new(0);
        let err = opt
            .with_context(|| {
                calls.set(calls.get() + 1);
                "lazy"
            })
            .unwrap_err();

        assert_eq!(calls.get(), 1);

        let s = format!("{err}");
        assert!(s.contains(r#""lazy""#), "got: {s:?}");
    }

    #[test]
    fn option_with_context_field_none_is_lazy_and_called_once() {
        let opt: Option<i32> = None;

        let calls = Cell::new(0);
        let err = opt
            .with_context_field("k", || {
                calls.set(calls.get() + 1);
                "v"
            })
            .unwrap_err();

        assert_eq!(calls.get(), 1);

        let s = format!("{err}");
        assert!(s.contains(r#"k="v""#), "got: {s:?}");
    }

    #[test]
    fn errorext_context_reuses_existing_context_wrapper() {
        // First wrap
        let err1: BoxError = io_err("boom").context("a");
        // Second wrap should mutate existing wrapper, not create another layer
        let err2: BoxError = err1.context("b");

        let s = format!("{err2}");

        // Both values should be present
        assert!(s.contains(r#""a""#), "got: {s:?}");
        assert!(s.contains(r#""b""#), "got: {s:?}");

        // And there should be only one " | " separator (one context wrapper)
        assert_eq!(s.matches(" | ").count(), 1, "got: {s:?}");
    }

    #[test]
    fn errorext_context_field_reuses_existing_context_wrapper() {
        let err1: BoxError = io_err("boom").context_field("k1", "v1");
        let err2: BoxError = err1.context_field("k2", "v2");

        let s = format!("{err2}");

        assert!(s.contains(r#"k1="v1""#), "got: {s:?}");
        assert!(s.contains(r#"k2="v2""#), "got: {s:?}");
        assert_eq!(s.matches(" | ").count(), 1, "got: {s:?}");
    }

    #[test]
    fn errorext_backtrace_wraps_error_and_preserves_source() {
        let err: BoxError = io_err("boom").backtrace();

        // Display default should be source only
        assert_eq!(format!("{err}"), "boom");

        // Alternate display should include "Backtrace:" label
        let pretty = format!("{err:#}");
        assert!(pretty.starts_with("boom\n"), "got: {pretty:?}");
        assert!(
            pretty.contains("\nBacktrace:\n") || pretty.contains("\nBacktrace:\r\n"),
            "got: {pretty:?}"
        );

        // Source chain still points to underlying error
        let src = err.source().expect("source exists");
        assert_eq!(src.to_string(), "boom");
    }

    #[test]
    fn errorcontext_for_result_converts_error_into_boxerror() {
        // Ensure Into<BoxError> conversion path works.
        #[derive(Debug)]
        struct MyErr;

        impl std::fmt::Display for MyErr {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "myerr")
            }
        }

        impl StdError for MyErr {}

        // This requires that BoxError supports From<MyErr> via Into<BoxError>.
        let res: Result<(), MyErr> = Err(MyErr);

        let err = res.context("ctx").unwrap_err();
        let s = format!("{err}");

        assert!(s.starts_with("myerr"), "got: {s:?}");
        assert!(s.contains(r#""ctx""#), "got: {s:?}");
    }
}
