use core::fmt;

use super::{
    context::{DebugContextValue, ErrorWithContext, HexContextValue},
    opaque::StaticStrError,
};
use crate::{
    BoxError,
    std::{Arc, Box, String},
};

/// An error more than one owner can keep.
///
/// [`BoxError`] belongs to one owner: passing it on moves it. Some errors are held by several
/// values at once — a terminal connection error that every stream on that connection reports,
/// say — and their cause is often not [`Clone`]. This shares one cause between those owners.
///
/// It displays as the error it shares and downcasts to it, so a message reads the same either
/// way. Its source is that error, which is one step a chain would not have without the sharing:
/// that is what lets a cause be recovered by type after context is wrapped around it. A caller
/// that would rather not show the step — an error that stores its cause this way but wants its
/// own chain to lead straight to the failure — can use [`ArcError::as_error`].
///
/// Adding context produces a new value; what other owners of the same cause already see never
/// changes.
#[derive(Clone)]
pub struct ArcError(Arc<dyn core::error::Error + Send + Sync + 'static>);

impl ArcError {
    /// Share a concrete error. The error moves straight into the shared allocation.
    pub fn new<E>(error: E) -> Self
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        Self(Arc::new(error))
    }

    /// Share a static message. One allocation for the sharing, none for the message.
    pub fn from_static_str(message: &'static str) -> Self {
        Self::new(StaticStrError(message))
    }

    /// Share an error that is already boxed. The box's value moves into the shared allocation.
    pub fn from_box_error(error: BoxError) -> Self {
        Self(Arc::from(error))
    }

    /// The error this shares, as an error: what a chain should continue with when the sharing
    /// itself is storage rather than a step worth showing.
    pub fn as_error(&self) -> &(dyn core::error::Error + 'static) {
        self.0.as_ref()
    }

    /// The concrete error inside, if it is a `T`.
    pub fn downcast_ref<T: core::error::Error + 'static>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }

    #[must_use]
    /// Wrap the error in a context, as [`ErrorExt::context`](crate::ErrorExt::context) does.
    pub fn context<M>(self, value: M) -> Self
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        self.layer(|fields| fields.insert_value(value))
    }

    #[must_use]
    /// Wrap the error in a keyed context, as
    /// [`ErrorExt::context_field`](crate::ErrorExt::context_field) does.
    pub fn context_field<M>(self, key: &'static str, value: M) -> Self
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        self.layer(|fields| fields.insert_key_value(key, value))
    }

    #[must_use]
    /// Wrap the error in a keyed context from a string-like value, for a value that cannot be
    /// borrowed for the error's lifetime.
    pub fn context_str_field<M>(self, key: &'static str, value: M) -> Self
    where
        M: Into<String>,
    {
        self.layer(|fields| fields.insert_key_value_str(key, value))
    }

    #[must_use]
    /// Wrap the error in a context, using [`fmt::LowerHex`] as [`fmt::Debug`] and
    /// [`fmt::Display`].
    pub fn context_hex<M>(self, value: M) -> Self
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.context(HexContextValue(value))
    }

    #[must_use]
    /// Wrap the error in a context, using [`fmt::Debug`] as [`fmt::Display`].
    pub fn context_debug<M>(self, value: M) -> Self
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.context(DebugContextValue(value))
    }

    #[must_use]
    /// Wrap the error in a keyed context, using [`fmt::LowerHex`] as [`fmt::Debug`] and
    /// [`fmt::Display`].
    pub fn context_hex_field<M>(self, key: &'static str, value: M) -> Self
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.context_field(key, HexContextValue(value))
    }

    #[must_use]
    /// Wrap the error in a keyed context, using [`fmt::Debug`] as [`fmt::Display`].
    pub fn context_debug_field<M>(self, key: &'static str, value: M) -> Self
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.context_field(key, DebugContextValue(value))
    }

    #[must_use]
    /// Wrap the error with a context the caller builds only now.
    pub fn with_context<C, F>(self, cb: F) -> Self
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context(cb())
    }

    #[must_use]
    /// Wrap the error with a context the caller builds only now, using [`fmt::LowerHex`].
    pub fn with_context_hex<C, F>(self, cb: F) -> Self
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context_hex(cb())
    }

    #[must_use]
    /// Wrap the error with a context the caller builds only now, using [`fmt::Debug`].
    pub fn with_context_debug<C, F>(self, cb: F) -> Self
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context_debug(cb())
    }

    #[must_use]
    /// Wrap the error with a keyed context the caller builds only now.
    pub fn with_context_field<C, F>(self, key: &'static str, cb: F) -> Self
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context_field(key, cb())
    }

    #[must_use]
    /// Wrap the error with a keyed string-like context the caller builds only now.
    pub fn with_context_str_field<C, F>(self, key: &'static str, cb: F) -> Self
    where
        C: Into<String>,
        F: FnOnce() -> C,
    {
        self.context_str_field(key, cb())
    }

    #[must_use]
    /// Wrap the error with a keyed context the caller builds only now, using [`fmt::LowerHex`].
    pub fn with_context_hex_field<C, F>(self, key: &'static str, cb: F) -> Self
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context_hex_field(key, cb())
    }

    #[must_use]
    /// Wrap the error with a keyed context the caller builds only now, using [`fmt::Debug`].
    pub fn with_context_debug_field<C, F>(self, key: &'static str, cb: F) -> Self
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context_debug_field(key, cb())
    }

    /// A cause nobody else holds takes the context in place; a shared one gets a layer of its
    /// own that keeps the cause, so what other owners see stays as it was.
    fn layer(mut self, apply: impl FnOnce(&mut ErrorWithContext)) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.0)
            && let Some(existing) = inner.downcast_mut::<ErrorWithContext>()
        {
            apply(existing);
            return self;
        }
        let mut wrapped = ErrorWithContext::new(Box::new(self));
        apply(&mut wrapped);
        Self(Arc::new(wrapped))
    }
}

impl fmt::Debug for ArcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for ArcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for ArcError {
    /// The error this shares. A chain through an `ArcError` reaches the concrete cause and can
    /// be downcast to it, which is what makes a cause survive being wrapped in context; the
    /// wrapper's own [`fmt::Display`] is that cause's, so it reads the same either way.
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl From<BoxError> for ArcError {
    fn from(error: BoxError) -> Self {
        Self::from_box_error(error)
    }
}

// `Box<dyn Error>` already accepts any concrete error, `ArcError` included, so there is nothing
// to add for that direction.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorExt as _, error_chain};

    /// A cause that cannot be cloned, so sharing has to be what keeps it alive.
    #[derive(Debug)]
    struct Cause {
        source: Option<Box<dyn core::error::Error + Send + Sync + 'static>>,
    }

    impl fmt::Display for Cause {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("the cause")
        }
    }

    impl core::error::Error for Cause {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            self.source.as_deref().map(|source| source as _)
        }
    }

    /// A context value that cannot be cloned either.
    #[derive(Debug)]
    struct Note(u32);

    impl fmt::Display for Note {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "note {}", self.0)
        }
    }

    fn cause() -> Cause {
        Cause { source: None }
    }

    #[test]
    fn sharing_keeps_the_message_and_the_chain_of_the_error_inside() {
        let deep = Cause {
            source: Some(Box::new(cause())),
        };
        let shared = ArcError::new(deep);
        assert_eq!(shared.to_string(), "the cause");
        assert!(shared.downcast_ref::<Cause>().is_some());
        assert!(
            core::error::Error::source(&shared)
                .is_some_and(|source| source.downcast_ref::<Cause>().is_some()),
            "the source is the cause itself, so it can be recovered by type"
        );
        let chain: Vec<String> = error_chain(&shared, 8).map(ToString::to_string).collect();
        assert_eq!(
            chain.len(),
            3,
            "the shared error, the cause it shares, and what was under it: {chain:?}"
        );
    }

    #[test]
    fn a_clone_keeps_the_same_cause_and_does_not_see_context_added_to_another() {
        let shared = ArcError::new(cause());
        let other = shared.clone();
        let annotated = shared.context_field("where", "here");
        assert!(
            annotated.to_string().contains("here"),
            "the new value carries the context: {annotated}"
        );
        assert_eq!(
            other.to_string(),
            "the cause",
            "and the clone that was made before it does not"
        );
        assert!(
            other.downcast_ref::<Cause>().is_some(),
            "which still holds the same cause"
        );
    }

    #[test]
    fn context_added_to_the_only_owner_needs_no_second_layer() {
        let once = ArcError::new(cause()).context(Note(1)).context(Note(2));
        let rendered = once.to_string();
        assert!(rendered.contains("note 1"), "{rendered}");
        assert!(rendered.contains("note 2"), "{rendered}");
        let wrappers = error_chain(&once, 8)
            .filter(|error| error.downcast_ref::<ErrorWithContext>().is_some())
            .count();
        assert_eq!(
            wrappers, 1,
            "one context wrapper over the cause, not one per context: {once}"
        );
    }

    #[test]
    fn a_typed_cause_survives_context_whether_shared_or_not() {
        let sole = ArcError::new(cause())
            .context(Note(7))
            .context_field("k", "v");
        assert!(
            error_chain(&sole, 8).any(|error| error.downcast_ref::<Cause>().is_some()),
            "the cause is recoverable by type through the only owner's context: {sole}"
        );

        let shared = ArcError::new(cause());
        let kept = shared.clone();
        let annotated = shared.context(Note(7));
        assert!(annotated.to_string().contains("note 7"));
        assert!(
            error_chain(&annotated, 8).any(|error| error.downcast_ref::<Cause>().is_some()),
            "and through a shared one's: {annotated}"
        );
        assert!(
            error_chain(&kept, 8).any(|error| error.downcast_ref::<Cause>().is_some()),
            "the clone made before the context still has it"
        );
        let after = annotated.clone();
        assert!(
            error_chain(&after, 8).any(|error| error.downcast_ref::<Cause>().is_some()),
            "and so does one made after it"
        );
    }

    /// What was beneath the cause is beneath it still.
    #[test]
    fn context_keeps_the_whole_chain_beneath_the_cause() {
        #[derive(Debug)]
        struct Deepest;
        impl fmt::Display for Deepest {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the bottom")
            }
        }
        impl core::error::Error for Deepest {}

        let deep = Cause {
            source: Some(Box::new(Deepest)),
        };
        let annotated = ArcError::new(deep).context_field("stage", "one");
        assert!(
            error_chain(&annotated, 8).any(|error| error.downcast_ref::<Deepest>().is_some()),
            "the error under the cause is still in the chain: {annotated}"
        );
    }

    /// Every context method answers with a shared error. A method that fell through to the
    /// blanket trait would return a `BoxError` and fail to compile here.
    #[test]
    fn the_context_methods_all_answer_with_a_shared_error() {
        let shared = ArcError::new(cause());
        let _: ArcError = shared.clone().context(Note(1));
        let _: ArcError = shared.clone().context_field("k", Note(2));
        let _: ArcError = shared.clone().context_str_field("k", "v");
        let _: ArcError = shared.clone().context_debug(3u8);
        let _: ArcError = shared.clone().context_hex(4u8);
        let _: ArcError = shared.clone().context_debug_field("k", 5u8);
        let _: ArcError = shared.clone().context_hex_field("k", 6u8);
        let _: ArcError = shared.clone().with_context(|| Note(7));
        let _: ArcError = shared.clone().with_context_debug(|| 8u8);
        let _: ArcError = shared.clone().with_context_hex(|| 9u8);
        let _: ArcError = shared.clone().with_context_field("k", || Note(10));
        let _: ArcError = shared.clone().with_context_str_field("k", || "v");
        let _: ArcError = shared.clone().with_context_debug_field("k", || 11u8);
        let last: ArcError = shared.with_context_hex_field("k", || 12u8);
        assert!(
            error_chain(&last, 8).any(|error| error.downcast_ref::<Cause>().is_some()),
            "and each of them keeps the cause"
        );
    }

    /// A cycle in the chain still ends: the bound belongs to the walk, and sharing does not
    /// lengthen the way out of it.
    #[test]
    fn a_cyclic_chain_still_ends() {
        struct Loop;
        impl fmt::Debug for Loop {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("Loop")
            }
        }
        impl fmt::Display for Loop {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("round")
            }
        }
        impl core::error::Error for Loop {
            fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                Some(self)
            }
        }

        let shared = ArcError::new(Loop).context(Note(1));
        assert_eq!(
            error_chain(&shared, 4).count(),
            4,
            "the walk stops at the bound it was given"
        );
        assert!(
            format!("{shared}").contains("note 1"),
            "and the context still renders"
        );
    }

    #[test]
    fn a_boxed_error_moves_into_the_shared_allocation() {
        let boxed: BoxError = Box::new(cause());
        let shared = ArcError::from(boxed);
        assert!(shared.downcast_ref::<Cause>().is_some(), "the same value");
        assert_eq!(shared.to_string(), "the cause");
    }

    #[test]
    fn a_static_message_needs_no_string() {
        let shared = ArcError::from_static_str("nothing to report");
        assert_eq!(shared.to_string(), "nothing to report");
        let boxed: BoxError = Box::new(shared.clone());
        assert_eq!(boxed.to_string(), "nothing to report");
    }

    #[test]
    fn context_values_are_escaped_the_way_every_other_error_escapes_them() {
        let shared = ArcError::new(cause()).context_field("what", "a\nb");
        let rendered = shared.to_string();
        assert!(rendered.contains("a\\nb"), "{rendered}");
        assert!(!rendered.contains('\n'), "{rendered}");
    }

    #[test]
    fn an_error_shared_after_context_keeps_that_context() {
        let with_context = cause().context_field("stage", "handshake");
        let shared = ArcError::from(with_context);
        assert!(shared.to_string().contains("handshake"));
        let further = shared.context_field("path", "one");
        assert!(further.to_string().contains("handshake"));
        assert!(further.to_string().contains("one"));
    }
}
