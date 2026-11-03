use core::{error::Error, fmt};

use crate::{
    BoxError,
    chain::DEFAULT_MAX_DEPTH,
    error_chain,
    ext::{location_of, transparent_inner, write_escaped_display},
    std::{Box, Vec},
};

/// Several failures reported as one error, such as every attempt of a race or
/// every resolver of a fallback chain.
///
/// One of them is the primary failure: it is the [`Error::source`], so
/// [`error_chain`](crate::error_chain) and code that classifies an error by its
/// chain keep working as for a single failure. By default the first pushed
/// error is primary; [`ErrorList::push_primary`] picks another one.
///
/// [`CauseExt`](crate::CauseExt) searches every failure in the list, not only
/// the primary one.
///
/// `{}` renders the failures on one line, `{:#}` renders each with its own
/// cause chain. Both escape control characters and write at most 64 errors,
/// nested lists included.
///
/// ```
/// use rama_error::{BoxError, BoxErrorExt, CauseExt, ErrorList};
///
/// let mut errors = ErrorList::new();
/// errors.push(BoxError::from_static_str("refused"));
/// errors.push(std::fmt::Error);
///
/// assert_eq!(errors.len(), 2);
/// assert_eq!(errors.to_string(), "2 errors: refused; an error occurred when formatting an argument");
/// assert!(errors.has_cause::<std::fmt::Error>());
/// ```
#[derive(Default)]
pub struct ErrorList {
    errors: Vec<BoxError>,
    primary: usize,
}

/// How many failures `{}` writes before summarizing the rest.
const DISPLAY_LIMIT: usize = 8;

impl ErrorList {
    /// An empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            errors: Vec::new(),
            primary: 0,
        }
    }

    /// An empty list with room for `capacity` failures.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            errors: Vec::with_capacity(capacity),
            primary: 0,
        }
    }

    /// Add a failure.
    pub fn push(&mut self, error: impl Into<BoxError>) {
        self.errors.push(error.into());
    }

    /// Add a failure and make it the primary one.
    pub fn push_primary(&mut self, error: impl Into<BoxError>) {
        self.primary = self.errors.len();
        self.errors.push(error.into());
    }

    /// The number of failures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Whether no failure was added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// The primary failure, if any.
    #[must_use]
    pub fn primary(&self) -> Option<&(dyn Error + Send + Sync + 'static)> {
        self.errors.get(self.primary).map(AsRef::as_ref)
    }

    /// Every failure, in the order they were added.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &(dyn Error + Send + Sync + 'static)> {
        self.errors.iter().map(AsRef::as_ref)
    }

    /// Every failure, in the order they were added.
    #[must_use]
    pub fn into_vec(self) -> Vec<BoxError> {
        self.errors
    }

    /// Turn this list into a single error: the only failure when there is one,
    /// otherwise the list itself. `None` when the list is empty.
    #[must_use]
    pub fn into_error(mut self) -> Option<BoxError> {
        match self.errors.len() {
            0 => None,
            1 => self.errors.pop(),
            _ => Some(Box::new(self)),
        }
    }
}

impl fmt::Display for ErrorList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut render = Render {
            budget: DEFAULT_MAX_DEPTH,
            truncated: false,
        };
        if f.alternate() {
            render.tree(f, self, 0)
        } else {
            render.line(f, self)
        }
    }
}

impl fmt::Debug for ErrorList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Errors<'a>(&'a ErrorList);

        impl fmt::Debug for Errors<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut render = Render {
                    budget: DEFAULT_MAX_DEPTH,
                    truncated: false,
                };
                render.line(f, self.0)
            }
        }

        f.debug_struct("ErrorList")
            .field("primary", &self.primary)
            .field("errors", &Errors(self))
            .finish()
    }
}

/// Renders a list, nested lists included, writing at most `budget` errors in total.
struct Render {
    budget: usize,
    truncated: bool,
}

impl Render {
    fn take(&mut self) -> bool {
        self.budget
            .checked_sub(1)
            .map(|left| self.budget = left)
            .is_some()
    }

    fn header(f: &mut fmt::Formatter<'_>, list: &ErrorList) -> fmt::Result {
        match list.errors.len() {
            0 => f.write_str("no errors"),
            1 => f.write_str("1 error"),
            n => write!(f, "{n} errors"),
        }
    }

    /// One error on one line. Nested lists and this crate's wrappers are rendered
    /// here, not by their own `Display`, so they share this budget.
    fn error(&mut self, f: &mut fmt::Formatter<'_>, error: &(dyn Error + 'static)) -> fmt::Result {
        if let Some(nested) = error.downcast_ref::<ErrorList>() {
            f.write_str("(")?;
            self.line(f, nested)?;
            return f.write_str(")");
        }
        let Some((inner, context)) = transparent_inner(error) else {
            return write_escaped_display(f, error);
        };
        if !self.take() {
            return f.write_str("…");
        }
        self.error(f, inner)?;
        match context {
            Some(context) => context.fmt_inline_fields(f),
            None => Ok(()),
        }
    }

    fn line(&mut self, f: &mut fmt::Formatter<'_>, list: &ErrorList) -> fmt::Result {
        Self::header(f, list)?;
        if list.errors.is_empty() {
            return Ok(());
        }
        f.write_str(": ")?;
        for (idx, error) in list.errors.iter().enumerate() {
            if idx > 0 {
                f.write_str("; ")?;
            }
            if idx == DISPLAY_LIMIT || !self.take() {
                return write!(f, "… ({} more)", list.errors.len() - idx);
            }
            self.error(f, error.as_ref())?;
        }
        Ok(())
    }

    fn tree(&mut self, f: &mut fmt::Formatter<'_>, list: &ErrorList, depth: usize) -> fmt::Result {
        Self::header(f, list)?;
        if list.errors.is_empty() {
            return Ok(());
        }
        f.write_str(":")?;
        let pad = depth * 4;
        for (idx, error) in list.errors.iter().enumerate() {
            if !self.take() {
                return self.truncate(f, pad);
            }
            let mark = if idx == list.primary {
                " (primary)"
            } else {
                ""
            };
            write!(f, "\n{:pad$}  {idx}{mark}: ", "")?;
            self.branch(f, error.as_ref(), depth)?;
            if self.truncated {
                return Ok(());
            }
        }
        Ok(())
    }

    /// One failure with its location and cause chain. A nested list becomes a
    /// sub-tree, and its primary failure is not walked a second time.
    fn branch(
        &mut self,
        f: &mut fmt::Formatter<'_>,
        error: &(dyn Error + 'static),
        depth: usize,
    ) -> fmt::Result {
        if let Some(nested) = error.downcast_ref::<ErrorList>() {
            return self.tree(f, nested, depth + 1);
        }
        let pad = depth * 4;
        self.error(f, error)?;
        if let Some(location) = location_of(error) {
            write!(f, "\n{:pad$}     at {location}", "")?;
        }
        for cause in error_chain(error).skip(1) {
            if !self.take() {
                return self.truncate(f, pad);
            }
            write!(f, "\n{:pad$}     caused by: ", "")?;
            if let Some(nested) = cause.downcast_ref::<ErrorList>() {
                return self.tree(f, nested, depth + 2);
            }
            self.error(f, cause)?;
            if let Some(location) = location_of(cause) {
                write!(f, "\n{:pad$}       at {location}", "")?;
            }
        }
        Ok(())
    }

    fn truncate(&mut self, f: &mut fmt::Formatter<'_>, pad: usize) -> fmt::Result {
        if self.truncated {
            return Ok(());
        }
        self.truncated = true;
        write!(f, "\n{:pad$}  … (truncated)", "")
    }
}

impl Error for ErrorList {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors
            .get(self.primary)
            .map(|error| error.as_ref() as _)
    }
}

impl<E: Into<BoxError>> Extend<E> for ErrorList {
    fn extend<I: IntoIterator<Item = E>>(&mut self, iter: I) {
        self.errors.extend(iter.into_iter().map(Into::into));
    }
}

impl<E: Into<BoxError>> FromIterator<E> for ErrorList {
    fn from_iter<I: IntoIterator<Item = E>>(iter: I) -> Self {
        Self {
            errors: iter.into_iter().map(Into::into).collect(),
            primary: 0,
        }
    }
}

/// Collect every failure of an iterator of results, instead of stopping at the
/// first one as [`Iterator::collect`] does.
///
/// ```
/// use rama_error::CollectErrors;
///
/// let parsed: Result<Vec<u8>, _> = ["1", "x", "3", "y"]
///     .into_iter()
///     .map(str::parse::<u8>)
///     .collect_errors();
/// assert_eq!(parsed.unwrap_err().len(), 2);
///
/// let parsed: Vec<u8> = ["1", "2"].into_iter().map(str::parse::<u8>).collect_errors().unwrap();
/// assert_eq!(parsed, [1, 2]);
/// ```
pub trait CollectErrors<T, E>: Iterator<Item = Result<T, E>> + private::Sealed {
    /// Collect all `Ok` values, or all failures when there is at least one.
    ///
    /// The whole iterator is consumed either way.
    fn collect_errors<C: FromIterator<T>>(self) -> Result<C, ErrorList>;
}

impl<I, T, E> CollectErrors<T, E> for I
where
    I: Iterator<Item = Result<T, E>>,
    E: Into<BoxError>,
{
    fn collect_errors<C: FromIterator<T>>(mut self) -> Result<C, ErrorList> {
        let mut errors = ErrorList::new();
        let values = self
            .by_ref()
            .filter_map(|result| match result {
                Ok(value) => Some(value),
                Err(error) => {
                    errors.push(error);
                    None
                }
            })
            .collect();
        // A collection can stop early (`Option` stops at `None`); the rest may still fail.
        errors.extend(self.filter_map(Result::err));
        if errors.is_empty() {
            Ok(values)
        } else {
            Err(errors)
        }
    }
}

mod private {
    use crate::BoxError;

    pub trait Sealed {}

    impl<I, T, E> Sealed for I
    where
        I: Iterator<Item = Result<T, E>>,
        E: Into<BoxError>,
    {
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::{ArcError, BoxErrorExt as _, CauseExt as _, ErrorExt as _};

    #[derive(Debug)]
    struct Marker(u8);

    impl fmt::Display for Marker {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "marker {}", self.0)
        }
    }

    impl Error for Marker {}

    fn list_of(errors: impl IntoIterator<Item = BoxError>) -> ErrorList {
        errors.into_iter().collect()
    }

    #[test]
    fn empty_list() {
        let list = ErrorList::new();
        assert!(list.is_empty());
        assert!(list.primary().is_none());
        assert!(list.source().is_none());
        assert_eq!(list.to_string(), "no errors");
        assert_eq!(format!("{list:#}"), "no errors");
        assert!(list.into_error().is_none());
    }

    #[test]
    fn single_failure_becomes_that_failure() {
        let mut list = ErrorList::new();
        list.push(Marker(1));
        assert_eq!(list.to_string(), "1 error: marker 1");
        let error = list.into_error().unwrap();
        assert!(error.is::<Marker>());
    }

    #[test]
    fn primary_is_the_source_and_first_by_default() {
        let mut list = ErrorList::with_capacity(3);
        list.push(Marker(1));
        list.push(Marker(2));
        assert_eq!(list.source().unwrap().to_string(), "marker 1");

        list.push_primary(Marker(3));
        list.push(Marker(4));
        assert_eq!(list.primary().unwrap().to_string(), "marker 3");
        let chain: Vec<_> = error_chain(&list).map(|error| error.to_string()).collect();
        assert_eq!(
            chain,
            [
                "4 errors: marker 1; marker 2; marker 3; marker 4",
                "marker 3"
            ]
        );
    }

    #[test]
    fn display_is_one_line_and_bounded() {
        let list = list_of((0..20).map(|idx| Marker(idx).into_box_error()));
        let line = list.to_string();
        assert!(!line.contains('\n'), "{line}");
        assert!(line.starts_with("20 errors: marker 0; "), "{line}");
        assert!(line.contains("marker 7; … (12 more)"), "{line}");
        assert!(!line.contains("marker 8"), "{line}");
    }

    #[test]
    fn display_escapes_context_like_any_other_error() {
        let list = list_of([Marker(1).context_field("k", "a\nb\x1b[0m")]);
        let line = list.to_string();
        assert!(!line.contains('\n') && !line.contains('\x1b'), "{line:?}");
        let pretty = format!("{list:#}");
        assert!(!pretty.contains('\x1b'), "{pretty:?}");
    }

    #[test]
    fn alternate_lists_every_failure_with_causes_and_locations() {
        let (inner, line) = (BoxError::from_static_str("inner"), line!());
        let mut list = ErrorList::new();
        list.push(Marker(1));
        list.push_primary(inner.context_field("addr", "10.0.0.1"));
        let pretty = format!("{list:#}");
        assert!(
            pretty.starts_with(
                "2 errors:\n  0: marker 1\n  1 (primary): inner | addr=\"10.0.0.1\"\n"
            ),
            "{pretty}"
        );
        assert!(
            pretty.contains(&format!("     at {}:{line}:", file!())),
            "{pretty}"
        );
        assert!(pretty.contains("     caused by: inner\n"), "{pretty}");
    }

    #[test]
    fn cause_lookup_searches_every_failure() {
        let list = list_of([
            BoxError::from_static_str("first"),
            Marker(7).context("second"),
        ]);
        assert_eq!(list.find_cause::<Marker>().map(|m| m.0), Some(7));
        assert!(
            !error_chain(&list).any(|error| error.is::<Marker>()),
            "the chain follows the primary only"
        );

        let wrapped = list.context("all failed");
        assert!(wrapped.has_cause::<Marker>());
        assert!(wrapped.root_cause().to_string() == "first");
    }

    #[test]
    fn cause_lookup_enters_nested_lists() {
        let inner = list_of([BoxError::from_static_str("a"), Marker(9).into_box_error()]);
        let outer = list_of([BoxError::from_static_str("b"), Box::new(inner)]);
        assert_eq!(outer.find_cause::<Marker>().map(|m| m.0), Some(9));
        assert!(outer.has_cause::<ErrorList>());
    }

    #[test]
    fn cause_lookup_is_bounded_in_total() {
        // 100 failures, the marker last: past the 64-error budget.
        let mut list: ErrorList = (0..99).map(|_| BoxError::from_static_str("x")).collect();
        list.push(Marker(1));
        assert!(!list.has_cause::<Marker>());

        let mut list: ErrorList = (0..62).map(|_| BoxError::from_static_str("x")).collect();
        list.push(Marker(1));
        assert!(list.has_cause::<Marker>(), "the list plus 63 failures fit");
    }

    #[test]
    fn collect_errors_keeps_every_failure_and_consumes_everything() {
        let mut seen = 0;
        let result: Result<Vec<u8>, _> = ["1", "x", "3", "y"]
            .into_iter()
            .inspect(|_| seen += 1)
            .map(str::parse::<u8>)
            .collect_errors();
        assert_eq!(seen, 4);
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 2);

        let ok: Vec<u8> = ["1", "2"]
            .into_iter()
            .map(str::parse::<u8>)
            .collect_errors()
            .unwrap();
        assert_eq!(ok, [1, 2]);

        let none: Vec<u8> = core::iter::empty::<Result<u8, Marker>>()
            .collect_errors()
            .unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn collect_errors_keeps_failures_after_the_collection_stops() {
        let items: [Result<Option<u8>, Marker>; 3] = [Ok(None), Err(Marker(1)), Ok(Some(2))];
        let result: Result<Option<Vec<u8>>, _> = items.into_iter().collect_errors();
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors.has_cause::<Marker>());
    }

    #[test]
    fn nested_lists_render_inline_within_one_budget() {
        let mut list = list_of([Marker(0).into_box_error()]);
        for depth in 1..=200 {
            list = list_of([Box::new(list) as BoxError, Marker(depth).into_box_error()]);
        }
        let line = list.to_string();
        assert!(line.starts_with("2 errors: (2 errors: ("), "{line}");
        // The outer list plus one nested list per budgeted error.
        assert_eq!(
            line.matches("errors:").count(),
            DEFAULT_MAX_DEPTH + 1,
            "{line}"
        );
        let pretty = format!("{list:#}");
        assert!(
            pretty.matches("errors").count() <= DEFAULT_MAX_DEPTH + 1,
            "{pretty}"
        );
        assert!(pretty.ends_with("… (truncated)"), "{pretty}");
    }

    #[test]
    fn rendering_is_bounded_for_cyclic_failures() {
        static DISPLAYS: AtomicUsize = AtomicUsize::new(0);

        #[derive(Debug)]
        struct Cycle;

        impl fmt::Display for Cycle {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                DISPLAYS.fetch_add(1, Ordering::Relaxed);
                f.write_str("cycle")
            }
        }

        impl Error for Cycle {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(self)
            }
        }

        let list: ErrorList = (0..100).map(|_| Cycle).collect();
        let pretty = format!("{list:#}");
        assert!(pretty.ends_with("… (truncated)"), "{pretty}");
        assert_eq!(DISPLAYS.load(Ordering::Relaxed), DEFAULT_MAX_DEPTH);
    }

    #[test]
    fn rendering_escapes_control_characters_of_failures() {
        let list = list_of([
            BoxError::from_static_str("line\nbreak\x1b[31m"),
            Marker(1).context_field("k", "a\x1bb"),
        ]);
        for rendered in [list.to_string(), format!("{list:#}"), format!("{list:?}")] {
            assert!(!rendered.contains('\x1b'), "{rendered:?}");
        }
        assert!(
            list.to_string().contains("line\\nbreak\\u{1b}[31m"),
            "{list}"
        );
        assert!(!list.to_string().contains('\n'), "{list}");
    }

    #[test]
    fn lists_nested_through_wrappers_share_the_budget() {
        let mut error: BoxError = Marker(0).into_box_error();
        for depth in 0..2_000 {
            let mut list = ErrorList::new();
            list.push(error.context_field("depth", depth));
            error = match depth % 3 {
                0 => ArcError::from_box_error(Box::new(list)).into_box_error(),
                // io errors are seen through with the std feature only.
                1 if cfg!(feature = "std") => std::io::Error::other(list).into_box_error(),
                _ => Box::new(list),
            };
        }
        let list = list_of([error]);
        // Run on a small stack: rendering must not recurse per nesting level.
        let rendered = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let rendered = [list.to_string(), format!("{list:#}"), format!("{list:?}")];
                // Dropping a deeply nested value recurses; do that on the test's own stack.
                (rendered, list)
            })
            .unwrap()
            .join()
            .unwrap()
            .0;
        for rendered in rendered {
            assert!(
                rendered.matches("1 error").count() <= DEFAULT_MAX_DEPTH + 1,
                "{rendered}"
            );
            assert!(rendered.contains('…'), "{rendered}");
        }
    }

    #[test]
    fn debug_shows_the_failures_escaped() {
        let list = list_of([Marker(1).context_field("k", "a\nb\x1b")]);
        for rendered in [format!("{list:?}"), format!("{list:#?}")] {
            assert!(rendered.starts_with("ErrorList {"), "{rendered}");
            assert!(rendered.contains("marker 1 | k="), "{rendered}");
            assert!(!rendered.contains('\x1b'), "{rendered:?}");
            assert!(rendered.contains("a\\nb\\u{1b}"), "{rendered}");
        }
    }

    #[test]
    fn rendering_escapes_custom_display_and_keeps_quotes() {
        #[derive(Debug)]
        struct Hostile;

        impl fmt::Display for Hostile {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("say \"hi\" \\ \u{9b}31m\r\n")
            }
        }

        impl Error for Hostile {}

        let list = list_of([Hostile.into_box_error()]);
        let line = list.to_string();
        assert_eq!(line, r#"1 error: say "hi" \ \u{9b}31m\r\n"#);
        let pretty = format!("{list:#}");
        assert!(
            !pretty.contains('\u{9b}') && !pretty.contains('\r'),
            "{pretty:?}"
        );
    }

    #[test]
    fn alternate_renders_nested_lists_as_branches_with_their_causes() {
        let (secondary, line) = (BoxError::from_static_str("secondary-leaf"), line!());
        let mut inner = ErrorList::new();
        inner.push_primary(fmt::Error);
        inner.push(secondary.context("secondary-wrapper"));
        let mut outer = ErrorList::new();
        outer.push(Marker(1));
        outer.push(Box::new(inner) as BoxError);

        let pretty = format!("{outer:#}");
        assert!(
            pretty.contains("\n  1: 2 errors:\n      0 (primary): "),
            "{pretty}"
        );
        assert!(pretty.contains("secondary-wrapper"), "{pretty}");
        assert!(pretty.contains("caused by: secondary-leaf"), "{pretty}");
        assert!(pretty.contains(&format!("{}:{line}:", file!())), "{pretty}");
        assert_eq!(pretty.matches("an error occurred").count(), 1, "{pretty}");

        // Reached through a context wrapper, the nested list is still expanded.
        let wrapped = list_of([outer.context("outer")]);
        let pretty = format!("{wrapped:#}");
        assert!(pretty.contains("caused by: secondary-leaf"), "{pretty}");
    }

    #[test]
    fn extend_appends_in_order() {
        let mut list = ErrorList::new();
        list.extend([Marker(1), Marker(2)]);
        let order: Vec<_> = list.iter().map(|error| error.to_string()).collect();
        assert_eq!(order, ["marker 1", "marker 2"]);
        assert_eq!(list.into_vec().len(), 2);
    }
}
