//! [`DomainLabels`] — structural, label-aware operations over a domain-like
//! type.
//!
//! Implemented for [`Domain`] and for [`Host`](super::super::Host) (the
//! [`Host::Name`](super::super::Host::Name) variant delegates; the
//! [`Host::Address`](super::super::Host::Address) variant has no labels).
//!
//! Presentation-format only — no octets generic, no DNS wire format, no
//! parsed-name layer.

use super::{Domain, Label};

mod sealed {
    pub trait Sealed {}
}

/// A label-aware view over a domain-like type.
///
/// Every method composes purely from [`labels`](Self::labels), so any type
/// that can produce a sequence of [`Label`]s in DNS-natural order (most
/// specific label first, TLD last) inherits suffix/subdomain/parent behavior
/// for free.
pub trait DomainLabels: sealed::Sealed {
    /// Iterator over the labels of `self`, yielded most-specific-first
    /// (`"www.example.com".labels()` yields `www`, `example`, `com`).
    type LabelIter<'a>: Iterator<Item = &'a Label> + DoubleEndedIterator + Clone
    where
        Self: 'a;

    /// Returns an iterator over the labels of `self`.
    fn labels(&self) -> Self::LabelIter<'_>;

    /// Returns the number of labels.
    fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Returns `true` if `self`'s labels start with `prefix`'s labels
    /// (most-specific-end).
    ///
    /// Note that `starts_with` operates on the left edge — the side closest to
    /// the leaf. So `"www.example.com".starts_with("www")` is `true`.
    fn starts_with<D: DomainLabels + ?Sized>(&self, prefix: &D) -> bool {
        let mut a = self.labels();
        let mut b = prefix.labels();
        loop {
            match (b.next(), a.next()) {
                (None, _) => return true,
                (Some(_), None) => return false,
                (Some(y), Some(x)) => {
                    if x != y {
                        return false;
                    }
                }
            }
        }
    }

    /// Returns `true` if `self`'s labels end with `suffix`'s labels
    /// (TLD-end).
    ///
    /// `"www.example.com".ends_with("example.com")` is `true`.
    fn ends_with<D: DomainLabels + ?Sized>(&self, suffix: &D) -> bool {
        let mut a = self.labels().rev();
        let mut b = suffix.labels().rev();
        loop {
            match (b.next(), a.next()) {
                (None, _) => return true,
                (Some(_), None) => return false,
                (Some(y), Some(x)) => {
                    if x != y {
                        return false;
                    }
                }
            }
        }
    }

    /// Returns `true` if `self` is a subdomain of `parent` (or equal to it).
    ///
    /// Returns `false` when `parent` has zero labels (e.g. an IP-valued
    /// [`Host`](super::super::Host)).
    fn is_subdomain_of<D: DomainLabels + ?Sized>(&self, parent: &D) -> bool {
        // One walk: walk reverse together. Empty-parent check is folded in —
        // if parent has no labels at all, `b.next()` is None on the first
        // iteration *and* we've consumed nothing, so we return false.
        let mut a = self.labels().rev();
        let mut b = parent.labels().rev();
        let mut matched_any = false;
        loop {
            match (b.next(), a.next()) {
                (None, _) => return matched_any,
                (Some(_), None) => return false,
                (Some(y), Some(x)) => {
                    if x != y {
                        return false;
                    }
                    matched_any = true;
                }
            }
        }
    }

    /// Returns the parent [`Domain`] (everything but the leftmost label), or
    /// `None` if `self` has fewer than two labels.
    fn parent(&self) -> Option<Domain> {
        let mut it = self.labels();
        let _leaf = it.next()?;
        let rest: Vec<&str> = it.map(Label::as_str).collect();
        if rest.is_empty() {
            return None;
        }
        let joined = rest.join(".");
        // Safety: each piece is a validated `&Label`, joined by '.' — this is
        // exactly the presentation form of the parent domain.
        Some(unsafe { Domain::from_maybe_borrowed_unchecked(joined) })
    }

    /// Iterator over `self` and each successive parent, ending just before the
    /// empty domain. For `"a.b.c"` yields `"a.b.c"`, `"b.c"`, `"c"`.
    fn suffix_iter(&self) -> SuffixIter<'_, Self>
    where
        Self: Sized,
    {
        SuffixIter {
            iter: Some(self.labels()),
        }
    }
}

/// Iterator returned by [`DomainLabels::suffix_iter`].
///
/// Yields one [`Domain`] per call, each successively losing its leftmost label
/// until the single-label TLD is yielded.
#[derive(Clone)]
pub struct SuffixIter<'a, D: DomainLabels + ?Sized + 'a> {
    iter: Option<D::LabelIter<'a>>,
}

impl<'a, D: DomainLabels + ?Sized + 'a> Iterator for SuffixIter<'a, D> {
    type Item = Domain;

    fn next(&mut self) -> Option<Domain> {
        let it = self.iter.as_ref()?;
        // Collect labels from this point on; if empty, terminate.
        let parts: Vec<&str> = it.clone().map(Label::as_str).collect();
        if parts.is_empty() {
            self.iter = None;
            return None;
        }
        // Advance the stored iter by one label for the next call.
        let mut next_it = it.clone();
        let _ = next_it.next();
        self.iter = Some(next_it);

        let joined = parts.join(".");
        // Safety: same as `parent`.
        Some(unsafe { Domain::from_maybe_borrowed_unchecked(joined) })
    }
}

/// Iterator over the labels of a [`Domain`].
#[derive(Clone)]
pub struct DomainLabelIter<'a>(std::str::Split<'a, char>);

impl<'a> DomainLabelIter<'a> {
    pub(super) fn new(buf: &'a str) -> Self {
        // After validation, the buffer is non-empty and contains no double
        // dots. Strip the optional leading and trailing FQDN dots so split('.')
        // yields exactly the labels — no leading or trailing empty strings.
        let s = buf.strip_prefix('.').unwrap_or(buf);
        let s = s.strip_suffix('.').unwrap_or(s);
        Self(s.split('.'))
    }
}

impl<'a> Iterator for DomainLabelIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<&'a Label> {
        self.0
            // Safety: post-validation, every produced slice is a valid label.
            .next()
            .map(|s| unsafe { Label::from_str_unchecked(s) })
    }
}

impl<'a> DoubleEndedIterator for DomainLabelIter<'a> {
    fn next_back(&mut self) -> Option<&'a Label> {
        self.0
            .next_back()
            .map(|s| unsafe { Label::from_str_unchecked(s) })
    }
}

impl sealed::Sealed for Domain {}
impl sealed::Sealed for super::super::Host {}

impl DomainLabels for Domain {
    type LabelIter<'a> = DomainLabelIter<'a>;

    fn labels(&self) -> Self::LabelIter<'_> {
        DomainLabelIter::new(self.as_str())
    }

    /// `Domain`-specialized fast path: slices the underlying buffer instead
    /// of `collect`ing labels into a `Vec` and `join`-ing them.
    fn parent(&self) -> Option<Domain> {
        let s = self.as_str();
        // Strip optional leading/trailing FQDN dots so we slice between real
        // labels.
        let start = if s.starts_with('.') { 1 } else { 0 };
        let end = if s.len() > start && s.ends_with('.') {
            s.len() - 1
        } else {
            s.len()
        };
        let trimmed = &s[start..end];
        // Drop the leftmost label by slicing past the first '.'.
        let dot = trimmed.find('.')?;
        let rest = &trimmed[dot + 1..];
        if rest.is_empty() {
            return None;
        }
        // Safety: `rest` is a suffix of a validated domain at a label
        // boundary. No `*` can be present (the wildcard is only valid as
        // the leftmost label, which we just dropped).
        Some(unsafe { Self::from_maybe_borrowed_unchecked(rest) })
    }
}

#[cfg(test)]
mod tests {
    use super::super::Domain;
    use super::DomainLabels;

    fn labels_of(s: &str) -> Vec<String> {
        Domain::try_from(s.to_owned())
            .unwrap()
            .labels()
            .map(|l| l.as_str().to_owned())
            .collect()
    }

    #[test]
    fn forward_iter_order() {
        assert_eq!(labels_of("www.example.com"), vec!["www", "example", "com"]);
        assert_eq!(labels_of("example.com"), vec!["example", "com"]);
        assert_eq!(labels_of("com"), vec!["com"]);
        // wildcard label exposed as-is
        assert_eq!(labels_of("*.example.com"), vec!["*", "example", "com"]);
        // FQDN trailing dot normalized away
        assert_eq!(labels_of("example.com."), vec!["example", "com"]);
        // leading dot normalized away
        assert_eq!(labels_of(".example.com"), vec!["example", "com"]);
        assert_eq!(labels_of(".example.com."), vec!["example", "com"]);
    }

    #[test]
    fn reverse_iter() {
        let d = Domain::from_static("www.example.com");
        let rev: Vec<&str> = d.labels().rev().map(|l| l.as_str()).collect();
        assert_eq!(rev, vec!["com", "example", "www"]);
    }

    #[test]
    fn iter_is_clone_double_ended() {
        let d = Domain::from_static("a.b.c");
        let it = d.labels();
        let cloned = it.clone();
        assert_eq!(it.count(), 3);
        assert_eq!(cloned.count(), 3);
    }

    #[test]
    fn label_count() {
        assert_eq!(Domain::from_static("com").label_count(), 1);
        assert_eq!(Domain::from_static("example.com").label_count(), 2);
        assert_eq!(Domain::from_static("a.b.c.d").label_count(), 4);
        assert_eq!(Domain::from_static("example.com.").label_count(), 2);
    }

    #[test]
    fn starts_with() {
        let d = Domain::from_static("www.example.com");
        assert!(d.starts_with(&Domain::from_static("www")));
        assert!(d.starts_with(&Domain::from_static("www.example")));
        assert!(d.starts_with(&Domain::from_static("www.example.com")));
        assert!(!d.starts_with(&Domain::from_static("example")));
        assert!(!d.starts_with(&Domain::from_static("www.example.com.uk")));
        // case-insensitive at label layer
        assert!(d.starts_with(&Domain::from_static("WWW.eXaMpLe")));
    }

    #[test]
    fn ends_with() {
        let d = Domain::from_static("www.example.com");
        assert!(d.ends_with(&Domain::from_static("com")));
        assert!(d.ends_with(&Domain::from_static("example.com")));
        assert!(d.ends_with(&Domain::from_static("www.example.com")));
        assert!(!d.ends_with(&Domain::from_static("foo.example.com")));
        assert!(!d.ends_with(&Domain::from_static("www")));
        // case-insensitive at label layer
        assert!(d.ends_with(&Domain::from_static("ExAmPlE.CoM")));
        // FQDN normalization
        assert!(d.ends_with(&Domain::from_static("example.com.")));
    }

    #[test]
    fn is_subdomain_of_table() {
        let cases: &[(&str, &str, bool)] = &[
            ("www.example.com", "example.com", true),
            ("example.com", "example.com", true), // equal counts as subdomain
            ("a.b.example.com", "example.com", true),
            ("example.com", "www.example.com", false),
            ("example.org", "example.com", false),
            ("www.example.com", "ample.com", false), // not a label boundary
        ];
        for (a, b, want) in cases {
            let da = Domain::from_static(a);
            let db = Domain::from_static(b);
            assert_eq!(
                da.is_subdomain_of(&db),
                *want,
                "{a}.is_subdomain_of({b}) — want {want}"
            );
        }
    }

    #[test]
    fn parent_chain() {
        let d = Domain::from_static("a.b.c.example.com");
        let p1 = d.parent().expect("p1");
        assert_eq!(p1.as_str(), "b.c.example.com");
        let p2 = p1.parent().expect("p2");
        assert_eq!(p2.as_str(), "c.example.com");
        let p3 = p2.parent().expect("p3");
        assert_eq!(p3.as_str(), "example.com");
        let p4 = p3.parent().expect("p4");
        assert_eq!(p4.as_str(), "com");
        assert!(p4.parent().is_none(), "tld has no parent");
    }

    #[test]
    fn suffix_iter_order() {
        let d = Domain::from_static("a.b.example.com");
        let got: Vec<String> = d.suffix_iter().map(|s| s.as_str().to_owned()).collect();
        assert_eq!(
            got,
            vec!["a.b.example.com", "b.example.com", "example.com", "com"]
        );

        let tld = Domain::from_static("com");
        let got_tld: Vec<String> = tld.suffix_iter().map(|s| s.as_str().to_owned()).collect();
        assert_eq!(got_tld, vec!["com"]);
    }
}
