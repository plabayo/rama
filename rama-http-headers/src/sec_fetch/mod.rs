//! [Fetch Metadata] request headers.
//!
//! Browsers attach `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest` and
//! `Sec-Fetch-User` to describe the context a request was made in. Each is a
//! [`TypedHeader`] of its own; [`FetchMetadata`] reads them together, since the
//! headers only carry their full meaning as a set.
//!
//! `Sec-Purpose` ([`SecPurpose`]) marks a speculative request. It is not
//! defined by the Fetch Metadata spec, but describes the same request context,
//! so it lives here and [`FetchMetadata`] carries it too.
//!
//! [Fetch Metadata]: https://w3c.github.io/webappsec-fetch-metadata/
//! [`TypedHeader`]: crate::TypedHeader

use rama_http_types::HeaderMap;

use crate::{HeaderEncode, HeaderMapExt};

/// Implement [`TypedHeader`], [`HeaderDecode`] and [`HeaderEncode`] for a
/// Structured Field Token enum built with `enum_builder!`.
///
/// [`TypedHeader`]: crate::TypedHeader
/// [`HeaderDecode`]: crate::HeaderDecode
/// [`HeaderEncode`]: crate::HeaderEncode
macro_rules! token_header {
    ($ty:ident, $name:ident) => {
        impl $crate::TypedHeader for $ty {
            fn name() -> &'static ::rama_http_types::HeaderName {
                &::rama_http_types::header::$name
            }
        }

        impl $crate::HeaderDecode for $ty {
            fn decode<'i, I>(values: &mut I) -> Result<Self, $crate::Error>
            where
                I: Iterator<Item = &'i ::rama_http_types::HeaderValue>,
            {
                // A Structured Field Item: several lines combine to no valid one (RFC 9651 §4.2).
                let value = $crate::util::single_value(values)?;
                value
                    .to_str()
                    .ok()
                    .and_then(|s| (!s.is_empty()).then(|| Self::from(s)))
                    .ok_or_else($crate::Error::invalid)
            }
        }

        impl $crate::HeaderEncode for $ty {
            fn encode<E: Extend<::rama_http_types::HeaderValue>>(&self, values: &mut E) {
                match self.as_static_str() {
                    ::std::borrow::Cow::Borrowed(s) => values.extend(::std::iter::once(
                        ::rama_http_types::HeaderValue::from_static(s),
                    )),
                    ::std::borrow::Cow::Owned(s) => {
                        values.extend(::rama_http_types::HeaderValue::try_from(s).ok())
                    }
                }
            }
        }
    };
}

mod dest;
pub use dest::SecFetchDest;

mod mode;
pub use mode::SecFetchMode;

mod site;
pub use site::SecFetchSite;

mod purpose;
pub use purpose::{SecPurpose, SecPurposeKind};

mod user;
pub use user::SecFetchUser;

/// The [Fetch Metadata] request headers of a request, read together.
///
/// This is a view over [`SecFetchSite`], [`SecFetchMode`], [`SecFetchDest`]
/// and [`SecFetchUser`], not a [`TypedHeader`] of its own: it spans four
/// header names. A header that is absent or fails to decode leaves its field
/// empty, so a partial set (some embedded browsers only send `Sec-Fetch-Site`)
/// still yields the fields that were sent.
///
/// It also carries [`SecPurpose`], which marks a speculative request (see
/// [`is_speculative`]). That header is not defined by the Fetch Metadata spec,
/// but is read alongside the four that are, as it describes the same context.
///
/// [`is_speculative`]: Self::is_speculative
/// [Fetch Metadata]: https://w3c.github.io/webappsec-fetch-metadata/
/// [`TypedHeader`]: crate::TypedHeader
///
/// # Example
///
/// ```
/// use rama_http_headers::{FetchMetadata, SecFetchDest, SecFetchMode, SecFetchSite};
/// use rama_http_types::HeaderMap;
///
/// let navigation = FetchMetadata::default()
///     .with_site(SecFetchSite::None)
///     .with_mode(SecFetchMode::Navigate)
///     .with_dest(SecFetchDest::Document)
///     .with_user(true);
///
/// let mut headers = HeaderMap::new();
/// navigation.insert_into(&mut headers);
/// assert_eq!(headers["sec-fetch-user"], "?1");
///
/// assert_eq!(FetchMetadata::from_headers(&headers), Some(navigation));
/// assert_eq!(FetchMetadata::from_headers(&HeaderMap::new()), None);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct FetchMetadata {
    /// The `Sec-Fetch-Site` header.
    pub site: Option<SecFetchSite>,
    /// The `Sec-Fetch-Mode` header.
    pub mode: Option<SecFetchMode>,
    /// The `Sec-Fetch-Dest` header.
    pub dest: Option<SecFetchDest>,
    /// Whether the `Sec-Fetch-User` header was sent, marking a navigation
    /// triggered by user activation.
    pub user: bool,
    /// The `Sec-Purpose` header, sent on a speculative request.
    pub purpose: Option<SecPurpose>,
}

impl FetchMetadata {
    /// Read the fetch metadata headers from `headers`.
    ///
    /// Returns `None` when none of them is present with a valid value: a
    /// non-browser client, or a browser too old to send them. That is a
    /// different answer from "sent, with these values".
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let metadata = Self {
            site: headers.typed_get(),
            mode: headers.typed_get(),
            dest: headers.typed_get(),
            user: headers.typed_get::<SecFetchUser>().is_some(),
            purpose: headers.typed_get(),
        };
        (!metadata.is_empty()).then_some(metadata)
    }

    /// Write this metadata into `headers`.
    ///
    /// Present fields replace their header; absent fields remove it, so the
    /// map carries exactly this metadata afterwards.
    pub fn insert_into(&self, headers: &mut HeaderMap) {
        // Destructured so a new field fails to compile until it is written here.
        let Self {
            site,
            mode,
            dest,
            user,
            purpose,
        } = self;
        insert_or_remove(headers, site.clone());
        insert_or_remove(headers, mode.clone());
        insert_or_remove(headers, dest.clone());
        insert_or_remove(headers, user.then_some(SecFetchUser));
        insert_or_remove(headers, purpose.clone());
    }

    /// Whether no field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        // Destructured so a new field fails to compile until it is checked here.
        let Self {
            site,
            mode,
            dest,
            user,
            purpose,
        } = self;
        site.is_none() && mode.is_none() && dest.is_none() && !user && purpose.is_none()
    }

    /// Whether the browser marked this request as speculative: a prefetch or
    /// prerender (`Sec-Purpose`) rather than a load the user asked for.
    ///
    /// This labels a request, it does not prove the response was never shown.
    /// When the user goes on to a prefetched or prerendered page, the browser
    /// uses the speculative response and sends no second request. Excluding
    /// speculative requests from page-view counts therefore undercounts;
    /// knowing whether one was seen takes a client-side signal, such as
    /// `document.prerendering` and the `prerenderingchange` event.
    #[must_use]
    pub fn is_speculative(&self) -> bool {
        self.purpose.is_some()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `Sec-Fetch-Site` value.
        pub fn site(mut self, site: Option<SecFetchSite>) -> Self {
            self.site = site;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `Sec-Fetch-Mode` value.
        pub fn mode(mut self, mode: Option<SecFetchMode>) -> Self {
            self.mode = mode;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `Sec-Fetch-Dest` value.
        pub fn dest(mut self, dest: Option<SecFetchDest>) -> Self {
            self.dest = dest;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether the request was triggered by user activation (`Sec-Fetch-User`).
        pub fn user(mut self, user: bool) -> Self {
            self.user = user;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `Sec-Purpose` value.
        pub fn purpose(mut self, purpose: Option<SecPurpose>) -> Self {
            self.purpose = purpose;
            self
        }
    }
}

fn insert_or_remove<H: HeaderEncode>(headers: &mut HeaderMap, header: Option<H>) {
    match header {
        Some(header) => headers.typed_insert(header),
        None => {
            headers.remove(H::name());
        }
    }
}

#[cfg(test)]
mod tests;
