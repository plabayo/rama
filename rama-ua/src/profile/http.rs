use rama_http_types::{
    HeaderName,
    proto::{
        h1::Http1HeaderMap,
        h2::{PseudoHeaderOrder, frame::SettingsConfig},
    },
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Marker header name for custom headers.
///
/// Header value: `x-rama-custom-header-marker`
///
/// This is used to identify in the [`HttpHeadersProfile`]
/// the initial location of custom headers, which is also
/// by the [`UserAgentEmulateRequestModifier`] used to place
/// any original request headers that were not present in the
/// [`HttpHeadersProfile`] (also called base headers).
///
/// If this header is not present in the [`HttpHeadersProfile`]
/// then it will be assumed that remaining headers are to be
/// put as the final headers in the request header map.
///
/// [`HttpHeadersProfile`]: crate::profile::HttpHeadersProfile
/// [`UserAgentEmulateHttpRequestModifier`]: crate::emulate::UserAgentEmulateHttpRequestModifier
pub static CUSTOM_HEADER_MARKER: HeaderName =
    HeaderName::from_static("x-rama-custom-header-marker");

#[derive(Debug, Clone)]
/// A User Agent (UA) profile for HTTP.
///
/// This profile contains the HTTP profiles for
/// [`Http1`][`Http1Profile`] and [`Http2`][`Http2Profile`].
///
/// [`Http1Profile`]: crate::profile::Http1Profile
/// [`Http2Profile`]: crate::profile::Http2Profile
pub struct HttpProfile {
    /// The HTTP/1.1 profile.
    pub h1: Arc<Http1Profile>,
    /// The HTTP/2 profile.
    pub h2: Arc<Http2Profile>,
}

impl<'de> Deserialize<'de> for HttpProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let input = HttpProfileDeserialize::deserialize(deserializer)?;
        Ok(Self {
            h1: Arc::new(input.h1),
            h2: Arc::new(input.h2),
        })
    }
}

impl Serialize for HttpProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        HttpProfileSerialize {
            h1: self.h1.as_ref(),
            h2: self.h2.as_ref(),
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Serialize)]
struct HttpProfileSerialize<'a> {
    h1: &'a Http1Profile,
    h2: &'a Http2Profile,
}

#[derive(Debug, Deserialize)]
struct HttpProfileDeserialize {
    h1: Http1Profile,
    h2: Http2Profile,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HttpHeadersProfile {
    /// The headers to be used for navigation requests.
    ///
    /// A navigation request is the regular request that a user-agent
    /// makes automatically or on behalf of the user, but that is not
    /// triggered directly by a script.
    pub navigate: Http1HeaderMap,
    /// The headers to be used for fetch requests.
    ///
    /// A fetch request is a request made by a script to retrieve a resource from a server,
    /// using the [`fetch`][`fetch`] API.
    ///
    /// In case the user-agent does not support the [`fetch`][`fetch`] API,
    /// then it is recommended to try to use the `xhr` headers,
    /// and as a final fallback use the `navigate` headers.
    ///
    /// [`fetch`]: https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API
    pub fetch: Option<Http1HeaderMap>,
    /// The headers to be used for XMLHttpRequest requests.
    ///
    /// An [`XMLHttpRequest`](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest)
    /// is a request made by a script to retrieve a resource from a server.
    ///
    /// In case the user-agent does not support the [`XMLHttpRequest`][`XMLHttpRequest`] API,
    /// then it is recommended to try to use the `fetch` headers,
    /// and as a final fallback use the `navigate` headers.
    pub xhr: Option<Http1HeaderMap>,
    /// The headers to be used for form submissions.
    ///
    /// A form submission is a request made by a script to submit a form to a server.
    ///
    /// In case the user-agent does not support forms (e.g. because it does not handle html forms),
    /// then it is recommended to try to use the `fetch` headers and any fallbacks that the latter may have.
    pub form: Option<Http1HeaderMap>,
}

#[derive(Debug, Deserialize, Serialize)]
/// The HTTP/1.1 profile.
///
/// This profile contains the headers and settings for the HTTP/1.1 protocol.
pub struct Http1Profile {
    /// The (base) headers to be used for the HTTP/1.1 profile.
    pub headers: HttpHeadersProfile,
    /// The settings for the HTTP/1.1 profile.
    pub settings: Http1Settings,
}

#[derive(Debug, Deserialize, Serialize, Default)]
/// The settings for the HTTP/1.1 profile.
pub struct Http1Settings {
    /// Whether to enforce title case the headers.
    pub title_case_headers: bool,
}

#[derive(Debug, Deserialize, Serialize)]
/// The HTTP/2 profile.
///
/// This profile contains the headers and settings for the HTTP/2 protocol.
pub struct Http2Profile {
    /// The headers to be used for the HTTP/2 profile.
    pub headers: HttpHeadersProfile,
    /// The settings for the HTTP/2 profile.
    pub settings: Http2Settings,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
/// The settings for the HTTP/2 profile.
pub struct Http2Settings {
    /// The pseudo headers to be used for the HTTP/2 profile.
    ///
    /// See [`PseudoHeader`] for more details.
    pub http_pseudo_headers: Option<PseudoHeaderOrder>,

    /// The (initial) h2 settings to be used for the HTTP/2 profile.
    ///
    /// See [`SettingsConfig`] for more details.
    pub initial_config: Option<SettingsConfig>,
}
