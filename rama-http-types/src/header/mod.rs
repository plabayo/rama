//! Forked from the `http` crate (v1.4.0, MIT) — vendored so rama owns its HTTP
//! header types. See `docs/thirdparty/fork/README.md`. The fork-style lint
//! allows below also cover the `name`/`value`/`map` child modules.
//!
//! HTTP header types
//!
//! The module provides [`HeaderName`], [`HeaderMap`], and a number of types
//! used for interacting with `HeaderMap`. These types allow representing both
//! HTTP/1 and HTTP/2 headers.
//!
//! # `HeaderName`
//!
//! The `HeaderName` type represents both standard header names as well as
//! custom header names. The type handles the case insensitive nature of header
//! names and is used as the key portion of `HeaderMap`. Header names are
//! normalized to lower case. In other words, when creating a `HeaderName` with
//! a string, even if upper case characters are included, when getting a string
//! representation of the `HeaderName`, it will be all lower case. This allows
//! for faster `HeaderMap` comparison operations.
//!
//! The internal representation is optimized to efficiently handle the cases
//! most commonly encountered when working with HTTP. Standard header names are
//! special cased and are represented internally as an enum. Short custom
//! headers will be stored directly in the `HeaderName` struct and will not
//! incur any allocation overhead, however longer strings will require an
//! allocation for storage.
//!
//! ## Limitations
//!
//! `HeaderName` has a max length of 32,768 for header names. Attempting to
//! parse longer names will result in a panic.
//!
//! # `HeaderMap`
//!
//! The [`HeaderMap`] type is a specialized
//! [multimap](<https://en.wikipedia.org/wiki/Multimap>) structure for storing
//! header names and values. It is designed specifically for efficient
//! manipulation of HTTP headers. It supports multiple values per header name
//! and provides specialized APIs for insertion, retrieval, and iteration.
//!
//! [*See also the `HeaderMap` type.*](HeaderMap)

// Vendored verbatim: keep upstream's style/idioms rather than rama's. We keep
// `clippy::correctness` active (to catch any copy error) but silence the style/
// pedantic/nursery groups and the restriction lints upstream uses freely.
#![allow(
    unreachable_pub,
    clippy::allow_attributes,
    clippy::style,
    clippy::complexity,
    clippy::perf,
    clippy::suspicious,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::get_unwrap,
    clippy::assertions_on_result_states,
    clippy::str_to_string,
    clippy::let_underscore_must_use,
    clippy::multiple_unsafe_ops_per_block,
    clippy::unnecessary_safety_comment,
    clippy::map_err_ignore,
    dead_code,
    mismatched_lifetime_syntaxes,
    unsafe_op_in_unsafe_fn
)]

mod map;
mod name;
mod value;

pub use self::map::{
    AsHeaderName, Drain, Entry, GetAll, HeaderMap, IntoHeaderName, IntoIter, Iter, IterMut, Keys,
    MaxSizeReached, OccupiedEntry, VacantEntry, ValueDrain, ValueIter, ValueIterMut, Values,
    ValuesMut,
};
pub use self::name::{HeaderName, InvalidHeaderName};
pub use self::value::{HeaderValue, InvalidHeaderValue, ToStrError};

// Use header name constants
#[rustfmt::skip]
pub use self::name::{
    ACCEPT,
    ACCEPT_CHARSET,
    ACCEPT_ENCODING,
    ACCEPT_LANGUAGE,
    ACCEPT_RANGES,
    ACCESS_CONTROL_ALLOW_CREDENTIALS,
    ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS,
    ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS,
    ACCESS_CONTROL_REQUEST_METHOD,
    AGE,
    ALLOW,
    ALT_SVC,
    AUTHORIZATION,
    CACHE_CONTROL,
    CACHE_STATUS,
    CDN_CACHE_CONTROL,
    CONNECTION,
    CONTENT_DISPOSITION,
    CONTENT_ENCODING,
    CONTENT_LANGUAGE,
    CONTENT_LENGTH,
    CONTENT_LOCATION,
    CONTENT_RANGE,
    CONTENT_SECURITY_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY,
    CONTENT_TYPE,
    COOKIE,
    DNT,
    DATE,
    ETAG,
    EXPECT,
    EXPIRES,
    FORWARDED,
    FROM,
    HOST,
    IF_MATCH,
    IF_MODIFIED_SINCE,
    IF_NONE_MATCH,
    IF_RANGE,
    IF_UNMODIFIED_SINCE,
    LAST_MODIFIED,
    LINK,
    LOCATION,
    MAX_FORWARDS,
    ORIGIN,
    PRAGMA,
    PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION,
    PUBLIC_KEY_PINS,
    PUBLIC_KEY_PINS_REPORT_ONLY,
    RANGE,
    REFERER,
    REFERRER_POLICY,
    REFRESH,
    RETRY_AFTER,
    SEC_WEBSOCKET_ACCEPT,
    SEC_WEBSOCKET_EXTENSIONS,
    SEC_WEBSOCKET_KEY,
    SEC_WEBSOCKET_PROTOCOL,
    SEC_WEBSOCKET_VERSION,
    SERVER,
    SET_COOKIE,
    STRICT_TRANSPORT_SECURITY,
    TE,
    TRAILER,
    TRANSFER_ENCODING,
    UPGRADE,
    UPGRADE_INSECURE_REQUESTS,
    USER_AGENT,
    VARY,
    VIA,
    WARNING,
    WWW_AUTHENTICATE,
    X_CONTENT_TYPE_OPTIONS,
    X_DNS_PREFETCH_CONTROL,
    X_FRAME_OPTIONS,
    X_XSS_PROTECTION,
    X_FORWARDED_HOST,
    X_FORWARDED_FOR,
    X_FORWARDED_PROTO,
    X_ROBOTS_TAG,
    X_CLACKS_OVERHEAD,
    SEC_GPC,
    SEC_FETCH_SITE,
    PERMISSIONS_POLICY,
    CROSS_ORIGIN_EMBEDDER_POLICY,
    CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY,
    CROSS_ORIGIN_OPENER_POLICY,
    CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY,
    CROSS_ORIGIN_RESOURCE_POLICY,
    KEEP_ALIVE,
    PROXY_CONNECTION,
    LAST_EVENT_ID,
    CF_CONNECTING_IP,
    TRUE_CLIENT_IP,
    CLIENT_IP,
    X_CLIENT_IP,
    X_REAL_IP,
    ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK,
    ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK,
    SEC_CH_SAVE_DATA,
    SEC_CH_ECT,
    SEC_CH_RTT,
    SEC_CH_DOWNLINK,
    ACCEPT_CH,
    CRITICAL_CH,
};

/// Maximum length of a header name
///
/// Generally, 64kb for a header name is WAY too much than would ever be needed
/// in practice. Restricting it to this size enables using `u16` values to
/// represent offsets when dealing with header names.
const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;

/// Static Header Value that is can be used as `User-Agent` or `Server` header.
pub static RAMA_ID_HEADER_VALUE: HeaderValue = HeaderValue::from_static(const_format::formatcp!(
    "{}/{}",
    rama_utils::info::NAME,
    rama_utils::info::VERSION
));
