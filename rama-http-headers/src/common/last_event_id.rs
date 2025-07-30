use crate::util::HeaderValueString;
use std::{fmt, str::FromStr};

/// `Last-Event-ID` header, defined in
/// [WhatWG's SSE spec](https://html.spec.whatwg.org/multipage/server-sent-events.html#the-last-event-id-header)
///
/// The Last-Event-ID` HTTP request header reports an EventSource object's
/// last event ID string to the server when the user agent is to reestablish the connection.
///
/// The spec is a String with the id of the last event, it can be
/// an empty string which acts a sort of "reset".
#[derive(Clone, Debug, PartialEq)]
pub struct LastEventId(HeaderValueString);

derive_header! {
    LastEventId(_),
    name: LAST_EVENT_ID
}

impl LastEventId {
    #[inline]
    /// Return the id as a borrowed string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for LastEventId {
    #[inline]
    /// Return the id as a borrowed string.
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl LastEventId {
    /// Create a `LastEventId` with a static string.
    ///
    /// # Panic
    ///
    /// Panics if the string is not a legal header value.
    #[must_use]
    pub fn from_static(s: &'static str) -> Self {
        Self(HeaderValueString::from_static(s))
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "last-event-id is not valid"]
    pub struct InvalidLastEventId;
}

impl FromStr for LastEventId {
    type Err = InvalidLastEventId;
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        HeaderValueString::from_str(src)
            .map(LastEventId)
            .map_err(|_| InvalidLastEventId)
    }
}

impl fmt::Display for LastEventId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
