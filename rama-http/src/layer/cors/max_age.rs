use crate::{
    header::{HeaderMap, HeaderValue},
    headers::{AccessControlMaxAge, HeaderMapExt as _, util::Seconds},
    request::Parts as RequestParts,
};
use std::{fmt, sync::Arc};

#[derive(Clone)]
pub(super) enum MaxAge {
    Const(AccessControlMaxAge),
    Predicate(
        Arc<
            dyn for<'a> Fn(&'a HeaderValue, &'a RequestParts) -> Option<Seconds>
                + Send
                + Sync
                + 'static,
        >,
    ),
}

impl MaxAge {
    pub(super) fn extend_headers(
        &self,
        headers: &mut HeaderMap,
        origin: Option<&HeaderValue>,
        parts: &RequestParts,
    ) {
        match self {
            Self::Const(header) => headers.typed_insert(header),
            Self::Predicate(predicate) => {
                if let Some(origin) = origin
                    && let Some(secs) = predicate(origin, parts)
                {
                    headers.typed_insert(AccessControlMaxAge::from(secs));
                }
            }
        }
    }
}

impl fmt::Debug for MaxAge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(header) => f.debug_tuple("Const").field(&header.as_secs()).finish(),
            Self::Predicate(_) => f.debug_tuple("Predicate").finish(),
        }
    }
}
