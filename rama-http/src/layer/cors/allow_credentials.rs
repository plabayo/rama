use crate::{
    header::{HeaderMap, HeaderValue},
    headers::{AccessControlAllowCredentials, HeaderMapExt as _},
    request::Parts as RequestParts,
};
use std::{fmt, sync::Arc};

#[derive(Clone)]
pub(super) enum AllowCredentials {
    Const,
    Predicate(
        Arc<dyn for<'a> Fn(&'a HeaderValue, &'a RequestParts) -> bool + Send + Sync + 'static>,
    ),
}

impl AllowCredentials {
    pub(super) fn extend_headers(
        &self,
        headers: &mut HeaderMap,
        origin: Option<&HeaderValue>,
        parts: &RequestParts,
    ) {
        match self {
            Self::Const => headers.typed_insert(AccessControlAllowCredentials::default()),
            Self::Predicate(predicate) => {
                if let Some(origin) = origin
                    && predicate(origin, parts)
                {
                    headers.typed_insert(AccessControlAllowCredentials::default())
                }
            }
        }
    }
}

impl fmt::Debug for AllowCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const => f.debug_tuple("Yes").finish(),
            Self::Predicate(_) => f.debug_tuple("Predicate").finish(),
        }
    }
}
