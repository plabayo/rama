use crate::{
    header::{HeaderMap, HeaderValue},
    headers::{AccessControlAllowOrigin, HeaderMapExt as _},
    request::Parts as RequestParts,
};
use std::{fmt, sync::Arc};

#[derive(Clone)]
pub(super) enum AllowOrigin {
    Any,
    Null,
    MirrorRequest,
    Predicate(
        Arc<dyn for<'a> Fn(&'a HeaderValue, &'a RequestParts) -> bool + Send + Sync + 'static>,
    ),
}

impl AllowOrigin {
    pub(super) fn is_any(&self) -> bool {
        match self {
            Self::Any => true,
            Self::Null | Self::MirrorRequest | Self::Predicate(_) => false,
        }
    }

    pub(super) fn extend_headers(
        &self,
        headers: &mut HeaderMap,
        origin: Option<&HeaderValue>,
        parts: &RequestParts,
    ) {
        match self {
            Self::Any => headers.typed_insert(AccessControlAllowOrigin::ANY),
            Self::Null => {
                if origin
                    .map(|v| v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"null"))
                    .unwrap_or(true)
                {
                    headers.typed_insert(AccessControlAllowOrigin::NULL);
                }
            }
            Self::MirrorRequest => {
                if let Some(origin) = origin
                    && let Some(header) =
                        AccessControlAllowOrigin::try_from_origin_header_value(origin)
                {
                    headers.typed_insert(header);
                }
            }
            Self::Predicate(predicate) => {
                if let Some(origin) = origin
                    && predicate(origin, parts)
                    && let Some(header) =
                        AccessControlAllowOrigin::try_from_origin_header_value(origin)
                {
                    headers.typed_insert(header);
                }
            }
        }
    }
}

impl fmt::Debug for AllowOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.debug_tuple("Any").finish(),
            Self::Null => f.debug_tuple("Null").finish(),
            Self::MirrorRequest => f.debug_tuple("MirrorRequest").finish(),
            Self::Predicate(_) => f.debug_tuple("Predicate").finish(),
        }
    }
}
