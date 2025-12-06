use rama_http_headers::{AccessControlAllowHeaders, AccessControlRequestHeaders, HeaderMapExt};
use rama_http_types::{HeaderMap, request::Parts as RequestParts};

#[derive(Clone, Debug)]
pub(super) enum AllowHeaders {
    Const(AccessControlAllowHeaders),
    MirrorRequest,
}

impl AllowHeaders {
    pub(super) fn is_any(&self) -> bool {
        match self {
            Self::Const(header) => header.is_any(),
            Self::MirrorRequest => false,
        }
    }

    pub(super) fn extend_headers(&self, headers: &mut HeaderMap, parts: &RequestParts) {
        match self {
            Self::Const(header) => headers.typed_insert(header),
            Self::MirrorRequest => {
                if let Some(AccessControlRequestHeaders(header_names)) = parts.headers.typed_get() {
                    headers.typed_insert(AccessControlAllowHeaders::new_values(header_names));
                }
            }
        }
    }
}
