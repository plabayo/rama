use rama_http_headers::{AccessControlAllowMethods, AccessControlRequestMethod, HeaderMapExt as _};
use rama_http_types::{HeaderMap, request::Parts as RequestParts};

#[derive(Clone, Debug)]
pub(super) enum AllowMethods {
    Const(AccessControlAllowMethods),
    MirrorRequest,
}

impl AllowMethods {
    pub(super) fn is_any(&self) -> bool {
        match self {
            Self::Const(header) => header.is_any(),
            Self::MirrorRequest => false,
        }
    }

    /// Whether the emitted `Access-Control-Allow-Methods` depends on
    /// `Access-Control-Request-Method`. When true, the derived `Vary`
    /// must advertise it so caches don't serve one preflight's allowance
    /// to a different method.
    pub(super) fn varies_with_request_method(&self) -> bool {
        matches!(self, Self::MirrorRequest)
    }

    pub(super) fn extend_headers(&self, headers: &mut HeaderMap, parts: &RequestParts) {
        match self {
            Self::Const(header) => headers.typed_insert(header),
            Self::MirrorRequest => {
                if let Some(AccessControlRequestMethod(method)) = parts.headers.typed_get() {
                    headers.typed_insert(AccessControlAllowMethods::new(method));
                }
            }
        }
    }
}
