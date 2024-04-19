/// Can be used to communicate the desire to limit the size of request/response bodies.
///
/// It is for example used by the [`BodyLimitLayer`] to add this to the request [`Context`],
/// such that http services used can apply the limit when found in that [`Context`].
///
/// [`Context`]: crate::service::Context`
/// [`BodyLimitLayer`]: crate::service::layer::http::BodyLimitLayer
#[derive(Debug, Clone, Copy)]
pub struct BodyLimit {
    kind: Option<BodyLimitKind>,
}

#[derive(Debug, Clone, Copy)]
enum BodyLimitKind {
    Bidirectional(usize, usize),
    Request(usize),
    Response(usize),
}

impl BodyLimit {
    /// Create a new [`BodyLimit`], with the given limit to be applied to the request only.
    pub fn request_only(limit: usize) -> Self {
        Self {
            kind: if limit == 0 {
                None
            } else {
                Some(BodyLimitKind::Request(limit))
            },
        }
    }

    /// Create a new [`BodyLimit`], with the given limit to be applied to the response only.
    pub fn response_only(limit: usize) -> Self {
        Self {
            kind: if limit == 0 {
                None
            } else {
                Some(BodyLimitKind::Response(limit))
            },
        }
    }

    /// Create a new [`BodyLimit`], with the given limit to be applied to both the request and response bodies.
    pub fn symmetric(limit: usize) -> Self {
        Self {
            kind: if limit == 0 {
                None
            } else {
                Some(BodyLimitKind::Bidirectional(limit, limit))
            },
        }
    }

    /// Create a new [`BodyLimit`], with the given limits
    /// respectively to be applied to the request and response bodies.
    pub fn asymmetric(request: usize, response: usize) -> Self {
        match (request, response) {
            (0, 0) => Self { kind: None },
            (0, response) => Self {
                kind: Some(BodyLimitKind::Response(response)),
            },
            (request, 0) => Self {
                kind: Some(BodyLimitKind::Request(request)),
            },
            (request, response) => Self {
                kind: Some(BodyLimitKind::Bidirectional(request, response)),
            },
        }
    }

    /// Get the limit for the request body, if any.
    pub fn request(&self) -> Option<usize> {
        match self.kind {
            Some(BodyLimitKind::Request(limit)) => Some(limit),
            Some(BodyLimitKind::Bidirectional(request, _)) => Some(request),
            _ => None,
        }
    }

    /// Get the limit for the response body, if any.
    pub fn response(&self) -> Option<usize> {
        match self.kind {
            Some(BodyLimitKind::Response(limit)) => Some(limit),
            Some(BodyLimitKind::Bidirectional(_, response)) => Some(response),
            _ => None,
        }
    }
}
