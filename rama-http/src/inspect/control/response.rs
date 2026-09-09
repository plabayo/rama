use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseSpec {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Default for ResponseSpec {
    fn default() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            headers: [
                (
                    header::CONTENT_TYPE,
                    crate::HeaderValue::from_static("text/plain; charset=utf-8"),
                ),
                (
                    header::CACHE_CONTROL,
                    crate::HeaderValue::from_static("no-store"),
                ),
            ]
            .into_iter()
            .collect(),
            body: "Blocked by Rama proxy.\n".into(),
        }
    }
}

impl ResponseSpec {
    pub(super) fn validate(&self) -> Result<(), BoxError> {
        let status = self.status;
        if !(200..=599).contains(&self.status.as_u16()) || status == StatusCode::SWITCHING_PROTOCOLS
        {
            return Err(BoxError::from_static_str(
                "local responses must have a final HTTP status",
            ));
        }
        if matches!(self.status.as_u16(), 204 | 205 | 304) && !self.body.is_empty() {
            return Err(BoxError::from_static_str(
                "this status does not permit a response body",
            ));
        }
        if self.body.len() > MAX_MESSAGE_BYTES {
            return Err(BoxError::from_static_str("response body is too large"));
        }
        let headers = validate_headers(&self.headers)?;
        if hop_by_hop_header_names(headers)
            .chain([
                header::CONTENT_LENGTH,
                header::PROXY_AUTHENTICATE,
                header::PROXY_AUTHORIZATION,
            ])
            .any(|name| headers.contains_key(name))
        {
            return Err(BoxError::from_static_str(
                "Rama manages local-response framing and proxy headers",
            ));
        }
        if matches!(self.status.as_u16(), 301 | 302 | 303 | 307 | 308)
            && headers
                .get(header::LOCATION)
                .is_none_or(|v| v.as_bytes().is_empty())
        {
            return Err(BoxError::from_static_str(
                "redirect responses require a Location header",
            ));
        }
        Ok(())
    }

    pub fn build(&self, message: &Message) -> Response {
        // Stored configuration and manual decisions are validated before publication.
        let spec = if message.method == Method::CONNECT && self.status.is_success() {
            std::borrow::Cow::Owned(Self::error(
                StatusCode::BAD_GATEWAY,
                "A local response cannot establish a CONNECT tunnel.",
            ))
        } else if self.status == StatusCode::NOT_MODIFIED && !message.conditional {
            std::borrow::Cow::Owned(Self::error(
                StatusCode::PRECONDITION_FAILED,
                "Not Modified requires a conditional GET or HEAD request.",
            ))
        } else {
            std::borrow::Cow::Borrowed(self)
        };
        let mut response = Response::new(if message.method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(spec.body.clone())
        });
        *response.status_mut() = spec.status;
        *response.version_mut() = message.version();
        *response.headers_mut() = spec.headers.clone();
        if !matches!(spec.status.as_u16(), 204 | 304) {
            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, spec.body.len().into());
        }
        // Unread request bodies cannot be reused as the next HTTP/1 request.
        if matches!(message.direction, Direction::Ingress) && message.version() != Version::HTTP_2 {
            response
                .headers_mut()
                .insert(header::CONNECTION, crate::HeaderValue::from_static("close"));
        }
        response
    }

    pub fn error(status: StatusCode, body: &str) -> Self {
        Self {
            status,
            body: body.into(),
            ..Self::default()
        }
    }
}
