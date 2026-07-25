use rama_http_types::{HeaderMap, HeaderName, HeaderValue, Version, header, request, response};

use crate::{JsError, JsHostClass, JsHostClassBuilder, JsStr};

pub(super) trait HttpMessage: Send + 'static {
    fn version(&self) -> Version;
    fn version_mut(&mut self) -> &mut Version;
    fn headers(&self) -> &HeaderMap<HeaderValue>;
    fn headers_mut(&mut self) -> &mut HeaderMap<HeaderValue>;
}

impl HttpMessage for request::Parts {
    fn version(&self) -> Version {
        self.version
    }

    fn version_mut(&mut self) -> &mut Version {
        &mut self.version
    }

    fn headers(&self) -> &HeaderMap<HeaderValue> {
        &self.headers
    }

    fn headers_mut(&mut self) -> &mut HeaderMap<HeaderValue> {
        &mut self.headers
    }
}

impl HttpMessage for response::Parts {
    fn version(&self) -> Version {
        self.version
    }

    fn version_mut(&mut self) -> &mut Version {
        &mut self.version
    }

    fn headers(&self) -> &HeaderMap<HeaderValue> {
        &self.headers
    }

    fn headers_mut(&mut self) -> &mut HeaderMap<HeaderValue> {
        &mut self.headers
    }
}

pub(super) fn http_message_class<T>() -> JsHostClassBuilder<T>
where
    T: HttpMessage,
{
    JsHostClass::<T>::builder()
        .getter("version", |message: &T| message.version().as_str())
        .setter(
            "version",
            |message: &mut T, version: JsStr| -> Result<(), JsError> {
                *message.version_mut() = parse_version(&version)?;
                Ok(())
            },
        )
        .method(
            "header",
            |message: &T, name: JsStr| -> Result<Option<JsStr>, JsError> {
                let name = parse_header_name(&name)?;
                message
                    .headers()
                    .get(&name)
                    .map(|value| header_value_to_js(&name, value))
                    .transpose()
            },
        )
        .method(
            "headers",
            |message: &T, name: JsStr| -> Result<Vec<JsStr>, JsError> {
                let name = parse_header_name(&name)?;
                message
                    .headers()
                    .get_all(&name)
                    .iter()
                    .map(|value| header_value_to_js(&name, value))
                    .collect()
            },
        )
        .method("headerNames", |message: &T| {
            message
                .headers()
                .keys()
                .map(|name| JsStr::new(name.as_str()))
                .collect::<Vec<_>>()
        })
        .method(
            "containsHeader",
            |message: &T, name: JsStr| -> Result<bool, JsError> {
                Ok(message.headers().contains_key(parse_header_name(&name)?))
            },
        )
        .method_mut(
            "setHeader",
            |message: &mut T, name: JsStr, value: JsStr| -> Result<(), JsError> {
                message
                    .headers_mut()
                    .insert(mutable_header_name(&name)?, parse_header_value(&value)?);
                Ok(())
            },
        )
        .method_mut(
            "appendHeader",
            |message: &mut T, name: JsStr, value: JsStr| -> Result<(), JsError> {
                message
                    .headers_mut()
                    .append(mutable_header_name(&name)?, parse_header_value(&value)?);
                Ok(())
            },
        )
        .method_mut(
            "removeHeader",
            |message: &mut T, name: JsStr| -> Result<bool, JsError> {
                Ok(message
                    .headers_mut()
                    .remove(mutable_header_name(&name)?)
                    .is_some())
            },
        )
}

fn parse_header_name(name: &JsStr) -> Result<HeaderName, JsError> {
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|err| JsError::conversion(format!("invalid HTTP header name `{name}`: {err}")))
}

/// Parse a header name for mutation, rejecting headers which describe the
/// payload or its framing: the body stays Rust-owned, so a script rewriting
/// these would desync the message from the bytes actually on the wire.
fn mutable_header_name(name: &JsStr) -> Result<HeaderName, JsError> {
    const DENIED: &[HeaderName] = &[
        header::CONTENT_LENGTH,
        header::TRANSFER_ENCODING,
        header::CONTENT_ENCODING,
        header::CONTENT_RANGE,
        header::TRAILER,
        header::TE,
    ];

    let name = parse_header_name(name)?;
    if DENIED.contains(&name) {
        return Err(JsError::conversion(format!(
            "HTTP header `{}` describes the payload and cannot be modified from JavaScript",
            name.as_str()
        )));
    }
    Ok(name)
}

fn parse_header_value(value: &JsStr) -> Result<HeaderValue, JsError> {
    let value = HeaderValue::from_bytes(value.as_bytes())
        .map_err(|err| JsError::conversion(format!("invalid HTTP header value: {err}")))?;
    value
        .to_str()
        .map_err(|err| JsError::conversion(format!("HTTP header value is not text: {err}")))?;
    Ok(value)
}

fn header_value_to_js(name: &HeaderName, value: &HeaderValue) -> Result<JsStr, JsError> {
    value.to_str().map(JsStr::new).map_err(|err| {
        JsError::conversion(format!(
            "HTTP header `{}` contains a non-text value: {err}",
            name.as_str()
        ))
    })
}

fn parse_version(version: &str) -> Result<Version, JsError> {
    version
        .parse()
        .map_err(|_e| JsError::conversion(format!("invalid HTTP version `{version}`")))
}
