use rama_http_types::{HeaderName, HeaderValue, Method};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Access-Control-Request-Method` header, part of
/// [CORS](http://www.w3.org/TR/cors/#access-control-request-method-request-header)
///
/// The `Access-Control-Request-Method` header indicates which method will be
/// used in the actual request as part of the preflight request.
/// # ABNF
///
/// ```text
/// Access-Control-Request-Method: \"Access-Control-Request-Method\" \":\" Method
/// ```
///
/// # Example values
/// * `GET`
///
/// # Examples
///
/// ```
/// use rama_http_headers::AccessControlRequestMethod;
/// use rama_http_types::Method;
///
/// let req_method = AccessControlRequestMethod::from(Method::GET);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccessControlRequestMethod(Method);

impl TypedHeader for AccessControlRequestMethod {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::ACCESS_CONTROL_REQUEST_METHOD
    }
}

impl HeaderDecode for AccessControlRequestMethod {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .next()
            .and_then(|value| Method::from_bytes(value.as_bytes()).ok())
            .map(AccessControlRequestMethod)
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for AccessControlRequestMethod {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        // For the more common methods, try to use a static string.
        let s = match self.0 {
            Method::GET => "GET",
            Method::POST => "POST",
            Method::PUT => "PUT",
            Method::DELETE => "DELETE",
            _ => {
                let val = HeaderValue::from_str(self.0.as_ref())
                    .expect("Methods are also valid HeaderValues");
                values.extend(::std::iter::once(val));
                return;
            }
        };

        values.extend(::std::iter::once(HeaderValue::from_static(s)));
    }
}

impl From<Method> for AccessControlRequestMethod {
    fn from(method: Method) -> Self {
        Self(method)
    }
}

impl From<AccessControlRequestMethod> for Method {
    fn from(method: AccessControlRequestMethod) -> Self {
        method.0
    }
}
