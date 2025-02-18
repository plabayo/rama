use std::fmt;

/// ICAP status codes as defined in RFC 3507
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusCode {
    // 1xx Informational
    Continue = 100,

    // 2xx Success
    Ok = 200,
    NoContent = 204,

    // 4xx Client Errors
    BadRequest = 400,
    ServiceNotFound = 404,
    MethodNotAllowed = 405,
    RequestTimeout = 408,

    // 5xx Server Errors
    ServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceOverloaded = 503,
    VersionNotSupported = 505,
}

impl StatusCode {
    /// Creates a new StatusCode from a u16 status code
    pub fn from_u16(code: u16) -> Option<StatusCode> {
        match code {
            100 => Some(StatusCode::Continue),
            200 => Some(StatusCode::Ok),
            204 => Some(StatusCode::NoContent),
            400 => Some(StatusCode::BadRequest),
            404 => Some(StatusCode::ServiceNotFound),
            405 => Some(StatusCode::MethodNotAllowed),
            408 => Some(StatusCode::RequestTimeout),
            500 => Some(StatusCode::ServerError),
            501 => Some(StatusCode::NotImplemented),
            502 => Some(StatusCode::BadGateway),
            503 => Some(StatusCode::ServiceOverloaded),
            505 => Some(StatusCode::VersionNotSupported),
            _ => None,
        }
    }

    /// Returns true if status code is informational (1xx)
    pub fn is_informational(&self) -> bool {
        (*self as u16) >= 100 && (*self as u16) < 200
    }

    /// Returns true if status code indicates success (2xx)
    pub fn is_success(&self) -> bool {
        (*self as u16) >= 200 && (*self as u16) < 300
    }

    /// Returns true if status code indicates client error (4xx)
    pub fn is_client_error(&self) -> bool {
        (*self as u16) >= 400 && (*self as u16) < 500
    }

    /// Returns true if status code indicates server error (5xx)
    pub fn is_server_error(&self) -> bool {
        (*self as u16) >= 500 && (*self as u16) < 600
    }

    /// Returns true if status code indicates any kind of error (4xx or 5xx)
    pub fn is_error(&self) -> bool {
        self.is_client_error() || self.is_server_error()
    }

    /// Returns the canonical reason phrase for this status code
    pub fn canonical_reason(&self) -> &'static str {
        match *self {
            StatusCode::Continue => "Continue",
            StatusCode::Ok => "OK",
            StatusCode::NoContent => "No Content",
            StatusCode::BadRequest => "Bad Request",
            StatusCode::ServiceNotFound => "Service Not Found",
            StatusCode::MethodNotAllowed => "Method Not Allowed",
            StatusCode::RequestTimeout => "Request Timeout",
            StatusCode::ServerError => "Server Error",
            StatusCode::NotImplemented => "Not Implemented",
            StatusCode::BadGateway => "Bad Gateway",
            StatusCode::ServiceOverloaded => "Service Overloaded",
            StatusCode::VersionNotSupported => "ICAP Version Not Supported",
        }
    }

    /// Returns the status code as a u16
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.as_u16(), self.canonical_reason())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_from_u16() {
        assert_eq!(StatusCode::from_u16(100), Some(StatusCode::Continue));
        assert_eq!(StatusCode::from_u16(200), Some(StatusCode::Ok));
        assert_eq!(StatusCode::from_u16(204), Some(StatusCode::NoContent));
        assert_eq!(StatusCode::from_u16(999), None);
    }

    #[test]
    fn test_status_code_categories() {
        assert!(StatusCode::Continue.is_informational());
        assert!(StatusCode::Ok.is_success());
        assert!(StatusCode::BadRequest.is_client_error());
        assert!(StatusCode::ServerError.is_server_error());
        assert!(StatusCode::BadRequest.is_error());
    }

    #[test]
    fn test_status_code_display() {
        assert_eq!(StatusCode::Ok.to_string(), "200 OK");
        assert_eq!(StatusCode::NoContent.to_string(), "204 No Content");
        assert_eq!(StatusCode::BadRequest.to_string(), "400 Bad Request");
    }
}
