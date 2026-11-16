use crate::{StatusCode, body::util::is_length_limit_error};
use rama_core::error::is_timeout_error;
use std::error::Error;

/// The status that answers a request whose body failed to be read with `error`.
pub(crate) fn body_error_status(error: &(dyn Error + 'static)) -> StatusCode {
    if is_length_limit_error(error) {
        StatusCode::PAYLOAD_TOO_LARGE
    } else if is_timeout_error(error) {
        StatusCode::REQUEST_TIMEOUT
    } else {
        StatusCode::BAD_REQUEST
    }
}
