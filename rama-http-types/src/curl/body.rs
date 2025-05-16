use crate::{Body, Request};
use rama_core::error::OpaqueError;

pub fn request_to_curl_command<T: IntoCurlCommand>(request: T) -> Result<(String, Request), OpaqueError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{Body, Request};
    use rama_core::error::OpaqueError;

    // TODO: add tests
}