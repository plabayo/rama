use rama_core::error::OpaqueError;

pub fn request_headers_to_curl_command<T: IntoCurlHeadersCommand>(request: T) -> Result<String, OpaqueError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::error::OpaqueError;

    // TODO: add tests
}