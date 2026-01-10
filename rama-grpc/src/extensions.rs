/// A gRPC Method info extension.
#[derive(Debug, Clone)]
pub struct GrpcMethod<'a> {
    service: &'a str,
    method: &'a str,
}

impl<'a> GrpcMethod<'a> {
    /// Create a new `GrpcMethod` extension.
    #[doc(hidden)]
    #[must_use]
    pub fn new(service: &'a str, method: &'a str) -> Self {
        Self { service, method }
    }

    /// gRPC service name
    #[must_use]
    pub fn service(&self) -> &str {
        self.service
    }
    /// gRPC method name
    #[must_use]
    pub fn method(&self) -> &str {
        self.method
    }
}
