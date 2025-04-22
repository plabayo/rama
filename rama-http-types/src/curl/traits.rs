use crate::{Body, Request, Parts}
use crate::dep::http_body;
use bytes::Bytes;
use rama_core::error::{BoxError, OpaqueError};

mod sealed {
    pub trait Sealed {}

    impl<B> Sealed for crate::Request<B> 
    where 
    B: http_body::Body<Data = Bytes, Error = Into<BoxError>> + Send + Sync 
    {}

    impl Sealed for crate::Parts {}

    impl<T: Sealed> Sealed for &T {}
}

/// Sealed trait for converting HTTP request headers into a curl command

pub trait IntoCurlHeadersCommand: sealed::Sealed {
    fn into_curl_headers_command(&self) -> Result<String, OpaqueError>;
}


/// Sealed trait for converting a full HTTP request into a curl command.
pub trait IntoCurlCommand: sealed::Sealed {
    fn into_curl_command(self) -> Result<(String, Request), OpaqueError>;
}

impl<B> IntoCurlHeadersCommand for Request<B> 
where
B: http_body::Body<Data = Bytes, Error = Into<BoxError>> + Send + Sync
{
   fn into_curl_headers_command(&self) -> Result<String, OpaqueError> {
    todo!()
   }
}

impl<B> IntoCurlHeadersCommand for Parts {
    fn into_curl_headers_commandh(&self) -> Result<String, OpaqueError> {
        // TODO: to use the implementation method from headers.rs
        todo!()
    }
}

impl<B> IntoCurlCommand for Request<B> 
where 
B: http_body::Body<Data = Bytes, Error = Into<BoxError>> + Send + Sync
{
    fn into_curl_command(self) -> Result<(String, Request), OpaqueError> {
        // TODO: to use the implementation method from body.rs
        todo!()
    }
}