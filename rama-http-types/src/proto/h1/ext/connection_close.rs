use rama_core::extensions::Extension;

/// Marks an HTTP/1 message after which the connection cannot be reused.
///
/// The decoder derives this from the HTTP version and all `Connection`
/// fields. Client pools can therefore retire the connection synchronously
/// when returning a response, without racing the connection driver shutdown.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Extension)]
#[extension(tags(http))]
pub struct ConnectionClose;
