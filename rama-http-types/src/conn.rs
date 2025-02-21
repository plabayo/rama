//! HTTP connection utilities.

#[derive(Debug, Clone, Default)]
/// Optional parameters that can be set in the [`Context`] of a (h1) request
/// to customise the connection of the h1 connection.
///
/// Can be used by Http connector services, especially in the context of proxies,
/// where there might not be one static config that is to be applied to all client connections.
pub struct Http1ClientContextParams {
    /// Set whether HTTP/1 connections will write header names as title case at
    /// the socket level.
    ///
    /// Default is false.
    pub title_header_case: bool,
}
