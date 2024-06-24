use std::{future::Future, net::SocketAddr};

/// Generator-like trait that resolves a [`Authority`] to a list of [`SocketAddr`]esses.
///
/// [`Authority`]: crate::net::address::Authority
pub trait DnsResolver: Send + 'static {
    /// Returns the next [`SocketAddr`] in the list of resolved addresses.
    ///
    /// If there are no more addresses to resolve, it should return `None`.
    ///
    /// Errors should be handled by the resolver itself, and not propagated to the caller.
    /// The result of an error should be the same as if no more addresses were found.
    fn next_addr(&mut self) -> impl Future<Output = Option<SocketAddr>> + Send + '_;
}

impl<I> DnsResolver for I
where
    I: Iterator<Item = SocketAddr> + Send + 'static,
{
    async fn next_addr(&mut self) -> Option<SocketAddr> {
        self.next()
    }
}
