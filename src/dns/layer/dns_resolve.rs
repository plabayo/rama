use std::{future::Future, net::SocketAddr};

/// An implementation of `DynamicDnsResolver` is used to resolve a hostname to
/// a set of Socket addresses at runtime.
pub trait DynamicDnsResolver: Send + Sync + 'static {
    /// The type of iterator returned by `lookup_host`.
    type Iterator: Iterator<Item = SocketAddr> + Send + 'static;

    /// Resolve host names to a set of Socket addresses.
    fn lookup_host(
        &self,
        host: String,
    ) -> impl Future<Output = Result<Self::Iterator, std::io::Error>> + Send + '_;
}

impl<F, Fut, I> DynamicDnsResolver for F
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<I, std::io::Error>> + Send + 'static,
    I: Iterator<Item = SocketAddr> + Send + 'static,
{
    type Iterator = I;

    fn lookup_host(
        &self,
        host: String,
    ) -> impl Future<Output = Result<Self::Iterator, std::io::Error>> + Send + '_ {
        (self)(host)
    }
}

impl DynamicDnsResolver for () {
    type Iterator = std::iter::Empty<SocketAddr>;

    async fn lookup_host(&self, _host: String) -> Result<Self::Iterator, std::io::Error> {
        Ok(std::iter::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_dns_resolver_contract() {
        fn dynamic_dns_resolver_contract<T: DynamicDnsResolver>(_t: T) {}

        dynamic_dns_resolver_contract(());
        dynamic_dns_resolver_contract(tokio::net::lookup_host);
    }
}
