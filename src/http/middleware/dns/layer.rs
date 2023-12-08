use crate::{http::HeaderName, service::Layer};

use super::{DefaultDnsResolver, DnsResolver, DnsService, NoDnsResolver};

pub struct DnsLayer<R> {
    resolver: R,
    header_name: Option<HeaderName>,
}

impl DnsLayer<NoDnsResolver> {
    pub fn new() -> Self {
        Self {
            resolver: NoDnsResolver,
            header_name: None,
        }
    }
}

impl Default for DnsLayer<DefaultDnsResolver> {
    fn default() -> Self {
        Self {
            resolver: DefaultDnsResolver,
            header_name: None,
        }
    }
}

impl<R> DnsLayer<R> {
    pub fn resolver<T, S>(self, resolver: T) -> DnsLayer<S>
    where
        S: DnsResolver,
        T: Into<S>,
    {
        DnsLayer {
            resolver: resolver.into(),
            header_name: self.header_name,
        }
    }

    pub fn header_name<T>(mut self, header_name: T) -> Self
    where
        T: Into<HeaderName>,
    {
        self.header_name = Some(header_name.into());
        self
    }
}

impl<S, R> Layer<S> for DnsLayer<R>
where
    R: DnsResolver + Clone + Send + Sync + 'static,
{
    type Service = DnsService<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsService {
            inner,
            resolver: self.resolver.clone(),
            header_name: self.header_name.clone(),
        }
    }
}
