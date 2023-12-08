use crate::{http::HeaderName, service::Layer};

use super::{DnsResolver, DnsService};

pub struct DnsLayer<R> {
    resolver: R,
    header_name: Option<HeaderName>,
}

impl<R> DnsLayer<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            header_name: None,
        }
    }

    pub fn resolver<T>(self, resolver: T) -> DnsLayer<T> {
        DnsLayer {
            resolver,
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
