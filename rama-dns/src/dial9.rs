//! DNS candidate lookup events. A lookup completes at its first answer or at
//! exhaustion. Dropping it before either records a cancelled operation.

use dial9_trace_format::TraceEvent;
use pin_project_lite::pin_project;
use rama_core::{
    futures::Stream,
    telemetry::dial9::{Dial9Handle, Operation, Outcome, core::clock_monotonic_ns},
};
use rama_net::address::Domain;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[derive(TraceEvent)]
pub struct DnsLookupStarted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub domain: Domain,
    /// `4` for A records, `6` for AAAA records.
    pub query_family: u32,
}

#[derive(TraceEvent)]
pub struct DnsLookupResolved {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub domain: Domain,
    pub query_family: u32,
    #[traceevent(unit = "ms")]
    pub elapsed_ms: u64,
    pub success: bool,
}

pin_project! {
    pub(crate) struct Lookup<S> {
        #[pin]
        inner: S,
        domain: Option<Domain>,
        family: u32,
        operation: Option<Operation>,
    }
}

/// Capture only the name while enabled; creation alone emits no events.
pub(crate) fn lookup<S>(domain: Domain, family: u32, make: impl FnOnce(Domain) -> S) -> Lookup<S> {
    let recorded_domain = Dial9Handle::current().is_enabled().then(|| domain.clone());
    Lookup {
        inner: make(domain),
        domain: recorded_domain,
        family,
        operation: None,
    }
}

pub(crate) fn wrap<S>(domain: &Domain, family: u32, inner: S) -> Lookup<S> {
    let domain = Dial9Handle::current().is_enabled().then(|| domain.clone());
    Lookup {
        inner,
        domain,
        family,
        operation: None,
    }
}

impl<S, A, E> Stream for Lookup<S>
where
    S: Stream<Item = Result<A, E>>,
{
    type Item = Result<A, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if this.operation.is_none()
            && let Some(domain) = this.domain.as_ref()
        {
            let operation = Operation::new("dns.lookup");
            operation.record_event_with(|context| DnsLookupStarted {
                timestamp_ns: clock_monotonic_ns(),
                flow_id: context.flow_id(),
                operation_id: context.operation_id(),
                domain: domain.clone(),
                query_family: *this.family,
            });
            *this.operation = Some(operation);
        }
        let result = if let Some(operation) = this.operation.as_ref() {
            operation
                .context()
                .scope_sync(|| this.inner.as_mut().poll_next(cx))
        } else {
            this.inner.as_mut().poll_next(cx)
        };
        let success = matches!(result, Poll::Ready(Some(Ok(_))));
        if (success || matches!(result, Poll::Ready(None)))
            && let Some(operation) = this.operation.take()
            && let Some(domain) = this.domain.take()
        {
            operation.record_event_with(|context| DnsLookupResolved {
                timestamp_ns: clock_monotonic_ns(),
                flow_id: context.flow_id(),
                operation_id: context.operation_id(),
                domain,
                query_family: *this.family,
                elapsed_ms: u64::try_from(operation.elapsed().as_millis()).unwrap_or(u64::MAX),
                success,
            });
            operation.finish(if success {
                Outcome::Success
            } else {
                Outcome::Error
            });
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::resolver::{DnsAddressResolver, HappyEyeballAddressResolverExt};
    use dial9_trace_format::{decoder::Decoder, types::FieldValueRef};
    use rama_core::{
        futures::{StreamExt as _, stream},
        telemetry::dial9::{DiskBuffer, TokioAttachOptions, recorder_or_disabled},
    };
    use std::{
        collections::BTreeSet,
        convert::Infallible,
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    struct Resolver;
    impl DnsAddressResolver for Resolver {
        type Error = Infallible;
        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Infallible>> + Send + '_ {
            stream::iter([Ok(Ipv4Addr::LOCALHOST)])
        }
        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Infallible>> + Send + '_ {
            stream::iter([Ok(Ipv6Addr::LOCALHOST)])
        }
    }

    #[test]
    fn lookup_paths_record_real_work_and_pair_cancellation() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let recorder = recorder_or_disabled(
            DiskBuffer::builder()
                .base_path(dir.path())
                .max_total_size(4 << 20)
                .build(),
        )
        .build();
        assert!(recorder.handle().is_enabled());
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all().worker_threads(1);
        let runtime = rama_core::rt::OwnedRuntime::attach_dial9(
            recorder.handle().clone(),
            builder,
            TokioAttachOptions::default(),
        )
        .unwrap();
        runtime.block_on(async {
            let domain = Domain::try_from("recorded.example").unwrap();
            drop(Resolver.lookup_ipv4_first(domain.clone()));
            drop(Resolver.happy_eyeballs_resolver(domain.clone()).lookup_ip());
            Resolver
                .lookup_ipv4_first(domain.clone())
                .await
                .unwrap()
                .unwrap();
            Resolver
                .lookup_ipv6_first(domain.clone())
                .await
                .unwrap()
                .unwrap();
            Resolver
                .lookup_ipv4_rand(domain.clone())
                .await
                .unwrap()
                .unwrap();
            Resolver
                .lookup_ipv6_rand(domain.clone())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                Resolver
                    .happy_eyeballs_resolver(domain.clone())
                    .lookup_ip()
                    .count()
                    .await,
                2
            );
            let empty = lookup(domain.clone(), 4, |_| {
                stream::empty::<Result<u8, Infallible>>()
            });
            assert_eq!(empty.count().await, 0);
            let mut pending = std::pin::pin!(lookup(domain, 6, |_| stream::pending::<
                Result<u8, Infallible>,
            >()));
            std::future::poll_fn(|cx| {
                assert!(pending.as_mut().poll_next(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        });
        runtime.shutdown_bounded(Duration::from_secs(1));
        recorder.graceful_shutdown(Duration::from_secs(1));
        let bytes = std::fs::read(dir.path().join("trace.0.bin")).unwrap();
        let mut starts = BTreeSet::new();
        let mut resolved = BTreeSet::new();
        let mut cancelled = 0;
        Decoder::new(&bytes)
            .unwrap()
            .for_each_event(|event| {
                let value = |field| {
                    event
                        .field_names()
                        .zip(event.fields.iter())
                        .find_map(|(name, value)| {
                            if name == field
                                && let FieldValueRef::Varint(value) = value
                            {
                                Some(*value)
                            } else {
                                None
                            }
                        })
                };
                match event.name {
                    "DnsLookupStarted" => {
                        assert!(starts.insert(value("operation_id").unwrap()));
                    }
                    "DnsLookupResolved" => {
                        assert!(resolved.insert(value("operation_id").unwrap()));
                    }
                    "RamaOperationFinished"
                        if value("outcome") == Some(Outcome::Cancelled as u64) =>
                    {
                        cancelled += 1
                    }
                    _ => {}
                }
            })
            .unwrap();
        assert_eq!(starts.len(), 8);
        assert_eq!(resolved.len(), 7);
        assert!(resolved.is_subset(&starts));
        assert_eq!(cancelled, 1);
    }
}
