use rama_core::{
    combinators::Either,
    error::{BoxError, ErrorContext, OpaqueError},
    Context,
};
use rama_dns::{DnsOverwrite, DnsResolver};
use rama_net::address::{Authority, Domain, Host};
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{channel, Sender},
        Semaphore,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IPModes {
    Dual,
    SingleIpV4,
    SingleIpV6,
    DualPreferIpV4
}

impl Default for IPModes {
    fn default() -> Self {
        Self::Dual
    }
}

//DNS Resolver
#[derive(Clone)]
struct DnsResolveIpMode<D>{
    resolver: D,
    mode: IPModes
}

impl<D> DnsResolveIpMode<D>{
    fn new(resolver:D, mode: IPModes) -> Self {
        Self { resolver, mode}
    }
}

struct ConnectIpMode<C>{
    connector: C,
    ip_mode: IPModes
}

impl<C>ConnectIpMode<C>{
    fn new(connector: C, ip_mode: IPModes) -> Self {
        Self {connector, ip_mode}
    }
}



/// Trait used internally by [`tcp_connect`] and the `TcpConnector`
/// to actually establish the [`TcpStream`.]
pub trait TcpStreamConnector: Send + Sync + 'static {
    /// Type of error that can occurr when establishing the connection failed.
    type Error;

    /// Connect to the target via the given [`SocketAddr`]ess to establish a [`TcpStream`].
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, Self::Error>> + Send + '_;
}

impl TcpStreamConnector for () {
    type Error = std::io::Error;

    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, Self::Error>> + Send + '_ {
        TcpStream::connect(addr)
    }
}

impl<T: TcpStreamConnector> TcpStreamConnector for Arc<T> {
    type Error = T::Error;

    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, Self::Error>> + Send + '_ {
        (**self).connect(addr)
    }
}

impl<ConnectFn, ConnectFnFut, ConnectFnErr> TcpStreamConnector for ConnectFn
where
    ConnectFn: Fn(SocketAddr) -> ConnectFnFut + Send + Sync + 'static,
    ConnectFnFut: Future<Output = Result<TcpStream, ConnectFnErr>> + Send + 'static,
    ConnectFnErr: Into<BoxError> + Send + 'static,
{
    type Error = ConnectFnErr;

    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, Self::Error>> + Send + '_ {
        (self)(addr)
    }
}

macro_rules! impl_stream_connector_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> TcpStreamConnector for ::rama_core::combinators::$id<$($param),+>
        where
            $(
                $param: TcpStreamConnector<Error: Into<BoxError>>,
            )+
        {
            type Error = BoxError;

            async fn connect(
                &self,
                addr: SocketAddr,
            ) -> Result<TcpStream, Self::Error> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(s) => s.connect(addr).await.map_err(Into::into),
                    )+
                }
            }
        }
    };
}

::rama_core::combinators::impl_either!(impl_stream_connector_either);

/// Establish a [`TcpStream`] connection for the given [`Authority`].
pub async fn tcp_connect<State, Dns, Connector>(
    ctx: &Context<State>,
    authority: Authority,
    allow_overwrites: bool,
    dns: Dns,
    connector: Connector,
) -> Result<(TcpStream, SocketAddr), OpaqueError>
where
    State: Clone + Send + Sync + 'static,
    Dns: DnsResolver<Error: Into<BoxError>> + Clone,
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    let (host, port) = authority.into_parts();
    let domain = match host {
        Host::Name(domain) => domain,
        Host::Address(ip) => {
            // if the authority is already defined as an IP address, we can directly connect to it
            let addr = (ip, port).into();
            let stream = connector
                .connect(addr)
                .await
                .map_err(|err| OpaqueError::from_boxed(err.into()))
                .context("establish tcp client connection")?;
            return Ok((stream, addr));
        }
    };

    if allow_overwrites {
        if let Some(dns_overwrite) = ctx.get::<DnsOverwrite>() {
            if let Ok(tuple) = tcp_connect_inner(
                ctx,
                domain.clone(),
                port,
                dns_overwrite.deref().clone(),
                connector.clone(),
            )
            .await
            {
                return Ok(tuple);
            }
        }
    }

    //... otherwise we'll try to establish a connection,
    // with dual-stack parallel connections...

    tcp_connect_inner(ctx, domain, port, dns, connector).await
}

async fn tcp_connect_inner<State, Dns, Connector>(
    ctx: &Context<State>,
    domain: Domain,
    port: u16,
    dns: DnsResolveIpMode<Dns>,
    connector: ConnectIpMode<Connector>,
) -> Result<(TcpStream, SocketAddr), OpaqueError>
where
    State: Clone + Send + Sync + 'static,
    Dns: DnsResolver<Error: Into<BoxError>> + Clone,
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    let (tx, mut rx) = channel(1);

    let connected = Arc::new(AtomicBool::new(false));
    let sem = Arc::new(Semaphore::new(3));

    match dns.mode {
        DnsResolveIpMode::SingleIpV4 | DnsResolveIpMode::DualPreferIpV4 | DnsResovleIpMode::Dual =>{
            //IPV4
            ctx.spawn(tcp_connect_inner_branch(
                dns.clone(),
                connector.clone(),
                IpKind::Ipv4,
                domain.clone(),
                port,
                tx.clone(),
                connected.clone(),
                sem.clone(),
            ));
        }
        _ => {}

    }

    match dns.mode {
        DnsResolveIpMode::SingleIpV6 | DnsResovleIpMode::Dual =>{
            //IPV6
            ctx.spawn(tcp_connect_inner_branch(
                dns.clone(),
                connector.clone(),
                IpKind::Ipv6,
                domain.clone(),
                port,
                tx.clone(),
                connected.clone(),
                sem.clone(),
            ));
        }
        _ => {}

    }

    // wait for the first connection to succeed,
    // ignore the rest of the connections (sorry, but not sorry)
    if let Some((stream, addr)) = rx.recv().await {
        connected.store(true, Ordering::Release);
        return Ok((stream, addr));
    }

    Err(OpaqueError::from_display(format!(
        "failed to connect to any resolved IP address for {domain} (port {port})"
    )))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum IpKind {
    Ipv4,
    Ipv6,
}

#[allow(clippy::too_many_arguments)]
async fn tcp_connect_inner_branch<Dns, Connector>(
    dns: Dns,
    connector: Connector,
    ip_kind: IpKind,
    domain: Domain,
    port: u16,
    tx: Sender<(TcpStream, SocketAddr)>,
    connected: Arc<AtomicBool>,
    sem: Arc<Semaphore>,
) where
    Dns: DnsResolver<Error: Into<BoxError>> + Clone,
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    
    let ip_it = match ip_kind {
        IpKind::Ipv4 if matches!(dns.mode, DnsResolveIpMode::Dual |DnsResolveIpMode::SingleIpV4 |DnsResolveIpMode::DualPreferIpV4 ) =>{
            match dns.ipv4_lookup(domain).await {
            Ok(ips) => Either::A(ips.into_iter().map(IpAddr::V4)),
            Err(err) => {
                let err = OpaqueError::from_boxed(err.into());
                tracing::trace!(err = %err, "[{ip_kind:?}] failed to resolve domain to IPv4 addresses");
                return;
            }
        }
    },
        IpKind::Ipv6 if matches!(dns.mode, DnsResolveIpMode::Dual |DnsResolveIpMode::SingleIpV6)=> {
            match dns.ipv6_lookup(domain).await {
            Ok(ips) => Either::B(ips.into_iter().map(IpAddr::V6)),
            Err(err) => {
                let err = OpaqueError::from_boxed(err.into());
                tracing::trace!(err = ?err, "[{ip_kind:?}] failed to resolve domain to IPv6 addresses");
                return;
            }
        }
    },
        _ => return,
    };

    for (index, ip) in ip_it.enumerate() {
        let addr = (ip, port).into();

        let sem = sem.clone();
        let tx = tx.clone();
        let connected = connected.clone();

        // back off retries exponentially
        if index > 0 {
            let delay = match ip_kind {
                IpKind::Ipv4 => Duration::from_micros((21 * 2 * index) as u64),
                IpKind::Ipv6 => Duration::from_micros((15 * 2 * index) as u64),
            };
            tokio::time::sleep(delay).await;
        }

        if connected.load(Ordering::Acquire) {
            tracing::trace!("[{ip_kind:?}] #{index}: abort connect loop to {addr} (connection already established)");
            return;
        }

        let connector = connector.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if connected.load(Ordering::Acquire) {
                tracing::trace!("[{ip_kind:?}] #{index}: abort spawned attempt to {addr} (connection already established)");
                return;
            }

            tracing::trace!("[{ip_kind:?}] #{index}: tcp connect attempt to {addr}");

            match connector.connect(addr).await {
                Ok(stream) => {
                    tracing::trace!("[{ip_kind:?}] #{index}: tcp connection stablished to {addr}");
                    if let Err(err) = tx.send((stream, addr)).await {
                        tracing::trace!(err = %err, "[{ip_kind:?}] #{index}: failed to send resolved IP address");
                    }
                }
                Err(err) => {
                    let err = OpaqueError::from_boxed(err.into());
                    tracing::trace!(err = %err, "[{ip_kind:?}] #{index}: tcp connector failed to connect");
                }
            };
        });
    }
}
