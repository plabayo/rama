use std::{net::SocketAddr, sync::Arc};

use rama::net::address::SocketAddress;
use tokio::sync::Mutex;

pub(crate) const OBSERVED_HEADER: &str = "x-rama-tproxy-observed";
pub(crate) const BADGE_LABEL: &str = "ffi apple e2e badge";

#[derive(Clone, Copy, Debug)]
pub(crate) enum ProxyKind {
    None,
    Http,
    Socks5,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum TcpMode {
    Plain,
    Tls,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum HttpTargetKind {
    Plain,
    Tls,
}

#[derive(Clone, Debug)]
pub(crate) struct HttpObservation {
    pub(crate) uri: String,
    pub(crate) observed_header: Option<String>,
}

pub(crate) type SharedObservations = Arc<Mutex<Vec<HttpObservation>>>;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PortBlock {
    pub(crate) http: u16,
    pub(crate) https: u16,
    pub(crate) raw_tcp: u16,
    pub(crate) raw_tls: u16,
    pub(crate) udp: u16,
    pub(crate) proxy: u16,
}

#[inline(always)]
pub(crate) fn localhost(port: u16) -> SocketAddr {
    SocketAddress::local_ipv4(port).into()
}
