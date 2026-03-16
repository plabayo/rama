use std::{
    net::SocketAddr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU16, Ordering},
    },
};

use rama::net::address::SocketAddress;
use tokio::sync::Mutex;

const SERVER_PORT_BASE: u16 = 50000;
const SERVER_PORT_BLOCK_SIZE: u16 = 10;
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

pub(crate) fn next_port_block() -> PortBlock {
    let base = next_server_port_counter().fetch_add(SERVER_PORT_BLOCK_SIZE, Ordering::SeqCst);
    PortBlock {
        http: base + 1,
        https: base + 2,
        raw_tcp: base + 3,
        raw_tls: base + 4,
        udp: base + 5,
        proxy: base + 6,
    }
}

fn process_port_offset() -> u16 {
    let pid = std::process::id() as u16;
    (pid % 100) * 10
}

fn next_server_port_counter() -> &'static AtomicU16 {
    static NEXT_SERVER_PORT: OnceLock<AtomicU16> = OnceLock::new();
    NEXT_SERVER_PORT.get_or_init(|| AtomicU16::new(SERVER_PORT_BASE + process_port_offset()))
}
