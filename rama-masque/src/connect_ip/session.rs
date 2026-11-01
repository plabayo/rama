use super::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, ConnectIpCapsule, ConnectIpPolicy, ConnectIpProtocolError,
    ConnectIpState, ConnectIpStateLimits, IpPacketDrop, ROUTE_ADVERTISEMENT, decode_ip_datagram,
    encode_ip_datagram,
};
use parking_lot::Mutex;
use rama_core::{bytes::Bytes, extensions::ExtensionsRef};
use rama_http::{
    datagram::{
        DatagramTransport, HttpDatagramSession, NativeDatagrams, NativeSendError, NativeSendPolicy,
        SessionConfig, SessionError, SessionEvent, SessionReceiver, SessionSender,
        capsule::{CapsuleConfig, UnknownCapsules},
    },
    io::upgrade::Upgraded,
};
use rama_net::ip::{IpPacket, decrement_hop_limit};
use rama_utils::rate::{Acquire, Rate, RateLimiter};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Notify,
    time::{Instant, timeout_at},
};

/// Packet/byte rates and a lifetime byte quota, shared by both tunnel directions.
#[derive(Debug, Clone, Copy)]
pub struct IpBudgetConfig {
    /// Packet rate (also charges control messages and unknown contexts).
    pub packets: Rate,
    /// Maximum packet burst.
    pub packet_burst: u64,
    /// Byte rate, before validation; unknown/oversized packets are charged too.
    pub bytes: Rate,
    /// Maximum byte burst.
    pub byte_burst: u64,
    /// Lifetime byte quota. `None` leaves lifetime bytes unlimited, but rates apply.
    pub byte_quota: Option<u64>,
}
impl Default for IpBudgetConfig {
    fn default() -> Self {
        Self {
            packets: Rate::per_sec(10000),
            packet_burst: 1000,
            bytes: Rate::per_sec(16 * 1024 * 1024),
            byte_burst: 1024 * 1024,
            byte_quota: None,
        }
    }
}
/// A shared principal/connection budget. Clones spend the same counters/buckets.
#[derive(Debug, Clone)]
pub struct ConnectIpBudget {
    packets: RateLimiter,
    bytes: RateLimiter,
    remaining: Option<Arc<AtomicU64>>,
}
impl ConnectIpBudget {
    /// Construct a budget; zero bursts are refused.
    pub fn new(config: IpBudgetConfig) -> Result<Self, ConnectIpError> {
        if config.packet_burst == 0 || config.byte_burst == 0 {
            return Err(ConnectIpError::Config);
        }
        Ok(Self {
            packets: RateLimiter::new(config.packets, config.packet_burst),
            bytes: RateLimiter::new(config.bytes, config.byte_burst),
            remaining: config.byte_quota.map(|q| Arc::new(AtomicU64::new(q))),
        })
    }
    pub(super) fn charge(&self, bytes: u64) -> bool {
        if let Some(remaining) = &self.remaining
            && remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    v.checked_sub(bytes)
                })
                .is_err()
        {
            return false;
        }
        // Failed attempts retain their charge: a malformed flood cannot gain free work.
        let packet = self.packets.try_acquire(1) == Acquire::Granted;
        let bytes = self.bytes.try_acquire(bytes) == Acquire::Granted;
        packet && bytes
    }
}

/// Configuration shared by a tunnel's send and receive halves.
#[derive(Debug, Clone)]
pub struct ConnectIpSessionConfig {
    /// Locally authorized packet permissions; peer declarations cannot extend them.
    pub policy: ConnectIpPolicy,
    /// Bounded control state.
    pub state: ConnectIpStateLimits,
    /// Largest accepted IP packet, excluding the Context ID; up to 65575 bytes.
    pub max_packet_size: usize,
    /// IPv6 link MTU guaranteed out of band, or `None` to disable IPv6.
    ///
    /// Set only after verifying the complete tunnel path (including intermediaries),
    /// or an RFC 9484 §7.2 probe. Merely assuming the outer QUIC MTU is insufficient.
    /// Otherwise leave this unset and call [`ConnectIpSession::probe_ipv6_mtu`].
    /// Native path shrink below 1280 aborts an IPv6-enabled tunnel.
    pub ipv6_link_mtu: Option<u16>,
    /// Maximum time without accepted packet/control activity.
    pub idle_timeout: Duration,
    /// Maximum time a reliable send/close may remain blocked.
    pub write_timeout: Duration,
    /// Per-tunnel rate/quota configuration; instantiated for each new session.
    pub budget: IpBudgetConfig,
    /// Optional shared principal/connection budgets, charged before the tunnel budget.
    pub shared_budgets: Vec<ConnectIpBudget>,
}
impl ConnectIpSessionConfig {
    /// A bounded session, with IPv6 disabled until its link MTU is verified.
    #[must_use]
    pub fn new(policy: ConnectIpPolicy) -> Self {
        Self {
            policy,
            state: ConnectIpStateLimits::default(),
            max_packet_size: 65575,
            ipv6_link_mtu: None,
            idle_timeout: Duration::from_secs(120),
            write_timeout: Duration::from_secs(5),
            budget: IpBudgetConfig::default(),
            shared_budgets: Vec::new(),
        }
    }
    fn validate(&self) -> Result<(), ConnectIpError> {
        if self.max_packet_size < 20
            || self.max_packet_size > 65575
            || self.state.max_entries == 0
            || self.state.max_entries > 4096
            || self.state.max_request_ids == 0
            || self.state.max_request_ids > 65536
            || self.idle_timeout.is_zero()
            || self.write_timeout.is_zero()
            || self
                .ipv6_link_mtu
                .is_some_and(|n| n < 1280 || usize::from(n) > self.max_packet_size)
        {
            return Err(ConnectIpError::Config);
        }
        Ok(())
    }
    /// HTTP framing configuration, also used when constructing external test carriers.
    pub fn http_config(&self) -> Result<SessionConfig, ConnectIpError> {
        self.validate()?;
        Ok(SessionConfig {
            capsules: CapsuleConfig {
                max_datagram_size: self.max_packet_size + 8,
                max_capsule_size: self.state.max_entries * 40,
                capsule_types: Box::new([ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT]),
                unknown: UnknownCapsules::Skip,
                oversized_datagram_prefix: 8,
            },
            native_send: NativeSendPolicy::RejectWhenFull,
            ..SessionConfig::default()
        })
    }
}
/// Terminal session failures. Ordinary IP forwarding errors are reported as drops.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectIpError {
    /// Total or principal tunnel admission capacity was reached.
    Admission,
    /// Invalid local configuration.
    Config,
    /// Malformed control state/framing.
    Protocol(ConnectIpProtocolError),
    /// HTTP carrier failure.
    Carrier(SessionError),
    /// Tunnel closed, including cancellation of a send in progress.
    Closed,
    /// An idle or write deadline expired.
    Timeout,
    /// Native datagram capacity or probing cannot sustain the IPv6 link MTU.
    Ipv6Mtu,
}
impl fmt::Display for ConnectIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission => f.write_str("CONNECT-IP admission limit reached"),
            Self::Config => f.write_str("invalid CONNECT-IP configuration"),
            Self::Protocol(e) => e.fmt(f),
            Self::Carrier(e) => e.fmt(f),
            Self::Closed => f.write_str("CONNECT-IP tunnel closed"),
            Self::Timeout => f.write_str("CONNECT-IP deadline expired"),
            Self::Ipv6Mtu => f.write_str("CONNECT-IP IPv6 link MTU below 1280"),
        }
    }
}
impl std::error::Error for ConnectIpError {}
impl From<ConnectIpProtocolError> for ConnectIpError {
    fn from(e: ConnectIpProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<SessionError> for ConnectIpError {
    fn from(e: SessionError) -> Self {
        Self::Carrier(e)
    }
}

/// Observable tunnel events. Control snapshots have already been validated/applied.
#[derive(Debug, Clone)]
pub enum ConnectIpEvent {
    /// An authorized complete IP packet.
    Packet {
        /// Raw IP packet, without Context ID.
        packet: Bytes,
        /// Actual HTTP delivery mode.
        transport: DatagramTransport,
    },
    /// The application can answer requests or react to assignment/route changes.
    Control(ConnectIpCapsule),
    /// A packet was discarded; the request stream remains usable.
    Dropped(IpPacketDrop),
}
/// Whether an outgoing packet was generated here or is crossing links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPacketOrigin {
    /// Already prepared by a local IP stack; do not decrement its hop count again.
    Local,
    /// Rama forwards this packet between links; decrement once before encapsulation.
    Forwarded,
}
/// Result of a packet send. Unreliable delivery does not imply peer receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPacketSend {
    /// Accepted by the HTTP carrier.
    Sent(DatagramTransport),
    /// Refused locally; no packet was sent.
    Dropped(IpPacketDrop),
}
/// Cheap counters without addresses, payloads or credentials.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectIpStats {
    /// Authorized packets sent.
    pub sent: u64,
    /// Authorized packets received.
    pub received: u64,
    /// Rejected packet attempts in either direction.
    pub dropped: u64,
}

#[derive(Debug)]
struct Shared {
    config: ConnectIpSessionConfig,
    state: Mutex<ConnectIpState>,
    native: Option<NativeDatagrams>,
    ipv6_mtu: AtomicU16,
    budget: ConnectIpBudget,
    closed: AtomicBool,
    notify: Notify,
    last_activity: Mutex<Instant>,
    sent: AtomicU64,
    received: AtomicU64,
    dropped: AtomicU64,
}
impl Shared {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
    fn active(&self) -> Result<(), ConnectIpError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ConnectIpError::Closed);
        }
        if self.ipv6_mtu.load(Ordering::Relaxed) != 0
            && self
                .native
                .as_ref()
                .and_then(|n| n.channel().max_payload_size())
                .is_some_and(|n| n < 1281)
        {
            self.close();
            return Err(ConnectIpError::Ipv6Mtu);
        }
        Ok(())
    }
    pub(super) fn charge(&self, bytes: u64) -> bool {
        self.config.shared_budgets.iter().all(|b| b.charge(bytes)) && self.budget.charge(bytes)
    }
    fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }
    fn stats(&self) -> ConnectIpStats {
        ConnectIpStats {
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
    fn check(&self, bytes: &[u8], outgoing: bool) -> Result<(), IpPacketDrop> {
        if bytes.len() > self.config.max_packet_size {
            return Err(IpPacketDrop::TooLarge);
        }
        let packet = IpPacket::parse(bytes).map_err(|_error| IpPacketDrop::Invalid)?;
        if packet.as_bytes().len() != bytes.len() {
            return Err(IpPacketDrop::Invalid);
        }
        if matches!(packet, IpPacket::V6(_)) {
            let mtu = self.ipv6_mtu.load(Ordering::Relaxed);
            if mtu == 0 {
                return Err(IpPacketDrop::Ipv6Disabled);
            }
            if bytes.len() > usize::from(mtu) {
                return Err(IpPacketDrop::TooLarge);
            }
        }
        self.config
            .policy
            .check(packet, outgoing, &self.state.lock())
    }
    fn drop_packet(&self, reason: IpPacketDrop) -> IpPacketSend {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        IpPacketSend::Dropped(reason)
    }
}
struct SendGuard {
    shared: Arc<Shared>,
    complete: bool,
}
impl Drop for SendGuard {
    fn drop(&mut self) {
        if !self.complete {
            self.shared.close();
        }
    }
}

/// One CONNECT-IP stream, independent of HTTP version and platform packet interfaces.
#[derive(Debug)]
pub struct ConnectIpSession<T = Upgraded> {
    sender: ConnectIpSender<T>,
    receiver: ConnectIpReceiver<T>,
}
impl<T: AsyncRead + AsyncWrite + ExtensionsRef> ConnectIpSession<T> {
    /// Wrap an accepted HTTP upgrade. Handshake and admission must happen first.
    pub fn new(io: T, config: ConnectIpSessionConfig) -> Result<Self, ConnectIpError> {
        let http = HttpDatagramSession::with_config(io, config.http_config()?);
        let native = http.native().cloned();
        let state = ConnectIpState::new(config.state);
        let budget = ConnectIpBudget::new(config.budget)?;
        let shared = Arc::new(Shared {
            ipv6_mtu: AtomicU16::new(config.ipv6_link_mtu.unwrap_or(0)),
            config,
            state: Mutex::new(state),
            native,
            budget,
            closed: AtomicBool::new(false),
            notify: Notify::new(),
            last_activity: Mutex::new(Instant::now()),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        });
        shared.active()?;
        let (sender, receiver) = http.split();
        Ok(Self {
            sender: ConnectIpSender {
                http: sender,
                shared: shared.clone(),
            },
            receiver: ConnectIpReceiver {
                http: receiver,
                shared,
            },
        })
    }
    /// Validate a previously unverified IPv6 path with a 1280-byte ICMPv6 echo.
    ///
    /// Run before splitting the session or forwarding IPv6. `nonce` must be fresh
    /// for this probe; use unpredictable bytes when stale or injected replies are
    /// a concern. Both addresses must be authorized by the local packet policy.
    /// The peer must answer ICMPv6 echo (an IP stack, or a concurrent call to this
    /// method). No TUN or host routes are needed.
    ///
    /// Non-probe packets are discarded during validation. Up to 16 control updates
    /// are applied and returned so the caller can handle address requests; their
    /// combined entries are bounded by the configured state limit. A write/idle
    /// failure, missing reply, overflow or cancellation aborts the tunnel. Success
    /// enables an IPv6 link MTU of 1280; larger MTUs still need separate validation.
    pub async fn probe_ipv6_mtu(
        &mut self,
        source: std::net::Ipv6Addr,
        peer: std::net::Ipv6Addr,
        nonce: [u8; 16],
    ) -> Result<Vec<ConnectIpCapsule>, ConnectIpError> {
        use rama_net::ip::{
            IpProtocol,
            icmp::{encode_icmpv6_echo, icmpv6_checksum},
        };
        if self.sender.shared.ipv6_mtu.load(Ordering::Relaxed) != 0
            || self.sender.shared.config.max_packet_size < 1280
            || source.is_unspecified()
            || source.is_multicast()
            || peer.is_unspecified()
        {
            return Err(ConnectIpError::Config);
        }
        let mut guard = SendGuard {
            shared: self.sender.shared.clone(),
            complete: false,
        };
        // Exclusive &mut self keeps ordinary packet I/O unavailable until success.
        self.sender.shared.ipv6_mtu.store(1280, Ordering::Relaxed);
        let mut data = [0; 1232];
        data[..16].copy_from_slice(&nonce);
        let mut packet = [0; 1280];
        encode_icmpv6_echo(source, peer, 0, 0, &data, false, &mut packet)
            .map_err(|_error| ConnectIpError::Config)?;
        let deadline = Instant::now() + self.sender.shared.config.write_timeout;
        let result = timeout_at(deadline, async {
            if !matches!(
                self.send_packet(Bytes::copy_from_slice(&packet), IpPacketOrigin::Local)
                    .await?,
                IpPacketSend::Sent(_)
            ) {
                return Err(ConnectIpError::Ipv6Mtu);
            }
            let mut controls = Vec::new();
            let mut entries = 0;
            loop {
                match self.recv().await?.ok_or(ConnectIpError::Closed)? {
                    ConnectIpEvent::Packet { packet, .. } => {
                        let IpPacket::V6(ip) =
                            IpPacket::parse(&packet).map_err(|_error| ConnectIpError::Config)?
                        else {
                            continue;
                        };
                        if packet.len() != 1280
                            || ip.next_header() != IpProtocol::ICMPV6
                            || ip.destination() != source
                            || ip.source().is_multicast()
                            || ip.source().is_unspecified()
                        {
                            continue;
                        }
                        let body = ip.payload();
                        if body[1] != 0
                            || icmpv6_checksum(ip.source(), ip.destination(), body) != Ok(0)
                        {
                            continue;
                        }
                        if body[0] == 129
                            && (peer.is_multicast() || ip.source() == peer)
                            && body[4..8] == [0; 4]
                            && body[8..] == data
                        {
                            return Ok(controls);
                        }
                        if body[0] == 128 {
                            let mut reply = [0; 1280];
                            encode_icmpv6_echo(
                                source,
                                ip.source(),
                                u16::from_be_bytes([body[4], body[5]]),
                                u16::from_be_bytes([body[6], body[7]]),
                                &body[8..],
                                true,
                                &mut reply,
                            )
                            .map_err(|_error| ConnectIpError::Config)?;
                            if !matches!(
                                self.send_packet(
                                    Bytes::copy_from_slice(&reply),
                                    IpPacketOrigin::Local
                                )
                                .await?,
                                IpPacketSend::Sent(_)
                            ) {
                                return Err(ConnectIpError::Ipv6Mtu);
                            }
                        }
                    }
                    ConnectIpEvent::Control(control) => {
                        entries += match &control {
                            ConnectIpCapsule::AddressAssign(v) => v.len(),
                            ConnectIpCapsule::AddressRequest(v) => v.len(),
                            ConnectIpCapsule::RouteAdvertisement(v) => v.len(),
                        };
                        if controls.len() == 16
                            || entries > self.sender.shared.config.state.max_entries
                        {
                            return Err(ConnectIpProtocolError::Limit.into());
                        }
                        controls.push(control);
                    }
                    ConnectIpEvent::Dropped(_) => (),
                }
            }
        })
        .await;
        match result {
            Ok(Ok(controls)) => {
                guard.complete = true;
                Ok(controls)
            }
            other => {
                self.sender.http.abort();
                Err(match other {
                    Ok(Err(e)) => e,
                    _ => ConnectIpError::Timeout,
                })
            }
        }
    }
    /// Separate packet/control sending from reception; dropping either half aborts the tunnel.
    pub fn split(self) -> (ConnectIpSender<T>, ConnectIpReceiver<T>) {
        (self.sender, self.receiver)
    }
    /// Receive an authorized packet or control-state event.
    pub async fn recv(&mut self) -> Result<Option<ConnectIpEvent>, ConnectIpError> {
        self.receiver.recv().await
    }
    /// Send a packet, applying local authorization and optional forwarding hop decrement.
    pub async fn send_packet(
        &mut self,
        packet: Bytes,
        origin: IpPacketOrigin,
    ) -> Result<IpPacketSend, ConnectIpError> {
        self.sender.send_packet(packet, origin).await
    }
    /// Send a validated control snapshot/request.
    pub async fn send_control(&mut self, capsule: ConnectIpCapsule) -> Result<(), ConnectIpError> {
        self.sender.send_control(capsule).await
    }
    /// Reserve an unused local address request ID.
    pub fn next_request_id(&self) -> Result<u64, ConnectIpError> {
        self.sender.next_request_id()
    }
    /// Current state snapshot.
    #[must_use]
    pub fn state(&self) -> ConnectIpState {
        self.sender.state()
    }
    /// Locally authorized policy, including the pinned resolved scope.
    #[must_use]
    pub fn policy(&self) -> &ConnectIpPolicy {
        &self.sender.shared.config.policy
    }
    /// Current carrier limit for an IP packet, excluding Context ID overhead.
    /// IPv6 also remains subject to the configured verified link MTU.
    #[must_use]
    pub fn max_packet_size(&self) -> usize {
        self.sender.max_packet_size()
    }
    /// Counters for this tunnel.
    #[must_use]
    pub fn stats(&self) -> ConnectIpStats {
        self.sender.stats()
    }
    /// Finish the request stream within the configured write deadline.
    pub async fn close(&mut self) -> Result<(), ConnectIpError> {
        self.sender.close().await
    }
}
/// The unique send half; state is shared with the receive half.
#[derive(Debug)]
pub struct ConnectIpSender<T = Upgraded> {
    http: SessionSender<T>,
    shared: Arc<Shared>,
}
impl<T> ConnectIpSender<T> {
    /// Current directional control state.
    #[must_use]
    pub fn state(&self) -> ConnectIpState {
        self.shared.state.lock().clone()
    }
    /// Locally authorized policy, including the pinned resolved scope.
    #[must_use]
    pub fn policy(&self) -> &ConnectIpPolicy {
        &self.shared.config.policy
    }
    /// Current carrier limit after subtracting the one-byte Context ID.
    #[must_use]
    pub fn max_packet_size(&self) -> usize {
        let configured = self.shared.config.max_packet_size;
        self.shared
            .native
            .as_ref()
            .and_then(|n| n.channel().max_payload_size())
            .map_or(configured, |n| configured.min(n.saturating_sub(1)))
    }
    /// Current packet counters.
    #[must_use]
    pub fn stats(&self) -> ConnectIpStats {
        self.shared.stats()
    }
    /// Reserve an address request ID.
    pub fn next_request_id(&self) -> Result<u64, ConnectIpError> {
        self.shared.active()?;
        Ok(self.shared.state.lock().next_request_id()?)
    }
}
impl<T: AsyncWrite> ConnectIpSender<T> {
    /// Send control state. Cancellation after state reservation closes both halves.
    pub async fn send_control(&mut self, capsule: ConnectIpCapsule) -> Result<(), ConnectIpError> {
        if let Err(error) = self.shared.active() {
            self.http.abort();
            return Err(error);
        }
        let value = capsule.encode(self.shared.config.state.max_entries)?;
        if !self.shared.charge(value.len() as u64) {
            self.shared.close();
            self.http.abort();
            return Err(ConnectIpError::Protocol(ConnectIpProtocolError::Limit));
        }
        self.shared.state.lock().sent(&capsule)?;
        let mut guard = SendGuard {
            shared: self.shared.clone(),
            complete: false,
        };
        let result = timeout_at(
            Instant::now() + self.shared.config.write_timeout,
            self.http.send_capsule(capsule.capsule_type(), value),
        )
        .await;
        match result {
            Ok(Ok(())) => {
                guard.complete = true;
                self.shared.touch();
                Ok(())
            }
            Ok(Err(e)) => {
                self.http.abort();
                Err(e.into())
            }
            Err(_) => {
                self.http.abort();
                Err(ConnectIpError::Timeout)
            }
        }
    }
    /// Send an IP packet. Forwarded link-local packets are never sent to another link.
    pub async fn send_packet(
        &mut self,
        mut packet: Bytes,
        origin: IpPacketOrigin,
    ) -> Result<IpPacketSend, ConnectIpError> {
        if let Err(error) = self.shared.active() {
            self.http.abort();
            return Err(error);
        }
        if !self.shared.charge(packet.len() as u64) {
            return Ok(self.shared.drop_packet(IpPacketDrop::Budget));
        }
        if let Err(reason) = self.shared.check(&packet, true) {
            return Ok(self.shared.drop_packet(reason));
        }
        if origin == IpPacketOrigin::Forwarded {
            let p = IpPacket::parse(&packet).map_err(|_error| ConnectIpError::Config)?;
            if link_local(p.source()) || link_local(p.destination()) {
                return Ok(self.shared.drop_packet(IpPacketDrop::Scope));
            }
            let mut owned = packet.to_vec();
            if decrement_hop_limit(&mut owned).is_err() {
                return Ok(self.shared.drop_packet(IpPacketDrop::HopLimit));
            }
            packet = Bytes::from(owned);
        }
        let mut guard = SendGuard {
            shared: self.shared.clone(),
            complete: false,
        };
        let result = timeout_at(
            Instant::now() + self.shared.config.write_timeout,
            self.http.send_datagram(encode_ip_datagram(&packet)),
        )
        .await;
        match result {
            Ok(Ok(mode)) => {
                guard.complete = true;
                self.shared.touch();
                self.shared.sent.fetch_add(1, Ordering::Relaxed);
                Ok(IpPacketSend::Sent(mode))
            }
            Ok(Err(SessionError::Native(NativeSendError::TooLarge { max }))) => {
                if self.shared.ipv6_mtu.load(Ordering::Relaxed) != 0 && max < 1281 {
                    self.http.abort();
                    return Err(ConnectIpError::Ipv6Mtu);
                }
                guard.complete = true;
                Ok(self.shared.drop_packet(IpPacketDrop::TooLarge))
            }
            Ok(Err(SessionError::Native(NativeSendError::Full))) => {
                guard.complete = true;
                Ok(self.shared.drop_packet(IpPacketDrop::QueueFull))
            }
            Ok(Err(e)) => {
                self.http.abort();
                Err(e.into())
            }
            Err(_) => {
                self.http.abort();
                Err(ConnectIpError::Timeout)
            }
        }
    }
    /// Close the stream and wake any pending receive.
    pub async fn close(&mut self) -> Result<(), ConnectIpError> {
        let mut guard = SendGuard {
            shared: self.shared.clone(),
            complete: false,
        };
        let result = timeout_at(
            Instant::now() + self.shared.config.write_timeout,
            self.http.close(),
        )
        .await;
        self.shared.close();
        guard.complete = true;
        if let Ok(v) = result {
            v.map_err(Into::into)
        } else {
            self.http.abort();
            Err(ConnectIpError::Timeout)
        }
    }
}
impl<T> Drop for ConnectIpSender<T> {
    fn drop(&mut self) {
        self.shared.close();
        self.http.abort();
    }
}
/// The unique receive half; malformed control closes the request stream.
#[derive(Debug)]
pub struct ConnectIpReceiver<T = Upgraded> {
    http: SessionReceiver<T>,
    shared: Arc<Shared>,
}
impl<T> ConnectIpReceiver<T> {
    /// Current directional control state after the latest received update.
    #[must_use]
    pub fn state(&self) -> ConnectIpState {
        self.shared.state.lock().clone()
    }
    /// Locally authorized policy, including the pinned resolved scope.
    #[must_use]
    pub fn policy(&self) -> &ConnectIpPolicy {
        &self.shared.config.policy
    }
    /// Counters shared with the send half.
    #[must_use]
    pub fn stats(&self) -> ConnectIpStats {
        self.shared.stats()
    }
}
impl<T: AsyncRead> ConnectIpReceiver<T> {
    /// Receive one event. Invalid packets are observable drops, not protocol errors.
    pub async fn recv(&mut self) -> Result<Option<ConnectIpEvent>, ConnectIpError> {
        if let Err(error) = self.shared.active() {
            self.http.abort();
            return Err(error);
        }
        tokio::task::consume_budget().await;
        loop {
            let deadline = *self.shared.last_activity.lock() + self.shared.config.idle_timeout;
            let event = tokio::select! {
                _=self.shared.cancelled()=>{self.http.abort();return Err(ConnectIpError::Closed);}
                result=timeout_at(deadline,self.http.recv())=>match result {Ok(Ok(event))=>event,Ok(Err(e))=>{self.shared.close();self.http.abort();return Err(e.into());},Err(_)=>{
                    if Instant::now()<*self.shared.last_activity.lock()+self.shared.config.idle_timeout {continue;}
                    self.shared.close();self.http.abort();return Err(ConnectIpError::Timeout);
                }}
            };
            let Some(event) = event else {
                self.shared.close();
                return Ok(None);
            };
            if let Err(error) = self.shared.active() {
                self.http.abort();
                return Err(error);
            }
            match event {
                SessionEvent::Datagram { payload, transport } => {
                    let reason = if !self.shared.charge(payload.len() as u64) {
                        Some(IpPacketDrop::Budget)
                    } else {
                        match decode_ip_datagram(&payload) {
                            Err(_) => Some(IpPacketDrop::Invalid),
                            Ok((id, _)) if id != 0 => Some(IpPacketDrop::UnknownContext),
                            Ok((_, packet)) => match self.shared.check(packet, false) {
                                Ok(()) => {
                                    let offset = payload.len() - packet.len();
                                    self.shared.touch();
                                    self.shared.received.fetch_add(1, Ordering::Relaxed);
                                    return Ok(Some(ConnectIpEvent::Packet {
                                        packet: payload.slice(offset..),
                                        transport,
                                    }));
                                }
                                Err(reason) => Some(reason),
                            },
                        }
                    };
                    if let Some(reason) = reason {
                        self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                        return Ok(Some(ConnectIpEvent::Dropped(reason)));
                    }
                }
                SessionEvent::Capsule { ty, value } => {
                    let result = if !self.shared.charge(value.len() as u64) {
                        Err(ConnectIpProtocolError::Limit)
                    } else {
                        ConnectIpCapsule::decode(ty, &value, self.shared.config.state.max_entries)
                    };
                    let capsule = match result {
                        Ok(v) => v,
                        Err(e) => {
                            self.http.abort_malformed();
                            self.shared.close();
                            return Err(e.into());
                        }
                    };
                    if let Err(e) = self.shared.state.lock().receive(&capsule) {
                        self.http.abort_malformed();
                        self.shared.close();
                        return Err(e.into());
                    }
                    self.shared.touch();
                    return Ok(Some(ConnectIpEvent::Control(capsule)));
                }
                SessionEvent::OversizedDatagram { length, .. } => {
                    let reason = if self.shared.charge(length) {
                        IpPacketDrop::TooLarge
                    } else {
                        IpPacketDrop::Budget
                    };
                    self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(Some(ConnectIpEvent::Dropped(reason)));
                }
                SessionEvent::UnknownCapsule(_) | SessionEvent::UnknownCapsuleData(_) => (),
            }
        }
    }
}
impl<T> Drop for ConnectIpReceiver<T> {
    fn drop(&mut self) {
        self.shared.close();
        self.http.abort();
    }
}
fn link_local(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(a) => {
            a.is_link_local() || a.is_broadcast() || a.octets()[..3] == [224, 0, 0]
        }
        std::net::IpAddr::V6(a) => {
            a.is_unicast_link_local() || a.is_multicast() && (a.segments()[0] & 15) <= 2
        }
    }
}
