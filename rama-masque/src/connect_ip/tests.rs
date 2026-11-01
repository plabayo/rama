use super::*;
use rama_core::{
    Service, ServiceInput, bytes::Bytes, extensions::ExtensionsRef as _, rt::Executor,
    service::service_fn,
};
use rama_http::{
    Request, StatusCode, Version,
    datagram::{
        DatagramTransport, HttpDatagramSession, NativeDatagramChannel, NativeDatagrams,
        NativeRecvError, NativeSendError, NativeSendPolicy, NativeSendReady,
    },
};
use rama_net::{
    address::ip::ipnet::IpNet,
    ip::{IpPacket, IpProtocol, Ipv4Header, Ipv6Header},
    user::UserId,
};
use std::{
    convert::Infallible,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{io::DuplexStream, time::timeout};

fn prefix(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn route(s: &str) -> IpRoute {
    IpRoute::from_prefix(prefix(s), None)
}

fn assignment(s: &str, id: u64) -> AddressAssignment {
    AddressAssignment {
        request_id: id,
        prefix: prefix(s),
    }
}

fn request(s: &str, id: u64) -> AddressRequest {
    AddressRequest {
        request_id: id,
        prefix: prefix(s),
    }
}

#[test]
fn control_wire_vectors_and_nonminimal_varints() {
    let capsule = ConnectIpCapsule::AddressAssign(vec![assignment("192.0.2.1/32", 0)]);
    assert_eq!(&capsule.encode(10).unwrap()[..], &[0, 4, 192, 0, 2, 1, 32]);
    assert_eq!(
        ConnectIpCapsule::decode(ADDRESS_ASSIGN, &[0x40, 0, 4, 192, 0, 2, 1, 32], 10).unwrap(),
        capsule
    );
    assert_eq!(
        decode_ip_datagram(&[0x40, 0, 0x45]).unwrap(),
        (0, &[0x45][..])
    );
    for capsule in [
        capsule,
        ConnectIpCapsule::AddressRequest(vec![request("::/128", 1), request("0.0.0.0/32", 7)]),
        ConnectIpCapsule::RouteAdvertisement(vec![route("192.0.2.0/24"), route("2001:db8::/32")]),
    ] {
        let bytes = capsule.encode(10).unwrap();
        assert_eq!(
            ConnectIpCapsule::decode(capsule.capsule_type(), &bytes, 10).unwrap(),
            capsule
        );
        capsule.encode(0).unwrap_err();
    }
    for raw in [
        &[0][..],
        &[0, 5],
        &[0, 4, 192, 0, 2, 1, 33],
        &[0, 4, 192, 0, 2, 1, 24],
    ] {
        ConnectIpCapsule::decode(ADDRESS_ASSIGN, raw, 10).unwrap_err();
    }
    assert_eq!(
        ConnectIpCapsule::decode(ADDRESS_REQUEST, &[], 10),
        Err(ConnectIpProtocolError::EmptyRequest)
    );
    assert_eq!(
        ConnectIpCapsule::decode(ADDRESS_REQUEST, &[0, 4, 0, 0, 0, 0, 32], 10),
        Err(ConnectIpProtocolError::RequestId)
    );
}

#[test]
fn route_ranges_ordering_and_all_protocol_overlap() {
    let a = route("192.0.2.0/25");
    let b = route("192.0.2.128/25");
    validate_routes(&[a, b]).unwrap();
    assert!(validate_routes(&[b, a]).is_err());
    assert!(validate_routes(&[a, a]).is_err());
    let mut tcp = a;
    tcp.protocol = Some(IpProtocol::TCP);
    let mut udp = a;
    udp.protocol = Some(IpProtocol::UDP);
    validate_routes(&[tcp, udp]).unwrap();
    assert!(validate_routes(&[a, tcp]).is_err());
    let range = IpRoute {
        start: "192.0.2.3".parse().unwrap(),
        end: "192.0.2.19".parse().unwrap(),
        protocol: None,
    };
    validate_routes(&[range]).unwrap();
    assert!(range.contains("192.0.2.17".parse().unwrap()));
    assert!(!range.contains("192.0.2.20".parse().unwrap()));
    assert!(validate_routes(&[route("::/0"), a]).is_err());
}

#[test]
fn state_snapshots_withdraw_and_reject_atomically() {
    let mut state = ConnectIpState::default();
    state
        .sent(&ConnectIpCapsule::AddressRequest(vec![request(
            "0.0.0.0/32",
            1,
        )]))
        .unwrap();
    assert_eq!(state.pending_requests(), 1);
    state
        .receive(&ConnectIpCapsule::AddressAssign(vec![assignment(
            "192.0.2.1/32",
            1,
        )]))
        .unwrap();
    assert_eq!(state.pending_requests(), 0);
    assert_eq!(state.local_addresses().len(), 1);
    let invalid = ConnectIpCapsule::AddressAssign(vec![
        assignment("192.0.2.2/32", 0),
        assignment("192.0.2.3/32", 99),
    ]);
    state.receive(&invalid).unwrap_err();
    assert_eq!(state.local_addresses()[0].prefix, prefix("192.0.2.1/32"));
    state
        .receive(&ConnectIpCapsule::AddressAssign(vec![]))
        .unwrap();
    assert!(state.local_addresses().is_empty());
    assert!(
        state
            .sent(&ConnectIpCapsule::AddressRequest(vec![request(
                "0.0.0.0/32",
                1
            )]))
            .is_err()
    );
    state
        .receive(&ConnectIpCapsule::RouteAdvertisement(vec![route(
            "192.0.2.0/24",
        )]))
        .unwrap();
    state
        .receive(&ConnectIpCapsule::RouteAdvertisement(vec![]))
        .unwrap();
    assert!(state.peer_routes().is_empty());
    state
        .sent(&ConnectIpCapsule::AddressRequest(vec![request(
            "::/128", 2,
        )]))
        .unwrap();
    state
        .receive(&ConnectIpCapsule::AddressAssign(vec![assignment(
            "::/128", 2,
        )]))
        .unwrap();
    assert!(state.local_addresses().is_empty());
    assert_eq!(state.pending_requests(), 0);
}

#[test]
fn request_id_history_is_bounded_and_duplicate_batches_are_atomic() {
    let mut state = ConnectIpState::new(ConnectIpStateLimits {
        max_entries: 4,
        max_request_ids: 2,
    });
    assert!(
        state
            .receive(&ConnectIpCapsule::AddressRequest(vec![
                request("::/128", 1),
                request("::/128", 1)
            ]))
            .is_err()
    );
    state
        .receive(&ConnectIpCapsule::AddressRequest(vec![
            request("::/128", 1),
            request("::/128", 2),
        ]))
        .unwrap();
    assert_eq!(
        state.receive(&ConnectIpCapsule::AddressRequest(vec![request(
            "::/128", 3
        )])),
        Err(ConnectIpProtocolError::Limit)
    );
}

#[test]
fn templates_cover_http_versions_scopes_and_erratum_8444() {
    let template = ConnectIpTemplate::try_new(
        "https://proxy.example/.well-known/masque/ip/{target}/{ipproto}/",
    )
    .unwrap();
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let req = template
            .request(&ConnectIpScope::default(), version)
            .unwrap();
        assert!(req.uri().to_string().contains("/%2A/%2A/"));
        assert_eq!(
            template.match_request(&req).unwrap(),
            ConnectIpScope::default()
        );
        let scope =
            ConnectIpScope::from_template_values(Some("2001:db8::/32"), Some("17")).unwrap();
        let req = template.request(&scope, version).unwrap();
        assert_eq!(template.match_request(&req).unwrap(), scope);
        assert!(req.uri().to_string().contains("2001%3Adb8%3A%3A%2F32"));
    }
    for input in [
        "http://proxy.example/ip",
        "https://{proxy}/ip",
        "https://proxy.example",
        "https://user@proxy.example/ip",
        "https://proxy.example/{+target}",
        "https://proxy.example/ip#fragment",
    ] {
        assert!(ConnectIpTemplate::try_new(input).is_err(), "{input}");
    }
    for target in [
        "",
        "192.0.2.1/24",
        "::1/64",
        "fe80::1%eth0",
        "[::1]",
        "example.org/24",
    ] {
        assert!(
            ConnectIpScope::from_template_values(Some(target), None).is_err(),
            "{target}"
        );
    }
    for p in ["", "256", "-1", "0x11"] {
        ConnectIpScope::from_template_values(None, Some(p)).unwrap_err();
    }
    assert_eq!(
        ConnectIpScope::from_template_values(None, Some("0"))
            .unwrap()
            .protocol,
        Some(IpProtocol::HOP_BY_HOP)
    );
    let fixed = ConnectIpTemplate::try_new("https://proxy.example/vpn").unwrap();
    fixed
        .request(
            &ConnectIpScope::from_template_values(None, Some("17")).unwrap(),
            Version::HTTP_3,
        )
        .unwrap_err();
}

fn policy(role: ConnectIpRole) -> ConnectIpPolicy {
    let mut p = ConnectIpPolicy::new(role);
    let direction = IpDirectionPolicy {
        sources: IpSourcePolicy::Static(vec![prefix("192.0.2.0/24"), prefix("2001:db8::/32")]),
        destinations: vec![route("192.0.2.0/24"), route("2001:db8::/32")],
        require_advertised_route: false,
    };
    p.send = direction.clone();
    p.receive = direction;
    p
}

fn config(role: ConnectIpRole) -> ConnectIpSessionConfig {
    let mut c = ConnectIpSessionConfig::new(policy(role));
    c.ipv6_link_mtu = Some(1400);
    c
}

fn pair() -> (
    ConnectIpSession<ServiceInput<DuplexStream>>,
    ConnectIpSession<ServiceInput<DuplexStream>>,
) {
    let (a, b) = tokio::io::duplex(65536);
    (
        ConnectIpSession::new(ServiceInput::new(a), config(ConnectIpRole::Client)).unwrap(),
        ConnectIpSession::new(ServiceInput::new(b), config(ConnectIpRole::Proxy)).unwrap(),
    )
}

fn v4(src: Ipv4Addr, dst: Ipv4Addr) -> Bytes {
    let mut bytes = [0; 64];
    let n = Ipv4Header::new(src, dst, IpProtocol::UDP)
        .encode(&[], b"packet contents", &mut bytes)
        .unwrap();
    Bytes::copy_from_slice(&bytes[..n])
}

fn packet() -> Bytes {
    v4(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2))
}

#[tokio::test]
async fn reliable_packet_and_bidirectional_control_exchange() {
    timeout(Duration::from_secs(3), async {
        let (mut a, mut b) = pair();
        for capsule in [
            ConnectIpCapsule::AddressRequest(vec![request("0.0.0.0/32", 1)]),
            ConnectIpCapsule::RouteAdvertisement(vec![route("192.0.2.0/24")]),
        ] {
            a.send_control(capsule.clone()).await.unwrap();
            assert!(matches!(b.recv().await.unwrap(), Some(ConnectIpEvent::Control(got)) if got == capsule));
        }
        b.send_control(ConnectIpCapsule::AddressAssign(vec![assignment("192.0.2.1/32", 1)]))
            .await.unwrap();
        a.recv().await.unwrap();
        assert_eq!(a.state().local_addresses().len(), 1);
        assert_eq!(a.send_packet(packet(), IpPacketOrigin::Forwarded).await.unwrap(),
            IpPacketSend::Sent(DatagramTransport::Capsule));
        let Some(ConnectIpEvent::Packet { packet: p, .. }) = b.recv().await.unwrap() else { panic!() };
        assert_eq!(IpPacket::parse(&p).unwrap().hop_limit(), 63);
        assert_eq!(b.send_packet(packet(), IpPacketOrigin::Local).await.unwrap(),
            IpPacketSend::Sent(DatagramTransport::Capsule));
        a.recv().await.unwrap();
        let mut raw = [0; 1400];
        let n = Ipv6Header::new("2001:db8::1".parse().unwrap(), "2001:db8::2".parse().unwrap(), IpProtocol::UDP)
            .encode(&[9; 1240], &mut raw).unwrap();
        a.send_packet(Bytes::copy_from_slice(&raw[..n]), IpPacketOrigin::Local).await.unwrap();
        assert!(matches!(b.recv().await.unwrap(), Some(ConnectIpEvent::Packet { packet: p, .. }) if p.len() == 1280));
        b.send_control(ConnectIpCapsule::AddressAssign(vec![])).await.unwrap();
        a.recv().await.unwrap();
        assert!(a.state().local_addresses().is_empty());
    }).await.unwrap();
}

#[tokio::test]
async fn invalid_packets_drop_without_killing_control() {
    let (a, b) = tokio::io::duplex(65536);
    let mut cfg = config(ConnectIpRole::Proxy);
    cfg.idle_timeout = Duration::from_millis(100);
    let mut raw =
        HttpDatagramSession::with_config(ServiceInput::new(a), cfg.http_config().unwrap());
    let mut session = ConnectIpSession::new(ServiceInput::new(b), cfg).unwrap();
    for (payload, expected) in [
        (Bytes::from_static(&[1, 0x45]), IpPacketDrop::UnknownContext),
        (Bytes::from_static(&[0, 0x45]), IpPacketDrop::Invalid),
        (
            encode_ip_datagram(&v4(Ipv4Addr::LOCALHOST, Ipv4Addr::new(192, 0, 2, 2))),
            IpPacketDrop::Source,
        ),
    ] {
        raw.send_datagram(payload).await.unwrap();
        assert!(
            matches!(session.recv().await.unwrap(),Some(ConnectIpEvent::Dropped(r)) if r==expected)
        );
    }
    raw.send_capsule(ROUTE_ADVERTISEMENT, Bytes::new())
        .await
        .unwrap();
    assert!(matches!(
        session.recv().await.unwrap(),
        Some(ConnectIpEvent::Control(_))
    ));
    raw.send_capsule(ADDRESS_REQUEST, Bytes::new())
        .await
        .unwrap();
    assert!(matches!(
        session.recv().await,
        Err(ConnectIpError::Protocol(
            ConnectIpProtocolError::EmptyRequest
        ))
    ));
}

#[tokio::test(start_paused = true)]
async fn cancellation_deadlines_and_principal_quotas() {
    let (mut a, _b) = pair();
    assert!(matches!(
        timeout(Duration::from_secs(121), a.recv()).await.unwrap(),
        Err(ConnectIpError::Timeout)
    ));
    let (a, _b) = tokio::io::duplex(1);
    let session =
        ConnectIpSession::new(ServiceInput::new(a), config(ConnectIpRole::Client)).unwrap();
    let (mut send, mut recv) = session.split();
    let capsule = ConnectIpCapsule::RouteAdvertisement(vec![route("192.0.2.0/24")]);
    timeout(Duration::from_millis(1), send.send_control(capsule))
        .await
        .unwrap_err();
    assert!(matches!(recv.recv().await, Err(ConnectIpError::Closed)));
    let cfg = IpAdmissionLimits {
        max_tunnels_per_principal: 1,
        budget: IpBudgetConfig {
            byte_quota: Some(10),
            ..Default::default()
        },
        ..Default::default()
    };
    let limits = ConnectIpLimits::try_new(cfg).unwrap();
    let req = Request::new(rama_http::Body::empty());
    let lease = limits.admit(&req).unwrap();
    assert_eq!(limits.live_tunnels(), 1);
    limits.admit(&req).unwrap_err();
    assert!(lease.budget.charge(10));
    drop(lease);
    assert_eq!(limits.live_tunnels(), 0);
    let lease = limits.admit(&req).unwrap();
    assert!(!lease.budget.charge(1));
}

#[derive(Debug)]
struct Native {
    mtu: Arc<AtomicUsize>,
    send_error: Option<NativeSendError>,
}

impl NativeDatagramChannel for Native {
    fn max_payload_size(&self) -> Option<usize> {
        Some(self.mtu.load(Ordering::Relaxed))
    }

    fn send(&self, p: Bytes, policy: NativeSendPolicy) -> Result<(), NativeSendError> {
        assert_eq!(policy, NativeSendPolicy::RejectWhenFull);
        if let Some(error) = self.send_error {
            return Err(error);
        }
        let max = self.mtu.load(Ordering::Relaxed);
        if p.len() > max {
            Err(NativeSendError::TooLarge { max })
        } else {
            Ok(())
        }
    }

    fn send_ready(&self) -> NativeSendReady {
        NativeSendReady::now()
    }

    fn poll_recv(&self, _: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        Poll::Pending
    }

    fn dropped(&self) -> u64 {
        0
    }
}

#[tokio::test]
async fn native_ipv6_mtu_shrink_is_terminal_not_reliable_fallback() {
    let (a, _b) = tokio::io::duplex(65536);
    let io = ServiceInput::new(a);
    let mtu = Arc::new(AtomicUsize::new(1401));
    io.extensions().insert(NativeDatagrams::new(Native {
        mtu: mtu.clone(),
        send_error: None,
    }));
    let mut session = ConnectIpSession::new(io, config(ConnectIpRole::Client)).unwrap();
    assert_eq!(
        session
            .send_packet(packet(), IpPacketOrigin::Local)
            .await
            .unwrap(),
        IpPacketSend::Sent(DatagramTransport::Native)
    );
    mtu.store(1280, Ordering::Relaxed);
    assert!(matches!(
        session.send_packet(packet(), IpPacketOrigin::Local).await,
        Err(ConnectIpError::Ipv6Mtu)
    ));
}

#[test]
fn peer_claims_never_override_local_authorization() {
    let p = packet();
    let mut state = ConnectIpState::default();
    state
        .receive(&ConnectIpCapsule::RouteAdvertisement(vec![route(
            "0.0.0.0/0",
        )]))
        .unwrap();
    assert!(
        ConnectIpPolicy::new(ConnectIpRole::Client)
            .check(IpPacket::parse(&p).unwrap(), true, &state)
            .is_err()
    );
    let mut policy = policy(ConnectIpRole::Client);
    policy.scope_protocol = Some(IpProtocol::TCP);
    assert_eq!(
        policy.check(IpPacket::parse(&p).unwrap(), true, &state),
        Err(IpPacketDrop::Scope)
    );
    policy.scope_protocol = None;
    policy.send.sources = IpSourcePolicy::Assigned(vec![prefix("192.0.2.0/24")]);
    assert_eq!(
        policy.check(IpPacket::parse(&p).unwrap(), true, &state),
        Err(IpPacketDrop::Source)
    );
    state
        .receive(&ConnectIpCapsule::AddressAssign(vec![assignment(
            "192.0.2.1/32",
            0,
        )]))
        .unwrap();
    policy
        .check(IpPacket::parse(&p).unwrap(), true, &state)
        .unwrap();
    state
        .receive(&ConnectIpCapsule::AddressAssign(vec![]))
        .unwrap();
    assert_eq!(
        policy.check(IpPacket::parse(&p).unwrap(), true, &state),
        Err(IpPacketDrop::Source)
    );
}

#[tokio::test]
async fn authentication_and_secure_transport_are_checked_before_acceptance() {
    let template = ConnectIpTemplate::try_new("https://proxy.example/vpn").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let service = ConnectIpService::new(
        template.clone(),
        service_fn(move |r: ConnectIpRequest| {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::Relaxed);
                if r.request.extensions().contains::<UserId>() {
                    Ok(config(ConnectIpRole::Proxy))
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "secret",
                    ))
                }
            }
        }),
        service_fn(async |_s: ConnectIpSession| Ok::<_, Infallible>(())),
        Executor::new(),
    );
    let req = template
        .request(&ConnectIpScope::default(), Version::HTTP_11)
        .unwrap();
    assert_eq!(
        service.serve(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let req = template
        .request(&ConnectIpScope::default(), Version::HTTP_2)
        .unwrap();
    req.extensions()
        .insert(rama_tls::SecureTransport::default());
    let response = service.serve(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!format!("{response:?}").contains("secret"));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn icmp_errors_are_bound_to_the_authorized_quoted_flow() {
    use rama_net::ip::icmp::{IcmpErrorKind, encode_icmp_error};
    let mut p = policy(ConnectIpRole::Client);
    p.scope_targets = vec![prefix("192.0.2.2/32")];
    p.scope_protocol = Some(IpProtocol::UDP);
    let state = ConnectIpState::default();
    let invoking = packet();
    let mut bytes = [0; 1280];
    let n = encode_icmp_error(
        IpPacket::parse(&invoking).unwrap(),
        "198.51.100.1".parse().unwrap(),
        IcmpErrorKind::HopLimitExceeded,
        &mut bytes,
    )
    .unwrap()
    .unwrap();
    p.check(IpPacket::parse(&bytes[..n]).unwrap(), false, &state)
        .unwrap();
    let mut other_tenant = p.clone();
    other_tenant.scope_targets = vec![prefix("192.0.2.3/32")];
    assert_eq!(
        other_tenant.check(IpPacket::parse(&bytes[..n]).unwrap(), false, &state),
        Err(IpPacketDrop::Scope)
    );
    bytes[n - 1] ^= 1;
    assert_eq!(
        p.check(IpPacket::parse(&bytes[..n]).unwrap(), false, &state),
        Err(IpPacketDrop::Invalid)
    );
    // A protocol from the wrong address family is not an ICMP exception.
    let h = Ipv4Header::new(
        "192.0.2.1".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        IpProtocol::ICMPV6,
    );
    let n = h
        .encode(&[], &[128, 0, 0, 0, 0, 0, 0, 0], &mut bytes)
        .unwrap();
    assert_eq!(
        p.check(IpPacket::parse(&bytes[..n]).unwrap(), true, &state),
        Err(IpPacketDrop::Scope)
    );
}

#[test]
fn extension_and_fragment_policy_cannot_hide_a_different_protocol() {
    let mut p = policy(ConnectIpRole::Client);
    p.scope_protocol = Some(IpProtocol::UDP);
    let state = ConnectIpState::default();
    let mut bytes = [0; 256];
    let header = Ipv6Header::new(
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        IpProtocol::DESTINATION_OPTIONS,
    );
    for (proto, expected) in [(17, Ok(())), (6, Err(IpPacketDrop::Scope))] {
        let n = header
            .encode(&[proto, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4], &mut bytes)
            .unwrap();
        assert_eq!(
            p.check(IpPacket::parse(&bytes[..n]).unwrap(), true, &state),
            expected
        );
    }
    let mut header = header;
    header.next_header = IpProtocol::FRAGMENT;
    // Non-initial fragment: the missing destination-options header hides the protocol.
    let n = header
        .encode(&[60, 0, 0, 8, 0, 0, 0, 1, 1, 2, 3, 4], &mut bytes)
        .unwrap();
    assert_eq!(
        p.check(IpPacket::parse(&bytes[..n]).unwrap(), true, &state),
        Err(IpPacketDrop::Scope)
    );
    // A directly identifiable UDP fragment remains usable without reassembly.
    bytes[40] = 17;
    p.check(IpPacket::parse(&bytes[..n]).unwrap(), true, &state)
        .unwrap();
    header.next_header = IpProtocol::ROUTING;
    let n = header
        .encode(&[17, 0, 2, 1, 0, 0, 0, 0], &mut bytes)
        .unwrap();
    assert_eq!(
        p.check(IpPacket::parse(&bytes[..n]).unwrap(), true, &state),
        Err(IpPacketDrop::Destination)
    );
    let h = Ipv4Header::new(
        "192.0.2.1".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        IpProtocol::UDP,
    );
    for kind in [131, 137] {
        let n = h
            .encode(&[kind, 7, 4, 198, 51, 100, 1, 0], &[1, 2], &mut bytes)
            .unwrap();
        assert_eq!(
            p.check(IpPacket::parse(&bytes[..n]).unwrap(), true, &state),
            Err(IpPacketDrop::Destination)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn slow_consumers_and_principals_remain_isolated() {
    let (io, _blocked_peer) = tokio::io::duplex(1);
    let mut blocked =
        ConnectIpSession::new(ServiceInput::new(io), config(ConnectIpRole::Client)).unwrap();
    let (mut a, mut b) = pair();
    let (stalled, healthy) = tokio::join!(
        blocked.send_packet(packet(), IpPacketOrigin::Local),
        async {
            a.send_packet(packet(), IpPacketOrigin::Local)
                .await
                .unwrap();
            b.recv().await.unwrap()
        }
    );
    assert!(matches!(stalled, Err(ConnectIpError::Timeout)));
    assert!(matches!(healthy, Some(ConnectIpEvent::Packet { .. })));
    let limits = ConnectIpLimits::try_new(IpAdmissionLimits {
        max_tunnels_per_principal: 1,
        max_principals: 1,
        ..Default::default()
    })
    .unwrap();
    let first = Request::new(rama_http::Body::empty());
    first.extensions().insert(UserId::Username("alice".into()));
    let second = Request::new(rama_http::Body::empty());
    second.extensions().insert(UserId::Username("bob".into()));
    let lease = limits.admit(&first).unwrap();
    limits.admit(&second).unwrap_err();
    drop(lease);
    limits.admit(&second).unwrap_err();
    tokio::time::advance(Duration::from_secs(61)).await;
    let lease = limits.admit(&second).unwrap();
    assert_eq!(limits.live_tunnels(), 1);
    drop(lease);
    assert_eq!(limits.live_tunnels(), 0);
}

#[derive(Debug)]
struct Resolver {
    results: Vec<std::net::Ipv4Addr>,
    pending: bool,
    repeat: bool,
}

impl rama_dns::client::resolver::DnsAddressResolver for Resolver {
    type Error = Infallible;
    fn lookup_ipv4(
        &self,
        _: rama_net::address::Domain,
    ) -> impl rama_core::futures::Stream<Item = Result<std::net::Ipv4Addr, Infallible>> + Send + '_
    {
        use rama_core::futures::{StreamExt as _, stream};
        stream::iter(self.results.iter().copied().map(Ok))
            .chain(
                stream::repeat(Ok(Ipv4Addr::new(192, 0, 2, 2))).take(if self.repeat {
                    usize::MAX
                } else {
                    0
                }),
            )
            .chain(stream::pending().take(usize::from(self.pending)))
    }

    fn lookup_ipv6(
        &self,
        _: rama_net::address::Domain,
    ) -> impl rama_core::futures::Stream<Item = Result<std::net::Ipv6Addr, Infallible>> + Send + '_
    {
        rama_core::futures::stream::empty()
    }
}

#[tokio::test(start_paused = true)]
async fn hostname_resolution_is_bounded_filtered_and_pinned() {
    let target = || IpTarget::Hostname(rama_net::address::Domain::from_static("host.example"));
    let ext = Default::default();
    let destinations = [route("192.0.2.0/24")];
    let mut resolver = Arc::new(Resolver {
        results: vec![Ipv4Addr::LOCALHOST, "192.0.2.2".parse().unwrap()],
        pending: false,
        repeat: false,
    });
    let pinned = super::server::resolve_scope(&resolver, target(), &ext, &destinations)
        .await
        .unwrap();
    assert_eq!(pinned, [prefix("192.0.2.2/32")]);
    Arc::get_mut(&mut resolver).unwrap().results = vec![Ipv4Addr::LOCALHOST];
    let mut p = policy(ConnectIpRole::Client);
    p.scope_targets = pinned;
    p.check(
        IpPacket::parse(&packet()).unwrap(),
        true,
        &ConnectIpState::default(),
    )
    .unwrap();
    assert_eq!(
        super::server::resolve_scope(&resolver, target(), &ext, &destinations).await,
        Err(StatusCode::FORBIDDEN)
    );
    Arc::get_mut(&mut resolver).unwrap().results = (0..257)
        .map(|i| Ipv4Addr::new(192, 0, (2 + i / 256) as u8, (i % 256) as u8))
        .collect();
    assert_eq!(
        super::server::resolve_scope(&resolver, target(), &ext, &destinations).await,
        Err(StatusCode::BAD_GATEWAY)
    );
    Arc::get_mut(&mut resolver).unwrap().results.clear();
    Arc::get_mut(&mut resolver).unwrap().repeat = true;
    assert_eq!(
        super::server::resolve_scope(&resolver, target(), &ext, &destinations)
            .await
            .unwrap(),
        [prefix("192.0.2.2/32")]
    );
    Arc::get_mut(&mut resolver).unwrap().repeat = false;
    Arc::get_mut(&mut resolver).unwrap().pending = true;
    let template = ConnectIpTemplate::try_new("https://proxy.example/{target}/{ipproto}/").unwrap();
    let limits = ConnectIpLimits::default();
    let service = ConnectIpService::new(
        template.clone(),
        service_fn(async |_: ConnectIpRequest| Ok::<_, Infallible>(config(ConnectIpRole::Proxy))),
        service_fn(async |_: ConnectIpSession| Ok::<_, Infallible>(())),
        Executor::new(),
    )
    .with_resolver(resolver)
    .with_limits(limits.clone())
    .with_open_timeout(Duration::from_secs(1));
    let request = template
        .request(
            &ConnectIpScope {
                target: target(),
                protocol: None,
            },
            Version::HTTP_3,
        )
        .unwrap();
    assert_eq!(
        service.serve(request).await.unwrap().status(),
        StatusCode::GATEWAY_TIMEOUT
    );
    assert_eq!(limits.live_tunnels(), 0);
}

#[tokio::test(start_paused = true)]
async fn ipv6_mtu_requires_a_guarantee_or_a_successful_full_size_probe() {
    let (a, b) = tokio::io::duplex(65536);
    let mut cfg = config(ConnectIpRole::Client);
    cfg.ipv6_link_mtu = None;
    let mut client = ConnectIpSession::new(ServiceInput::new(a), cfg.clone()).unwrap();
    cfg.policy.role = ConnectIpRole::Proxy;
    let mut proxy = ConnectIpSession::new(ServiceInput::new(b), cfg.clone()).unwrap();
    let source = "2001:db8::1".parse().unwrap();
    let peer = "2001:db8::2".parse().unwrap();
    let mut bytes = [0; 1280];
    let n = Ipv6Header::new(source, peer, IpProtocol::UDP)
        .encode(&[42; 1240], &mut bytes)
        .unwrap();
    assert_eq!(
        client
            .send_packet(Bytes::copy_from_slice(&bytes[..n]), IpPacketOrigin::Local)
            .await
            .unwrap(),
        IpPacketSend::Dropped(IpPacketDrop::Ipv6Disabled)
    );
    let (a, b) = tokio::join!(
        client.probe_ipv6_mtu(source, peer, [1; 16]),
        proxy.probe_ipv6_mtu(peer, source, [2; 16])
    );
    assert!(a.unwrap().is_empty());
    assert!(b.unwrap().is_empty());
    assert!(matches!(
        client
            .send_packet(Bytes::copy_from_slice(&bytes[..n]), IpPacketOrigin::Local)
            .await
            .unwrap(),
        IpPacketSend::Sent(_)
    ));
    assert!(matches!(
        proxy.recv().await.unwrap(),
        Some(ConnectIpEvent::Packet { .. })
    ));
    let (a, _silent_peer) = tokio::io::duplex(65536);
    let mut session = ConnectIpSession::new(ServiceInput::new(a), cfg).unwrap();
    assert!(matches!(
        session.probe_ipv6_mtu(source, peer, [3; 16]).await,
        Err(ConnectIpError::Timeout)
    ));
    assert!(matches!(
        session.send_packet(packet(), IpPacketOrigin::Local).await,
        Err(ConnectIpError::Closed)
    ));
}

#[tokio::test]
async fn forwarding_keeps_link_local_and_limited_broadcast_on_the_link() {
    let (io, _peer) = tokio::io::duplex(65536);
    let mut cfg = config(ConnectIpRole::Client);
    cfg.policy.send.sources = IpSourcePolicy::Static(vec![prefix("0.0.0.0/0")]);
    cfg.policy.send.destinations = vec![route("0.0.0.0/0")];
    let mut session = ConnectIpSession::new(ServiceInput::new(io), cfg).unwrap();
    for destination in [
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(169, 254, 1, 2),
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        assert_eq!(
            session
                .send_packet(
                    v4(Ipv4Addr::new(192, 0, 2, 1), destination),
                    IpPacketOrigin::Forwarded
                )
                .await
                .unwrap(),
            IpPacketSend::Dropped(IpPacketDrop::Scope)
        );
    }
}

#[tokio::test]
async fn forwarding_preserves_shared_input_and_packet_contents() {
    timeout(Duration::from_secs(3), async {
        let (mut sender, mut receiver) = pair();
        let mut raw = [0; 128];
        let n = Ipv6Header::new(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            IpProtocol::UDP,
        )
        .encode(b"unchanged IPv6 payload", &mut raw)
        .unwrap();
        for original in [packet(), Bytes::copy_from_slice(&raw[..n])] {
            let before = original.to_vec();
            for origin in [IpPacketOrigin::Local, IpPacketOrigin::Forwarded] {
                assert_eq!(
                    sender.send_packet(original.clone(), origin).await.unwrap(),
                    IpPacketSend::Sent(DatagramTransport::Capsule)
                );
                let Some(ConnectIpEvent::Packet {
                    packet: received, ..
                }) = receiver.recv().await.unwrap()
                else {
                    panic!()
                };
                let expected = IpPacket::parse(&original).unwrap();
                let actual = IpPacket::parse(&received).unwrap(); // verifies the IPv4 checksum too
                assert_eq!(actual.source(), expected.source());
                assert_eq!(actual.destination(), expected.destination());
                assert_eq!(actual.upper_layer_payload(), expected.upper_layer_payload());
                assert_eq!(
                    actual.hop_limit(),
                    expected.hop_limit() - u8::from(origin == IpPacketOrigin::Forwarded)
                );
                assert_eq!(original.as_ref(), before);
            }
        }
        let mut header = Ipv4Header::new(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
            IpProtocol::UDP,
        );
        header.hop_limit = 1;
        let n = header.encode(&[], b"expired", &mut raw).unwrap();
        assert_eq!(
            sender
                .send_packet(Bytes::copy_from_slice(&raw[..n]), IpPacketOrigin::Forwarded)
                .await
                .unwrap(),
            IpPacketSend::Dropped(IpPacketDrop::HopLimit)
        );
        // A dropped packet must not damage subsequent framing or terminate the tunnel.
        sender
            .send_packet(packet(), IpPacketOrigin::Local)
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Some(ConnectIpEvent::Packet { .. })
        ));
    })
    .await
    .unwrap();
}

#[test]
fn invalid_control_updates_preserve_previous_snapshots() {
    let mut state = ConnectIpState::default();
    let good = ConnectIpCapsule::AddressAssign(vec![assignment("192.0.2.1/32", 0)]);
    state.receive(&good).unwrap();
    for invalid in [
        ConnectIpCapsule::AddressAssign(vec![
            assignment("192.0.2.2/32", 0),
            assignment("192.0.2.3/32", 1 << 62),
        ]),
        ConnectIpCapsule::AddressAssign(vec![
            assignment("192.0.2.2/32", 0),
            assignment("192.0.2.3/24", 0),
        ]),
    ] {
        invalid.encode(10).unwrap_err();
        state.receive(&invalid).unwrap_err();
        assert_eq!(state.local_addresses(), &[assignment("192.0.2.1/32", 0)]);
    }
    let routes = ConnectIpCapsule::RouteAdvertisement(vec![route("192.0.2.0/24")]);
    state.receive(&routes).unwrap();
    let bad_routes =
        ConnectIpCapsule::RouteAdvertisement(vec![route("192.0.2.0/24"), route("192.0.2.0/25")]);
    state.receive(&bad_routes).unwrap_err();
    assert_eq!(state.peer_routes(), &[route("192.0.2.0/24")]);
}

#[test]
fn control_encoding_accepts_exact_limits_and_sizes_mixed_entries() {
    let ids = [
        1,
        63,
        64,
        16383,
        16384,
        (1 << 30) - 1,
        1 << 30,
        (1 << 62) - 1,
    ];
    let assignments: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            assignment(
                if i % 2 == 0 {
                    "192.0.2.1/32"
                } else {
                    "2001:db8::1/128"
                },
                *id,
            )
        })
        .collect();
    let requests = assignments
        .iter()
        .map(|a| AddressRequest {
            request_id: a.request_id,
            prefix: a.prefix,
        })
        .collect();
    for capsule in [
        ConnectIpCapsule::AddressAssign(assignments),
        ConnectIpCapsule::AddressRequest(requests),
        ConnectIpCapsule::RouteAdvertisement(vec![route("192.0.2.1/32"), route("2001:db8::1/128")]),
    ] {
        let count = match &capsule {
            ConnectIpCapsule::AddressAssign(v) => v.len(),
            ConnectIpCapsule::AddressRequest(v) => v.len(),
            ConnectIpCapsule::RouteAdvertisement(v) => v.len(),
        };
        let bytes = capsule.encode(count).unwrap();
        // The allocation size must match the actual wire encoding, including varint boundaries.
        assert_eq!(capsule.encoded_len(count).unwrap(), bytes.len());
        assert_eq!(
            ConnectIpCapsule::decode(capsule.capsule_type(), &bytes, count).unwrap(),
            capsule
        );
        assert_eq!(
            capsule.encode(count - 1).unwrap_err(),
            ConnectIpProtocolError::Limit
        );
        assert_eq!(
            ConnectIpCapsule::decode(capsule.capsule_type(), &bytes, count - 1).unwrap_err(),
            ConnectIpProtocolError::Limit
        );
    }
}

#[test]
fn route_validation_rejects_invalid_ranges_and_accepts_single_hosts() {
    for host in ["192.0.2.1", "2001:db8::1"] {
        let ip = host.parse().unwrap();
        validate_routes(&[IpRoute {
            start: ip,
            end: ip,
            protocol: None,
        }])
        .unwrap();
    }
    for invalid in [
        IpRoute {
            start: "192.0.2.2".parse().unwrap(),
            end: "192.0.2.1".parse().unwrap(),
            protocol: None,
        },
        IpRoute {
            start: "2001:db8::2".parse().unwrap(),
            end: "2001:db8::1".parse().unwrap(),
            protocol: None,
        },
        IpRoute {
            start: "192.0.2.1".parse().unwrap(),
            end: "2001:db8::1".parse().unwrap(),
            protocol: None,
        },
        IpRoute {
            start: "2001:db8::1".parse().unwrap(),
            end: "192.0.2.1".parse().unwrap(),
            protocol: None,
        },
        IpRoute {
            protocol: Some(IpProtocol::HOP_BY_HOP),
            ..route("192.0.2.0/24")
        },
    ] {
        assert_eq!(
            validate_routes(&[invalid]),
            Err(ConnectIpProtocolError::Route)
        );
    }
}

#[test]
fn route_overlap_matches_inclusive_ranges_across_families_and_protocols() {
    let mut candidates = Vec::new();
    for ipv6 in [false, true] {
        for protocol in [None, Some(IpProtocol::TCP), Some(IpProtocol::UDP)] {
            for start in 0..4u8 {
                for end in start..4 {
                    let address = |n| {
                        if ipv6 {
                            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                                0x2001,
                                0xdb8,
                                0,
                                0,
                                0,
                                0,
                                0,
                                u16::from(n),
                            ))
                        } else {
                            std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
                        }
                    };
                    candidates.push(IpRoute {
                        start: address(start),
                        end: address(end),
                        protocol,
                    });
                }
            }
        }
    }
    for a in &candidates {
        for b in &candidates {
            let mut routes = [*a, *b];
            routes.sort_by_key(|r| {
                (
                    r.start.is_ipv6(),
                    r.protocol.map_or(0, IpProtocol::value),
                    r.start,
                )
            });
            let overlap = a.start.is_ipv6() == b.start.is_ipv6()
                && a.start <= b.end
                && b.start <= a.end
                && (a.protocol == b.protocol || a.protocol.is_none() || b.protocol.is_none());
            assert_eq!(validate_routes(&routes).is_ok(), !overlap, "{routes:?}");
        }
    }
}

#[tokio::test]
async fn site_to_site_routes_are_bidirectional_and_withdrawable() {
    timeout(Duration::from_secs(3), async {
        let branch = prefix("192.0.2.0/24");
        let corporate = prefix("203.0.113.0/24");
        let direction = |source, destination| IpDirectionPolicy {
            sources: IpSourcePolicy::Static(vec![source]),
            destinations: vec![IpRoute::from_prefix(destination, None)],
            require_advertised_route: true,
        };
        let mut client_policy = ConnectIpPolicy::new(ConnectIpRole::Client);
        client_policy.send = direction(branch, corporate);
        client_policy.receive = direction(corporate, branch);
        let mut proxy_policy = ConnectIpPolicy::new(ConnectIpRole::Proxy);
        proxy_policy.send = direction(corporate, branch);
        proxy_policy.receive = direction(branch, corporate);
        let (a, b) = tokio::io::duplex(4096);
        let mut client = ConnectIpSession::new(
            ServiceInput::new(a),
            ConnectIpSessionConfig::new(client_policy),
        )
        .unwrap();
        let mut proxy = ConnectIpSession::new(
            ServiceInput::new(b),
            ConnectIpSessionConfig::new(proxy_policy),
        )
        .unwrap();
        client
            .send_control(ConnectIpCapsule::RouteAdvertisement(vec![
                IpRoute::from_prefix(branch, None),
            ]))
            .await
            .unwrap();
        proxy.recv().await.unwrap();
        proxy
            .send_control(ConnectIpCapsule::RouteAdvertisement(vec![
                IpRoute::from_prefix(corporate, None),
            ]))
            .await
            .unwrap();
        client.recv().await.unwrap();
        let outbound = v4(
            "192.0.2.10".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
        );
        let inbound = v4(
            "203.0.113.20".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
        );
        for (from_client, packet) in [(true, outbound.clone()), (false, inbound)] {
            let (sender, receiver) = if from_client {
                (&mut client, &mut proxy)
            } else {
                (&mut proxy, &mut client)
            };
            assert!(matches!(
                sender
                    .send_packet(packet, IpPacketOrigin::Forwarded)
                    .await
                    .unwrap(),
                IpPacketSend::Sent(_)
            ));
            let Some(ConnectIpEvent::Packet { packet, .. }) = receiver.recv().await.unwrap() else {
                panic!()
            };
            assert_eq!(IpPacket::parse(&packet).unwrap().hop_limit(), 63);
        }
        proxy
            .send_control(ConnectIpCapsule::RouteAdvertisement(vec![]))
            .await
            .unwrap();
        client.recv().await.unwrap();
        assert_eq!(
            client
                .send_packet(outbound, IpPacketOrigin::Forwarded)
                .await
                .unwrap(),
            IpPacketSend::Dropped(IpPacketDrop::Destination)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_send_errors_respect_ipv6_mtu_and_queue_policy() {
    for ipv6_link_mtu in [None, Some(1400)] {
        for error in [
            NativeSendError::Full,
            NativeSendError::TooLarge { max: 1200 },
            NativeSendError::TooLarge { max: 1280 },
            NativeSendError::TooLarge { max: 1281 },
            NativeSendError::TooLarge { max: 1400 },
        ] {
            let (a, _b) = tokio::io::duplex(4096);
            let io = ServiceInput::new(a);
            // The send reports a capacity change after the initial MTU check.
            io.extensions().insert(NativeDatagrams::new(Native {
                mtu: Arc::new(AtomicUsize::new(1401)),
                send_error: Some(error),
            }));
            let mut cfg = config(ConnectIpRole::Client);
            cfg.ipv6_link_mtu = ipv6_link_mtu;
            let mut session = ConnectIpSession::new(io, cfg).unwrap();
            let result = session.send_packet(packet(), IpPacketOrigin::Local).await;
            if ipv6_link_mtu.is_some()
                && matches!(error, NativeSendError::TooLarge { max } if max < 1281)
            {
                assert!(matches!(result, Err(ConnectIpError::Ipv6Mtu)));
                assert!(matches!(
                    session.send_packet(packet(), IpPacketOrigin::Local).await,
                    Err(ConnectIpError::Closed)
                ));
            } else {
                let expected = if matches!(error, NativeSendError::Full) {
                    IpPacketDrop::QueueFull
                } else {
                    IpPacketDrop::TooLarge
                };
                assert_eq!(result.unwrap(), IpPacketSend::Dropped(expected));
                assert_eq!(
                    session
                        .send_packet(packet(), IpPacketOrigin::Local)
                        .await
                        .unwrap(),
                    IpPacketSend::Dropped(expected)
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn reliable_sender_waits_for_room_within_its_deadline() {
    let (a, b) = tokio::io::duplex(1);
    let cfg = config(ConnectIpRole::Client);
    let mut raw =
        HttpDatagramSession::with_config(ServiceInput::new(b), cfg.http_config().unwrap());
    let mut session = ConnectIpSession::new(ServiceInput::new(a), cfg).unwrap();
    let start = tokio::time::Instant::now();
    let (sent, received) = tokio::join!(
        session.send_packet(packet(), IpPacketOrigin::Local),
        async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            timeout(Duration::from_secs(1), raw.recv())
                .await
                .unwrap()
                .unwrap()
        }
    );
    assert_eq!(
        sent.unwrap(),
        IpPacketSend::Sent(DatagramTransport::Capsule)
    );
    assert!(matches!(
        received,
        Some(rama_http::datagram::SessionEvent::Datagram { .. })
    ));
    assert!(start.elapsed() >= Duration::from_millis(10));
}

#[test]
fn scoped_query_templates_support_hostnames_prefixes_and_other_ip_protocols() {
    for pattern in [
        "https://proxy.example/proxy{?target,ipproto}",
        "https://proxy.example/proxy?target={target}&ipproto={ipproto}",
    ] {
        let template = ConnectIpTemplate::try_new(pattern).unwrap();
        for scope in [
            ConnectIpScope::default(),
            ConnectIpScope::from_template_values(Some("target.example"), Some("132")).unwrap(),
            ConnectIpScope::from_template_values(Some("192.0.2.0/24"), Some("253")).unwrap(),
            ConnectIpScope::from_template_values(Some("2001:db8::/32"), Some("58")).unwrap(),
        ] {
            for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
                let request = template.request(&scope, version).unwrap();
                assert_eq!(template.match_request(&request).unwrap(), scope);
                if scope == ConnectIpScope::default() {
                    assert!(request.uri().to_string().contains("target=%2A&ipproto=%2A"));
                }
            }
        }
    }
}

#[tokio::test]
async fn blocked_send_releases_the_original_packet_owner() {
    struct Owner {
        packet: Bytes,
        drops: Arc<AtomicUsize>,
    }

    impl AsRef<[u8]> for Owner {
        fn as_ref(&self) -> &[u8] {
            &self.packet
        }
    }

    impl Drop for Owner {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let input = Bytes::from_owner(Owner {
        packet: packet(),
        drops: drops.clone(),
    });
    let (a, _blocked_peer) = tokio::io::duplex(1);
    let mut session =
        ConnectIpSession::new(ServiceInput::new(a), config(ConnectIpRole::Client)).unwrap();
    let mut send = Box::pin(session.send_packet(input, IpPacketOrigin::Forwarded));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(send.as_mut(), cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    drop(send);
}
