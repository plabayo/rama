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
    IpRoute::from_prefix(prefix(s), None).unwrap()
}

fn assignment(s: &str, id: u64) -> AddressAssignment {
    AddressAssignment {
        request_id: (id != 0).then(|| AddressRequestId::new(id).unwrap()),
        prefix: prefix(s),
    }
}

fn request(s: &str, id: u64) -> AddressRequest {
    AddressRequest {
        request_id: AddressRequestId::new(id).unwrap(),
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
        (crate::context::ContextId::IP, &[0x45][..])
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
    validate_routes(&[b, a]).unwrap_err();
    validate_routes(&[a, a]).unwrap_err();
    let mut tcp = a;
    tcp.protocol = Some(IpProtocol::TCP);
    let mut udp = a;
    udp.protocol = Some(IpProtocol::UDP);
    validate_routes(&[tcp, udp]).unwrap();
    validate_routes(&[a, tcp]).unwrap_err();
    let range = IpRoute {
        start: "192.0.2.3".parse().unwrap(),
        end: "192.0.2.19".parse().unwrap(),
        protocol: None,
    };
    validate_routes(&[range]).unwrap();
    assert!(range.contains("192.0.2.17".parse().unwrap()));
    assert!(!range.contains("192.0.2.20".parse().unwrap()));
    validate_routes(&[route("::/0"), a]).unwrap_err();
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
        max_entries: std::num::NonZeroU16::new(4).unwrap(),
        max_request_ids: std::num::NonZeroU32::new(2).unwrap(),
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
        ConnectIpScope::from_template_values(Some("192.0.2.0/24"), Some("0"))
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

fn policy() -> ConnectIpPolicy {
    let mut p = ConnectIpPolicy::new();
    let direction = IpDirectionPolicy {
        sources: IpSourcePolicy::Static(vec![prefix("192.0.2.0/24"), prefix("2001:db8::/32")]),
        destinations: vec![route("192.0.2.0/24"), route("2001:db8::/32")],
        require_advertised_route: false,
    };
    p.send = direction.clone();
    p.receive = direction;
    p
}

fn config() -> ConnectIpSessionConfig {
    let mut c = ConnectIpSessionConfig::new(policy());
    c = c.try_with_ipv6_link_mtu(Some(1400)).unwrap();
    c
}

fn pair() -> (
    ConnectIpSession<ServiceInput<DuplexStream>>,
    ConnectIpSession<ServiceInput<DuplexStream>>,
) {
    let (a, b) = tokio::io::duplex(65536);
    (
        ConnectIpSession::new(ServiceInput::new(a), ConnectIpRole::Client, config()).unwrap(),
        ConnectIpSession::new(ServiceInput::new(b), ConnectIpRole::Server, config()).unwrap(),
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
    let mut cfg = config();
    cfg = cfg
        .try_with_idle_timeout(Duration::from_millis(100))
        .unwrap();
    let mut raw = HttpDatagramSession::with_config(ServiceInput::new(a), cfg.http_config());
    let mut session =
        ConnectIpSession::new(ServiceInput::new(b), ConnectIpRole::Client, cfg).unwrap();
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
        ConnectIpSession::new(ServiceInput::new(a), ConnectIpRole::Client, config()).unwrap();
    let (mut send, mut recv) = session.split();
    let capsule = ConnectIpCapsule::RouteAdvertisement(vec![route("192.0.2.0/24")]);
    timeout(Duration::from_millis(1), send.send_control(capsule))
        .await
        .unwrap_err();
    assert!(matches!(recv.recv().await, Err(ConnectIpError::Closed)));
    let limits = ConnectIpLimits::new()
        .with_max_tunnels_per_principal(std::num::NonZeroUsize::new(1).unwrap())
        .with_principal_budget(crate::budget::PrincipalBudget::new().with_lifetime_quota(10));
    let req = Request::new(rama_http::Body::empty());
    let lease = limits.admit(&req).unwrap();
    assert_eq!(limits.live_tunnels(), 1);
    limits.admit(&req).unwrap_err();
    assert_eq!(
        lease.principal_spend().unwrap().charge(false, 10),
        crate::budget::Charge::Paid
    );
    drop(lease);
    assert_eq!(limits.live_tunnels(), 0);
    let lease = limits.admit(&req).unwrap();
    assert_eq!(
        lease.principal_spend().unwrap().charge(false, 1),
        crate::budget::Charge::OverQuota
    );
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
    let mut session = ConnectIpSession::new(io, ConnectIpRole::Client, config()).unwrap();
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
        ConnectIpPolicy::new()
            .check(
                IpPacket::parse(&p).unwrap(),
                true,
                ConnectIpRole::Client,
                &state
            )
            .is_err()
    );
    let mut policy = policy();
    policy.scope_protocol = Some(IpProtocol::TCP);
    assert_eq!(
        policy.check(
            IpPacket::parse(&p).unwrap(),
            true,
            ConnectIpRole::Client,
            &state
        ),
        Err(IpPacketDrop::Scope)
    );
    policy.scope_protocol = None;
    policy.send.sources = IpSourcePolicy::Assigned(vec![prefix("192.0.2.0/24")]);
    assert_eq!(
        policy.check(
            IpPacket::parse(&p).unwrap(),
            true,
            ConnectIpRole::Client,
            &state
        ),
        Err(IpPacketDrop::Source)
    );
    state
        .receive(&ConnectIpCapsule::AddressAssign(vec![assignment(
            "192.0.2.1/32",
            0,
        )]))
        .unwrap();
    policy
        .check(
            IpPacket::parse(&p).unwrap(),
            true,
            ConnectIpRole::Client,
            &state,
        )
        .unwrap();
    state
        .receive(&ConnectIpCapsule::AddressAssign(vec![]))
        .unwrap();
    assert_eq!(
        policy.check(
            IpPacket::parse(&p).unwrap(),
            true,
            ConnectIpRole::Client,
            &state
        ),
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
                    Ok(config())
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
    let mut p = policy();
    p.scope_targets = vec![prefix("192.0.2.2/32")];
    p.receive.sources = IpSourcePolicy::Static(vec![prefix("198.51.100.1/32")]);
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
    // Authorizing only the scoped target excludes an intermediate router's
    // errors. The client's explicit source policy can include that router.
    let mut target_only = p.clone();
    target_only.receive.sources = IpSourcePolicy::Static(p.scope_targets.clone());
    assert_eq!(
        target_only.check(
            IpPacket::parse(&bytes[..n]).unwrap(),
            false,
            ConnectIpRole::Client,
            &state,
        ),
        Err(IpPacketDrop::Source)
    );
    p.check(
        IpPacket::parse(&bytes[..n]).unwrap(),
        false,
        ConnectIpRole::Client,
        &state,
    )
    .unwrap();
    let mut other_tenant = p.clone();
    other_tenant.scope_targets = vec![prefix("192.0.2.3/32")];
    assert_eq!(
        other_tenant.check(
            IpPacket::parse(&bytes[..n]).unwrap(),
            false,
            ConnectIpRole::Client,
            &state
        ),
        Err(IpPacketDrop::Scope)
    );
    bytes[n - 1] ^= 1;
    assert_eq!(
        p.check(
            IpPacket::parse(&bytes[..n]).unwrap(),
            false,
            ConnectIpRole::Client,
            &state
        ),
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
        p.check(
            IpPacket::parse(&bytes[..n]).unwrap(),
            true,
            ConnectIpRole::Client,
            &state
        ),
        Err(IpPacketDrop::Scope)
    );
}

#[test]
fn extension_and_fragment_policy_cannot_hide_a_different_protocol() {
    let mut p = policy();
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
            p.check(
                IpPacket::parse(&bytes[..n]).unwrap(),
                true,
                ConnectIpRole::Client,
                &state
            ),
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
        p.check(
            IpPacket::parse(&bytes[..n]).unwrap(),
            true,
            ConnectIpRole::Client,
            &state
        ),
        Err(IpPacketDrop::Scope)
    );
    // A directly identifiable UDP fragment remains usable without reassembly.
    bytes[40] = 17;
    p.check(
        IpPacket::parse(&bytes[..n]).unwrap(),
        true,
        ConnectIpRole::Client,
        &state,
    )
    .unwrap();
    header.next_header = IpProtocol::ROUTING;
    let n = header
        .encode(&[17, 0, 2, 1, 0, 0, 0, 0], &mut bytes)
        .unwrap();
    assert_eq!(
        p.check(
            IpPacket::parse(&bytes[..n]).unwrap(),
            true,
            ConnectIpRole::Client,
            &state
        ),
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
            p.check(
                IpPacket::parse(&bytes[..n]).unwrap(),
                true,
                ConnectIpRole::Client,
                &state
            ),
            Err(IpPacketDrop::Destination)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn slow_consumers_and_principals_remain_isolated() {
    let (io, _blocked_peer) = tokio::io::duplex(1);
    let mut blocked =
        ConnectIpSession::new(ServiceInput::new(io), ConnectIpRole::Client, config()).unwrap();
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
    let limits = ConnectIpLimits::new()
        .with_max_tunnels_per_principal(std::num::NonZeroUsize::new(1).unwrap())
        .with_max_principals(std::num::NonZeroUsize::new(1).unwrap());
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
    let mut p = policy();
    p.scope_targets = pinned;
    p.check(
        IpPacket::parse(&packet()).unwrap(),
        true,
        ConnectIpRole::Client,
        &ConnectIpState::default(),
    )
    .unwrap();
    assert_eq!(
        super::server::resolve_scope(&resolver, target(), &ext, &destinations).await,
        Err(rama_http::headers::ProxyErrorType::DestinationIpProhibited)
    );
    Arc::get_mut(&mut resolver).unwrap().results = (0..257)
        .map(|i| Ipv4Addr::new(192, 0, (2 + i / 256) as u8, (i % 256) as u8))
        .collect();
    assert_eq!(
        super::server::resolve_scope(&resolver, target(), &ext, &destinations).await,
        Err(rama_http::headers::ProxyErrorType::DnsError)
    );
    Arc::get_mut(&mut resolver).unwrap().results.clear();
    Arc::get_mut(&mut resolver).unwrap().repeat = true;
    assert_eq!(
        super::server::resolve_scope(&resolver, target(), &ext, &destinations).await,
        Err(rama_http::headers::ProxyErrorType::DnsError)
    );
    Arc::get_mut(&mut resolver).unwrap().repeat = false;
    Arc::get_mut(&mut resolver).unwrap().pending = true;
    let template = ConnectIpTemplate::try_new("https://proxy.example/{target}/{ipproto}/").unwrap();
    let limits = ConnectIpLimits::default();
    let service = ConnectIpService::new(
        template.clone(),
        service_fn(async |_: ConnectIpRequest| Ok::<_, Infallible>(config())),
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
    let mut cfg = config();
    cfg = cfg.try_with_ipv6_link_mtu(None).unwrap();
    let mut client =
        ConnectIpSession::new(ServiceInput::new(a), ConnectIpRole::Client, cfg.clone()).unwrap();
    let mut proxy =
        ConnectIpSession::new(ServiceInput::new(b), ConnectIpRole::Server, cfg.clone()).unwrap();
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
    let mut session =
        ConnectIpSession::new(ServiceInput::new(a), ConnectIpRole::Client, cfg).unwrap();
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
    let mut cfg = config();
    cfg.policy.send.sources = IpSourcePolicy::Static(vec![prefix("0.0.0.0/0")]);
    cfg.policy.send.destinations = vec![route("0.0.0.0/0")];
    let mut session =
        ConnectIpSession::new(ServiceInput::new(io), ConnectIpRole::Client, cfg).unwrap();
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
    let invalid = ConnectIpCapsule::AddressAssign(vec![
        assignment("192.0.2.2/32", 0),
        assignment("192.0.2.3/24", 0),
    ]);
    invalid.encode(10).unwrap_err();
    state.receive(&invalid).unwrap_err();
    assert_eq!(state.local_addresses(), &[assignment("192.0.2.1/32", 0)]);
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
            request_id: a.request_id.unwrap(),
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
            destinations: vec![IpRoute::from_prefix(destination, None).unwrap()],
            require_advertised_route: true,
        };
        let mut client_policy = ConnectIpPolicy::new();
        client_policy.send = direction(branch, corporate);
        client_policy.receive = direction(corporate, branch);
        let mut proxy_policy = ConnectIpPolicy::new();
        proxy_policy.send = direction(corporate, branch);
        proxy_policy.receive = direction(branch, corporate);
        let (a, b) = tokio::io::duplex(4096);
        let mut client = ConnectIpSession::new(
            ServiceInput::new(a),
            ConnectIpRole::Client,
            ConnectIpSessionConfig::new(client_policy),
        )
        .unwrap();
        let mut proxy = ConnectIpSession::new(
            ServiceInput::new(b),
            ConnectIpRole::Server,
            ConnectIpSessionConfig::new(proxy_policy),
        )
        .unwrap();
        client
            .send_control(ConnectIpCapsule::RouteAdvertisement(vec![
                IpRoute::from_prefix(branch, None).unwrap(),
            ]))
            .await
            .unwrap();
        proxy.recv().await.unwrap();
        proxy
            .send_control(ConnectIpCapsule::RouteAdvertisement(vec![
                IpRoute::from_prefix(corporate, None).unwrap(),
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
            let mut cfg = config();
            cfg = cfg.try_with_ipv6_link_mtu(ipv6_link_mtu).unwrap();
            let mut session = ConnectIpSession::new(io, ConnectIpRole::Client, cfg).unwrap();
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
    let cfg = config();
    let mut raw = HttpDatagramSession::with_config(ServiceInput::new(b), cfg.http_config());
    let mut session =
        ConnectIpSession::new(ServiceInput::new(a), ConnectIpRole::Client, cfg).unwrap();
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
        ConnectIpSession::new(ServiceInput::new(a), ConnectIpRole::Client, config()).unwrap();
    let mut send = Box::pin(session.send_packet(input, IpPacketOrigin::Forwarded));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(send.as_mut(), cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    drop(send);
}

#[test]
fn icmp_outer_sources_remain_subject_to_assignment_and_local_policy() {
    use rama_net::ip::icmp::{IcmpErrorKind, encode_icmp_error};
    for ipv6 in [false, true] {
        let client = if ipv6 { "2001:db8::1" } else { "192.0.2.1" };
        let target = if ipv6 { "2001:db8::2" } else { "192.0.2.2" };
        let spoofed = if ipv6 {
            "2001:db8:ffff::1"
        } else {
            "203.0.113.66"
        };
        let client_prefix = format!("{client}/{}", if ipv6 { 128 } else { 32 });
        let mut original = [0; 128];
        let n = if ipv6 {
            Ipv6Header::new(
                target.parse().unwrap(),
                client.parse().unwrap(),
                IpProtocol::UDP,
            )
            .encode(b"quoted", &mut original)
            .unwrap()
        } else {
            Ipv4Header::new(
                target.parse().unwrap(),
                client.parse().unwrap(),
                IpProtocol::UDP,
            )
            .encode(&[], b"quoted", &mut original)
            .unwrap()
        };
        for role in [ConnectIpRole::Client, ConnectIpRole::Server] {
            for outgoing in [false, true] {
                for assigned in [false, true] {
                    let mut policy = policy();
                    let sources = if assigned {
                        IpSourcePolicy::Assigned(vec![prefix(&client_prefix)])
                    } else {
                        IpSourcePolicy::Static(vec![prefix(&client_prefix)])
                    };
                    if outgoing {
                        policy.send.sources = sources;
                    } else {
                        policy.receive.sources = sources;
                    }
                    let mut state = ConnectIpState::default();
                    let assignment =
                        ConnectIpCapsule::AddressAssign(vec![assignment(&client_prefix, 0)]);
                    if outgoing {
                        state.receive(&assignment).unwrap();
                    } else {
                        state.sent(&assignment).unwrap();
                    }
                    for (source, expected) in
                        [(spoofed, Err(IpPacketDrop::Source)), (client, Ok(()))]
                    {
                        let mut error = [0; 1280];
                        let len = encode_icmp_error(
                            IpPacket::parse(&original[..n]).unwrap(),
                            source.parse().unwrap(),
                            IcmpErrorKind::NoRoute,
                            &mut error,
                        )
                        .unwrap()
                        .unwrap();
                        assert_eq!(
                            policy.check(
                                IpPacket::parse(&error[..len]).unwrap(),
                                outgoing,
                                role,
                                &state
                            ),
                            expected,
                            "ipv6={ipv6} role={role:?} outgoing={outgoing} assigned={assigned}"
                        );
                        let index = super::policy::PolicyIndex::new(&policy);
                        assert_eq!(
                            policy.check_indexed(
                                IpPacket::parse(&error[..len]).unwrap(),
                                outgoing,
                                role,
                                &state,
                                Some(&index)
                            ),
                            expected
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn graceful_half_close_preserves_the_opposite_direction() {
    let (a, mut b) = pair();
    let (mut sender, mut receiver) = a.split();
    sender.close().await.unwrap();
    assert!(matches!(
        sender.send_packet(packet(), IpPacketOrigin::Local).await,
        Err(ConnectIpError::Closed)
    ));
    drop(sender); // A completed send half must not reset the receive half.
    assert!(b.recv().await.unwrap().is_none());
    b.send_packet(packet(), IpPacketOrigin::Local)
        .await
        .unwrap();
    assert!(matches!(
        receiver.recv().await.unwrap(),
        Some(ConnectIpEvent::Packet { .. })
    ));
    b.send_control(ConnectIpCapsule::RouteAdvertisement(vec![route(
        "192.0.2.0/24",
    )]))
    .await
    .unwrap();
    assert!(matches!(
        receiver.recv().await.unwrap(),
        Some(ConnectIpEvent::Control(_))
    ));
    b.close().await.unwrap();
    assert!(receiver.recv().await.unwrap().is_none());
    assert!(receiver.recv().await.unwrap().is_none());
    drop(receiver);
    drop(b);
}

#[test]
fn session_configuration_preserves_cross_field_invariants() {
    config().try_with_max_packet_size(19).unwrap_err();
    config().try_with_max_packet_size(65576).unwrap_err();
    config().try_with_max_packet_size(1399).unwrap_err();
    config().try_with_ipv6_link_mtu(Some(1279)).unwrap_err();
    config().try_with_idle_timeout(Duration::ZERO).unwrap_err();
    config().try_with_write_timeout(Duration::ZERO).unwrap_err();
    let small = config()
        .try_with_ipv6_link_mtu(None)
        .unwrap()
        .try_with_max_packet_size(20)
        .unwrap();
    assert_eq!(small.max_packet_size(), 20);
    small.try_with_ipv6_link_mtu(Some(1280)).unwrap_err();
    AddressRequestId::new(0).unwrap_err();
    AddressRequestId::new(1 << 62).unwrap_err();
    assert_eq!(
        AddressRequestId::from_static((1 << 62) - 1).value(),
        (1 << 62) - 1
    );
}

#[tokio::test]
async fn client_builder_checks_endpoint_after_header_customization() {
    let endpoint = ConnectIpTemplate::try_new("https://proxy.example/vpn").unwrap();
    let mut builder = ConnectIpRequestBuilder::new(
        &endpoint,
        &ConnectIpScope::default(),
        Version::HTTP_11,
        config(),
    )
    .unwrap();
    builder.headers_mut().insert(
        rama_http::header::HOST,
        rama_http::HeaderValue::from_static("elsewhere.example"),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let client = service_fn(move |_: Request| {
        seen.fetch_add(1, Ordering::Relaxed);
        async { Ok::<_, Infallible>(rama_http::Response::new(())) }
    });
    builder.connect(&client).await.unwrap_err();
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let mut request = endpoint
        .request(&ConnectIpScope::default(), Version::HTTP_2)
        .unwrap();
    *request.body_mut() = rama_http::Body::from("optimistic tunnel bytes");
    ConnectIpRequestBuilder::try_from_request(&endpoint, request, config()).unwrap_err();
}

#[test]
fn typed_authority_matches_ipv6_spellings_and_https_default_port() {
    let endpoint = ConnectIpTemplate::try_new("https://[2001:db8::1]/vpn").unwrap();
    let mut request = endpoint
        .request(&ConnectIpScope::default(), Version::HTTP_11)
        .unwrap();
    request.headers_mut().insert(
        rama_http::header::HOST,
        rama_http::HeaderValue::from_static("[2001:0db8:0:0:0:0:0:1]:443"),
    );
    assert_eq!(
        endpoint.match_request(&request).unwrap(),
        ConnectIpScope::default()
    );
    request.headers_mut().insert(
        rama_http::header::HOST,
        rama_http::HeaderValue::from_static("[2001:db8::1]:444"),
    );
    endpoint.match_request(&request).unwrap_err();
}

#[test]
fn immutable_routing_views_survive_later_control_updates() {
    let mut state = ConnectIpState::default();
    state
        .receive(&ConnectIpCapsule::RouteAdvertisement(vec![route(
            "192.0.2.0/24",
        )]))
        .unwrap();
    let before = state.snapshot();
    state
        .receive(&ConnectIpCapsule::RouteAdvertisement(vec![]))
        .unwrap();
    assert_eq!(before.peer_routes(), &[route("192.0.2.0/24")]);
    assert!(state.snapshot().peer_routes().is_empty());
}

#[test]
fn route_index_matches_linear_authorization_for_overlapping_protocols() {
    let mut routes = Vec::new();
    for family in [false, true] {
        for protocol in [Some(IpProtocol::TCP), Some(IpProtocol::UDP)] {
            for suffix in (0..=240).step_by(16) {
                let network = if family {
                    format!("2001:db8::{suffix:x}/128")
                } else {
                    format!("192.0.2.{suffix}/32")
                };
                routes.push(IpRoute::from_prefix(prefix(&network), protocol).unwrap());
            }
        }
    }
    let mut state = ConnectIpState::default();
    state
        .receive(&ConnectIpCapsule::RouteAdvertisement(routes.clone()))
        .unwrap();
    let snapshot = state.snapshot();
    let (_, index) = snapshot.destination_index(true);
    for family in [false, true] {
        for suffix in 0..=255 {
            let address = if family {
                format!("2001:db8::{suffix:x}")
            } else {
                format!("192.0.2.{suffix}")
            }
            .parse()
            .unwrap();
            for protocol in [
                None,
                Some(IpProtocol::TCP),
                Some(IpProtocol::UDP),
                Some(IpProtocol::ICMP),
                Some(IpProtocol::ICMPV6),
            ] {
                assert_eq!(
                    index.allows(address, protocol),
                    routes.iter().any(|r| r.allows(address, protocol))
                );
            }
        }
    }
    let addresses = vec![
        assignment("192.0.2.0/24", 0),
        assignment("192.0.2.0/25", 0),
        assignment("2001:db8::/32", 0),
    ];
    state
        .receive(&ConnectIpCapsule::AddressAssign(addresses.clone()))
        .unwrap();
    for raw in [
        "192.0.2.0",
        "192.0.2.127",
        "192.0.2.255",
        "192.0.3.0",
        "2001:db8::1",
        "2001:db9::",
    ] {
        let address = raw.parse().unwrap();
        assert_eq!(
            state.snapshot().source_index(true).contains(address),
            addresses.iter().any(|a| a.prefix.contains(&address))
        );
    }
}

#[tokio::test]
async fn generic_request_bodies_and_custom_principals_reach_admission() {
    let template = ConnectIpTemplate::try_new("https://proxy.example/vpn").unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let admission_seen = seen.clone();
    let limits = ConnectIpLimits::new()
        .with_max_tunnels_per_principal(std::num::NonZeroUsize::MIN)
        .with_keyer_for::<Request<std::cell::Cell<u8>>, _>(
            |request: &Request<std::cell::Cell<u8>>| {
                Ok::<_, rama_core::error::BoxError>(
                    request
                        .headers()
                        .get("x-tenant")
                        .map(|h| h.to_str().unwrap().to_owned()),
                )
            },
        );
    let service = ConnectIpService::new(
        template.clone(),
        service_fn(move |request: ConnectIpRequest<std::cell::Cell<u8>>| {
            assert_eq!(request.request.headers()["x-tenant"], "test");
            admission_seen.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(config()) }
        }),
        service_fn(async |_: ConnectIpSession| Ok::<_, Infallible>(())),
        Executor::new(),
    )
    .with_limits(limits.clone());
    let mut request = template
        .request(&ConnectIpScope::default(), Version::HTTP_2)
        .unwrap()
        .map(|_| std::cell::Cell::new(0));
    request
        .headers_mut()
        .insert("x-tenant", rama_http::HeaderValue::from_static("test"));
    request
        .extensions()
        .insert(rama_tls::SecureTransport::default());
    assert_eq!(
        service.serve(request).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(seen.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn unknown_control_capsules_consume_budget_without_protocol_errors() {
    let (a, b) = tokio::io::duplex(4096);
    let mut cfg = config();
    cfg.budget = crate::budget::TunnelBudget::new().with_quota(1);
    let mut receiver =
        ConnectIpSession::new(ServiceInput::new(b), ConnectIpRole::Server, cfg).unwrap();
    let mut raw = HttpDatagramSession::new(ServiceInput::new(a));
    raw.send_capsule(
        rama_http::proto::capsule::CapsuleType::from_static(71),
        Bytes::from_static(b"ignored"),
    )
    .await
    .unwrap();
    assert!(matches!(receiver.recv().await, Err(ConnectIpError::Budget)));
}

#[test]
fn compiled_local_policy_matches_unindexed_checks() {
    use super::policy::PolicyIndex;
    for ipv6 in [false, true] {
        for scoped in [false, true] {
            for assigned in [false, true] {
                let network = if ipv6 {
                    "2001:db8::/120"
                } else {
                    "192.0.2.0/24"
                };
                let mut policy = policy();
                if scoped {
                    policy.scope_targets = vec![prefix(network)];
                    policy.scope_protocol = Some(IpProtocol::UDP);
                }
                let direction = IpDirectionPolicy {
                    sources: if assigned {
                        IpSourcePolicy::Assigned(vec![prefix(network)])
                    } else {
                        IpSourcePolicy::Static(vec![prefix(network)])
                    },
                    destinations: vec![
                        IpRoute::from_prefix(prefix(network), Some(IpProtocol::UDP)).unwrap(),
                    ],
                    require_advertised_route: assigned,
                };
                policy.send = direction.clone();
                policy.receive = direction;
                let mut state = ConnectIpState::default();
                let addresses = ConnectIpCapsule::AddressAssign(vec![assignment(network, 0)]);
                state.sent(&addresses).unwrap();
                state.receive(&addresses).unwrap();
                let index = PolicyIndex::new(&policy);
                for source_inside in [false, true] {
                    for destination_inside in [false, true] {
                        for protocol in [IpProtocol::TCP, IpProtocol::UDP, IpProtocol::ICMPV6] {
                            let mut bytes = [0; 64];
                            let n = if ipv6 {
                                let address = |inside| {
                                    if inside {
                                        "2001:db8::1"
                                    } else {
                                        "2001:db8:1::1"
                                    }
                                    .parse()
                                    .unwrap()
                                };
                                Ipv6Header::new(
                                    address(source_inside),
                                    address(destination_inside),
                                    protocol,
                                )
                                .encode(&[128; 8], &mut bytes)
                                .unwrap()
                            } else {
                                let address = |inside| {
                                    if inside { "192.0.2.1" } else { "192.0.3.1" }
                                        .parse()
                                        .unwrap()
                                };
                                Ipv4Header::new(
                                    address(source_inside),
                                    address(destination_inside),
                                    protocol,
                                )
                                .encode(&[], &[128; 8], &mut bytes)
                                .unwrap()
                            };
                            let packet = IpPacket::parse(&bytes[..n]).unwrap();
                            for role in [ConnectIpRole::Client, ConnectIpRole::Server] {
                                for outgoing in [false, true] {
                                    assert_eq!(
                                        policy.check_indexed(
                                            packet,
                                            outgoing,
                                            role,
                                            &state,
                                            Some(&index)
                                        ),
                                        policy.check(packet, outgoing, role, &state)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn public_route_construction_rejects_invalid_ranges() {
    for (start, end) in [
        ("192.0.2.2", "192.0.2.1"),
        ("2001:db8::2", "2001:db8::1"),
        ("192.0.2.1", "2001:db8::1"),
    ] {
        assert_eq!(
            IpRoute::new(start.parse().unwrap(), end.parse().unwrap(), None),
            Err(ConnectIpProtocolError::Route)
        );
    }
    assert_eq!(
        IpRoute::from_prefix(prefix("192.0.2.0/24"), Some(IpProtocol::HOP_BY_HOP)),
        Err(ConnectIpProtocolError::Route)
    );
}

#[test]
fn icmp_quoted_flow_requires_either_assignment_or_advertised_route() {
    use rama_net::ip::icmp::{IcmpErrorKind, encode_icmp_error};
    let mut policy = policy();
    policy.send.require_advertised_route = true;
    policy.receive.sources = IpSourcePolicy::Static(vec![prefix("198.51.100.1/32")]);
    let original = packet();
    let mut bytes = [0; 1280];
    let n = encode_icmp_error(
        IpPacket::parse(&original).unwrap(),
        "198.51.100.1".parse().unwrap(),
        IcmpErrorKind::HopLimitExceeded,
        &mut bytes,
    )
    .unwrap()
    .unwrap();
    let error = IpPacket::parse(&bytes[..n]).unwrap();
    let index = super::policy::PolicyIndex::new(&policy);
    for assigned in [false, true] {
        for routed in [false, true] {
            let mut state = ConnectIpState::default();
            if assigned {
                state
                    .sent(&ConnectIpCapsule::AddressAssign(vec![assignment(
                        "192.0.2.2/32",
                        0,
                    )]))
                    .unwrap();
            }
            if routed {
                state
                    .receive(&ConnectIpCapsule::RouteAdvertisement(vec![route(
                        "192.0.2.2/32",
                    )]))
                    .unwrap();
            }
            let expected = if assigned || routed {
                Ok(())
            } else {
                Err(IpPacketDrop::Destination)
            };
            for compiled in [None, Some(&index)] {
                assert_eq!(
                    policy.check_indexed(error, false, ConnectIpRole::Client, &state, compiled),
                    expected,
                    "assigned={assigned} routed={routed}"
                );
                assert_eq!(
                    policy.check_indexed(
                        IpPacket::parse(&original).unwrap(),
                        true,
                        ConnectIpRole::Client,
                        &state,
                        compiled
                    ),
                    expected
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn unfinished_halves_abort_but_received_eof_preserves_sender() {
    let (a, _b) = pair();
    let (sender, mut receiver) = a.split();
    drop(sender);
    assert!(matches!(
        timeout(Duration::from_millis(100), receiver.recv())
            .await
            .unwrap(),
        Err(ConnectIpError::Closed)
    ));

    let (a, _b) = pair();
    let (mut sender, receiver) = a.split();
    drop(receiver);
    assert!(matches!(
        sender.send_packet(packet(), IpPacketOrigin::Local).await,
        Err(ConnectIpError::Closed)
    ));

    let (a, mut b) = pair();
    let (mut sender, mut receiver) = a.split();
    b.close().await.unwrap();
    assert!(receiver.recv().await.unwrap().is_none());
    drop(receiver);
    assert!(matches!(
        sender
            .send_packet(packet(), IpPacketOrigin::Local)
            .await
            .unwrap(),
        IpPacketSend::Sent(_)
    ));
    assert!(matches!(
        timeout(Duration::from_millis(100), b.recv())
            .await
            .unwrap()
            .unwrap(),
        Some(ConnectIpEvent::Packet { .. })
    ));
    sender.close().await.unwrap();
    assert!(b.recv().await.unwrap().is_none());
}

fn assert_refusal(
    response: &rama_http::Response,
    error: rama_http::headers::ProxyErrorType,
    name: &str,
) {
    use rama_http::headers::{HeaderMapExt as _, ProxyStatus, ProxyStatusEntry};
    let expected = if error == rama_http::headers::ProxyErrorType::HttpRequestError {
        StatusCode::BAD_REQUEST
    } else {
        error.recommended_status().unwrap()
    };
    assert_eq!(response.status(), expected);
    let status: ProxyStatus = response.headers().typed_get().unwrap();
    assert_eq!(status.entries(), &[ProxyStatusEntry::error(name, error)]);
}

#[tokio::test(start_paused = true)]
async fn refusal_reasons_distinguish_admission_dns_and_destination_policy() {
    use rama_core::error::BoxError;
    use rama_http::headers::ProxyErrorType;
    let template = ConnectIpTemplate::try_new("https://proxy.example/{target}/{ipproto}/").unwrap();
    let request = || {
        template
            .request(&ConnectIpScope::default(), Version::HTTP_3)
            .unwrap()
    };
    let service = ConnectIpService::new(
        template.clone(),
        service_fn(async |_: ConnectIpRequest| Ok::<_, Infallible>(config())),
        service_fn(async |_: ConnectIpSession| Ok::<_, Infallible>(())),
        Executor::new(),
    );

    let insecure = template
        .request(&ConnectIpScope::default(), Version::HTTP_11)
        .unwrap();
    let response = service.serve(insecure).await.unwrap();
    assert_refusal(
        &response,
        ProxyErrorType::HttpRequestDenied,
        "proxy.example",
    );
    assert_eq!(response.headers()[rama_http::header::CONNECTION], "close");

    let mut malformed = request();
    *malformed.method_mut() = rama_http::Method::POST;
    assert_refusal(
        &service
            .clone()
            .with_proxy_name(Arc::from("edge-7"))
            .serve(malformed)
            .await
            .unwrap(),
        ProxyErrorType::HttpRequestError,
        "edge-7",
    );

    let missing = ConnectIpLimits::new()
        .with_max_tunnels_per_principal(std::num::NonZeroUsize::MIN)
        .with_keyer(|_: &Request| Ok::<Option<u64>, BoxError>(None));
    assert_refusal(
        &service
            .clone()
            .with_limits(missing)
            .serve(request())
            .await
            .unwrap(),
        ProxyErrorType::HttpRequestDenied,
        "proxy.example",
    );
    let failing = ConnectIpLimits::new()
        .with_max_tunnels_per_principal(std::num::NonZeroUsize::MIN)
        .with_keyer(|_: &Request| Err::<Option<u64>, BoxError>("key-store secret".into()));
    let response = service
        .clone()
        .with_limits(failing)
        .serve(request())
        .await
        .unwrap();
    assert_refusal(
        &response,
        ProxyErrorType::ProxyInternalError,
        "proxy.example",
    );
    assert!(!format!("{response:?}").contains("key-store secret"));
    let limits = ConnectIpLimits::new().with_max_tunnels(std::num::NonZeroUsize::MIN);
    let held = limits
        .try_acquire(crate::limits::PrincipalKey::ANONYMOUS)
        .unwrap();
    assert_refusal(
        &service
            .clone()
            .with_limits(limits)
            .serve(request())
            .await
            .unwrap(),
        ProxyErrorType::ConnectionLimitReached,
        "proxy.example",
    );
    drop(held);

    for (resolver, error) in [
        (
            Resolver {
                results: vec![],
                pending: false,
                repeat: false,
            },
            ProxyErrorType::DnsError,
        ),
        (
            Resolver {
                results: vec![Ipv4Addr::LOCALHOST],
                pending: false,
                repeat: false,
            },
            ProxyErrorType::DestinationIpProhibited,
        ),
        (
            Resolver {
                results: vec![],
                pending: false,
                repeat: true,
            },
            ProxyErrorType::DnsError,
        ),
        (
            Resolver {
                results: vec![],
                pending: true,
                repeat: false,
            },
            ProxyErrorType::DnsTimeout,
        ),
    ] {
        let scope = ConnectIpScope::new(IpTarget::Hostname(
            rama_net::address::Domain::from_static("target.example"),
        ));
        let request = template.request(&scope, Version::HTTP_3).unwrap();
        let response = service
            .clone()
            .with_resolver(resolver)
            .with_open_timeout(Duration::from_secs(1))
            .serve(request)
            .await
            .unwrap();
        assert_refusal(&response, error, "proxy.example");
    }

    let pending = ConnectIpService::new(
        template.clone(),
        service_fn(async |_: ConnectIpRequest| {
            std::future::pending::<Result<ConnectIpSessionConfig, Infallible>>().await
        }),
        service_fn(async |_: ConnectIpSession| Ok::<_, Infallible>(())),
        Executor::new(),
    )
    .with_open_timeout(Duration::from_secs(1));
    assert_refusal(
        &pending.serve(request()).await.unwrap(),
        ProxyErrorType::HttpResponseTimeout,
        "proxy.example",
    );
    let denied = ConnectIpService::new(
        template,
        service_fn(async |_: ConnectIpRequest| {
            Err::<ConnectIpSessionConfig, BoxError>("auth secret".into())
        }),
        service_fn(async |_: ConnectIpSession| Ok::<_, Infallible>(())),
        Executor::new(),
    );
    let denied_request = ConnectIpTemplate::try_new("https://proxy.example/{target}/{ipproto}/")
        .unwrap()
        .request(&ConnectIpScope::default(), Version::HTTP_3)
        .unwrap();
    assert_refusal(
        &denied.serve(denied_request).await.unwrap(),
        ProxyErrorType::HttpRequestDenied,
        "proxy.example",
    );
}

#[tokio::test]
async fn extension_protocol_scopes_require_an_explicit_ipv4_target() {
    use rama_http::headers::ProxyErrorType;
    let template = ConnectIpTemplate::try_new("https://proxy.example/{target}/{ipproto}/").unwrap();
    let service = ConnectIpService::new(
        template.clone(),
        service_fn(
            async |_: ConnectIpRequest| -> Result<ConnectIpSessionConfig, Infallible> {
                panic!("invalid scope reached admission")
            },
        ),
        service_fn(async |_: ConnectIpSession| Ok::<_, Infallible>(())),
        Executor::new(),
    );
    for protocol in [IpProtocol::ESP, IpProtocol::DESTINATION_OPTIONS] {
        for target in [
            IpTarget::Any,
            IpTarget::Prefix(prefix("2001:db8::/32")),
            IpTarget::Hostname(rama_net::address::Domain::from_static("target.example")),
        ] {
            let scope = ConnectIpScope::new(target).with_protocol(protocol);
            assert_eq!(
                ConnectIpScope::from_template_values(
                    Some(&scope.target.to_string()),
                    Some(&protocol.value().to_string())
                ),
                Err(ConnectIpRequestError::Scope)
            );
            for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
                assert!(matches!(
                    template.request(&scope, version),
                    Err(ConnectIpRequestError::Scope)
                ));
                let mut request = template
                    .request(
                        &ConnectIpScope::new(scope.target.clone()).with_protocol(IpProtocol::UDP),
                        version,
                    )
                    .unwrap();
                // Keep the template's escaping but bypass its typed protocol validation.
                let uri = request
                    .uri()
                    .to_string()
                    .replace("/17/", &format!("/{}/", protocol.value()));
                *request.uri_mut() = uri.parse().unwrap();
                request
                    .extensions()
                    .insert(rama_tls::SecureTransport::default());
                assert_refusal(
                    &service.serve(request).await.unwrap(),
                    ProxyErrorType::HttpRequestError,
                    "proxy.example",
                );
            }
        }
        let scope =
            ConnectIpScope::new(IpTarget::Prefix(prefix("192.0.2.0/24"))).with_protocol(protocol);
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let request = template.request(&scope, version).unwrap();
            assert_eq!(template.match_request(&request).unwrap(), scope);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn directional_session_rate_refusal_preserves_quota() {
    use crate::budget::{DatagramRate, TunnelBudget};
    use rama_utils::rate::Rate;
    for role in [ConnectIpRole::Client, ConnectIpRole::Server] {
        let (a, b) = tokio::io::duplex(65536);
        let mut cfg = config();
        let rate = DatagramRate::new(Rate::per_sec(1), Rate::per_sec(1000));
        let budget = TunnelBudget::new().with_quota(128);
        cfg.budget = match role {
            ConnectIpRole::Client => budget.with_to_target(rate),
            ConnectIpRole::Server => budget.with_to_client(rate),
        };
        let mut session = ConnectIpSession::new(ServiceInput::new(a), role, cfg).unwrap();
        let _peer = b;
        assert!(matches!(
            session
                .send_packet(packet(), IpPacketOrigin::Local)
                .await
                .unwrap(),
            IpPacketSend::Sent(_)
        ));
        assert!(matches!(
            session
                .send_packet(packet(), IpPacketOrigin::Local)
                .await
                .unwrap(),
            IpPacketSend::Dropped(IpPacketDrop::Budget)
        ));
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(matches!(
            session
                .send_packet(packet(), IpPacketOrigin::Local)
                .await
                .unwrap(),
            IpPacketSend::Sent(_)
        ));
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(matches!(
            session
                .send_packet(packet(), IpPacketOrigin::Local)
                .await
                .unwrap(),
            IpPacketSend::Dropped(IpPacketDrop::Budget)
        ));
    }
}

#[test]
fn typed_scope_normalizes_target_and_protocol_is_optional() {
    let mut scope = ConnectIpScope::new(IpTarget::Prefix(prefix("192.0.2.17/24")));
    assert_eq!(scope.target, IpTarget::Prefix(prefix("192.0.2.0/24")));
    assert_eq!(scope.protocol, None);
    scope.set_protocol(IpProtocol::UDP);
    assert_eq!(scope.protocol, Some(IpProtocol::UDP));
    scope.maybe_set_protocol(None);
    assert_eq!(scope.protocol, None);
    let scope = scope.with_protocol(IpProtocol::new(0));
    assert_eq!(scope.protocol, Some(IpProtocol::new(0)));
    assert_eq!(scope.maybe_with_protocol(None).protocol, None);
}
