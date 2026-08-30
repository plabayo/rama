use std::{error::Error as _, net::Ipv4Addr};

use rama_core::bytes::Bytes;
use rama_net::address::Domain;

use super::*;

const FOO_EXAMPLE_COM: &[u8] = b"\x03foo\x07example\x03com\x00";

fn binding(priority: u16, target: &[u8], params: &[(u16, &[u8])]) -> Vec<u8> {
    let mut wire = priority.to_be_bytes().to_vec();
    wire.extend_from_slice(target);
    for (key, value) in params {
        wire.extend_from_slice(&key.to_be_bytes());
        wire.extend_from_slice(&(value.len() as u16).to_be_bytes());
        wire.extend_from_slice(value);
    }
    wire
}

#[test]
fn record_type_covers_existing_and_new_resolver_types() {
    let assigned = [
        (0, RecordType::Reserved),
        (1, RecordType::A),
        (2, RecordType::NS),
        (3, RecordType::MD),
        (4, RecordType::MF),
        (5, RecordType::CNAME),
        (6, RecordType::SOA),
        (7, RecordType::MB),
        (8, RecordType::MG),
        (9, RecordType::MR),
        (10, RecordType::NULL),
        (11, RecordType::WKS),
        (12, RecordType::PTR),
        (13, RecordType::HINFO),
        (14, RecordType::MINFO),
        (15, RecordType::MX),
        (16, RecordType::TXT),
        (17, RecordType::RP),
        (18, RecordType::AFSDB),
        (19, RecordType::X25),
        (20, RecordType::ISDN),
        (21, RecordType::RT),
        (22, RecordType::NSAP),
        (23, RecordType::NSAP_PTR),
        (24, RecordType::SIG),
        (25, RecordType::KEY),
        (26, RecordType::PX),
        (27, RecordType::GPOS),
        (28, RecordType::AAAA),
        (29, RecordType::LOC),
        (30, RecordType::NXT),
        (31, RecordType::EID),
        (32, RecordType::NIMLOC),
        (33, RecordType::SRV),
        (34, RecordType::ATMA),
        (35, RecordType::NAPTR),
        (36, RecordType::KX),
        (37, RecordType::CERT),
        (38, RecordType::A6),
        (39, RecordType::DNAME),
        (40, RecordType::SINK),
        (41, RecordType::OPT),
        (42, RecordType::APL),
        (43, RecordType::DS),
        (44, RecordType::SSHFP),
        (45, RecordType::IPSECKEY),
        (46, RecordType::RRSIG),
        (47, RecordType::NSEC),
        (48, RecordType::DNSKEY),
        (49, RecordType::DHCID),
        (50, RecordType::NSEC3),
        (51, RecordType::NSEC3PARAM),
        (52, RecordType::TLSA),
        (53, RecordType::SMIMEA),
        (55, RecordType::HIP),
        (56, RecordType::NINFO),
        (57, RecordType::RKEY),
        (58, RecordType::TALINK),
        (59, RecordType::CDS),
        (60, RecordType::CDNSKEY),
        (61, RecordType::OPENPGPKEY),
        (62, RecordType::CSYNC),
        (63, RecordType::ZONEMD),
        (64, RecordType::SVCB),
        (65, RecordType::HTTPS),
        (66, RecordType::DSYNC),
        (67, RecordType::HHIT),
        (68, RecordType::BRID),
        (69, RecordType::UNECE),
        (70, RecordType::ISO),
        (99, RecordType::SPF),
        (100, RecordType::UINFO),
        (101, RecordType::UID),
        (102, RecordType::GID),
        (103, RecordType::UNSPEC),
        (104, RecordType::NID),
        (105, RecordType::L32),
        (106, RecordType::L64),
        (107, RecordType::LP),
        (108, RecordType::EUI48),
        (109, RecordType::EUI64),
        (128, RecordType::NXNAME),
        (249, RecordType::TKEY),
        (250, RecordType::TSIG),
        (251, RecordType::IXFR),
        (252, RecordType::AXFR),
        (253, RecordType::MAILB),
        (254, RecordType::MAILA),
        (255, RecordType::ANY),
        (256, RecordType::URI),
        (257, RecordType::CAA),
        (258, RecordType::AVC),
        (259, RecordType::DOA),
        (260, RecordType::AMTRELAY),
        (261, RecordType::RESINFO),
        (262, RecordType::WALLET),
        (263, RecordType::CLA),
        (264, RecordType::IPN),
        (32_768, RecordType::TA),
        (32_769, RecordType::DLV),
        (u16::MAX, RecordType::ReservedMax),
    ];
    assert_eq!(assigned.len(), 101);
    for (number, record_type) in assigned {
        assert_eq!(RecordType::from(number), record_type);
        assert_eq!(u16::from(record_type), number);
    }

    assert_eq!(RecordType::from(54), RecordType::Unknown(54));
    assert_eq!(u16::from(RecordType::Unknown(65_280)), 65_280);
    assert!(RecordType::Unknown(54) < RecordType::SVCB);
    assert!(RecordType::Unknown(65_280) < RecordType::ReservedMax);
    assert_ne!(RecordType::HTTPS, RecordType::Unknown(65));
    assert_ne!(
        RecordType::HTTPS.cmp(&RecordType::Unknown(65)),
        core::cmp::Ordering::Equal
    );
    assert!(SvcParamKey::Unknown(7) < SvcParamKey::Invalid);
}

#[test]
fn name_canonicalizes_ascii_case_and_formats_escaped_octets() {
    let upper = Name::from_wire(b"\x03WWW\x07Example\x03COM\x00").unwrap();
    let lower = Name::from_wire(b"\x03www\x07example\x03com\x00").unwrap();
    assert_eq!(upper, lower);
    assert_eq!(upper.as_wire(), b"\x03www\x07example\x03com\x00");
    assert_eq!(upper.to_string(), "www.example.com.");
    assert_eq!(format!("{upper:?}"), "Name(\"www.example.com.\")");
    let domain = upper.to_domain().unwrap();
    assert_eq!(domain, Domain::from_static("www.example.com."));
    assert!(domain.is_fqdn());
    assert!(Name::root().to_domain().is_none());

    let escaped = Name::from_wire(b"\x03a.b\x02\\\xff\x00").unwrap();
    assert_eq!(escaped.to_string(), "a\\046b.\\092\\255.");
    assert!(escaped.to_domain().is_none());

    let non_ascii_utf8 = Name::from_wire(b"\x02\xc3\xa9\x00").unwrap();
    assert!(non_ascii_utf8.to_domain().is_none());
}

#[test]
fn name_rejects_compression_truncation_oversize_and_trailing_data() {
    let compressed = Name::from_wire(&[0xc0, 0]).unwrap_err();
    assert_eq!(
        compressed.to_string(),
        "compressed DNS name is not allowed in this field"
    );
    assert_eq!(
        Name::from_wire(&[1, b'a']).unwrap_err().to_string(),
        "DNS name has no terminating root label"
    );
    assert_eq!(
        Name::from_wire(&[3, b'f']).unwrap_err().to_string(),
        "DNS name ends within a label"
    );
    Name::from_wire(&[0, 1]).unwrap_err();

    let mut maximum = Vec::new();
    for label_len in [63, 63, 63, 61] {
        maximum.push(label_len);
        maximum.extend(std::iter::repeat_n(b'a', usize::from(label_len)));
    }
    maximum.push(0);
    assert_eq!(maximum.len(), Name::MAX_WIRE_LEN);
    let maximum_name = Name::from_wire(&maximum).unwrap();
    assert_eq!(maximum_name.as_wire(), maximum);
    let maximum_domain = maximum_name.to_domain().unwrap();
    assert_eq!(maximum_domain.as_str().len(), Domain::MAX_LEN + 1);
    assert!(maximum_domain.is_fqdn());

    let mut one_too_long = Vec::new();
    for label_len in [63, 63, 63, 62] {
        one_too_long.push(label_len);
        one_too_long.extend(std::iter::repeat_n(b'a', usize::from(label_len)));
    }
    one_too_long.push(0);
    assert_eq!(one_too_long.len(), Name::MAX_WIRE_LEN + 1);
    assert_eq!(
        Name::from_wire(&one_too_long).unwrap_err().to_string(),
        "DNS name exceeds 255 wire octets"
    );

    let mut boundary_truncation = Vec::new();
    for label_len in [63, 63, 62] {
        boundary_truncation.push(label_len);
        boundary_truncation.extend(std::iter::repeat_n(b'a', usize::from(label_len)));
    }
    boundary_truncation.push(63);
    boundary_truncation.extend_from_slice(&[b'a'; 62]);
    assert_eq!(boundary_truncation.len(), 254);
    assert_eq!(
        Name::from_wire(&boundary_truncation)
            .unwrap_err()
            .to_string(),
        "DNS name ends within a label"
    );

    let mut oversized_truncation = Vec::new();
    for label_len in [63, 63, 62, 1] {
        oversized_truncation.push(label_len);
        oversized_truncation.extend(std::iter::repeat_n(b'a', usize::from(label_len)));
    }
    oversized_truncation.push(63);
    oversized_truncation.extend_from_slice(&[b'a'; 62]);
    assert_eq!(oversized_truncation.len(), 256);
    assert_eq!(
        Name::from_wire(&oversized_truncation)
            .unwrap_err()
            .to_string(),
        "DNS name exceeds 255 wire octets"
    );
}

#[test]
fn parses_rfc_9460_alias_and_root_target_vectors() {
    let alias = ServiceBinding::parse_rdata(&binding(0, FOO_EXAMPLE_COM, &[])).unwrap();
    assert!(alias.is_alias_mode());
    assert_eq!(alias.target().to_string(), "foo.example.com.");

    let root = ServiceBinding::parse_rdata(&binding(1, &[0], &[])).unwrap();
    assert!(root.is_service_mode());
    assert!(!root.is_alias_mode());
    assert!(root.target().is_root());
}

#[test]
fn parses_rfc_9460_port_and_opaque_unknown_key_vectors() {
    let port = ServiceBinding::parse_rdata(&binding(
        16,
        FOO_EXAMPLE_COM,
        &[(u16::from(SvcParamKey::Port), &[0, 53])],
    ))
    .unwrap();
    assert_eq!(port.priority(), 16);
    assert_eq!(port.param(SvcParamKey::Port), Some(&SvcParam::Port(53)));
    assert_eq!(port.port(), Some(53));
    assert!(!port.has_no_default_alpn());

    let unknown =
        ServiceBinding::parse_rdata(&binding(1, FOO_EXAMPLE_COM, &[(667, b"hello\xd2qoo")]))
            .unwrap();
    assert_eq!(
        unknown.param(SvcParamKey::Unknown(667)),
        Some(&SvcParam::Unknown {
            key: SvcParamKey::Unknown(667),
            value: Bytes::from_static(b"hello\xd2qoo"),
        })
    );
}

#[test]
fn parses_rfc_9460_opaque_alpn_vector() {
    let parsed = ServiceBinding::parse_rdata(&binding(
        16,
        b"\x03foo\x07example\x03org\x00",
        &[(u16::from(SvcParamKey::Alpn), b"\x08f\\oo,bar\x02h2")],
    ))
    .unwrap();
    let protocols = parsed.alpn_protocols().unwrap();
    assert_eq!(protocols.as_wire(), b"\x08f\\oo,bar\x02h2");

    let mut protocols = protocols.iter();
    assert_eq!(protocols.len(), 2);
    assert_eq!(protocols.next(), Some(b"f\\oo,bar".as_slice()));
    assert_eq!(protocols.len(), 1);
    assert_eq!(protocols.next(), Some(b"h2".as_slice()));
    assert_eq!(protocols.next(), None);
    assert_eq!(protocols.next(), None);
}

#[test]
fn parses_rfc_9460_ipv6_hint_vector() {
    let value = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20, 0x01, 0x0d, 0xb8, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x53, 0, 1,
    ];
    let parsed = ServiceBinding::parse_rdata(&binding(
        1,
        FOO_EXAMPLE_COM,
        &[(u16::from(SvcParamKey::Ipv6Hint), &value)],
    ))
    .unwrap();
    assert_eq!(
        parsed.param(SvcParamKey::Ipv6Hint),
        Some(&SvcParam::Ipv6Hint(Box::new([
            "2001:db8::1".parse().unwrap(),
            "2001:db8::53:1".parse().unwrap(),
        ])))
    );
    assert_eq!(parsed.ipv6_hints().unwrap().len(), 2);
}

#[test]
fn parses_rfc_9460_mandatory_alpn_and_ipv4_hint_vector() {
    let mandatory = [0, 1, 0, 4];
    let alpn = b"\x02h2\x05h3-19";
    let ipv4 = [192, 0, 2, 1];
    let parsed = ServiceBinding::parse_rdata(&binding(
        16,
        b"\x03foo\x07example\x03org\x00",
        &[
            (u16::from(SvcParamKey::Mandatory), &mandatory),
            (u16::from(SvcParamKey::Alpn), alpn),
            (u16::from(SvcParamKey::Ipv4Hint), &ipv4),
        ],
    ))
    .unwrap();

    assert_eq!(
        parsed.mandatory_keys(),
        Some(&[SvcParamKey::Alpn, SvcParamKey::Ipv4Hint][..])
    );
    let protocols = parsed.alpn_protocols().unwrap();
    assert_eq!(protocols.len(), 2);
    assert_eq!(
        protocols.iter().collect::<Vec<_>>(),
        [b"h2".as_slice(), b"h3-19".as_slice()]
    );
    assert_eq!(
        parsed.param(SvcParamKey::Ipv4Hint),
        Some(&SvcParam::Ipv4Hint(Box::new([Ipv4Addr::new(192, 0, 2, 1)])))
    );
    assert_eq!(
        parsed.ipv4_hints(),
        Some(&[Ipv4Addr::new(192, 0, 2, 1)][..])
    );
}

#[test]
fn owned_parse_shares_opaque_and_alpn_bytes() {
    let wire = Bytes::from(binding(
        1,
        &[0],
        &[(u16::from(SvcParamKey::Alpn), b"\x02h2"), (667, b"hello")],
    ));
    let allocation_start = wire.as_ptr() as usize;
    let allocation_end = allocation_start + wire.len();
    let parsed = ServiceBinding::parse_rdata_bytes(&wire).unwrap();

    let SvcParam::Alpn(protocols) = parsed.param(SvcParamKey::Alpn).unwrap() else {
        panic!("expected alpn parameter");
    };
    let SvcParam::Unknown { value, .. } = parsed.param(SvcParamKey::Unknown(667)).unwrap() else {
        panic!("expected unknown parameter");
    };
    for bytes in [
        parsed.target().as_wire(),
        protocols.as_wire(),
        protocols.iter().next().unwrap(),
        value.as_ref(),
    ] {
        let start = bytes.as_ptr() as usize;
        assert!((allocation_start..allocation_end).contains(&start));
    }
}

#[test]
fn parses_ech_config_list_framing_without_tls_interpretation() {
    let ech = [0, 4, 0xfe, 0x0d, 0, 0];
    let parsed =
        ServiceBinding::parse_rdata(&binding(1, &[0], &[(u16::from(SvcParamKey::Ech), &ech)]))
            .unwrap();
    assert_eq!(
        parsed.param(SvcParamKey::Ech),
        Some(&SvcParam::Ech(Bytes::copy_from_slice(&ech)))
    );
    assert_eq!(
        parsed.ech_config_list(),
        Some(&Bytes::copy_from_slice(&ech))
    );

    let ech_with_contents = [0, 5, 0xfe, 0x0d, 0, 1, 42];
    ServiceBinding::parse_rdata(&binding(
        1,
        &[0],
        &[(u16::from(SvcParamKey::Ech), &ech_with_contents)],
    ))
    .unwrap();

    for invalid in [
        &[0, 0][..],
        &ech[..1],
        &[0, 3, 0xfe, 0x0d, 0][..],
        &[0, 4, 0xfe, 0x0d, 0, 1][..],
    ] {
        ServiceBinding::parse_rdata(&binding(1, &[0], &[(u16::from(SvcParamKey::Ech), invalid)]))
            .unwrap_err();
    }
}

#[test]
fn rejects_truncated_duplicate_descending_and_invalid_keys() {
    assert_eq!(SvcParamKey::from(u16::MAX), SvcParamKey::Invalid);
    assert_eq!(
        ServiceBinding::parse_rdata(&vec![0; usize::from(u16::MAX) + 1])
            .unwrap_err()
            .to_string(),
        "service binding RDATA exceeds the DNS record size limit"
    );
    ServiceBinding::parse_rdata(&[]).unwrap_err();
    ServiceBinding::parse_rdata(&[0, 1]).unwrap_err();
    ServiceBinding::parse_rdata(&binding(1, &[0], &[(1, &[2, b'h'])])).unwrap_err();
    ServiceBinding::parse_rdata(&binding(1, &[0], &[(3, &[0, 1]), (3, &[0, 2])])).unwrap_err();
    ServiceBinding::parse_rdata(&binding(1, &[0], &[(3, &[0, 1]), (1, &[2, b'h', b'2'])]))
        .unwrap_err();
    ServiceBinding::parse_rdata(&binding(1, &[0], &[(u16::MAX, &[])])).unwrap_err();
    ServiceBinding::parse_rdata(&binding(0, &[0], &[(0, &[u8::MAX, u8::MAX])])).unwrap_err();

    let opaque = vec![0; usize::from(u16::MAX) - 7];
    let maximum = binding(1, &[0], &[(7, &opaque)]);
    assert_eq!(maximum.len(), usize::from(u16::MAX));
    ServiceBinding::parse_rdata(&maximum).unwrap();

    let mut truncated_header = binding(1, &[0], &[]);
    truncated_header.extend_from_slice(&[0]);
    ServiceBinding::parse_rdata(&truncated_header).unwrap_err();

    let mut truncated_value = binding(1, &[0], &[]);
    truncated_value.extend_from_slice(&[0, 7, 0, 2, 1]);
    ServiceBinding::parse_rdata(&truncated_value).unwrap_err();
}

#[test]
fn validates_each_known_parameter_wire_format() {
    let invalid_cases: &[(u16, &[u8])] = &[
        (0, &[]),
        (0, &[0]),
        (0, &[0, 2, 0, 1]),
        (1, &[]),
        (1, &[0]),
        (1, &[2, b'h']),
        (2, &[1]),
        (3, &[]),
        (3, &[0]),
        (3, &[0, 1, 2]),
        (4, &[]),
        (4, &[127]),
        (6, &[]),
        (6, &[0; 15]),
    ];
    for &(key, value) in invalid_cases {
        ServiceBinding::parse_rdata(&binding(1, &[0], &[(key, value)])).unwrap_err();
    }
}

#[test]
fn skips_service_mode_cross_parameter_checks_in_alias_mode() {
    let no_default = (u16::from(SvcParamKey::NoDefaultAlpn), &[][..]);
    ServiceBinding::parse_rdata(&binding(1, &[0], &[no_default])).unwrap_err();
    let alias = ServiceBinding::parse_rdata(&binding(0, &[0], &[no_default])).unwrap();
    assert!(alias.has_no_default_alpn());
    ServiceBinding::parse_rdata(&binding(0, &[0], &[(1, &[2, b'h'])])).unwrap_err();

    let valid = ServiceBinding::parse_rdata(&binding(
        1,
        &[0],
        &[
            (u16::from(SvcParamKey::Alpn), b"\x02h2"),
            (u16::from(SvcParamKey::NoDefaultAlpn), &[]),
        ],
    ))
    .unwrap();
    assert_eq!(
        valid.param(SvcParamKey::NoDefaultAlpn),
        Some(&SvcParam::NoDefaultAlpn)
    );
    assert!(valid.has_no_default_alpn());

    for priority in [0, 1] {
        assert_eq!(
            ServiceBinding::parse_rdata(&binding(priority, &[0], &[(0, &[0, 0])]))
                .unwrap_err()
                .to_string(),
            "mandatory must not list itself"
        );
    }

    for mandatory in [&[0, 7][..], &[0, 7, 0, 7][..]] {
        ServiceBinding::parse_rdata(&binding(
            1,
            &[0],
            &[(u16::from(SvcParamKey::Mandatory), mandatory)],
        ))
        .unwrap_err();
    }
}

#[test]
fn parse_errors_are_actionable_and_preserve_their_source() {
    let error = ServiceBinding::parse_rdata(&[0, 1, 0xc0, 0]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid service binding target name: compressed DNS name is not allowed in this field"
    );
    assert!(error.source().is_some());
}
