use std::{
    borrow::Cow,
    error::Error as _,
    hash::{Hash as _, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
};

use rama_core::bytes::Bytes;
use rama_net::{address::Domain, tls::ApplicationProtocol};

use super::{message::bounded_capacity, *};

const FOO_EXAMPLE_COM: &[u8] = b"\x03foo\x07example\x03com\x00";

#[derive(Default)]
struct RecordingHasher(Vec<u8>);

impl Hasher for RecordingHasher {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

fn name_hash_input(name: &Name) -> Vec<u8> {
    let mut hasher = RecordingHasher::default();
    name.hash(&mut hasher);
    hasher.0
}

fn txt_strings(txt: &Txt) -> Vec<&[u8]> {
    let limit = txt.len().saturating_add(1);
    txt.iter().take(limit).collect()
}

fn owned_txt_strings(iter: impl ExactSizeIterator<Item = Bytes>) -> Vec<Bytes> {
    let limit = iter.len().saturating_add(1);
    iter.take(limit).collect()
}

const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_CH: u16 = 3;

fn dns_message(id: u16, flags: u16, counts: [u16; 4], sections: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(MessageHeader::WIRE_LEN + sections.len());
    wire.extend_from_slice(&id.to_be_bytes());
    wire.extend_from_slice(&flags.to_be_bytes());
    for count in counts {
        wire.extend_from_slice(&count.to_be_bytes());
    }
    wire.extend_from_slice(sections);
    wire
}

fn question_wire(name: &[u8], record_type: RecordType, class: u16) -> Vec<u8> {
    let mut wire = name.to_vec();
    wire.extend_from_slice(&u16::from(record_type).to_be_bytes());
    wire.extend_from_slice(&class.to_be_bytes());
    wire
}

fn record_wire(
    name: &[u8],
    record_type: RecordType,
    class: u16,
    ttl: u32,
    rdata: &[u8],
) -> Vec<u8> {
    let mut wire = question_wire(name, record_type, class);
    wire.extend_from_slice(&ttl.to_be_bytes());
    wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    wire.extend_from_slice(rdata);
    wire
}

/// One answer section holding a single record with a root owner name.
fn one_answer(record_type: RecordType, class: u16, rdata: &[u8]) -> Vec<u8> {
    dns_message(
        0,
        0,
        [0, 1, 0, 0],
        &record_wire(b"\0", record_type, class, 0, rdata),
    )
}

fn points_into(slice: &[u8], parent: &[u8]) -> bool {
    let start = parent.as_ptr() as usize;
    (start..start + parent.len()).contains(&(slice.as_ptr() as usize))
}

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
fn name_parses_compressed_message_names_and_reports_encoded_length() {
    let mut message = b"\x07example\x03com\x00".to_vec();
    let alias_offset = message.len();
    message.extend_from_slice(b"\x03www\xc0\x00");

    let (name, encoded_len) = Name::from_message(&message, alias_offset).unwrap();
    assert_eq!(encoded_len, 6);
    assert_eq!(name.as_wire(), b"\x03www\x07example\x03com\x00");
    assert_eq!(name.to_string(), "www.example.com.");

    let message = b"prefix\x03foo\0suffix";
    let (name, encoded_len) = Name::from_message(message, 6).unwrap();
    assert_eq!(encoded_len, 5);
    assert_eq!(name.as_wire(), b"\x03foo\0");
}

#[test]
fn name_rejects_invalid_compression_without_looping() {
    for (message, offset, expected) in [
        (&b"\xc0"[..], 0, "ends within a compression pointer"),
        (
            &b"\xc0\x00"[..],
            0,
            "does not refer to a prior name occurrence",
        ),
        (&b"\x40"[..], 0, "unsupported label kind"),
    ] {
        let error = Name::from_message(message, offset).unwrap_err();
        assert!(error.to_string().contains(expected), "got: {error}");
    }

    let mut pointer_chain = vec![0];
    let mut previous = 0_u16;
    for _ in 0..1_024 {
        pointer_chain.extend_from_slice(&(0xc000 | previous).to_be_bytes());
        previous = u16::try_from(pointer_chain.len() - 2).unwrap();
    }
    let (root, consumed) = Name::from_message(&pointer_chain, usize::from(previous)).unwrap();
    assert!(root.is_root());
    assert_eq!(consumed, 2);

    // A pointer can be backwards from its own location while still cycling
    // back to labels already consumed in the same encoded name.
    let cyclic = b"prefix\x01a\xc0\x06";
    assert_eq!(
        Name::from_message(cyclic, 6).unwrap_err().to_string(),
        "DNS compression pointer does not refer to a prior name occurrence"
    );
}

#[test]
fn name_converts_from_domain_without_presentation_reparsing() {
    let domain = Domain::try_from("WWW.Example.com.").unwrap();
    let name = Name::from(&domain);
    assert_eq!(name.as_wire(), b"\x03WWW\x07Example\x03com\x00");

    let wire = Bytes::from_static(b"\x03FOO\x07Example\x03COM\x00");
    let shared = Name::from_wire_bytes(&wire).unwrap();
    assert_eq!(shared.as_wire().as_ptr(), wire.as_ptr());
    assert_eq!(shared.as_wire(), wire.as_ref());
}

#[test]
fn address_rdata_parses_all_structural_values() {
    assert_eq!(parse_a_rdata(&[0, 0, 0, 0]).unwrap(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(
        parse_a_rdata(&[192, 0, 2, 1]).unwrap(),
        Ipv4Addr::new(192, 0, 2, 1)
    );
    assert_eq!(parse_aaaa_rdata(&[0; 16]).unwrap(), Ipv6Addr::UNSPECIFIED);
    assert_eq!(
        parse_aaaa_rdata(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,]).unwrap(),
        "2001:db8::1".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn address_rdata_rejects_every_wrong_length_with_context() {
    for len in [0, 1, 3, 5, 15, 17, 255] {
        let error = parse_a_rdata(&vec![0; len]).unwrap_err();
        assert_eq!(error.record_type(), RecordType::A);
        assert_eq!(error.expected_len(), 4);
        assert_eq!(error.actual_len(), len);
        assert_eq!(
            error.to_string(),
            format!("A (0x0001) RDATA must contain exactly 4 octets, got {len}")
        );

        let error = parse_aaaa_rdata(&vec![0; len]).unwrap_err();
        assert_eq!(error.record_type(), RecordType::AAAA);
        assert_eq!(error.expected_len(), 16);
        assert_eq!(error.actual_len(), len);
        assert_eq!(
            error.to_string(),
            format!("AAAA (0x001c) RDATA must contain exactly 16 octets, got {len}")
        );
    }
}

#[test]
fn txt_preserves_binary_strings_and_exact_boundaries() {
    let txt = Txt::parse_rdata(b"\x03foo\x00\x04\x00\xff\x80A").unwrap();
    assert_eq!(txt.len(), 3);
    assert_eq!(txt.as_wire(), b"\x03foo\x00\x04\x00\xff\x80A");
    assert_eq!(
        txt_strings(&txt),
        vec![&b"foo"[..], &b""[..], &b"\x00\xff\x80A"[..]]
    );
}

#[test]
fn txt_display_preserves_boundaries_escaping_and_binary_data() {
    let txt = Txt::try_from_strings([
        b"hello world".as_slice(),
        b"quote\" slash\\ line\n".as_slice(),
        &[0xff, 0x00],
        b"",
    ])
    .unwrap();
    assert_eq!(
        txt.to_string(),
        r#""hello world" "quote\" slash\\ line\n" 0xFF00 """#
    );
}

#[test]
fn txt_owned_and_borrowed_parsing_are_equal() {
    let wire = Bytes::from_static(b"\x03foo\x03bar");
    let borrowed = Txt::parse_rdata(&wire).unwrap();
    let owned = Txt::parse_rdata_bytes(&wire).unwrap();
    assert_eq!(borrowed, owned);
    assert_eq!(owned.as_wire().as_ptr(), wire.as_ptr());
}

#[test]
fn txt_requires_one_or_more_exactly_tiling_strings() {
    assert_eq!(
        Txt::parse_rdata(&[]).unwrap_err().to_string(),
        "TXT RDATA must contain at least one character-string"
    );
    assert_eq!(
        txt_strings(&Txt::parse_rdata(&[0]).unwrap()),
        vec![&b""[..]]
    );

    for wire in [&[1][..], &[2, b'a'][..], &[0, 3, b'f', b'o'][..]] {
        Txt::parse_rdata(wire).unwrap_err();
    }
}

#[test]
fn txt_accepts_maximum_string_and_rdata_boundaries() {
    let mut maximum_string = vec![255];
    maximum_string.extend(0_u8..=254);
    let txt = Txt::parse_rdata(&maximum_string).unwrap();
    assert_eq!(txt.len(), 1);
    assert_eq!(txt.iter().next().unwrap().len(), 255);

    let maximum_rdata = vec![0; usize::from(u16::MAX)];
    let txt = Txt::parse_rdata(&maximum_rdata).unwrap();
    assert_eq!(txt.len(), usize::from(u16::MAX));
    assert_eq!(txt_strings(&txt).len(), usize::from(u16::MAX));
    assert!(txt_strings(&txt).into_iter().all(<[u8]>::is_empty));

    let oversized = vec![0; usize::from(u16::MAX) + 1];
    assert_eq!(
        Txt::parse_rdata(&oversized).unwrap_err().to_string(),
        "TXT RDATA length 65536 exceeds 65535 octets"
    );
}

#[test]
fn txt_constructs_canonical_wire_from_decoded_strings() {
    let txt = Txt::try_from_strings([&b"first"[..], &b""[..], &b"\x00\xff"[..]]).unwrap();
    assert_eq!(txt.as_wire(), b"\x05first\x00\x02\x00\xff");
    assert_eq!(
        txt_strings(&txt),
        vec![&b"first"[..], &b""[..], &b"\x00\xff"[..]]
    );
    Txt::try_from_strings(Vec::<Bytes>::new()).unwrap_err();
    Txt::try_from_strings([vec![0; 256]]).unwrap_err();

    let full_string = vec![0; usize::from(u8::MAX)];
    let final_string = vec![0; usize::from(u8::MAX) - 1];
    let maximum = Txt::try_from_strings(
        std::iter::repeat_n(full_string.as_slice(), 255).chain([final_string.as_slice()]),
    )
    .expect("exact maximum RDATA length");
    assert_eq!(maximum.as_wire().len(), usize::from(u16::MAX));
    assert_eq!(maximum.len(), 256);

    Txt::try_from_strings(
        std::iter::repeat_n(full_string.as_slice(), 255)
            .chain([final_string.as_slice(), b"".as_slice()]),
    )
    .unwrap_err();
}

#[test]
fn txt_iterators_are_cloneable_exact_and_fused() {
    let txt = Txt::parse_rdata(b"\x03foo\x03bar").unwrap();
    let mut borrowed = txt.iter();
    assert_eq!(borrowed.len(), 2);
    let borrowed_clone = borrowed.clone();
    assert_eq!(borrowed.next(), Some(&b"foo"[..]));
    assert_eq!(borrowed.len(), 1);
    let borrowed_clone_limit = borrowed_clone.len().saturating_add(1);
    assert_eq!(
        borrowed_clone
            .take(borrowed_clone_limit)
            .collect::<Vec<_>>(),
        vec![&b"foo"[..], &b"bar"[..]]
    );
    assert_eq!(
        borrowed.by_ref().take(2).collect::<Vec<_>>(),
        vec![&b"bar"[..]]
    );
    assert_eq!(borrowed.next(), None);
    assert_eq!(borrowed.next(), None);
    drop(borrowed);

    let wire_start = txt.as_wire().as_ptr() as usize;
    let mut owned = txt.into_strings();
    assert_eq!(owned.len(), 2);
    let owned_clone = owned.clone();
    let first = owned.next().expect("first string");
    assert_eq!(first, Bytes::from_static(b"foo"));
    assert_eq!(first.as_ptr() as usize, wire_start + 1);
    assert_eq!(owned.len(), 1);
    assert_eq!(
        owned_txt_strings(owned_clone),
        vec![Bytes::from_static(b"foo"), Bytes::from_static(b"bar")]
    );
    assert_eq!(
        owned.by_ref().take(2).collect::<Vec<_>>(),
        vec![Bytes::from_static(b"bar")]
    );
    assert_eq!(owned.next(), None);
    assert_eq!(owned.next(), None);
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
fn name_preserves_ascii_case_with_case_insensitive_identity() {
    let upper = Name::from_wire(b"\x03WWW\x07Example\x03COM\x00").unwrap();
    let lower = Name::from_wire(b"\x03www\x07example\x03com\x00").unwrap();
    let different = Name::from_wire(b"\x03www\x07example\x03net\x00").unwrap();
    assert_eq!(upper, lower);
    assert_ne!(upper, different);
    assert_eq!(upper.cmp(&lower), core::cmp::Ordering::Equal);
    assert_eq!(upper.partial_cmp(&lower), Some(core::cmp::Ordering::Equal));
    assert_eq!(name_hash_input(&upper), b"\x03www\x07example\x03com\x00");
    assert_eq!(name_hash_input(&upper), name_hash_input(&lower));
    assert_ne!(name_hash_input(&upper), name_hash_input(&different));

    assert_eq!(upper.as_wire(), b"\x03WWW\x07Example\x03COM\x00");
    assert_eq!(upper.to_string(), "WWW.Example.COM.");
    assert_eq!(format!("{upper:?}"), "Name(\"WWW.Example.COM.\")");
    let domain = upper.to_domain().unwrap();
    assert_eq!(domain, Domain::from_static("www.example.com."));
    assert_eq!(domain.as_str(), "WWW.Example.COM.");
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
        Name::from_wire(&[0x40]).unwrap_err().to_string(),
        "DNS name uses an unsupported label kind"
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
    let (maximum_message_name, consumed) = Name::from_message(&maximum, 0).unwrap();
    assert_eq!(maximum_message_name, maximum_name);
    assert_eq!(consumed, Name::MAX_WIRE_LEN);
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
    assert_eq!(
        Name::from_message(&one_too_long, 0)
            .unwrap_err()
            .to_string(),
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
        protocols
            .iter()
            .take(protocols.len().saturating_add(1))
            .collect::<Vec<_>>(),
        [b"h2".as_slice(), b"h3-19".as_slice()]
    );
    let mut typed = protocols.application_protocols();
    assert_eq!(typed.len(), 2);
    assert_eq!(typed.next(), Some(ApplicationProtocol::HTTP_2));
    assert_eq!(typed.next(), Some(ApplicationProtocol::from(b"h3-19")));
    assert_eq!(typed.next(), None);
    assert_eq!(typed.next(), None);
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
fn service_binding_display_covers_every_parameter_kind() {
    let mandatory = [0, 1, 0, 3];
    let ipv4 = [192, 0, 2, 1, 198, 51, 100, 2];
    let ech = [0, 4, 0xfe, 0x0d, 0, 0];
    let mut ipv6 = [0; 16];
    ipv6[15] = 1;
    let parsed = ServiceBinding::parse_rdata(&binding(
        1,
        &[0],
        &[
            (u16::from(SvcParamKey::Mandatory), &mandatory),
            (u16::from(SvcParamKey::Alpn), b"\x02h2\x02h3"),
            (u16::from(SvcParamKey::NoDefaultAlpn), &[]),
            (u16::from(SvcParamKey::Port), &[0x20, 0xfb]),
            (u16::from(SvcParamKey::Ipv4Hint), &ipv4),
            (u16::from(SvcParamKey::Ech), &ech),
            (u16::from(SvcParamKey::Ipv6Hint), &ipv6),
            (667, &[0xff, 0]),
        ],
    ))
    .unwrap();

    assert_eq!(
        parsed.to_string(),
        concat!(
            "1 . mandatory=alpn,port alpn=\"h2\",\"h3\" no-default-alpn ",
            "port=8443 ipv4hint=192.0.2.1,198.51.100.2 ",
            "ech=0x0004FE0D0000 ipv6hint=::1 key667=0xFF00"
        )
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

#[test]
fn message_parses_header_questions_and_compressed_typed_answers() {
    let mut sections = question_wire(FOO_EXAMPLE_COM, RecordType::A, DNS_CLASS_IN);
    // The CNAME target starts right after this record's compressed owner name
    // and its fixed fields, and itself points at the question's `example.com`.
    let cname_target_offset = MessageHeader::WIRE_LEN + sections.len() + 2 + 10;
    sections.extend(record_wire(
        b"\xc0\x0c",
        RecordType::CNAME,
        DNS_CLASS_IN,
        300,
        b"\x03cdn\xc0\x10",
    ));
    let alias_owner = (0xc000 | cname_target_offset as u16).to_be_bytes();
    sections.extend(record_wire(
        &alias_owner,
        RecordType::A,
        DNS_CLASS_IN,
        60,
        &[192, 0, 2, 1],
    ));
    sections.extend(record_wire(
        &alias_owner,
        RecordType::AAAA,
        DNS_CLASS_IN,
        60,
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    ));
    let wire = dns_message(0x1234, 0x8580, [1, 3, 0, 0], &sections);

    let message = Message::parse(&wire).unwrap();
    assert!(message.is_complete());
    let header = message.header();
    assert_eq!(header.id(), 0x1234);
    assert!(header.is_response());
    assert_eq!(header.opcode(), 0);
    assert!(header.is_authoritative());
    assert!(!header.is_truncated());
    assert!(header.is_recursion_desired());
    assert!(header.is_recursion_available());
    assert!(!header.is_authentic_data());
    assert!(!header.is_checking_disabled());
    assert_eq!(header.response_code(), ResponseCode::NoError);
    assert_eq!(header.question_count(), 1);
    assert_eq!(header.answer_count(), 3);

    let queried = Name::from_wire(FOO_EXAMPLE_COM).unwrap();
    let alias = Name::from_wire(b"\x03cdn\x07example\x03com\0").unwrap();
    let [question] = message.questions() else {
        panic!("one question: {:?}", message.questions());
    };
    assert_eq!(question.name(), &queried);
    assert_eq!(question.record_type(), RecordType::A);
    assert_eq!(question.class(), RecordClass::IN);

    let [cname, a, aaaa] = message.answers() else {
        panic!("three answers: {:?}", message.answers());
    };
    assert_eq!(cname.name(), &queried);
    assert_eq!(cname.record_type(), RecordType::CNAME);
    assert_eq!(cname.class(), RecordClass::IN);
    assert_eq!(cname.ttl(), 300);
    assert_eq!(cname.data(), &RecordData::Cname(alias.clone()));

    assert_eq!(a.name(), &alias);
    assert_eq!(a.record_type(), RecordType::A);
    assert_eq!(a.ttl(), 60);
    assert_eq!(a.data(), &RecordData::A(Ipv4Addr::new(192, 0, 2, 1)));

    assert_eq!(aaaa.name(), &alias);
    assert_eq!(aaaa.record_type(), RecordType::AAAA);
    assert_eq!(
        aaaa.data(),
        &RecordData::Aaaa("2001:db8::1".parse::<Ipv6Addr>().unwrap())
    );
}

#[test]
fn message_header_reads_each_flag_bit_opcode_rcode_and_count_separately() {
    let bits: [(u16, fn(&MessageHeader) -> bool); 7] = [
        (0x8000, MessageHeader::is_response),
        (0x0400, MessageHeader::is_authoritative),
        (0x0200, MessageHeader::is_truncated),
        (0x0100, MessageHeader::is_recursion_desired),
        (0x0080, MessageHeader::is_recursion_available),
        (0x0020, MessageHeader::is_authentic_data),
        (0x0010, MessageHeader::is_checking_disabled),
    ];
    for (index, &(mask, _)) in bits.iter().enumerate() {
        let header = MessageHeader::parse(&dns_message(0, mask, [0; 4], &[])).unwrap();
        assert_eq!(header.flags(), mask);
        for (other, &(other_mask, accessor)) in bits.iter().enumerate() {
            assert_eq!(
                accessor(&header),
                index == other,
                "{mask:#06x}/{other_mask:#06x}"
            );
        }
        // No flag bit leaks into the OPCODE or RCODE fields.
        assert_eq!(header.opcode(), 0);
        assert_eq!(header.response_code(), ResponseCode::NoError);
    }

    for opcode in 0..16_u8 {
        let flags = u16::from(opcode) << 11;
        let header = MessageHeader::parse(&dns_message(0, flags, [0; 4], &[])).unwrap();
        assert_eq!(header.opcode(), opcode);
        assert_eq!(header.response_code(), ResponseCode::NoError);
        assert!(!header.is_response());
    }

    for rcode in 0..16_u8 {
        let header = MessageHeader::parse(&dns_message(0, u16::from(rcode), [0; 4], &[])).unwrap();
        assert_eq!(header.response_code(), ResponseCode::from(rcode));
        assert_eq!(header.opcode(), 0);
    }

    let header = MessageHeader::parse(&dns_message(0xbeef, 0xffff, [9, 2, 3, 4], &[])).unwrap();
    assert_eq!(header.id(), 0xbeef);
    assert_eq!(header.opcode(), 0xf);
    assert_eq!(header.response_code(), ResponseCode::Unknown(15));
    assert!(bits.iter().all(|&(_, accessor)| accessor(&header)));
    assert_eq!(header.question_count(), 9);
    assert_eq!(header.answer_count(), 2);
    assert_eq!(header.authority_count(), 3);
    assert_eq!(header.additional_count(), 4);

    // A header is parseable on its own, without any section octets.
    let empty = Message::parse(&dns_message(7, 0, [0; 4], &[])).unwrap();
    assert_eq!(empty.header().id(), 7);
    assert!(empty.questions().is_empty());
    assert!(empty.answers().is_empty());
}

#[test]
fn message_header_requires_its_twelve_octets() {
    for len in 0..MessageHeader::WIRE_LEN {
        let truncated = vec![0; len];
        let expected = format!("DNS message header requires 12 octets, got {len}");
        assert_eq!(
            MessageHeader::parse(&truncated).unwrap_err().to_string(),
            expected
        );
        assert_eq!(
            Message::parse(&truncated).unwrap_err().to_string(),
            expected
        );
        // Below a header there is nothing to keep, so even the lenient
        // constructor fails and no partial message comes back.
        let error = Message::parse_strict(&truncated).unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.partial(), None);
        assert_eq!(error.into_partial(), None);
    }
    MessageHeader::parse(&[0; MessageHeader::WIRE_LEN]).unwrap();
}

#[test]
fn message_decodes_known_rdata_and_retains_everything_else_opaquely() {
    let txt = Txt::try_from_strings([&b"v=spf1 -all"[..]]).unwrap();
    let https = binding(1, b"\0", &[(u16::from(SvcParamKey::Alpn), b"\x02h2")]);
    let svcb = binding(0, b"\x03cdn\x07example\x03com\0", &[]);
    let mail = b"\x00\x0a\x04mail\x07example\x03com\0";

    let mut sections = Vec::new();
    sections.extend(record_wire(
        b"\0",
        RecordType::TXT,
        DNS_CLASS_IN,
        1,
        txt.as_wire(),
    ));
    sections.extend(record_wire(
        b"\0",
        RecordType::HTTPS,
        DNS_CLASS_IN,
        2,
        &https,
    ));
    sections.extend(record_wire(b"\0", RecordType::SVCB, DNS_CLASS_IN, 3, &svcb));
    sections.extend(record_wire(
        b"\0",
        RecordType::NS,
        DNS_CLASS_IN,
        4,
        b"\x02ns\x07example\x03com\0",
    ));
    sections.extend(record_wire(
        b"\0",
        RecordType::PTR,
        DNS_CLASS_IN,
        5,
        FOO_EXAMPLE_COM,
    ));
    sections.extend(record_wire(b"\0", RecordType::MX, DNS_CLASS_IN, 6, mail));
    sections.extend(record_wire(
        b"\0",
        RecordType::A,
        DNS_CLASS_CH,
        7,
        &[192, 0, 2, 9],
    ));
    sections.extend(record_wire(
        b"\0",
        RecordType::Unknown(65280),
        DNS_CLASS_IN,
        u32::MAX,
        b"private",
    ));
    let message = Message::parse(&dns_message(1, 0x8180, [0, 8, 0, 0], &sections)).unwrap();

    let answers = message.answers();
    assert_eq!(answers.len(), 8);
    assert!(answers.iter().all(|answer| answer.name().is_root()));
    assert_eq!(answers[0].data(), &RecordData::Txt(txt));
    assert_eq!(
        answers[1].data(),
        &RecordData::ServiceBinding(ServiceBinding::parse_rdata(&https).unwrap())
    );
    assert_eq!(
        answers[2].data(),
        &RecordData::ServiceBinding(ServiceBinding::parse_rdata(&svcb).unwrap())
    );
    assert_eq!(
        answers[3].data(),
        &RecordData::Ns(Name::from_wire(b"\x02ns\x07example\x03com\0").unwrap())
    );
    assert_eq!(
        answers[4].data(),
        &RecordData::Ptr(Name::from_wire(FOO_EXAMPLE_COM).unwrap())
    );
    // MX is not modelled by this wire vocabulary, so its RDATA stays opaque.
    assert_eq!(answers[5].record_type(), RecordType::MX);
    assert_eq!(
        answers[5].data(),
        &RecordData::Opaque(Bytes::from_static(mail))
    );
    // A well-formed A record outside the Internet class is not an address.
    assert_eq!(answers[6].record_type(), RecordType::A);
    assert_eq!(answers[6].class(), RecordClass::CH);
    assert_eq!(
        answers[6].data(),
        &RecordData::Opaque(Bytes::from_static(&[192, 0, 2, 9]))
    );
    assert_eq!(answers[7].record_type(), RecordType::Unknown(65280));
    assert_eq!(answers[7].ttl(), u32::MAX);
    assert_eq!(
        answers[7].data(),
        &RecordData::Opaque(Bytes::from_static(b"private"))
    );
}

#[test]
fn message_parses_rdata_names_that_use_compression() {
    let mut sections = question_wire(FOO_EXAMPLE_COM, RecordType::PTR, DNS_CLASS_IN);
    sections.extend(record_wire(
        b"\xc0\x0c",
        RecordType::PTR,
        DNS_CLASS_IN,
        0,
        b"\xc0\x10",
    ));
    let message = Message::parse(&dns_message(0, 0x8180, [1, 1, 0, 0], &sections)).unwrap();
    assert_eq!(
        message.answers()[0].data(),
        &RecordData::Ptr(Name::from_wire(b"\x07example\x03com\0").unwrap())
    );
}

#[test]
fn message_borrows_or_copies_rdata_according_to_its_constructor() {
    let wire = Bytes::from(one_answer(
        RecordType::Unknown(65280),
        DNS_CLASS_IN,
        b"opaque",
    ));

    let shared = Message::parse_bytes(&wire).unwrap();
    let RecordData::Opaque(rdata) = shared.answers()[0].data() else {
        panic!("opaque RDATA: {:?}", shared.answers()[0]);
    };
    assert_eq!(rdata, &Bytes::from_static(b"opaque"));
    assert!(points_into(rdata, &wire));

    let copied = Message::parse(&wire).unwrap();
    assert_eq!(copied, shared);
    let RecordData::Opaque(rdata) = copied.answers()[0].data() else {
        panic!("opaque RDATA: {:?}", copied.answers()[0]);
    };
    assert!(!points_into(rdata, &wire));
}

#[test]
fn message_stops_after_the_answer_section() {
    let mut sections = question_wire(FOO_EXAMPLE_COM, RecordType::A, DNS_CLASS_IN);
    sections.extend(record_wire(
        b"\xc0\x0c",
        RecordType::A,
        DNS_CLASS_IN,
        30,
        &[192, 0, 2, 1],
    ));
    // Octets that would fail to parse as a resource record, proving that the
    // authority and additional sections are never walked.
    sections.extend_from_slice(b"\xff\xff\xff");

    let message = Message::parse(&dns_message(3, 0x8180, [1, 1, 2, 5], &sections)).unwrap();
    assert_eq!(message.questions().len(), 1);
    assert_eq!(message.answers().len(), 1);
    assert_eq!(message.header().authority_count(), 2);
    assert_eq!(message.header().additional_count(), 5);
}

#[test]
fn message_parse_keeps_every_record_before_the_one_that_fails() {
    let mut sections = record_wire(b"\0", RecordType::A, DNS_CLASS_IN, 1, &[192, 0, 2, 1]);
    sections.extend(record_wire(
        b"\0",
        RecordType::A,
        DNS_CLASS_IN,
        2,
        &[192, 0, 2],
    ));
    sections.extend(record_wire(
        b"\0",
        RecordType::A,
        DNS_CLASS_IN,
        3,
        &[192, 0, 2, 3],
    ));
    let wire = dns_message(0, 0x8180, [0, 3, 0, 0], &sections);

    let message = Message::parse(&wire).unwrap();
    assert!(!message.is_complete());
    assert_eq!(message.header().answer_count(), 3);
    let [first] = message.answers() else {
        panic!("one answer: {:?}", message.answers());
    };
    assert_eq!(first.ttl(), 1);
    assert_eq!(first.data(), &RecordData::A(Ipv4Addr::new(192, 0, 2, 1)));
    let reason = message.incomplete_reason().expect("a reason");
    assert_eq!(
        reason.to_string(),
        "DNS answer 1 has invalid address RDATA: A (0x0001) RDATA must contain exactly 4 octets, got 3"
    );
    // The reason a message carries never nests a partial message of its own.
    assert_eq!(reason.partial(), None);

    // Strict parsing rejects the same message, and hands the partial back.
    let error = Message::parse_strict(&wire).unwrap_err();
    assert_eq!(error.to_string(), reason.to_string());
    assert_eq!(error.partial(), Some(&message));
    assert_eq!(
        Message::parse_bytes_strict(&Bytes::from(wire.clone()))
            .unwrap_err()
            .to_string(),
        error.to_string()
    );
    assert_eq!(
        Message::parse_bytes(&Bytes::from(wire)).unwrap(),
        message,
        "both constructors agree on where to stop"
    );
}

#[test]
fn message_parse_abandons_the_answer_section_when_a_question_fails() {
    let mut sections = question_wire(FOO_EXAMPLE_COM, RecordType::A, DNS_CLASS_IN);
    // A second question whose name points nowhere valid.
    sections.extend_from_slice(b"\xc0\xff");
    // A well-formed answer record follows, but the answer section's start
    // depends on where the questions end, so it is never reached.
    sections.extend(record_wire(
        b"\xc0\x0c",
        RecordType::A,
        DNS_CLASS_IN,
        30,
        &[192, 0, 2, 1],
    ));
    let message = Message::parse(&dns_message(0, 0x8180, [2, 1, 0, 0], &sections)).unwrap();

    assert!(!message.is_complete());
    assert_eq!(message.questions().len(), 1);
    assert!(message.answers().is_empty());
    assert_eq!(
        message
            .incomplete_reason()
            .map(ToString::to_string)
            .as_deref(),
        Some(
            "DNS question 1 has an invalid name: DNS compression pointer does not refer to a prior name occurrence"
        )
    );
}

#[test]
fn message_parse_reports_a_fully_decoded_message_as_complete() {
    let mut sections = question_wire(FOO_EXAMPLE_COM, RecordType::A, DNS_CLASS_IN);
    sections.extend(record_wire(
        b"\xc0\x0c",
        RecordType::A,
        DNS_CLASS_IN,
        30,
        &[192, 0, 2, 1],
    ));
    let wire = dns_message(0, 0x8180, [1, 1, 0, 0], &sections);

    for message in [
        Message::parse(&wire).unwrap(),
        Message::parse_strict(&wire).unwrap(),
        Message::parse_bytes(&Bytes::from(wire.clone())).unwrap(),
        Message::parse_bytes_strict(&Bytes::from(wire.clone())).unwrap(),
    ] {
        assert!(message.is_complete());
        assert_eq!(message.incomplete_reason(), None);
        assert_eq!(message.questions().len(), 1);
        assert_eq!(message.answers().len(), 1);
    }

    // An empty message declares nothing and is therefore complete.
    let empty = Message::parse_strict(&dns_message(0, 0, [0; 4], &[])).unwrap();
    assert!(empty.is_complete());
}

#[test]
fn message_parse_strict_rejects_truncated_sections_and_malformed_rdata() {
    // A second question that the message never encodes.
    let one_of_two_questions = question_wire(FOO_EXAMPLE_COM, RecordType::A, DNS_CLASS_IN);

    for (wire, expected) in [
        (
            dns_message(0, 0, [1, 0, 0, 0], b"\xc0\x0c"),
            "DNS question 0 has an invalid name: DNS compression pointer does not refer to a prior name occurrence",
        ),
        (
            dns_message(0, 0, [1, 0, 0, 0], b"\0\x00\x01"),
            "DNS question 0 ends within its QTYPE and QCLASS fields",
        ),
        (
            dns_message(0, 0, [2, 0, 0, 0], &one_of_two_questions),
            "DNS question 1 has an invalid name: DNS name ends within a label",
        ),
        (
            dns_message(0, 0, [0, 1, 0, 0], b"\xc0\x0c"),
            "DNS answer 0 has an invalid owner name: DNS compression pointer does not refer to a prior name occurrence",
        ),
        (
            dns_message(0, 0, [0, 1, 0, 0], b"\0\x00\x01\x00\x01\x00\x00\x00\x1e"),
            "DNS answer 0 ends within its record fields",
        ),
        (
            dns_message(
                0,
                0,
                [0, 1, 0, 0],
                b"\0\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x05\x00\x02",
            ),
            "DNS answer 0 declares 5 RDATA octets but 2 remain",
        ),
        (
            one_answer(RecordType::A, DNS_CLASS_IN, &[192, 0, 2]),
            "DNS answer 0 has invalid address RDATA: A (0x0001) RDATA must contain exactly 4 octets, got 3",
        ),
        (
            one_answer(RecordType::AAAA, DNS_CLASS_IN, &[0; 4]),
            "DNS answer 0 has invalid address RDATA: AAAA (0x001c) RDATA must contain exactly 16 octets, got 4",
        ),
        (
            one_answer(RecordType::CNAME, DNS_CLASS_IN, b"\x03cdn\0\0"),
            "DNS answer 0 declares 6 CNAME RDATA octets but its name uses 5",
        ),
        (
            one_answer(RecordType::NS, DNS_CLASS_IN, b"\x03ns"),
            "DNS answer 0 has an invalid NS RDATA name: DNS name ends within a label",
        ),
        (
            one_answer(RecordType::TXT, DNS_CLASS_IN, b"\x03ab"),
            "DNS answer 0 has invalid TXT RDATA: TXT character-string 0 declares 3 octets but only 2 remain",
        ),
        (
            one_answer(RecordType::HTTPS, DNS_CLASS_IN, &[0, 1, 0xc0, 0]),
            "DNS answer 0 has invalid HTTPS RDATA: invalid service binding target name: compressed DNS name is not allowed in this field",
        ),
        (
            one_answer(RecordType::SVCB, DNS_CLASS_IN, &[0, 1, 0xc0, 0]),
            "DNS answer 0 has invalid SVCB RDATA: invalid service binding target name: compressed DNS name is not allowed in this field",
        ),
    ] {
        let error = Message::parse_strict(&wire).unwrap_err();
        assert_eq!(error.to_string(), expected);

        // Each one has an intact header, so the lenient parser keeps what it
        // decoded and reports the same failure, which the strict error hands
        // back together with that partial message.
        let lenient = Message::parse(&wire).unwrap();
        assert!(!lenient.is_complete());
        assert_eq!(
            lenient
                .incomplete_reason()
                .map(ToString::to_string)
                .as_deref(),
            Some(expected)
        );
        assert_eq!(error.partial(), Some(&lenient));
        assert_eq!(error.into_partial().as_ref(), Some(&lenient));
    }
}

#[test]
fn message_reports_the_failing_answer_index_and_preserves_error_sources() {
    let mut sections = record_wire(b"\0", RecordType::A, DNS_CLASS_IN, 1, &[192, 0, 2, 1]);
    sections.extend(record_wire(
        b"\0",
        RecordType::A,
        DNS_CLASS_IN,
        1,
        &[192, 0, 2],
    ));
    let error = Message::parse_strict(&dns_message(0, 0, [0, 2, 0, 0], &sections)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "DNS answer 1 has invalid address RDATA: A (0x0001) RDATA must contain exactly 4 octets, got 3"
    );
    assert!(error.source().is_some());

    let error = Message::parse_strict(&one_answer(RecordType::CNAME, DNS_CLASS_IN, b"\xc0\x40"))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("DNS answer 0 has an invalid CNAME RDATA name:"),
        "got: {error}"
    );
    assert!(error.source().is_some());

    let error =
        Message::parse_strict(&one_answer(RecordType::TXT, DNS_CLASS_IN, b"\x03ab")).unwrap_err();
    assert!(
        error
            .source()
            .is_some_and(|source| source.to_string().starts_with("TXT character-string 0")),
        "got: {error:?}"
    );

    let error = Message::parse_strict(&one_answer(
        RecordType::HTTPS,
        DNS_CLASS_IN,
        &[0, 1, 0xc0, 0],
    ))
    .unwrap_err();
    assert!(
        error.source().is_some_and(|source| source
            .to_string()
            .starts_with("invalid service binding target name")),
        "got: {error:?}"
    );

    // Structural failures have nothing to chain to.
    let error = Message::parse_strict(&[0; 4]).unwrap_err();
    assert!(error.source().is_none());
    let error = Message::parse_strict(&dns_message(
        0,
        0,
        [0, 1, 0, 0],
        b"\0\x00\x01\x00\x01\x00\x00\x00\x1e",
    ))
    .unwrap_err();
    assert!(error.source().is_none());
}

#[test]
fn message_does_not_trust_counts_that_the_octets_cannot_back() {
    // A twelve-octet header claiming a full section of each kind must stop on
    // the first missing question rather than pre-allocating for 65535 of them.
    let wire = dns_message(0, 0, [u16::MAX; 4], &[]);
    let expected = "DNS question 0 has an invalid name: DNS name ends within a label";
    assert_eq!(
        Message::parse_strict(&wire).unwrap_err().to_string(),
        expected
    );

    let lenient = Message::parse(&wire).unwrap();
    assert!(lenient.questions().is_empty());
    assert!(lenient.answers().is_empty());
    assert_eq!(lenient.header().question_count(), u16::MAX);

    let mut sections = question_wire(FOO_EXAMPLE_COM, RecordType::A, DNS_CLASS_IN);
    sections.extend(record_wire(
        b"\xc0\x0c",
        RecordType::A,
        DNS_CLASS_IN,
        30,
        &[192, 0, 2, 1],
    ));
    let wire = dns_message(0, 0x8180, [1, u16::MAX, 0, 0], &sections);
    assert_eq!(
        Message::parse_strict(&wire).unwrap_err().to_string(),
        "DNS answer 1 has an invalid owner name: DNS name ends within a label"
    );

    // The one answer the octets do hold survives the overstated count.
    let lenient = Message::parse(&wire).unwrap();
    assert_eq!(lenient.questions().len(), 1);
    assert_eq!(lenient.answers().len(), 1);
    assert_eq!(lenient.header().answer_count(), u16::MAX);
}

#[test]
fn message_section_capacity_never_exceeds_what_the_octets_could_hold() {
    // A declared count is only trusted up to the records the octets after the
    // parse offset could encode, and is never rounded up past it.
    let message = vec![0; 4096];
    assert_eq!(bounded_capacity(0, &message, 12, 5), 0);
    assert_eq!(bounded_capacity(3, &message, 12, 5), 3);
    assert_eq!(bounded_capacity(u16::MAX, &message, message.len(), 5), 0);
    assert_eq!(bounded_capacity(u16::MAX, &message, 4092, 5), 0);
    assert_eq!(bounded_capacity(u16::MAX, &message, 4047, 5), 9);
    assert_eq!(bounded_capacity(u16::MAX, &message, 4075, 11), 1);
    assert_eq!(bounded_capacity(u16::MAX, &message, 0, 11), 4096 / 11);
    // An offset past the end reserves nothing instead of underflowing.
    assert_eq!(bounded_capacity(u16::MAX, &message, usize::MAX, 5), 0);
}

#[test]
fn response_code_covers_the_registry_and_retains_unassigned_values() {
    let assigned = [
        (0, ResponseCode::NoError),
        (1, ResponseCode::FormErr),
        (2, ResponseCode::ServFail),
        (3, ResponseCode::NXDomain),
        (4, ResponseCode::NotImp),
        (5, ResponseCode::Refused),
        (6, ResponseCode::YXDomain),
        (7, ResponseCode::YXRRSet),
        (8, ResponseCode::NXRRSet),
        (9, ResponseCode::NotAuth),
        (10, ResponseCode::NotZone),
        (11, ResponseCode::DSOTYPENI),
        (16, ResponseCode::BADVERS),
        (17, ResponseCode::BADKEY),
        (18, ResponseCode::BADTIME),
        (19, ResponseCode::BADMODE),
        (20, ResponseCode::BADNAME),
        (21, ResponseCode::BADALG),
        (22, ResponseCode::BADTRUNC),
        (23, ResponseCode::BADCOOKIE),
    ];
    for (value, code) in assigned {
        assert_eq!(ResponseCode::from(value), code);
        assert_eq!(u8::from(code), value);
    }

    for value in [12, 13, 14, 15, 24, 100, u8::MAX] {
        assert_eq!(ResponseCode::from(value), ResponseCode::Unknown(value));
        assert_eq!(u8::from(ResponseCode::Unknown(value)), value);
    }

    assert_eq!(ResponseCode::NXDomain.to_string(), "NXDomain (0x0003)");
    assert_eq!(ResponseCode::Unknown(12).to_string(), "Unknown (0x000c)");
}

#[test]
fn record_class_covers_the_registry_and_retains_unassigned_values() {
    let assigned = [
        (0, RecordClass::Reserved),
        (1, RecordClass::IN),
        (3, RecordClass::CH),
        (4, RecordClass::HS),
        (254, RecordClass::NONE),
        (255, RecordClass::ANY),
        (65535, RecordClass::ReservedMax),
    ];
    for (value, class) in assigned {
        assert_eq!(RecordClass::from(value), class);
        assert_eq!(u16::from(class), value);
    }

    for value in [2, 5, 253, 256, 65534] {
        assert_eq!(RecordClass::from(value), RecordClass::Unknown(value));
        assert_eq!(u16::from(RecordClass::Unknown(value)), value);
    }

    assert_eq!(RecordClass::IN.to_string(), "IN (0x0001)");
}

#[test]
fn wire_enums_expose_their_mnemonic_without_debug_coupling() {
    assert_eq!(RecordType::A.variant_name(), "A");
    assert_eq!(RecordType::HTTPS.variant_name(), "HTTPS");
    assert_eq!(RecordType::NSAP_PTR.variant_name(), "NSAP_PTR");
    assert_eq!(RecordType::Unknown(65280).variant_name(), "65280");
    assert!(matches!(RecordType::A.variant_name(), Cow::Borrowed("A")));
    assert!(matches!(
        RecordType::Unknown(65280).variant_name(),
        Cow::Owned(_)
    ));

    assert_eq!(ResponseCode::NoError.variant_name(), "NoError");
    assert_eq!(ResponseCode::NXDomain.variant_name(), "NXDomain");
    assert_eq!(ResponseCode::BADCOOKIE.variant_name(), "BADCOOKIE");
    assert_eq!(ResponseCode::Unknown(12).variant_name(), "12");

    assert_eq!(RecordClass::IN.variant_name(), "IN");
    assert_eq!(RecordClass::Unknown(2).variant_name(), "2");
    assert_eq!(SvcParamKey::NoDefaultAlpn.variant_name(), "NoDefaultAlpn");
}
