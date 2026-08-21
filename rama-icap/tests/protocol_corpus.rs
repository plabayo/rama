use rama_icap::codec::{
    DEFAULT_MAX_HEADERS, HeadParserConfig, HeaderFolding, HeaderSlot, HeaderValue, ParseError,
    ParseStatus, parse_chunk_line, parse_encapsulated, parse_request_head,
    parse_request_head_with_config, parse_response_head, parse_trailers,
};
use rama_icap::proto::{EncapsulatedKind, Method, MethodKind, StatusCode};

#[test]
fn parses_rfc_3507_request_head_corpus() {
    // RFC 3507 sections 4.8.3, 4.9.3, and 4.10.3.
    let corpus: &[&[u8]] = &[
        b"OPTIONS icap://icap.server.net/sample-service ICAP/1.0\r\n\
          Host: icap.server.net\r\n\
          User-Agent: ICAP-Client-Library/2.3\r\n\r\n",
        b"REQMOD icap://icap-server.net/server?arg=87 ICAP/1.0\r\n\
          Host: icap-server.net\r\n\
          Encapsulated: req-hdr=0, null-body=170\r\n\r\n",
        b"RESPMOD icap://icap.example.org/satisf ICAP/1.0\r\n\
          Host: icap.example.org\r\n\
          Allow: 204\r\n\
          Encapsulated: req-hdr=0, res-hdr=137, res-body=296\r\n\r\n",
    ];

    for wire in corpus {
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let Ok(ParseStatus::Complete(head, consumed)) = parse_request_head(wire, &mut headers)
        else {
            panic!("RFC request did not parse: {wire:?}");
        };
        assert_eq!(consumed, wire.len());
        assert_eq!(head.line().version().as_str(), "ICAP/1.0");
    }
}

#[test]
fn applies_icap_composition_errata() {
    // Erratum e4 requires a RESPMOD request to carry at least one actual HTTP
    // response part; this synthesized null-body-only request must fail.
    let obsolete = b"RESPMOD icap://icap.example.net/translate?mode=french ICAP/1.0\r\n\
        Host: icap.example.net\r\n\
        Encapsulated: null-body=0\r\n\r\n";
    let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
    assert_eq!(
        parse_request_head(obsolete, &mut headers),
        Err(ParseError::InvalidComposition)
    );

    // Erratum e1 prohibits a message body on a 204 response.
    let body_on_204 = b"ICAP/1.0 204 No Content\r\n\
        ISTag: \"rama\"\r\n\
        Encapsulated: res-hdr=0, res-body=10\r\n\r\n";
    assert_eq!(
        parse_response_head(MethodKind::Respmod, body_on_204, &mut headers),
        Err(ParseError::InvalidComposition)
    );
}

#[test]
fn parses_rfc_3507_folded_generic_field_value_in_compat_mode() {
    // RFC 3507 section 4.3 admits LWS in Generic-Field-Value.
    let wire = b"OPTIONS icap://icap.test/ ICAP/1.0\r\n\
      Service: first line\r\n second line\r\n\r\n";
    let config = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
    let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
    let Ok(ParseStatus::Complete(head, consumed)) =
        parse_request_head_with_config(wire, &mut headers, config)
    else {
        panic!("RFC-compatible folded field did not parse");
    };
    assert_eq!(consumed, wire.len());
    assert_eq!(
        head.header("service")
            .unwrap()
            .segments()
            .collect::<Vec<_>>(),
        [b"first line".as_slice(), b"second line".as_slice()]
    );
}

#[test]
fn parses_rfc_and_errata_response_head_corpus() {
    // RFC 3507 sections 4.8.3, 4.9.3, and 4.10.3; Preview; the
    // errata's bodyless responses; and the partial-content extension.
    let corpus: &[(&[u8], MethodKind, StatusCode)] = &[
        (
            b"ICAP/1.0 200 OK\r\n\
              Methods: RESPMOD\r\n\
              Service: FOO Tech Server 1.0\r\n\
              ISTag: \"W3E4R7U9-L2E4-2\"\r\n\
              Encapsulated: null-body=0\r\n\
              Preview: 2048\r\n\r\n",
            MethodKind::Options,
            StatusCode::OK,
        ),
        (
            b"ICAP/1.0 200 OK\r\n\
              Date: Mon, 10 Jan 2000 09:55:21 GMT\r\n\
              Server: ICAP-Server-Software/1.0\r\n\
              Connection: close\r\n\
              ISTag: \"W3E4R7U9-L2E4-2\"\r\n\
              Encapsulated: req-hdr=0, null-body=231\r\n\r\n",
            MethodKind::Reqmod,
            StatusCode::OK,
        ),
        (
            b"ICAP/1.0 200 OK\r\n\
              Date: Mon, 10 Jan 2000 09:55:21 GMT\r\n\
              Server: ICAP-Server-Software/1.0\r\n\
              Connection: close\r\n\
              ISTag: \"W3E4R7U9-L2E4-2\"\r\n\
              Encapsulated: req-hdr=0, req-body=244\r\n\r\n",
            MethodKind::Reqmod,
            StatusCode::OK,
        ),
        (
            b"ICAP/1.0 200 OK\r\n\
              Date: Mon, 10 Jan 2000 09:55:21 GMT\r\n\
              Server: ICAP-Server-Software/1.0\r\n\
              Connection: close\r\n\
              ISTag: \"W3E4R7U9-L2E4-2\"\r\n\
              Encapsulated: res-hdr=0, res-body=213\r\n\r\n",
            MethodKind::Reqmod,
            StatusCode::OK,
        ),
        (
            b"ICAP/1.0 200 OK\r\n\
              Date: Mon, 10 Jan 2000 09:55:21 GMT\r\n\
              Server: ICAP-Server-Software/1.0\r\n\
              Connection: close\r\n\
              ISTag: \"W3E4R7U9-L2E4-2\"\r\n\
              Encapsulated: res-hdr=0, res-body=222\r\n\r\n",
            MethodKind::Respmod,
            StatusCode::OK,
        ),
        (
            b"ICAP/1.0 100 Continue\r\nISTag: \"rama\"\r\n\r\n",
            MethodKind::Respmod,
            StatusCode::CONTINUE,
        ),
        (
            b"ICAP/1.0 204 No Content\r\nISTag: \"rama\"\r\n\r\n",
            MethodKind::Respmod,
            StatusCode::NO_MODIFICATION_NEEDED,
        ),
        (
            b"ICAP/1.0 206 Partial Content\r\n\
              ISTag: \"rama\"\r\n\
              Encapsulated: res-hdr=0, res-body=42\r\n\r\n",
            MethodKind::Respmod,
            StatusCode::PARTIAL_CONTENT,
        ),
        (
            b"ICAP/1.0 206 Partial Content\r\nISTag: \"rama\"\r\n\r\n",
            MethodKind::Reqmod,
            StatusCode::PARTIAL_CONTENT,
        ),
        (
            b"ICAP/1.0 206 Partial Content\r\nISTag: \"rama\"\r\n\r\n",
            MethodKind::Respmod,
            StatusCode::PARTIAL_CONTENT,
        ),
        (
            b"ICAP/1.0 206 Partial Content\r\n\
              ISTag: \"rama\"\r\n\
              Encapsulated: null-body=0\r\n\r\n",
            MethodKind::Reqmod,
            StatusCode::PARTIAL_CONTENT,
        ),
        (
            b"ICAP/1.0 206 Partial Content\r\n\
              ISTag: \"rama\"\r\n\
              Encapsulated: null-body=0\r\n\r\n",
            MethodKind::Respmod,
            StatusCode::PARTIAL_CONTENT,
        ),
    ];

    for (wire, method, status) in corpus {
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let Ok(ParseStatus::Complete(head, consumed)) =
            parse_response_head(*method, wire, &mut headers)
        else {
            panic!("ICAP response did not parse: {wire:?}");
        };
        assert_eq!(consumed, wire.len());
        assert_eq!(head.line().status(), *status);
    }
}

#[test]
fn parses_rfc_and_implementation_encapsulated_corpus() {
    let corpus: &[(&[u8], EncapsulatedKind, u64)] = &[
        (
            b"req-hdr=0, req-body=412",
            EncapsulatedKind::RequestBody,
            412,
        ),
        (b"req-hdr=0, null-body=412", EncapsulatedKind::NullBody, 412),
        (
            b"res-hdr=0,res-body=749",
            EncapsulatedKind::ResponseBody,
            749,
        ),
        (b"opt-body=0", EncapsulatedKind::OptionsBody, 0),
        (b"null-body=0", EncapsulatedKind::NullBody, 0),
    ];

    for (wire, kind, offset) in corpus {
        let value = parse_encapsulated(wire)
            .unwrap_or_else(|_| panic!("Encapsulated value did not parse: {wire:?}"));
        assert_eq!(value.offset(*kind), Some(*offset));
    }
}

#[test]
fn rejects_invalid_encapsulated_corpus() {
    // Invariants also exercised by icap-rs' public fuzz suite.
    for wire in [
        b"req-hdr=10, req-body=5".as_slice(),
        b"req-hdr=0, req-hdr=10, null-body=20".as_slice(),
        b"req-hdr=0, invalid=10".as_slice(),
        b"req-hdr=0".as_slice(),
    ] {
        parse_encapsulated(wire).unwrap_err();
    }
}

#[test]
fn parses_preview_and_partial_content_chunk_corpus() {
    // RFC 3507 Preview, c-icap, G3, and the partial-content draft all emit
    // these chunk-size line forms.
    let corpus: &[(&[u8], bool, Option<u64>)] = &[
        (b"0\r\n", false, None),
        (b"0; ieof\r\n", true, None),
        (b"0; IEOF\r\n", true, None),
        (b"0; use-original-body=0\r\n", false, Some(0)),
        (b"0; use-original-body=12\r\n", false, Some(12)),
        (b"4\r\n", false, None),
        (b"00000000000000004\r\n", false, None),
    ];

    for (wire, ieof, original_body) in corpus {
        let Ok(ParseStatus::Complete(line, consumed)) = parse_chunk_line(wire) else {
            panic!("chunk line did not parse: {wire:?}");
        };
        assert_eq!(consumed, wire.len());
        assert_eq!(line.is_ieof(), *ieof);
        assert_eq!(line.use_original_body(), Ok(*original_body));
    }
}

#[test]
fn accepts_encapsulated_http_trailers_from_errata_e2_and_e4() {
    for wire in [
        b"Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==\r\n\r\nNEXT".as_slice(),
        b"X-Request-Trailer: present\r\n\r\nNEXT".as_slice(),
        b"\r\nNEXT".as_slice(),
    ] {
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(trailers, consumed) = parse_trailers(wire, &mut headers).unwrap()
        else {
            panic!("errata trailer block did not parse: {wire:?}");
        };
        assert_eq!(&wire[consumed..], b"NEXT");
        assert_eq!(trailers.header_count(), usize::from(wire != b"\r\nNEXT"));
    }
}

#[test]
fn parser_remains_strict_about_crlf() {
    let lf_only = b"OPTIONS icap://icap.test/echo ICAP/1.0\n\n";
    let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
    parse_request_head(lf_only, &mut headers).unwrap_err();

    let request = b"OPTIONS icap://icap.test/echo ICAP/1.0\r\n\r\n";
    let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
    let Ok(ParseStatus::Complete(head, _)) = parse_request_head(request, &mut headers) else {
        panic!("strict request did not parse");
    };
    assert_eq!(head.line().method(), Method::Options);
    assert_eq!(head.header("missing").and_then(HeaderValue::as_bytes), None);
}
