//! Structured ICAP encoder/decoder round-trip fuzz target.
//!
//! Run with:
//!     cargo +nightly fuzz run icap_codec_roundtrip -- -timeout=5
#![expect(
    clippy::panic,
    reason = "a violated fuzz invariant must produce a crash artifact"
)]
#![no_main]

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary},
    fuzz_target,
};
use rama::icap::codec::{
    ChunkExtension, ChunkLineScanner, EncapsulatedContext, HeadParserConfig, HeadScanner, Header,
    HeaderSlot, ParseStatus, RequestLine, ResponseLine, ScanStatus, encode_chunk_line,
    encode_encapsulated, encode_request_head, encode_response_head, parse_chunk_line,
    parse_encapsulated, parse_request_head, parse_response_head,
};
use rama::icap::proto::{EncapsulatedKind, EncapsulatedSection, Method, MethodKind, StatusCode};

#[derive(Arbitrary, Debug)]
struct Input {
    method: u8,
    status: u16,
    preview: u64,
    first_offset: u64,
    second_offset: u64,
    body_kind: u8,
    chunk_size: u64,
    ieof: bool,
    use_original_body: bool,
}

fuzz_target!(|input: Input| {
    request_roundtrip(&input);
    response_roundtrip(&input);
    encapsulated_roundtrip(&input);
    chunk_roundtrip(&input);
    rejection_paths(&input);
});

fn request_roundtrip(input: &Input) {
    let extension = format!("X-{}", input.preview);
    let method = select_method(input.method, &extension);
    let Ok(line) = RequestLine::new(method, "icap://fuzz.test/service") else {
        panic!("valid request line was rejected");
    };
    let preview = input.preview.to_string();
    let Ok(host) = Header::new("Host", b"fuzz.test") else {
        panic!("valid Host header was rejected");
    };
    let Ok(preview) = Header::new("Preview", preview.as_bytes()) else {
        panic!("valid Preview header was rejected");
    };
    let encapsulated = match method {
        Method::Reqmod => {
            let Ok(header) = Header::new("Encapsulated", b"req-body=0") else {
                panic!("valid REQMOD composition was rejected");
            };
            Some(header)
        }
        Method::Respmod => {
            let Ok(header) = Header::new("Encapsulated", b"res-body=0") else {
                panic!("valid RESPMOD composition was rejected");
            };
            Some(header)
        }
        Method::Options | Method::Extension(_) => None,
    };
    let mut headers = vec![host];
    if matches!(method.kind(), MethodKind::Reqmod | MethodKind::Respmod) {
        headers.push(preview);
    }
    headers.extend(encapsulated);
    let mut encoded = [0; 256];
    let Ok(written) = encode_request_head(line, &headers, &mut encoded) else {
        panic!("valid request did not encode");
    };
    scan_head(&encoded[..written]);
    let mut parsed_headers = [HeaderSlot::EMPTY; 8];
    match parse_request_head(&encoded[..written], &mut parsed_headers) {
        Ok(ParseStatus::Complete(reparsed, consumed)) => {
            assert_eq!(consumed, written);
            assert_eq!(reparsed.line(), line);
            assert_eq!(reparsed.headers().collect::<Vec<_>>(), headers);
        }
        _ => panic!("encoded request did not reparse"),
    }
}

fn response_roundtrip(input: &Input) {
    let status = 100 + input.status % 900;
    let Ok(status) = StatusCode::from_u16(status) else {
        panic!("three-digit status was rejected");
    };
    let Ok(line) = ResponseLine::new(status, b"Fuzz Response") else {
        panic!("valid response line was rejected");
    };
    let Ok(tag) = Header::new("ISTag", b"\"fuzz\"") else {
        panic!("valid ISTag header was rejected");
    };
    let extension = format!("X-{}", input.first_offset);
    let method = select_method(input.method, &extension);
    let method_kind = method.kind();
    let mut headers = vec![tag];
    if method_kind == MethodKind::Options && status == StatusCode::OK {
        let Ok(methods) = Header::new("Methods", b"RESPMOD") else {
            panic!("valid Methods header was rejected");
        };
        let value = if input.body_kind.is_multiple_of(2) {
            b"opt-body=0".as_slice()
        } else {
            b"null-body=0".as_slice()
        };
        let Ok(encapsulated) = Header::new("Encapsulated", value) else {
            panic!("valid Encapsulated header was rejected");
        };
        headers.extend([methods, encapsulated]);
    } else if matches!(method_kind, MethodKind::Reqmod | MethodKind::Respmod)
        && matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT)
        && input.body_kind.is_multiple_of(2)
    {
        let Ok(encapsulated) = Header::new("Encapsulated", b"res-body=0") else {
            panic!("valid Encapsulated header was rejected");
        };
        headers.push(encapsulated);
    }
    let mut encoded = [0; 256];
    let result = encode_response_head(method_kind, line, &headers, &mut encoded);
    if status == StatusCode::PARTIAL_CONTENT
        && !matches!(method_kind, MethodKind::Reqmod | MethodKind::Respmod)
    {
        if result.is_ok() {
            panic!("206 response for an unsupported method encoded");
        }
        return;
    }
    let Ok(written) = result else {
        panic!("valid response did not encode");
    };
    scan_head(&encoded[..written]);
    let mut parsed_headers = [HeaderSlot::EMPTY; 8];
    match parse_response_head(method_kind, &encoded[..written], &mut parsed_headers) {
        Ok(ParseStatus::Complete(reparsed, consumed)) => {
            assert_eq!(consumed, written);
            assert_eq!(reparsed.line(), line);
            assert_eq!(reparsed.headers().collect::<Vec<_>>(), headers);
        }
        _ => panic!("encoded response did not reparse"),
    }
}

fn encapsulated_roundtrip(input: &Input) {
    let first_offset = input.first_offset.clamp(1, u64::MAX - 1);
    let second_offset = first_offset.saturating_add(input.second_offset.max(1));
    let request_header = EncapsulatedSection::new(EncapsulatedKind::RequestHeader, 0);
    let response_header = EncapsulatedSection::new(EncapsulatedKind::ResponseHeader, 0);
    let late_response_header =
        EncapsulatedSection::new(EncapsulatedKind::ResponseHeader, first_offset);
    let request_body = EncapsulatedSection::new(EncapsulatedKind::RequestBody, first_offset);
    let request_body_zero = EncapsulatedSection::new(EncapsulatedKind::RequestBody, 0);
    let response_body = EncapsulatedSection::new(EncapsulatedKind::ResponseBody, first_offset);
    let response_body_zero = EncapsulatedSection::new(EncapsulatedKind::ResponseBody, 0);
    let late_response_body =
        EncapsulatedSection::new(EncapsulatedKind::ResponseBody, second_offset);
    let request_null = EncapsulatedSection::new(EncapsulatedKind::NullBody, first_offset);
    let null_zero = EncapsulatedSection::new(EncapsulatedKind::NullBody, 0);
    let family = input.body_kind % 10;
    let sections = match family {
        0 => &[request_body_zero][..],
        1 => &[request_header, request_body][..],
        2 => &[request_header, request_null][..],
        3 => &[response_body_zero][..],
        4 => &[response_header, response_body][..],
        5 => &[response_header, request_null][..],
        6 => &[request_header, response_body][..],
        7 => &[request_header, late_response_header, late_response_body][..],
        8 => &[EncapsulatedSection::new(EncapsulatedKind::OptionsBody, 0)][..],
        _ => &[null_zero][..],
    };
    let mut encoded = [0; 128];
    let Ok(written) = encode_encapsulated(sections, &mut encoded) else {
        panic!("valid Encapsulated value did not encode");
    };
    match parse_encapsulated(&encoded[..written]) {
        Ok(reparsed) => {
            assert_eq!(reparsed.iter().collect::<Vec<_>>(), sections);
            let Ok(canonical) = parse_encapsulated(&encoded[..written]) else {
                panic!("encoded Encapsulated value did not parse twice");
            };
            assert_eq!(reparsed, canonical);
            let contexts = [
                EncapsulatedContext::ReqmodRequest,
                EncapsulatedContext::ReqmodResponse,
                EncapsulatedContext::RespmodRequest,
                EncapsulatedContext::RespmodResponse,
                EncapsulatedContext::OptionsRequest,
                EncapsulatedContext::OptionsResponse,
            ];
            let expected = match family {
                0..=2 => [true, true, false, false, false, false],
                3..=5 => [false, true, true, true, false, false],
                6..=7 => [false, false, true, false, false, false],
                8 => [false, false, false, false, true, true],
                _ => [false, true, false, true, true, true],
            };
            for (context, expected) in contexts.into_iter().zip(expected) {
                assert_eq!(reparsed.validate(context).is_ok(), expected);
            }
        }
        Err(_) => panic!("encoded Encapsulated value did not reparse"),
    }
}

fn chunk_roundtrip(input: &Input) {
    let original_body = input.preview.to_string();
    let Ok(ieof) = ChunkExtension::new("ieof", None) else {
        panic!("valid ieof extension was rejected");
    };
    let Ok(original) = ChunkExtension::new("use-original-body", Some(original_body.as_bytes()))
    else {
        panic!("valid use-original-body extension was rejected");
    };
    let Ok(generic) = ChunkExtension::new("fuzz", Some(original_body.as_bytes())) else {
        panic!("valid generic extension was rejected");
    };
    let size = input.chunk_size;
    let extensions = if size != 0 {
        &[generic][..]
    } else {
        match (input.ieof, input.use_original_body) {
            (true, _) => &[ieof][..],
            (false, true) => &[original][..],
            (false, false) => &[],
        }
    };
    let mut encoded = [0; 128];
    let Ok(written) = encode_chunk_line(size, extensions, &mut encoded) else {
        panic!("valid chunk line did not encode");
    };
    scan_chunk_line(&encoded[..written]);
    match parse_chunk_line(&encoded[..written]) {
        Ok(ParseStatus::Complete(reparsed, consumed)) => {
            assert_eq!(consumed, written);
            assert_eq!(reparsed.size(), size);
            assert_eq!(reparsed.extensions().iter().collect::<Vec<_>>(), extensions);
            let Ok(ParseStatus::Complete(canonical, _)) = parse_chunk_line(&encoded[..written])
            else {
                panic!("encoded chunk line did not parse twice");
            };
            assert_eq!(reparsed, canonical);
        }
        _ => panic!("encoded chunk line did not reparse"),
    }
}

fn rejection_paths(input: &Input) {
    let Ok(ieof) = ChunkExtension::new("ieof", None) else {
        panic!("valid ieof extension was rejected");
    };
    let offset = input.preview.to_string();
    let Ok(original) = ChunkExtension::new("use-original-body", Some(offset.as_bytes())) else {
        panic!("valid use-original-body extension was rejected");
    };
    let mut encoded = [0; 128];
    let Err(_) = encode_chunk_line(1, &[ieof], &mut encoded) else {
        panic!("non-zero ieof chunk encoded");
    };
    let Err(_) = encode_chunk_line(0, &[ieof, original], &mut encoded) else {
        panic!("conflicting terminator extensions encoded");
    };
    let Err(_) = encode_chunk_line(0, &[ieof, ieof], &mut encoded) else {
        panic!("duplicate ieof extensions encoded");
    };
    let Err(_) = encode_chunk_line(0, &[original, original], &mut encoded) else {
        panic!("duplicate use-original-body extensions encoded");
    };
    let Err(_) = ChunkExtension::new("use-original-body", Some(b"-1")) else {
        panic!("negative use-original-body offset was accepted");
    };
    for value in [
        "REQMOD",
        "RESPMOD",
        "OPTIONS",
        "bad method",
        "bad\r\nmethod",
    ] {
        let Err(_) = Method::extension(value) else {
            panic!("reserved or invalid extension method was accepted");
        };
    }
    for uri in ["icap://fuzz.test", "icap://fuzz.test?query"] {
        let Err(_) = RequestLine::new(Method::Options, uri) else {
            panic!("pathless ICAP URI was accepted");
        };
    }

    let invalid = [
        EncapsulatedSection::new(EncapsulatedKind::ResponseHeader, 0),
        EncapsulatedSection::new(EncapsulatedKind::RequestBody, 1),
    ];
    let Err(_) = encode_encapsulated(&invalid, &mut encoded) else {
        panic!("invalid Encapsulated composition encoded");
    };

    let Ok(server_error) = ResponseLine::new(StatusCode::INTERNAL_SERVER_ERROR, b"Error") else {
        panic!("valid response line was rejected");
    };
    let Ok(tag) = Header::new("ISTag", b"\"fuzz\"") else {
        panic!("valid ISTag was rejected");
    };
    let Ok(body) = Header::new("Encapsulated", b"res-body=0") else {
        panic!("valid Encapsulated header was rejected");
    };
    let Err(_) = encode_response_head(
        MethodKind::Respmod,
        server_error,
        &[tag, body],
        &mut encoded,
    ) else {
        panic!("body-bearing non-success response encoded");
    };
}

fn select_method<'a>(value: u8, extension: &'a str) -> Method<'a> {
    match value % 4 {
        0 => Method::Options,
        1 => Method::Reqmod,
        2 => Method::Respmod,
        _ => {
            let Ok(method) = Method::extension(extension) else {
                panic!("valid extension method was rejected");
            };
            method
        }
    }
}

fn scan_head(wire: &[u8]) {
    let config = HeadParserConfig::new();
    let mut scanner = HeadScanner::new();
    for byte in &wire[..wire.len() - 1] {
        let Ok(ScanStatus::Partial(next)) = scanner.scan(core::slice::from_ref(byte), config)
        else {
            panic!("scanner rejected an encoded partial head");
        };
        scanner = next;
    }
    let Ok(ScanStatus::Complete(framed)) = scanner.scan(&wire[wire.len() - 1..], config) else {
        panic!("scanner rejected an encoded complete head");
    };
    assert_eq!(framed.consumed(), wire.len());

    let mut with_body = wire.to_vec();
    with_body.extend_from_slice(b"\r\n");
    let Ok(ScanStatus::Complete(framed)) = HeadScanner::new().scan(&with_body, config) else {
        panic!("scanner rejected a complete head with trailing bytes");
    };
    assert_eq!(framed.consumed(), wire.len());
}

fn scan_chunk_line(wire: &[u8]) {
    let mut scanner = ChunkLineScanner::new();
    for byte in &wire[..wire.len() - 1] {
        let Ok(ScanStatus::Partial(next)) = scanner.scan(core::slice::from_ref(byte), wire.len())
        else {
            panic!("scanner rejected an encoded partial chunk line");
        };
        scanner = next;
    }
    let Ok(ScanStatus::Complete(framed)) = scanner.scan(&wire[wire.len() - 1..], wire.len()) else {
        panic!("scanner rejected an encoded complete chunk line");
    };
    assert_eq!(framed.consumed(), wire.len());
}
