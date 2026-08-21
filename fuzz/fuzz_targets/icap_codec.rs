//! Raw ICAP syntax and framing fuzz target.
//!
//! Successful parses are encoded into a canonical fixed buffer and parsed
//! again. This checks termination, bounds, and semantic round trips for
//! arbitrary bytes.
//!
//! Run with:
//!     cargo +nightly fuzz run icap_codec fuzz/corpus/icap_codec \
//!       fuzz/corpus-seeds/icap_codec -- \
//!       -dict=fuzz/dictionaries/icap.dict -max_len=65536 -timeout=5
#![expect(
    clippy::panic,
    reason = "a violated fuzz invariant must produce a crash artifact"
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::icap::codec::{
    ChunkLineScanner, CompositionValidation, EncapsulatedContext, HeadParserConfig, HeadScanner,
    HeaderFolding, HeaderSlot, ParseStatus, RequestLine, ScanStatus, ServiceTagSyntax,
    TrailerScanner, encode_chunk_line, encode_encapsulated, encode_parsed_request_head,
    encode_parsed_response_head, parse_chunk_line, parse_chunk_line_with_limit, parse_encapsulated,
    parse_request_head, parse_request_head_with_config, parse_response_head,
    parse_response_head_with_config, parse_trailers,
};
use rama::icap::proto::{
    EncapsulatedKind, EncapsulatedSection, Method, MethodKind, Preview, Version,
};

const MAX_INPUT: usize = 64 * 1024;
const MAX_HEADERS: usize = 32;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    exercise_request(data);
    for method in [
        MethodKind::Reqmod,
        MethodKind::Respmod,
        MethodKind::Options,
        MethodKind::Extension,
    ] {
        exercise_response(method, data);
    }
    exercise_compatibility_heads(data);
    exercise_chunk_line(data);
    exercise_encapsulated(data);
    exercise_trailers(data);
    exercise_scanners(data);
    exercise_synthesized_grammar(data);
    exercise_public_constructors(data);
    let _preview = std::hint::black_box(Preview::from_bytes(data));
    let _version = std::hint::black_box(Version::from_bytes(data));
});

fn exercise_public_constructors(data: &[u8]) {
    let parsed = Method::from_bytes(data);
    let Ok(value) = core::str::from_utf8(data) else {
        if parsed.is_ok() {
            panic!("non-UTF-8 ICAP method was accepted");
        }
        return;
    };
    let constructed = Method::extension(value);
    match parsed {
        Ok(Method::Extension(extension)) => {
            assert_eq!(constructed, Ok(Method::Extension(extension)));
        }
        Ok(Method::Reqmod | Method::Respmod | Method::Options) | Err(_) => {
            if constructed.is_ok() {
                panic!("invalid or reserved extension method was constructed");
            }
        }
    }
    let _line = std::hint::black_box(RequestLine::new(Method::Options, value));
}

fn exercise_request(data: &[u8]) {
    let mut headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    let Ok(ParseStatus::Complete(head, consumed)) = parse_request_head(data, &mut headers) else {
        return;
    };
    assert!(consumed <= data.len());

    let Some(capacity) = consumed
        .checked_add(head.header_count())
        .and_then(|value| value.checked_add(8))
    else {
        return;
    };
    let mut encoded = vec![0; capacity];
    let Ok(written) = encode_parsed_request_head(&head, &mut encoded) else {
        panic!("parsed ICAP request did not encode");
    };
    let original_headers = head.headers().collect::<Vec<_>>();
    let mut reparsed_headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    match parse_request_head(&encoded[..written], &mut reparsed_headers) {
        Ok(ParseStatus::Complete(reparsed, reparsed_len)) => {
            assert_eq!(reparsed_len, written);
            assert_eq!(reparsed.line(), head.line());
            assert_eq!(reparsed.headers().collect::<Vec<_>>(), original_headers);
        }
        _ => panic!("encoded ICAP request did not reparse"),
    }
}

fn exercise_response(method: MethodKind, data: &[u8]) {
    let mut headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    let Ok(ParseStatus::Complete(head, consumed)) = parse_response_head(method, data, &mut headers)
    else {
        return;
    };
    assert!(consumed <= data.len());

    let Some(capacity) = consumed
        .checked_add(head.header_count())
        .and_then(|value| value.checked_add(8))
    else {
        return;
    };
    let mut encoded = vec![0; capacity];
    let Ok(written) = encode_parsed_response_head(method, &head, &mut encoded) else {
        panic!("parsed ICAP response did not encode");
    };
    let original_headers = head.headers().collect::<Vec<_>>();
    let mut reparsed_headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    match parse_response_head(method, &encoded[..written], &mut reparsed_headers) {
        Ok(ParseStatus::Complete(reparsed, reparsed_len)) => {
            assert_eq!(reparsed_len, written);
            assert_eq!(reparsed.line(), head.line());
            assert_eq!(reparsed.headers().collect::<Vec<_>>(), original_headers);
        }
        _ => panic!("encoded ICAP response did not reparse"),
    }
}

fn exercise_chunk_line(data: &[u8]) {
    let _bounded = std::hint::black_box(parse_chunk_line_with_limit(data, data.len() / 2));
    let Ok(ParseStatus::Complete(line, consumed)) = parse_chunk_line(data) else {
        return;
    };
    assert!(consumed <= data.len());
    let extensions = line.extensions().iter().collect::<Vec<_>>();
    let Some(capacity) = consumed
        .checked_add(extensions.len().saturating_mul(2))
        .and_then(|value| value.checked_add(8))
    else {
        return;
    };
    let mut encoded = vec![0; capacity];
    let Ok(written) = encode_chunk_line(line.size(), &extensions, &mut encoded) else {
        panic!("parsed ICAP chunk line did not encode");
    };
    match parse_chunk_line(&encoded[..written]) {
        Ok(ParseStatus::Complete(reparsed, reparsed_len)) => {
            assert_eq!(reparsed_len, written);
            assert_eq!(reparsed, line);
        }
        _ => panic!("encoded ICAP chunk line did not reparse"),
    }
}

fn exercise_compatibility_heads(data: &[u8]) {
    let config = HeadParserConfig::new()
        .with_header_folding(HeaderFolding::Allow)
        .with_service_tag_syntax(ServiceTagSyntax::AllowUnquotedToken);
    let mut request_headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    if let Ok(ParseStatus::Complete(head, consumed)) =
        parse_request_head_with_config(data, &mut request_headers, config)
    {
        assert!(consumed <= data.len());
        let Some(capacity) = consumed
            .checked_add(head.header_count())
            .and_then(|value| value.checked_add(8))
        else {
            panic!("ICAP request output capacity overflowed");
        };
        let mut encoded = vec![0; capacity];
        let Ok(written) = encode_parsed_request_head(&head, &mut encoded) else {
            panic!("compatibility-parsed ICAP request did not encode");
        };
        assert_canonical_request(&encoded[..written]);
    }

    for method in [MethodKind::Reqmod, MethodKind::Respmod, MethodKind::Options] {
        let mut response_headers = [HeaderSlot::EMPTY; MAX_HEADERS];
        if let Ok(ParseStatus::Complete(head, consumed)) =
            parse_response_head_with_config(method, data, &mut response_headers, config)
        {
            assert!(consumed <= data.len());
            let Some(capacity) = consumed
                .checked_add(head.header_count())
                .and_then(|value| value.checked_add(8))
            else {
                panic!("ICAP response output capacity overflowed");
            };
            let mut encoded = vec![0; capacity];
            let Ok(written) = encode_parsed_response_head(method, &head, &mut encoded) else {
                panic!("compatibility-parsed ICAP response did not encode");
            };
            assert_canonical_response(method, &encoded[..written]);
        }
    }

    let syntax_only = config
        .with_composition_validation(CompositionValidation::Disabled)
        .with_service_tag_syntax(ServiceTagSyntax::AllowUnquotedToken);
    let mut request_headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    if let Ok(ParseStatus::Complete(head, _)) =
        parse_request_head_with_config(data, &mut request_headers, syntax_only)
    {
        let _validation = std::hint::black_box(head.validate());
    }
    for method in [
        MethodKind::Reqmod,
        MethodKind::Respmod,
        MethodKind::Options,
        MethodKind::Extension,
    ] {
        let mut response_headers = [HeaderSlot::EMPTY; MAX_HEADERS];
        if let Ok(ParseStatus::Complete(head, _)) =
            parse_response_head_with_config(method, data, &mut response_headers, syntax_only)
        {
            let _validation = std::hint::black_box(head.validate(method));
        }
    }
}

fn assert_canonical_request(encoded: &[u8]) {
    let mut headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    let Ok(ParseStatus::Complete(head, consumed)) = parse_request_head(encoded, &mut headers)
    else {
        panic!("normalized ICAP request did not parse strictly");
    };
    assert_eq!(consumed, encoded.len());
    let mut second = vec![0; encoded.len()];
    let Ok(written) = encode_parsed_request_head(&head, &mut second) else {
        panic!("strictly parsed request did not encode");
    };
    assert_eq!(&second[..written], encoded);
}

fn assert_canonical_response(method: MethodKind, encoded: &[u8]) {
    let mut headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    let Ok(ParseStatus::Complete(head, consumed)) =
        parse_response_head(method, encoded, &mut headers)
    else {
        panic!("normalized ICAP response did not parse strictly");
    };
    assert_eq!(consumed, encoded.len());
    let mut second = vec![0; encoded.len()];
    let Ok(written) = encode_parsed_response_head(method, &head, &mut second) else {
        panic!("strictly parsed response did not encode");
    };
    assert_eq!(&second[..written], encoded);
}

fn exercise_encapsulated(data: &[u8]) {
    let Ok(value) = parse_encapsulated(data) else {
        return;
    };
    let sections = value.iter().collect::<Vec<_>>();
    let Some(capacity) = data.len().checked_add(8) else {
        return;
    };
    let mut encoded = vec![0; capacity];
    let Ok(written) = encode_encapsulated(&sections, &mut encoded) else {
        panic!("parsed Encapsulated value did not encode");
    };
    match parse_encapsulated(&encoded[..written]) {
        Ok(reparsed) => {
            assert_eq!(reparsed, value);
            for context in [
                EncapsulatedContext::ReqmodRequest,
                EncapsulatedContext::ReqmodResponse,
                EncapsulatedContext::RespmodRequest,
                EncapsulatedContext::RespmodResponse,
                EncapsulatedContext::OptionsRequest,
                EncapsulatedContext::OptionsResponse,
            ] {
                assert_eq!(reparsed.validate(context), value.validate(context));
            }
        }
        Err(_) => panic!("encoded Encapsulated value did not reparse"),
    }
}

fn exercise_trailers(data: &[u8]) {
    let mut headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    let Ok(ParseStatus::Complete(trailers, consumed)) = parse_trailers(data, &mut headers) else {
        return;
    };
    assert!(consumed <= data.len());
    assert!(trailers.header_count() <= MAX_HEADERS);
    assert_eq!(trailers.headers().count(), trailers.header_count());
}

fn exercise_scanners(data: &[u8]) {
    let data = &data[..data.len().min(512)];
    for max_bytes in [0, data.len() / 2, data.len(), data.len().saturating_add(1)] {
        let config = HeadParserConfig::new().with_max_bytes(max_bytes);
        let direct_head = HeadScanner::new().scan(data, config);
        let direct_trailer = TrailerScanner::new().scan(data, config);
        let direct_chunk = ChunkLineScanner::new().scan(data, max_bytes);
        let derived_step = data
            .first()
            .copied()
            .map_or(1, |byte| usize::from(byte % 8) + 1);
        for step in [1, 2, 3, derived_step] {
            assert_eq!(direct_head, scan_head_chunks(data, config, step));
            assert_eq!(direct_trailer, scan_trailer_chunks(data, config, step));
            assert_eq!(direct_chunk, scan_chunk_chunks(data, max_bytes, step));
        }
    }
    if data.is_empty() {
        return;
    }
    let high = data.len() + 1;
    let lowered = data.len() - 1;
    let high_config = HeadParserConfig::new().with_max_bytes(high);
    let lowered_config = HeadParserConfig::new().with_max_bytes(lowered);
    if let Ok(ScanStatus::Partial(scanner)) = HeadScanner::new().scan(data, high_config) {
        assert!(matches!(
            scanner
                .clone()
                .scan(b"", HeadParserConfig::new().with_max_bytes(data.len()),),
            Ok(ScanStatus::Partial(_))
        ));
        assert!(matches!(
            scanner.clone().scan(b"", lowered_config),
            Err(rama::icap::codec::ParseError::HeadTooLarge)
        ));
        assert!(matches!(
            scanner.scan(b"x", lowered_config),
            Err(rama::icap::codec::ParseError::HeadTooLarge)
        ));
    }
    if let Ok(ScanStatus::Partial(scanner)) = TrailerScanner::new().scan(data, high_config) {
        assert!(matches!(
            scanner
                .clone()
                .scan(b"", HeadParserConfig::new().with_max_bytes(data.len()),),
            Ok(ScanStatus::Partial(_))
        ));
        assert!(matches!(
            scanner.clone().scan(b"", lowered_config),
            Err(rama::icap::codec::ParseError::HeadTooLarge)
        ));
        assert!(matches!(
            scanner.scan(b"x", lowered_config),
            Err(rama::icap::codec::ParseError::HeadTooLarge)
        ));
    }
    if let Ok(ScanStatus::Partial(scanner)) = ChunkLineScanner::new().scan(data, high) {
        assert!(matches!(
            scanner.clone().scan(b"", data.len()),
            Ok(ScanStatus::Partial(_))
        ));
        assert!(matches!(
            scanner.clone().scan(b"", lowered),
            Err(rama::icap::codec::ChunkLineError::LineTooLong)
        ));
        assert!(matches!(
            scanner.scan(b"x", lowered),
            Err(rama::icap::codec::ChunkLineError::LineTooLong)
        ));
    }
}

fn scan_head_chunks(
    data: &[u8],
    config: HeadParserConfig,
    step: usize,
) -> Result<ScanStatus<HeadScanner>, rama::icap::codec::ParseError> {
    let mut scanner = HeadScanner::new();
    for chunk in data.chunks(step) {
        match scanner.scan(chunk, config)? {
            ScanStatus::Partial(next) => scanner = next,
            complete @ ScanStatus::Complete(_) => return Ok(complete),
        }
    }
    Ok(ScanStatus::Partial(scanner))
}

fn scan_trailer_chunks(
    data: &[u8],
    config: HeadParserConfig,
    step: usize,
) -> Result<ScanStatus<TrailerScanner>, rama::icap::codec::ParseError> {
    let mut scanner = TrailerScanner::new();
    for chunk in data.chunks(step) {
        match scanner.scan(chunk, config)? {
            ScanStatus::Partial(next) => scanner = next,
            complete @ ScanStatus::Complete(_) => return Ok(complete),
        }
    }
    Ok(ScanStatus::Partial(scanner))
}

fn scan_chunk_chunks(
    data: &[u8],
    max_bytes: usize,
    step: usize,
) -> Result<ScanStatus<ChunkLineScanner>, rama::icap::codec::ChunkLineError> {
    let mut scanner = ChunkLineScanner::new();
    for chunk in data.chunks(step) {
        match scanner.scan(chunk, max_bytes)? {
            ScanStatus::Partial(next) => scanner = next,
            complete @ ScanStatus::Complete(_) => return Ok(complete),
        }
    }
    Ok(ScanStatus::Partial(scanner))
}

fn exercise_synthesized_grammar(data: &[u8]) {
    let selector = data.first().copied().unwrap_or_default() % 5;
    let (start, encapsulated) = match selector {
        0 => (
            b"REQMOD icap://fuzz.test/service ICAP/1.0\r\n".as_slice(),
            b"req-hdr=0, null-body=1".as_slice(),
        ),
        1 => (
            b"RESPMOD icap://fuzz.test/service ICAP/1.0\r\n".as_slice(),
            b"res-hdr=0, null-body=1".as_slice(),
        ),
        2 => (
            b"OPTIONS icap://fuzz.test/service ICAP/1.0\r\n".as_slice(),
            b"opt-body=0".as_slice(),
        ),
        3 => (
            b"LOG icap://fuzz.test/service ICAP/1.0\r\n".as_slice(),
            b"null-body=0".as_slice(),
        ),
        _ => (
            b"LOG icap://fuzz.test/service ICAP/1.0\r\n".as_slice(),
            b"req-body=0".as_slice(),
        ),
    };
    let mut request = start.to_vec();
    request.extend_from_slice(b"X-Fuzz: ");
    request.extend(
        data.iter()
            .take(256)
            .map(|byte| b'!' + byte % (b'~' - b'!')),
    );
    request.extend_from_slice(b"\r\nEncapsulated: ");
    request.extend_from_slice(encapsulated);
    request.extend_from_slice(b"\r\n\r\n");
    exercise_request(&request);

    let mut offset_bytes = [0; 8];
    let copied = data.len().min(offset_bytes.len());
    offset_bytes[..copied].copy_from_slice(&data[..copied]);
    let offset = u64::from_le_bytes(offset_bytes).max(1);
    let sections = [
        EncapsulatedSection::new(EncapsulatedKind::RequestHeader, 0),
        EncapsulatedSection::new(EncapsulatedKind::NullBody, offset),
    ];
    let mut encoded = [0; 96];
    if let Ok(written) = encode_encapsulated(&sections, &mut encoded) {
        exercise_encapsulated(&encoded[..written]);
    }
}
