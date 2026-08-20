//! Raw ICAP syntax and framing fuzz target.
//!
//! Successful parses are encoded into a canonical fixed buffer and parsed
//! again. This checks termination, bounds, and semantic round trips for
//! arbitrary bytes.
//!
//! Run with:
//!     cargo +nightly fuzz run icap_codec fuzz/corpus/icap_codec \
//!       fuzz/corpus-seeds/icap_codec -- \
//!       -dict=fuzz/dictionaries/icap.dict -max_len=65536
#![expect(
    clippy::panic,
    reason = "a violated fuzz invariant must produce a crash artifact"
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::icap::codec::{
    ChunkLineScanner, EncapsulatedContext, HeadParserConfig, HeadScanner, HeaderFolding,
    HeaderSlot, ParseStatus, RequestLine, encode_chunk_line, encode_encapsulated,
    encode_parsed_request_head, encode_parsed_response_head, parse_chunk_line,
    parse_chunk_line_with_limit, parse_encapsulated, parse_request_head,
    parse_request_head_with_config, parse_response_head, parse_response_head_with_config,
};
use rama::icap::proto::{EncapsulatedKind, EncapsulatedSection, Method, Preview, Version};

const MAX_INPUT: usize = 64 * 1024;
const MAX_HEADERS: usize = 32;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    exercise_request(data);
    let extension = extension_method();
    for method in [Method::Reqmod, Method::Respmod, Method::Options, extension] {
        exercise_response(method, data);
    }
    exercise_compatibility_heads(data);
    exercise_chunk_line(data);
    exercise_encapsulated(data);
    exercise_scanners(data);
    exercise_synthesized_grammar(data);
    exercise_public_constructors(data);
    let _preview = std::hint::black_box(Preview::parse(data));
    let _version = std::hint::black_box(Version::parse(data));
});

fn extension_method() -> Method<'static> {
    let Ok(method) = Method::extension("X-FUZZ") else {
        panic!("valid extension method was rejected");
    };
    method
}

fn exercise_public_constructors(data: &[u8]) {
    let parsed = Method::parse(data);
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
        .checked_add(head.headers().len())
        .and_then(|value| value.checked_add(8))
    else {
        return;
    };
    let mut encoded = vec![0; capacity];
    let Ok(written) = encode_parsed_request_head(&head, &mut encoded) else {
        return;
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

fn exercise_response(method: Method<'_>, data: &[u8]) {
    let mut headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    let Ok(ParseStatus::Complete(head, consumed)) = parse_response_head(method, data, &mut headers)
    else {
        return;
    };
    assert!(consumed <= data.len());

    let Some(capacity) = consumed
        .checked_add(head.headers().len())
        .and_then(|value| value.checked_add(8))
    else {
        return;
    };
    let mut encoded = vec![0; capacity];
    let Ok(written) = encode_parsed_response_head(method, &head, &mut encoded) else {
        return;
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
        return;
    };
    match parse_chunk_line(&encoded[..written]) {
        Ok(ParseStatus::Complete(reparsed, reparsed_len)) => {
            assert_eq!(reparsed_len, written);
            assert_eq!(reparsed.size(), line.size());
            assert_eq!(reparsed.extensions().iter().collect::<Vec<_>>(), extensions);
        }
        _ => panic!("encoded ICAP chunk line did not reparse"),
    }
}

fn exercise_compatibility_heads(data: &[u8]) {
    let config = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
    let mut request_headers = [HeaderSlot::EMPTY; MAX_HEADERS];
    if let Ok(ParseStatus::Complete(head, consumed)) =
        parse_request_head_with_config(data, &mut request_headers, config)
    {
        assert!(consumed <= data.len());
        let capacity = consumed
            .checked_add(head.headers().len())
            .and_then(|value| value.checked_add(8))
            .unwrap_or(consumed);
        let mut encoded = vec![0; capacity];
        if let Ok(written) = encode_parsed_request_head(&head, &mut encoded) {
            assert_canonical_request(&encoded[..written]);
        }
    }

    for method in [Method::Reqmod, Method::Respmod, Method::Options] {
        let mut response_headers = [HeaderSlot::EMPTY; MAX_HEADERS];
        if let Ok(ParseStatus::Complete(head, consumed)) =
            parse_response_head_with_config(method, data, &mut response_headers, config)
        {
            assert!(consumed <= data.len());
            let capacity = consumed
                .checked_add(head.headers().len())
                .and_then(|value| value.checked_add(8))
                .unwrap_or(consumed);
            let mut encoded = vec![0; capacity];
            if let Ok(written) = encode_parsed_response_head(method, &head, &mut encoded) {
                assert_canonical_response(method, &encoded[..written]);
            }
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

fn assert_canonical_response(method: Method<'_>, encoded: &[u8]) {
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
    for context in [
        EncapsulatedContext::ReqmodRequest,
        EncapsulatedContext::ReqmodResponse,
        EncapsulatedContext::RespmodRequest,
        EncapsulatedContext::RespmodResponse,
        EncapsulatedContext::OptionsRequest,
        EncapsulatedContext::OptionsResponse,
    ] {
        let _validation = std::hint::black_box(value.validate(context));
    }
    let Some(capacity) = data.len().checked_add(8) else {
        return;
    };
    let mut encoded = vec![0; capacity];
    let Ok(written) = encode_encapsulated(&sections, &mut encoded) else {
        return;
    };
    match parse_encapsulated(&encoded[..written]) {
        Ok(reparsed) => {
            assert_eq!(reparsed.iter().collect::<Vec<_>>(), sections);
        }
        Err(_) => panic!("encoded Encapsulated value did not reparse"),
    }
}

fn exercise_scanners(data: &[u8]) {
    let data = &data[..data.len().min(512)];
    for max_bytes in [0, data.len() / 2, data.len(), data.len().saturating_add(1)] {
        let config = HeadParserConfig::new().with_max_bytes(max_bytes);
        let mut direct = HeadScanner::new();
        let direct_result = direct.scan(data, config);
        if matches!(direct_result, Ok(ParseStatus::Complete(_, _))) {
            assert_eq!(direct.scan(data, config), direct_result);
            assert_eq!(
                direct.scan(b"replacement", HeadParserConfig::new().with_max_bytes(0)),
                direct_result
            );
        }
        let mut incremental = HeadScanner::new();
        let mut result = Ok(ParseStatus::Partial);
        for end in 0..=data.len() {
            result = incremental.scan(&data[..end], config);
            if !matches!(result, Ok(ParseStatus::Partial)) {
                break;
            }
        }
        assert_eq!(result, direct_result);
        if matches!(result, Ok(ParseStatus::Complete(_, _))) {
            assert_eq!(incremental.scan(data, config), result);
            assert_eq!(
                incremental.scan(b"", HeadParserConfig::new().with_max_bytes(0)),
                result
            );
        }

        let mut direct = ChunkLineScanner::new();
        let direct_result = direct.scan(data, max_bytes);
        if matches!(direct_result, Ok(ParseStatus::Complete(_, _))) {
            assert_eq!(direct.scan(data, max_bytes), direct_result);
            assert_eq!(direct.scan(b"replacement", 0), direct_result);
        }
        let mut incremental = ChunkLineScanner::new();
        let mut result = Ok(ParseStatus::Partial);
        for end in 0..=data.len() {
            result = incremental.scan(&data[..end], max_bytes);
            if !matches!(result, Ok(ParseStatus::Partial)) {
                break;
            }
        }
        assert_eq!(result, direct_result);
        if matches!(result, Ok(ParseStatus::Complete(_, _))) {
            assert_eq!(incremental.scan(data, max_bytes), result);
            assert_eq!(incremental.scan(b"", 0), result);
        }
    }

    let split = data.len() / 2;
    let mut head = HeadScanner::new();
    if matches!(
        head.scan(data, HeadParserConfig::new()),
        Ok(ParseStatus::Partial)
    ) {
        let _shrunk = std::hint::black_box(head.scan(&data[..split], HeadParserConfig::new()));
    }
    let mut chunk = ChunkLineScanner::new();
    if matches!(
        chunk.scan(data, DEFAULT_SCANNER_LIMIT),
        Ok(ParseStatus::Partial)
    ) {
        let _shrunk = std::hint::black_box(chunk.scan(&data[..split], DEFAULT_SCANNER_LIMIT));
    }
}

const DEFAULT_SCANNER_LIMIT: usize = 512;

fn exercise_synthesized_grammar(data: &[u8]) {
    let mut request = b"REQMOD icap://fuzz.test/service ICAP/1.0\r\nX-Fuzz: ".to_vec();
    request.extend(
        data.iter()
            .take(256)
            .map(|byte| b'!' + byte % (b'~' - b'!')),
    );
    request.extend_from_slice(b"\r\nEncapsulated: req-hdr=0, null-body=1\r\n\r\n");
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
