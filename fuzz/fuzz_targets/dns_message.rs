//! Fuzz the RFC 1035 DNS message parser: header, questions, and answers.
//!
//! Arbitrary octets must either parse or return a typed error — never panic,
//! read out of bounds, or hang on a compression loop. The hook also asserts
//! the parser's contract: only a message shorter than its fixed header is
//! rejected outright, a lenient parse never invents records beyond the
//! declared counts, the borrowing and copying constructors agree, and a
//! strict parse succeeds exactly when the lenient one is complete — handing
//! back that same message either way.
//!
//! Run with:
//!     cargo +nightly fuzz run dns_message -- -max_len=65535
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::{
    bytes::Bytes,
    dns::wire::{Message, MessageHeader},
};

fuzz_target!(|data: &[u8]| {
    let shared = Message::parse_bytes(&Bytes::copy_from_slice(data));
    let Ok(message) = Message::parse(data) else {
        assert!(data.len() < MessageHeader::WIRE_LEN);
        assert!(
            shared.is_err(),
            "shared parsing accepted a rejected message"
        );
        assert!(
            Message::parse_strict(data).is_err(),
            "strict parsing accepted a headerless message"
        );
        return;
    };
    assert_eq!(shared.ok().as_ref(), Some(&message));

    let header = message.header();
    assert_eq!(MessageHeader::parse(data), Ok(*header));
    let questions = message.questions().len();
    let answers = message.answers().len();
    assert!(questions <= usize::from(header.question_count()));
    assert!(answers <= usize::from(header.answer_count()));

    match Message::parse_strict(data) {
        Ok(strict) => {
            assert!(message.is_complete());
            assert_eq!(strict, message);
            assert_eq!(questions, usize::from(header.question_count()));
            assert_eq!(answers, usize::from(header.answer_count()));
        }
        Err(error) => {
            assert!(!message.is_complete());
            assert_eq!(error.partial(), Some(&message));
        }
    }
});
