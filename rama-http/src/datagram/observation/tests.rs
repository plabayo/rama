use super::*;
use crate::datagram::{
    HttpDatagramSession, SessionConfig,
    capsule::{CapsuleConfig, CapsuleDecoder, CapsuleError, UnknownCapsules, encode_capsule},
};
use parking_lot::Mutex;
use rama_core::{ServiceInput, bytes::Bytes};
use rama_http_types::proto::capsule::CapsuleType;
use std::{
    future::Future as _,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

#[derive(Clone, Default)]
struct Observer {
    rows: Arc<Mutex<Vec<(bool, CapsuleHeader)>>>,
    disabled: Arc<AtomicBool>,
}

impl CapsuleObserver for Observer {
    fn is_enabled(&self) -> bool {
        !self.disabled.load(Ordering::SeqCst)
    }
    fn created(&self, header: CapsuleHeader) {
        self.rows.lock().push((true, header));
    }
    fn parsed(&self, header: CapsuleHeader) {
        self.rows.lock().push((false, header));
    }
}

fn drain(decoder: &mut CapsuleDecoder) {
    while decoder.poll().unwrap().is_some() {}
}

#[test]
fn fragmented_skipped_forwarded_buffered_and_empty_values_report_complete_once() {
    for policy in [UnknownCapsules::Skip, UnknownCapsules::Forward] {
        let unknown = CapsuleType::new(0x2a).unwrap();
        let encoded = [
            encode_capsule(unknown, b"body-sentinel").unwrap(),
            encode_capsule(CapsuleType::DATAGRAM, b"").unwrap(),
            encode_capsule(CapsuleType::DATAGRAM, b"payload").unwrap(),
        ]
        .concat();
        for split in 0..=encoded.len() {
            let observer = Observer::default();
            let mut decoder = CapsuleDecoder::new(CapsuleConfig {
                unknown: policy,
                ..CapsuleConfig::default()
            })
            .with_observation(CapsuleObservation::new(observer.clone()));
            decoder
                .feed(Bytes::copy_from_slice(&encoded[..split]))
                .unwrap();
            drain(&mut decoder);
            decoder
                .feed(Bytes::copy_from_slice(&encoded[split..]))
                .unwrap();
            drain(&mut decoder);
            decoder.finish().unwrap();
            assert_eq!(
                *observer.rows.lock(),
                vec![
                    (false, CapsuleHeader::new(unknown, 13).unwrap()),
                    (false, CapsuleHeader::new(CapsuleType::DATAGRAM, 0).unwrap()),
                    (false, CapsuleHeader::new(CapsuleType::DATAGRAM, 7).unwrap())
                ]
            );
        }
    }
}

#[test]
fn incomplete_header_or_value_never_reports_parsed_including_skip_and_forward() {
    for policy in [UnknownCapsules::Skip, UnknownCapsules::Forward] {
        let capsule = encode_capsule(CapsuleType::new(0x2a).unwrap(), b"secret").unwrap();
        for end in 1..capsule.len() {
            let observer = Observer::default();
            let mut decoder = CapsuleDecoder::new(CapsuleConfig {
                unknown: policy,
                ..CapsuleConfig::default()
            })
            .with_observation(CapsuleObservation::new(observer.clone()));
            decoder.feed(capsule.slice(..end)).unwrap();
            drain(&mut decoder);
            assert_eq!(decoder.finish(), Err(CapsuleError::Truncated));
            assert!(observer.rows.lock().is_empty());
        }
    }
}

#[test]
fn zero_forwarded_value_and_dynamic_gate_use_actual_completion_boundary() {
    let ty = CapsuleType::new(0x2a).unwrap();
    let observer = Observer::default();
    observer.disabled.store(true, Ordering::SeqCst);
    let mut decoder = CapsuleDecoder::new(CapsuleConfig {
        unknown: UnknownCapsules::Forward,
        ..CapsuleConfig::default()
    })
    .with_observation(CapsuleObservation::new(observer.clone()));
    let bytes = encode_capsule(ty, b"abc").unwrap();
    decoder.feed(bytes.slice(..3)).unwrap();
    drain(&mut decoder);
    assert!(observer.rows.lock().is_empty());
    observer.disabled.store(false, Ordering::SeqCst);
    decoder.feed(bytes.slice(3..)).unwrap();
    drain(&mut decoder);
    decoder.feed(encode_capsule(ty, b"").unwrap()).unwrap();
    drain(&mut decoder);
    assert_eq!(observer.rows.lock().len(), 2);
    assert_eq!(
        observer.rows.lock()[1],
        (false, CapsuleHeader::new(ty, 0).unwrap())
    );
}

#[tokio::test]
async fn reliable_session_reports_created_only_after_full_value_acceptance() {
    let observer = Observer::default();
    let (left, _right) = tokio::io::duplex(128);
    let io = ServiceInput::new(left);
    io.extensions
        .insert(CapsuleObservation::new(observer.clone()));
    let mut session = HttpDatagramSession::with_config(io, SessionConfig::default());
    assert!(session.native().is_none());
    let ty = CapsuleType::new(0x2a).unwrap();
    session
        .start_capsule(CapsuleHeader::new(ty, 4).unwrap())
        .await
        .unwrap();
    assert!(observer.rows.lock().is_empty());
    session
        .send_capsule_data(Bytes::from_static(b"ab"))
        .await
        .unwrap();
    assert!(observer.rows.lock().is_empty());
    session
        .send_capsule_data(Bytes::from_static(b"cd"))
        .await
        .unwrap();
    assert_eq!(
        *observer.rows.lock(),
        [(true, CapsuleHeader::new(ty, 4).unwrap())]
    );
    session.send_capsule(ty, Bytes::new()).await.unwrap();
    assert_eq!(observer.rows.lock().len(), 2);
}

#[tokio::test]
async fn cancelled_pending_send_does_not_repeat_created_or_report_unsupplied_value() {
    let observer = Observer::default();
    let (left, _right) = tokio::io::duplex(1);
    let io = ServiceInput::new(left);
    io.extensions
        .insert(CapsuleObservation::new(observer.clone()));
    let mut session = HttpDatagramSession::new(io);
    let ty = CapsuleType::new(0x2a).unwrap();
    let future = session.send_capsule(ty, Bytes::from_static(b"large-enough-to-block"));
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    assert_eq!(observer.rows.lock().len(), 1);
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    assert_eq!(observer.rows.lock().len(), 1);
}
