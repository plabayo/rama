use std::{collections::BTreeSet, net::IpAddr};

use rama_net::{address::Domain, tls::ServerName};
use rama_tls::{CipherSuite, CompressionAlgorithm, ExtensionId, ProtocolVersion};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::profile::{
    capture::joint::{
        CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
    },
    evidence::{
        bucket::{CountedObservationBucket, ProfileBucketLimits},
        ingestion::ObservationId,
    },
    format::canonical::{CanonicalDomain, CanonicalValue, CanonicalWriter, ValueId},
};

fn hello(extensions: Vec<ClientHelloExtension>) -> ClientHello {
    ClientHello::new(
        ProtocolVersion::TLSv1_2,
        vec![CipherSuite::from(0x1301)],
        vec![CompressionAlgorithm::from(0)],
        extensions,
    )
}
fn opaque(id: u16, data: Vec<u8>) -> ClientHelloExtension {
    ClientHelloExtension::Opaque {
        id: ExtensionId::from(id),
        data,
    }
}
fn capture(hello: &ClientHello) -> TlsCapture {
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Quic,
        hello,
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

mod encoding;
mod ownership;
mod structure;

#[test]
fn ip_sni_capture_retains_the_policy_without_retaining_the_address() {
    let capture_ip = |ip: IpAddr| {
        capture(&hello(vec![ClientHelloExtension::ServerName(Some(
            ServerName::from(ip),
        ))]))
    };
    let first = capture_ip([192, 0, 2, 1].into());
    let second = capture_ip([192, 0, 2, 2].into());
    assert_eq!(first, second);
    assert!(matches!(
        first.extensions[0].value,
        TlsCapturedExtensionValue::IpServerName
    ));
    let encoded = first.canonical(TlsCaptureLimits::default()).unwrap();
    assert_eq!(
        TlsCapture::from_canonical(&encoded, TlsCaptureLimits::default()).unwrap(),
        first
    );
    let dns = capture(&hello(vec![ClientHelloExtension::ServerName(Some(
        Domain::example().into(),
    ))]));
    assert_ne!(first, dns);
    assert!(matches!(
        dns.extensions[0].value,
        TlsCapturedExtensionValue::ServerName { present: true }
    ));
}
