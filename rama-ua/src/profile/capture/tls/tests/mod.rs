use rama_net::address::Domain;
use rama_tls::{CipherSuite, CompressionAlgorithm, ExtensionId, ProtocolVersion};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

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
