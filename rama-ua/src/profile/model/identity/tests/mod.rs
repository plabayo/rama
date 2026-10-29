use std::collections::BTreeSet;

use rama_utils::octets::kib;
use sha2::{Digest as _, Sha256};

use crate::profile::format::canonical::{ValueId, edited};

use super::*;

#[test]
fn profile_identity_accepts_application_only_and_preserves_absence() {
    let mut key = ProfileKey::new("application");
    let absent = key.canonical(kib(4)).unwrap();
    assert_eq!(
        ProfileKey::from_canonical(&absent, kib(4))
            .unwrap()
            .canonical(kib(4))
            .unwrap()
            .id,
        absent.id
    );
    key.user_agent = Some("".into());
    assert_ne!(absent.id, key.canonical(kib(4)).unwrap().id);
    key.user_agent = None;
    assert_eq!(absent.id, key.canonical(kib(4)).unwrap().id);
    key.platform = Some(PlatformKind::IOS);
    key.device = Some(DeviceKind::Desktop);
    key.canonical(kib(4)).unwrap_err();
}

#[test]
fn flow_identity_preserves_protocol_initiator_and_context() {
    let mut ids = BTreeSet::new();
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for initiator in [
            None,
            Some(RequestInitiator::Navigate),
            Some(RequestInitiator::Fetch),
            Some(RequestInitiator::Xhr),
            Some(RequestInitiator::Form),
            Some(RequestInitiator::Ws),
        ] {
            for resumption in [
                ResumptionContext::Unknown,
                ResumptionContext::Fresh,
                ResumptionContext::Resumed,
            ] {
                let flow = FlowKey::Http {
                    version,
                    method: Method::GET,
                    initiator,
                    fetch: None,
                    connection: ConnectionContext {
                        resumption,
                        ..ConnectionContext::default()
                    },
                };
                let value = flow.canonical(kib(4)).unwrap();
                assert!(ids.insert(value.id));
                assert_eq!(
                    FlowKey::from_canonical(&value, kib(4))
                        .unwrap()
                        .canonical(kib(4))
                        .unwrap()
                        .id,
                    value.id
                );
                let restored: FlowKey =
                    serde_json::from_slice(&serde_json::to_vec(&flow).unwrap()).unwrap();
                assert_eq!(restored.canonical(kib(4)).unwrap().id, value.id);
            }
        }
    }
    assert_eq!(ids.len(), 54);
    let non_http = FlowKey::Other {
        protocol: "custom".into(),
        operation: "exchange".into(),
    };
    let value = non_http.canonical(kib(4)).unwrap();
    assert!(ids.insert(value.id));
    assert_eq!(
        FlowKey::from_canonical(&value, kib(4))
            .unwrap()
            .canonical(kib(4))
            .unwrap()
            .id,
        value.id
    );
}

#[test]
fn fetch_context_keeps_observed_omission() {
    assert!(
        FetchContext::from_headers(&HeaderMap::new(), 0)
            .unwrap()
            .is_none()
    );
    let mut headers = HeaderMap::new();
    headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
    let context = FetchContext::from_headers(&headers, kib(4))
        .unwrap()
        .unwrap();
    assert_eq!(context.mode.as_deref(), Some("navigate"));
    assert!(context.user_activation.is_none());
    FetchContext::from_headers(&headers, "sec-fetch-mode".len() + "navigate".len()).unwrap();
    FetchContext::from_headers(&headers, "sec-fetch-mode".len() + "navigate".len() - 1)
        .unwrap_err();
    headers.insert("sec-fetch-site", "none".parse().unwrap());
    let total = "sec-fetch-mode".len() + "navigate".len() + "sec-fetch-site".len() + "none".len();
    FetchContext::from_headers(&headers, total).unwrap();
    FetchContext::from_headers(&headers, total - 1).unwrap_err();
    headers.append("sec-fetch-mode", "cors".parse().unwrap());
    FetchContext::from_headers(&headers, kib(4)).unwrap_err();
}

#[test]
fn identity_golden_vectors_reject_truncation_and_oversized_input() {
    let profile = ProfileKey::new("app").canonical(kib(4)).unwrap();
    let flow = FlowKey::Other {
        protocol: "dns".into(),
        operation: "query".into(),
    }
    .canonical(kib(4))
    .unwrap();
    assert_eq!(
        profile.bytes.as_ref(),
        &[
            114, 97, 109, 97, 45, 112, 114, 111, 102, 105, 108, 101, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0,
            0, 0, 3, 97, 112, 112, 0, 0, 0, 0
        ]
    );
    assert_eq!(
        profile.id.0,
        [
            237, 1, 86, 142, 161, 121, 123, 238, 236, 230, 29, 117, 228, 170, 235, 30, 172, 223,
            211, 94, 81, 203, 196, 103, 173, 109, 166, 45, 227, 244, 10, 64
        ]
    );
    assert_eq!(
        flow.bytes.as_ref(),
        &[
            114, 97, 109, 97, 45, 112, 114, 111, 102, 105, 108, 101, 0, 0, 1, 0, 3, 1, 0, 0, 0, 0,
            0, 0, 0, 3, 100, 110, 115, 0, 0, 0, 0, 0, 0, 0, 5, 113, 117, 101, 114, 121
        ]
    );
    assert_eq!(
        flow.id.0,
        [
            53, 241, 37, 255, 172, 47, 42, 125, 175, 17, 139, 216, 107, 155, 25, 229, 247, 95, 173,
            238, 202, 72, 46, 20, 119, 45, 22, 190, 223, 36, 12, 32
        ]
    );
    for value in [&profile, &flow] {
        for length in 0..value.bytes.len() {
            let bytes = value.bytes.slice(..length);
            let truncated = CanonicalValue {
                id: ValueId(Sha256::digest(&bytes).into()),
                bytes,
            };
            ProfileKey::from_canonical(&truncated, kib(4)).unwrap_err();
            FlowKey::from_canonical(&truncated, kib(4)).unwrap_err();
        }
    }
    ProfileKey::new("app")
        .canonical(profile.bytes.len() - 1)
        .unwrap_err();
    ProfileKey::from_canonical(&profile, profile.bytes.len() - 1).unwrap_err();
    FlowKey::from_canonical(&flow, flow.bytes.len() - 1).unwrap_err();
    ProfileKey::new("").canonical(kib(4)).unwrap_err();
    FlowKey::Other {
        protocol: "".into(),
        operation: "query".into(),
    }
    .canonical(kib(4))
    .unwrap_err();
    let mut oversized = profile.clone();
    oversized.bytes = edited(&oversized.bytes, |bytes| bytes[17..25].fill(255));
    oversized.id.0 = Sha256::digest(&oversized.bytes).into();
    ProfileKey::from_canonical(&oversized, kib(4)).unwrap_err();
    let mut invalid = profile;
    invalid.bytes = edited(&invalid.bytes, |bytes| *bytes.last_mut().unwrap() = 2);
    invalid.id.0 = Sha256::digest(&invalid.bytes).into();
    ProfileKey::from_canonical(&invalid, kib(4)).unwrap_err();
}

#[test]
fn flow_round_trip_retains_explicit_fetch_and_connection_context() {
    for early_data in [None, Some(false), Some(true)] {
        for ip_family in [
            None,
            Some(ConnectionIpFamily::V4),
            Some(ConnectionIpFamily::V6),
        ] {
            let flow = FlowKey::Http {
                version: Version::HTTP_3,
                method: Method::POST,
                initiator: Some(RequestInitiator::Fetch),
                fetch: Some(FetchContext {
                    mode: Some("cors".into()),
                    site: Some("same-origin".into()),
                    destination: Some("".into()),
                    user_activation: None,
                }),
                connection: ConnectionContext {
                    resumption: ResumptionContext::Resumed,
                    early_data,
                    token_present: early_data,
                    ip_family,
                },
            };
            let value = flow.canonical(kib(4)).unwrap();
            assert_eq!(
                FlowKey::from_canonical(&value, kib(4))
                    .unwrap()
                    .canonical(kib(4))
                    .unwrap()
                    .id,
                value.id
            );
        }
    }
}

#[test]
fn http_flow_fixed_vectors_cover_all_owned_context_tags() {
    let expected = [
        [
            116, 13, 145, 26, 79, 250, 202, 46, 39, 9, 109, 139, 145, 204, 112, 140, 66, 125, 236,
            84, 172, 66, 55, 105, 32, 92, 74, 196, 223, 167, 210, 253,
        ],
        [
            137, 73, 1, 18, 78, 204, 165, 248, 253, 137, 148, 51, 66, 70, 133, 24, 83, 17, 151,
            213, 142, 182, 44, 254, 233, 39, 158, 89, 114, 13, 164, 240,
        ],
        [
            146, 232, 87, 127, 30, 247, 191, 205, 204, 166, 161, 50, 45, 230, 36, 217, 169, 234,
            135, 185, 191, 116, 126, 199, 233, 63, 155, 35, 101, 55, 151, 109,
        ],
        [
            96, 44, 224, 104, 63, 16, 104, 74, 129, 200, 170, 25, 67, 221, 237, 48, 194, 82, 75,
            107, 158, 58, 141, 165, 12, 132, 233, 149, 134, 120, 205, 68,
        ],
        [
            52, 27, 97, 15, 249, 243, 162, 42, 237, 246, 64, 48, 164, 172, 19, 24, 18, 237, 250,
            212, 7, 104, 12, 238, 27, 1, 17, 155, 57, 26, 112, 161,
        ],
        [
            196, 35, 47, 215, 95, 50, 63, 43, 196, 114, 89, 77, 132, 56, 200, 235, 26, 208, 103,
            205, 183, 17, 111, 221, 199, 152, 226, 216, 215, 164, 56, 10,
        ],
    ];
    let versions = [
        Version::HTTP_09,
        Version::HTTP_10,
        Version::HTTP_11,
        Version::HTTP_2,
        Version::HTTP_3,
    ];
    let initiators = [
        None,
        Some(RequestInitiator::Navigate),
        Some(RequestInitiator::Form),
        Some(RequestInitiator::Xhr),
        Some(RequestInitiator::Fetch),
        Some(RequestInitiator::Ws),
    ];
    let resumptions = [
        ResumptionContext::Unknown,
        ResumptionContext::Fresh,
        ResumptionContext::Resumed,
    ];
    let booleans = [None, Some(false), Some(true)];
    let families = [
        None,
        Some(ConnectionIpFamily::V4),
        Some(ConnectionIpFamily::V6),
    ];
    for (index, expected) in expected.into_iter().enumerate() {
        let fetch = match index {
            1 => Some(FetchContext {
                mode: Some("cors".into()),
                destination: Some("empty".into()),
                ..FetchContext::default()
            }),
            3 => Some(FetchContext {
                site: Some("same-origin".into()),
                user_activation: Some("?1".into()),
                ..FetchContext::default()
            }),
            5 => Some(FetchContext {
                mode: Some("".into()),
                site: Some("".into()),
                destination: Some("".into()),
                user_activation: Some("".into()),
            }),
            _ => None,
        };
        let flow = FlowKey::Http {
            version: versions[index % 5],
            method: if index == 5 {
                Method::from_bytes(b"CUSTOM").unwrap()
            } else {
                Method::GET
            },
            initiator: initiators[index],
            fetch,
            connection: ConnectionContext {
                resumption: resumptions[index % 3],
                early_data: booleans[index % 3],
                token_present: booleans[(index + 1) % 3],
                ip_family: families[(index + 2) % 3],
            },
        };
        let value = flow.canonical(kib(4)).unwrap();
        assert_eq!(value.id.0, expected, "vector {index}");
        assert_eq!(
            FlowKey::from_canonical(&value, kib(4))
                .unwrap()
                .canonical(kib(4))
                .unwrap()
                .bytes,
            value.bytes
        );
    }
}
