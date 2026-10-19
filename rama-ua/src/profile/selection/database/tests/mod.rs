use crate::{UserAgentKind, profile::format::input::UserAgentProfileInput};

use super::*;

#[test]
fn test_ua_db_empty() {
    let db = UserAgentDatabase::default();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
    assert!(db.iter_ua_str().next().is_none());
    assert!(db.get_exact_header_str("curl/8").next().is_none());
}

#[test]
fn exact_header_lookup_returns_every_profile_with_that_user_agent() {
    const UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0";
    let db: UserAgentDatabase = (0..3)
        .map(|_| UserAgentProfileInput::new(UA).try_into_profile().unwrap())
        .collect();
    assert_eq!(db.len(), 3);
    assert_eq!(db.iter_ua_str().collect::<Vec<_>>(), [UA]);
    assert_eq!(db.get_exact_header_str(UA).count(), 3);
    assert!(
        db.get_exact_header_str(UA)
            .all(|profile| profile.ua_kind == Some(UserAgentKind::Firefox))
    );
}

#[cfg(feature = "embed-profiles")]
#[test]
fn test_ua_db_embedded() {
    let db = UserAgentDatabase::try_embedded().unwrap();
    assert!(!db.is_empty());
    let all = db
        .candidates(ProfileCandidateFilter {
            client: None,
            platform: None,
            device: None,
            latest_versions: None,
            capabilities: ProfileCapabilities::default(),
        })
        .unwrap();
    assert_eq!(all.len(), db.len());
    let h3 = db
        .candidates(ProfileCandidateFilter {
            client: None,
            platform: None,
            device: None,
            latest_versions: None,
            capabilities: ProfileCapabilities {
                h3: true,
                tls_quic: true,
                quic: true,
                ..ProfileCapabilities::default()
            },
        })
        .unwrap();
    assert!(
        h3.iter()
            .any(|candidate| candidate.profile.ua_kind == Some(UserAgentKind::Firefox))
    );
    assert!(h3.iter().all(|candidate| {
        let components = &candidate.profile.captured.as_ref().unwrap().components;
        components.h3.is_some() && components.quic.is_some()
    }));
}
