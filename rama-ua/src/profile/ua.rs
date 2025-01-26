use crate::{DeviceKind, UserAgentKind};

#[derive(Debug)]
#[cfg_attr(feature = "memory-db", derive(venndb::VennDB))]
pub struct UserAgentProfile {
    #[cfg_attr(feature = "memory-db", venndb(key))]
    pub header: String,
    #[cfg_attr(feature = "memory-db", venndb(filter))]
    pub kind: Option<UserAgentKind>,
    #[cfg_attr(feature = "memory-db", venndb(filter))]
    pub platform_kind: Option<crate::PlatformKind>,
    #[cfg_attr(feature = "memory-db", venndb(filter))]
    pub device_kind: Option<DeviceKind>,
    pub version: Option<usize>,

    #[cfg(feature = "memory-db")]
    pub http_profiles: crate::HttpProfileDB,
    #[cfg(not(feature = "memory-db"))]
    pub http_profiles: Vec<crate::HttpProfile>,

    #[cfg(all(feature = "tls", feature = "memory-db"))]
    pub tls_profiles: crate::TlsProfileDB,
    #[cfg(all(feature = "tls", not(feature = "memory-db")))]
    pub tls_profiles: Vec<crate::TlsProfile>,
}

// TODO support serialize / deseralize fo this struct and its property types
// TODO implement querying profiles
// TODO add query tests
//
// TODO: do we really need VennDB here, we might be better off flattening it different...
// also we need to take into account the market spread
//
// TODO should we strip out heavy duplicate data? e.g. there is probably a lot of duplication
// in the TlsProfileData (inner) and HttpProfileData (inner)
//
// TODO: do we need to really take into account initiator, fetch and Resource type?
