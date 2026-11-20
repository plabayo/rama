#[cfg_attr(
    not(any(
        feature = "boring-native-verification",
        feature = "rustls-native-verification"
    )),
    expect(
        dead_code,
        reason = "material is only consumed when a TLS backend is enabled"
    )
)]
mod controller;
#[cfg_attr(
    not(any(
        feature = "boring-native-verification",
        feature = "rustls-native-verification"
    )),
    expect(
        dead_code,
        reason = "material is only consumed when a TLS backend is enabled"
    )
)]
mod snapshot;
mod trigger;
mod worker;

pub use controller::NativeTrustRefreshError;
pub(super) use controller::{NativeTrustReload, NativeTrustScope};
pub(super) use snapshot::NativeTrustSnapshot;
#[cfg(unix)]
pub use trigger::UnixSignalTrigger;
pub use trigger::{
    ChannelReloadClosed, ChannelReloadSender, ChannelReloadTrigger, IntoNativeTrustReloadTrigger,
};
pub use worker::NativeTrustStoreChanges;

#[cfg(feature = "boring-native-verification")]
mod boring;
#[cfg(feature = "rustls-native-verification")]
mod rustls;
#[cfg(any(
    feature = "boring-native-verification",
    feature = "rustls-native-verification"
))]
mod verification;

#[cfg(any(
    feature = "boring-native-verification",
    feature = "rustls-native-verification"
))]
use verification::StoreRoots;
#[cfg(feature = "boring-native-verification")]
pub use verification::{
    boring_native_root_store, boring_server_verification, boring_server_verification_async,
};
#[cfg(feature = "rustls-native-verification")]
pub use verification::{
    rustls_native_root_store, rustls_server_verification, rustls_server_verification_async,
    rustls_webpki_root_store,
};
