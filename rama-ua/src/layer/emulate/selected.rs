use rama_core::extensions::Extension;
use rama_utils::str::arcstr::ArcStr;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    PlatformKind, UserAgentKind,
    profile::model::ua::{UserAgentProfile, UserAgentRuntimeProfile},
};

#[derive(Debug, Clone, Serialize, Deserialize, Extension)]
#[extension(tags(ua))]
/// Identity of the profile selected by [`ProfileEmulateLayer`](super::ProfileEmulateLayer).
pub struct SelectedUserAgentProfile {
    /// The user agent header of the selected profile.
    pub user_agent_header: Option<ArcStr>,

    /// The kind of [`crate::UserAgent`]
    pub ua_kind: Option<UserAgentKind>,
    /// The version of the [`crate::UserAgent`]
    pub ua_version: Option<usize>,
    /// The platform the [`crate::UserAgent`] is running on.
    pub platform: Option<PlatformKind>,

    /// Runtime (meta) info about the UA profile of the [`crate::UserAgent`].
    pub runtime: Option<Arc<UserAgentRuntimeProfile>>,
}

impl From<&UserAgentProfile> for SelectedUserAgentProfile {
    fn from(profile: &UserAgentProfile) -> Self {
        Self {
            user_agent_header: profile.ua_str().map(Into::into),
            ua_kind: profile.ua_kind,
            ua_version: profile.ua_version,
            platform: profile.platform,
            runtime: profile.runtime.clone(),
        }
    }
}
