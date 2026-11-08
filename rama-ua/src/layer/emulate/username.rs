use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extensions,
    username::{UsernameLabelParser, UsernameLabelState},
};

use crate::{DeviceKind, PlatformKind, UserAgent, UserAgentKind};

const LABEL_PREFIX: &str = "ua_";

/// Parses `ua_<word>` username labels into a [`UserAgent`] that selects the
/// profile [`ProfileEmulateLayer`] emulates.
///
/// Each label names a browser, platform or device, as the User-Agent
/// classifier reads them: `john-ua_chrome-ua_macos` selects Chrome on macOS and
/// `john-ua_mobile` any mobile profile. Without such labels no [`UserAgent`] is
/// inserted and selection stays unrestricted. A word that names no class, or
/// one that contradicts an earlier label, aborts parsing.
///
/// Key and value share one label, so it combines with other parsers as a tuple,
/// such as the proxy filter parser of `rama-proxy`: `john-country-ua-ua_firefox`
/// selects a Ukrainian proxy and a Firefox profile.
///
/// [`ProfileEmulateLayer`]: super::ProfileEmulateLayer
#[derive(Debug, Clone, Default)]
pub struct ProfileSelectorUsernameParser {
    client: Option<UserAgentKind>,
    platform: Option<PlatformKind>,
    device: Option<DeviceKind>,
}

impl ProfileSelectorUsernameParser {
    /// Create a new [`ProfileSelectorUsernameParser`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn conflicts<T: PartialEq>(new: Option<T>, old: Option<T>) -> bool {
    matches!((new, old), (Some(new), Some(old)) if new != old)
}

impl UsernameLabelParser for ProfileSelectorUsernameParser {
    type Error = BoxError;

    fn parse_label(&mut self, label: &str) -> UsernameLabelState {
        let Some(word) = label
            .get(..LABEL_PREFIX.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(LABEL_PREFIX))
            .map(|_| label[LABEL_PREFIX.len()..].to_ascii_lowercase())
        else {
            return UsernameLabelState::Ignored;
        };

        let agent = UserAgent::new(word);
        let (client, platform, device) = (agent.ua_kind(), agent.platform(), agent.device());
        // A platform implies its device class, so only a different value conflicts.
        if (client.is_none() && platform.is_none() && device.is_none())
            || conflicts(client, self.client)
            || conflicts(platform, self.platform)
            || conflicts(device, self.device)
        {
            return UsernameLabelState::Abort;
        }
        self.client = self.client.or(client);
        self.platform = self.platform.or(platform);
        self.device = self.device.or(device);
        UsernameLabelState::Used
    }

    fn build(self, ext: &Extensions) -> Result<(), Self::Error> {
        let Self {
            client,
            platform,
            device,
        } = self;
        // Canonical class names keep the hint short, whatever the labels spelled.
        let words: Vec<&str> = [
            client.map(|kind| kind.as_str()),
            platform.map(|kind| kind.as_str()),
            device.map(|kind| kind.as_str()),
        ]
        .into_iter()
        .flatten()
        .collect();
        if words.is_empty() {
            return Ok(());
        }
        let agent = UserAgent::new(words.join(" "));
        if agent.ua_kind() != client || agent.platform() != platform || agent.device() != device {
            return Err(BoxError::from_static_str(
                "profile selector labels do not round-trip through the User-Agent classifier",
            ));
        }
        ext.insert(agent);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceKind, PlatformKind, UserAgentKind};
    use rama_core::username::parse_username;
    use rama_proxy::{ProxyFilter, ProxyFilterUsernameParser};

    fn parse(username: &str) -> Result<(String, Option<UserAgent>), BoxError> {
        let ext = Extensions::new();
        let name = parse_username(&ext, ProfileSelectorUsernameParser::new(), username)?;
        Ok((name, ext.get_ref::<UserAgent>().cloned()))
    }

    fn parse_with_proxy_filter(
        username: &str,
    ) -> Result<(Option<UserAgent>, Option<ProxyFilter>), BoxError> {
        let ext = Extensions::new();
        let name = parse_username(
            &ext,
            (
                ProxyFilterUsernameParser::new(),
                ProfileSelectorUsernameParser::new(),
            ),
            username,
        )?;
        assert_eq!(name, "john");
        Ok((
            ext.get_ref::<UserAgent>().cloned(),
            ext.get_ref::<ProxyFilter>().cloned(),
        ))
    }

    #[test]
    fn labels_name_the_client_platform_and_device_to_select() {
        let (name, agent) = parse("john-ua_chrome-ua_macos").unwrap();
        assert_eq!(name, "john");
        let agent = agent.unwrap();
        assert_eq!(agent.ua_kind(), Some(UserAgentKind::Chromium));
        assert_eq!(agent.platform(), Some(PlatformKind::MacOS));

        let agent = parse("john-UA_Mobile").unwrap().1.unwrap();
        assert_eq!(agent.ua_kind(), None);
        assert_eq!(agent.device(), Some(DeviceKind::Mobile));
    }

    #[test]
    fn no_labels_leave_selection_unrestricted() {
        assert!(parse("john").unwrap().1.is_none());
    }

    #[test]
    fn unknown_and_repeated_classes_are_rejected() {
        for username in [
            "john-ua_netscape",
            "john-ua_",
            "john-ua_chrome-ua_firefox",
            "john-ua_macos-ua_windows",
        ] {
            parse(username).unwrap_err();
        }
    }

    #[test]
    fn every_accepted_class_survives_into_the_selector() {
        let mut long_client = String::from("john-ua_chrome");
        long_client.push_str(&"x".repeat(506));
        long_client.push_str("-ua_macos");
        let agent = parse(&long_client).unwrap().1.unwrap();
        assert_eq!(agent.ua_kind(), Some(UserAgentKind::Chromium));
        assert_eq!(agent.platform(), Some(PlatformKind::MacOS));

        for client in ["chrome", "firefox", "safari"] {
            for platform in ["windows", "macos", "linux", "android", "ios"] {
                for device in ["desktop", "mobile"] {
                    let username = format!("john-ua_{client}-ua_{platform}-ua_{device}");
                    let words = [client, platform, device].map(UserAgent::new);
                    let merge = |class: fn(&UserAgent) -> Option<String>| {
                        let mut classes = words.iter().filter_map(class);
                        let first = classes.next();
                        classes
                            .all(|other| Some(&other) == first.as_ref())
                            .then_some(first)
                    };
                    let expected = (
                        merge(|agent| agent.ua_kind().map(|kind| kind.to_string())),
                        merge(|agent| agent.platform().map(|kind| kind.to_string())),
                        merge(|agent| agent.device().map(|kind| kind.to_string())),
                    );
                    match (parse(&username), expected) {
                        (Ok((_, Some(agent))), (Some(kind), Some(platform), Some(device))) => {
                            assert_eq!(agent.ua_kind().map(|v| v.to_string()), kind);
                            assert_eq!(agent.platform().map(|v| v.to_string()), platform);
                            assert_eq!(agent.device().map(|v| v.to_string()), device);
                        }
                        (Err(_), (kind, platform, device)) => assert!(
                            kind.is_none() || platform.is_none() || device.is_none(),
                            "{username} was rejected without a conflict"
                        ),
                        (parsed, _) => panic!("{username}: unexpected {parsed:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn proxy_filter_labels_and_profile_labels_stay_apart() {
        let (agent, filter) = parse_with_proxy_filter("john-country-ua-ua_firefox").unwrap();
        assert_eq!(agent.unwrap().ua_kind(), Some(UserAgentKind::Firefox));
        let filter = filter.unwrap();
        assert_eq!(filter.country.unwrap()[0].as_ref(), "ua");
        assert_eq!(filter.mobile, None);

        let (agent, filter) = parse_with_proxy_filter("john-ua_mobile").unwrap();
        assert_eq!(agent.unwrap().device(), Some(DeviceKind::Mobile));
        assert!(filter.is_none_or(|filter| filter.mobile.is_none()));

        let (agent, filter) = parse_with_proxy_filter("john-mobile-country-be").unwrap();
        assert!(agent.is_none());
        let filter = filter.unwrap();
        assert_eq!(filter.mobile, Some(true));
        assert_eq!(filter.country.unwrap()[0].as_ref(), "be");
    }
}
