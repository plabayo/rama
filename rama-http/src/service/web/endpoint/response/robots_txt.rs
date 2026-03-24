use std::{convert::Infallible, fmt, str::FromStr, time::Duration};

use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response};
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::submatch_ignore_ascii_case;

/// A typed `robots.txt` payload that can be parsed, inspected, serialized, and returned as a response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RobotsTxt {
    pub groups: Vec<RobotsGroup>,
    pub sitemaps: Vec<String>,
}

impl RobotsTxt {
    /// Create an empty [`RobotsTxt`] document.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            groups: Vec::new(),
            sitemaps: Vec::new(),
        }
    }

    /// Parse a `robots.txt` payload, ignoring malformed or invalid directives.
    #[must_use]
    pub fn parse(input: &str) -> Self {
        Self::parse_inner(input, false).unwrap_or_default()
    }

    /// Parse a `robots.txt` payload strictly.
    ///
    /// Unlike [`Self::parse`], this returns an error when a supported directive
    /// is malformed or has an invalid value.
    pub fn parse_strict(input: &str) -> Result<Self, RobotsDirectiveParseError> {
        Self::parse_inner(input, true)
    }

    fn parse_inner(input: &str, strict: bool) -> Result<Self, RobotsDirectiveParseError> {
        let mut robots = Self::new();
        let mut current_group = RobotsGroup::default();

        for (line_number, raw_line) in input.lines().enumerate() {
            let line_number = line_number + 1;
            let line = raw_line
                .split_once('#')
                .map(|(line, _)| line)
                .unwrap_or(raw_line)
                .trim();

            if line.is_empty() {
                continue;
            }

            let Some((directive, value)) = line.split_once(':') else {
                if strict {
                    return Err(RobotsDirectiveParseError::new(
                        line_number,
                        line,
                        "expected `name: value` directive",
                    ));
                }
                continue;
            };

            let directive = directive.trim();
            let value = value.trim();

            if directive.eq_ignore_ascii_case("user-agent") {
                if current_group.has_directives() {
                    robots.groups.push(current_group);
                    current_group = RobotsGroup::default();
                }
                current_group.user_agents.push(value.to_owned());
            } else if directive.eq_ignore_ascii_case("allow") {
                if !current_group.user_agents.is_empty() {
                    current_group.rules.push(RobotsRule::allow(value));
                }
            } else if directive.eq_ignore_ascii_case("disallow") {
                if !current_group.user_agents.is_empty() {
                    current_group.rules.push(RobotsRule::disallow(value));
                }
            } else if directive.eq_ignore_ascii_case("crawl-delay") {
                if !current_group.user_agents.is_empty() {
                    let seconds = match value.parse::<f64>() {
                        Ok(seconds) => seconds,
                        Err(_) if strict => {
                            return Err(RobotsDirectiveParseError::new(
                                line_number,
                                raw_line.trim(),
                                "invalid crawl-delay value",
                            ));
                        }
                        Err(_) => continue,
                    };
                    current_group.crawl_delay = Some(Duration::from_secs_f64(seconds));
                }
            } else if directive.eq_ignore_ascii_case("sitemap") {
                robots.sitemaps.push(value.to_owned());
            }
        }

        if !current_group.is_empty() {
            robots.groups.push(current_group);
        }

        Ok(robots)
    }

    generate_set_and_with! {
        /// Add a group to this `robots.txt` document.
        pub fn group(mut self, group: RobotsGroup) -> Self {
            self.groups.push(group);
            self
        }
    }

    generate_set_and_with! {
        /// Add a sitemap entry to this `robots.txt` document.
        pub fn sitemap(mut self, sitemap: impl Into<String>) -> Self {
            self.sitemaps.push(sitemap.into());
            self
        }
    }

    /// Resolve the effective rules for the given user-agent.
    #[must_use]
    pub fn rules_for(&self, user_agent: &str) -> RobotsClientRules<'_> {
        let best_match_len = self
            .groups
            .iter()
            .filter_map(|group| group.match_len(user_agent))
            .max()
            .unwrap_or_default();

        let groups = self
            .groups
            .iter()
            .filter(|group| group.match_len(user_agent) == Some(best_match_len))
            .collect();

        RobotsClientRules {
            groups,
            sitemaps: &self.sitemaps,
        }
    }
}

impl FromStr for RobotsTxt {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl fmt::Display for RobotsTxt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (group_index, group) in self.groups.iter().enumerate() {
            if group_index > 0 {
                writeln!(f)?;
            }
            write!(f, "{group}")?;
        }

        if !self.sitemaps.is_empty() && !self.groups.is_empty() {
            writeln!(f)?;
        }

        for (index, sitemap) in self.sitemaps.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "Sitemap: {sitemap}")?;
        }

        Ok(())
    }
}

impl IntoResponse for RobotsTxt {
    fn into_response(self) -> Response {
        (
            Headers::single(ContentType::text_utf8()),
            Body::from(self.to_string()),
        )
            .into_response()
    }
}

/// A user-agent group in a `robots.txt` document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RobotsGroup {
    pub user_agents: Vec<String>,
    pub rules: Vec<RobotsRule>,
    pub crawl_delay: Option<Duration>,
}

impl RobotsGroup {
    /// Create a group for a single user-agent token.
    #[must_use]
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agents: vec![user_agent.into()],
            rules: Vec::new(),
            crawl_delay: None,
        }
    }

    generate_set_and_with! {
        /// Add an additional user-agent token to this group.
        pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
            self.user_agents.push(user_agent.into());
            self
        }
    }

    generate_set_and_with! {
        /// Add an `Allow` directive to this group.
        pub fn allow(mut self, path: impl Into<String>) -> Self {
            self.rules.push(RobotsRule::allow(path));
            self
        }
    }

    generate_set_and_with! {
        /// Add a `Disallow` directive to this group.
        pub fn disallow(mut self, path: impl Into<String>) -> Self {
            self.rules.push(RobotsRule::disallow(path));
            self
        }
    }

    generate_set_and_with! {
        /// Set the crawl delay for this group.
        pub fn crawl_delay(mut self, delay: Duration) -> Self {
            self.crawl_delay = Some(delay);
            self
        }
    }

    fn is_empty(&self) -> bool {
        self.user_agents.is_empty() && self.rules.is_empty() && self.crawl_delay.is_none()
    }

    fn has_directives(&self) -> bool {
        !self.rules.is_empty() || self.crawl_delay.is_some()
    }

    fn match_len(&self, user_agent: &str) -> Option<usize> {
        self.user_agents
            .iter()
            .filter_map(|agent| agent_match_len(agent, user_agent))
            .max()
    }
}

impl fmt::Display for RobotsGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for user_agent in &self.user_agents {
            writeln!(f, "User-agent: {user_agent}")?;
        }
        for rule in &self.rules {
            writeln!(f, "{rule}")?;
        }
        if let Some(delay) = self.crawl_delay {
            write!(f, "Crawl-delay: {}", format_duration(delay))?;
        }
        Ok(())
    }
}

/// A single allow/disallow rule from a `robots.txt` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobotsRule {
    pub kind: RobotsRuleKind,
    pub path: String,
}

impl RobotsRule {
    /// Create an `Allow` rule.
    #[must_use]
    pub fn allow(path: impl Into<String>) -> Self {
        Self {
            kind: RobotsRuleKind::Allow,
            path: path.into(),
        }
    }

    /// Create a `Disallow` rule.
    #[must_use]
    pub fn disallow(path: impl Into<String>) -> Self {
        Self {
            kind: RobotsRuleKind::Disallow,
            path: path.into(),
        }
    }

    /// Returns `true` if this rule matches the provided path.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        robots_path_matches(&self.path, path)
    }

    fn match_len(&self) -> usize {
        self.path
            .chars()
            .filter(|ch| *ch != '*' && *ch != '$')
            .count()
    }
}

impl fmt::Display for RobotsRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.path)
    }
}

/// The kind of a robots rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RobotsRuleKind {
    Allow,
    Disallow,
}

impl fmt::Display for RobotsRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("Allow"),
            Self::Disallow => f.write_str("Disallow"),
        }
    }
}

/// The effective rules for a specific user-agent.
#[derive(Debug, Clone)]
pub struct RobotsClientRules<'a> {
    groups: Vec<&'a RobotsGroup>,
    sitemaps: &'a [String],
}

impl<'a> RobotsClientRules<'a> {
    /// The matching groups used to compute these effective rules.
    #[must_use]
    pub fn groups(&self) -> &[&'a RobotsGroup] {
        &self.groups
    }

    /// The declared sitemap URLs.
    #[must_use]
    pub fn sitemaps(&self) -> &'a [String] {
        self.sitemaps
    }

    /// Returns the first matching crawl-delay, if present.
    #[must_use]
    pub fn crawl_delay(&self) -> Option<Duration> {
        self.groups.iter().find_map(|group| group.crawl_delay)
    }

    /// Returns `true` if the given path is allowed.
    ///
    /// Longest matching rule wins. If there is a tie, `Allow` wins over `Disallow`.
    #[must_use]
    pub fn is_allowed(&self, path: &str) -> bool {
        let mut best_rule: Option<&RobotsRule> = None;

        for group in &self.groups {
            for rule in &group.rules {
                if !rule.matches(path) {
                    continue;
                }

                match best_rule {
                    Some(best) if best.match_len() > rule.match_len() => {}
                    Some(best)
                        if best.match_len() == rule.match_len()
                            && best.kind == RobotsRuleKind::Allow => {}
                    _ => best_rule = Some(rule),
                }
            }
        }

        !matches!(
            best_rule,
            Some(RobotsRule {
                kind: RobotsRuleKind::Disallow,
                ..
            })
        )
    }
}

/// Parse error returned for invalid supported `robots.txt` directives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobotsDirectiveParseError {
    pub line: usize,
    pub directive: String,
    pub reason: &'static str,
}

impl RobotsDirectiveParseError {
    fn new(line: usize, directive: impl Into<String>, reason: &'static str) -> Self {
        Self {
            line,
            directive: directive.into(),
            reason,
        }
    }
}

impl fmt::Display for RobotsDirectiveParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to parse robots.txt directive on line {} (`{}`): {}",
            self.line, self.directive, self.reason
        )
    }
}

impl std::error::Error for RobotsDirectiveParseError {}

fn agent_match_len(agent: &str, user_agent: &str) -> Option<usize> {
    let agent = agent.trim();

    if agent == "*" {
        Some(0)
    } else if submatch_ignore_ascii_case(user_agent, agent) {
        Some(agent.len())
    } else {
        None
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();

    if seconds.fract() == 0.0 {
        duration.as_secs().to_string()
    } else {
        let mut value = seconds.to_string();
        while value.contains('.') && value.ends_with('0') {
            value.pop();
        }
        value
    }
}

fn robots_path_matches(pattern: &str, path: &str) -> bool {
    let anchored = pattern.ends_with('$');
    let pattern = if anchored {
        &pattern[..pattern.len().saturating_sub(1)]
    } else {
        pattern
    };

    wildcard_match(pattern.as_bytes(), path.as_bytes(), anchored)
}

fn wildcard_match(pattern: &[u8], text: &[u8], anchored: bool) -> bool {
    if pattern.is_empty() {
        return !anchored || text.is_empty();
    }

    if pattern[0] == b'*' {
        let rest = &pattern[1..];
        for offset in 0..=text.len() {
            if wildcard_match(rest, &text[offset..], anchored) {
                return true;
            }
        }
        return false;
    }

    if text.is_empty() || pattern[0] != text[0] {
        return false;
    }

    wildcard_match(&pattern[1..], &text[1..], anchored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header;

    #[test]
    fn parse_and_render_robots_txt() {
        let robots = RobotsTxt::parse(
            r#"
            # comment
            User-agent: Googlebot
            Allow: /public/
            Disallow: /private/
            Crawl-delay: 1.5

            User-agent: *
            Disallow: /tmp/

            Sitemap: https://example.com/sitemap.xml
            "#,
        );

        assert_eq!(robots.groups.len(), 2);
        assert_eq!(robots.sitemaps, ["https://example.com/sitemap.xml"]);
        assert_eq!(
            robots.groups[0].crawl_delay,
            Some(Duration::from_secs_f64(1.5))
        );

        let rendered = robots.to_string();
        assert!(rendered.contains("User-agent: Googlebot"));
        assert!(rendered.contains("Allow: /public/"));
        assert!(rendered.contains("Disallow: /tmp/"));
        assert!(rendered.contains("Sitemap: https://example.com/sitemap.xml"));
    }

    #[test]
    fn parse_is_lossy_for_invalid_directives() {
        let robots = RobotsTxt::parse(
            r#"
            User-agent: *
            Crawl-delay: nope
            Disallow: /private/
            this is not a directive
            Sitemap: https://example.com/sitemap.xml
            "#,
        );

        assert_eq!(robots.groups.len(), 1);
        assert_eq!(robots.groups[0].crawl_delay, None);
        assert_eq!(
            robots.groups[0].rules,
            vec![RobotsRule::disallow("/private/")]
        );
        assert_eq!(robots.sitemaps, ["https://example.com/sitemap.xml"]);
    }

    #[test]
    fn parse_strict_errors_on_invalid_supported_directive() {
        let err = RobotsTxt::parse_strict(
            r#"
            User-agent: *
            Crawl-delay: nope
            "#,
        )
        .unwrap_err();

        assert_eq!(err.line, 3);
        assert_eq!(err.reason, "invalid crawl-delay value");
    }

    #[test]
    fn client_rules_pick_most_specific_user_agent_and_rule() {
        let robots = RobotsTxt::new()
            .with_group(
                RobotsGroup::new("*")
                    .with_disallow("/private/")
                    .with_allow("/private/public/"),
            )
            .with_group(RobotsGroup::new("googlebot").with_disallow("/search"))
            .with_group(RobotsGroup::new("googlebot-news").with_allow("/search/news"));

        let googlebot_news = robots.rules_for("Mozilla/5.0 Googlebot-News");
        assert!(googlebot_news.is_allowed("/search/news"));
        assert!(googlebot_news.is_allowed("/search"));

        let generic = robots.rules_for("SomeBot");
        assert!(generic.is_allowed("/private/public/page"));
        assert!(!generic.is_allowed("/private/page"));
        assert!(generic.is_allowed("/elsewhere"));
    }

    #[test]
    fn client_rules_merge_groups_with_equal_user_agent_specificity() {
        let robots = RobotsTxt::new()
            .with_group(RobotsGroup::new("googlebot").with_disallow("/search"))
            .with_group(RobotsGroup::new("googlebot").with_allow("/search/public"));

        let rules = robots.rules_for("Googlebot");
        assert!(!rules.is_allowed("/search"));
        assert!(rules.is_allowed("/search/public"));
    }

    #[test]
    fn robots_rule_supports_wildcards_and_end_anchors() {
        let robots = RobotsTxt::new().with_group(
            RobotsGroup::new("*")
                .with_disallow("/*.php$")
                .with_allow("/public/*.php$"),
        );

        let rules = robots.rules_for("test-bot");
        assert!(!rules.is_allowed("/index.php"));
        assert!(rules.is_allowed("/index.php/extra"));
        assert!(rules.is_allowed("/public/index.php"));
    }

    #[test]
    fn robots_txt_into_response_sets_text_content_type() {
        let response = RobotsTxt::new()
            .with_group(RobotsGroup::new("*").with_disallow("/private"))
            .into_response();

        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn parse_real_world_github_excerpt() {
        let robots = RobotsTxt::parse(
            r#"
# If you would like to crawl GitHub contact us via https://support.github.com?tags=dotcom-robots
User-agent: bingbot
Disallow: /account-login
Disallow: */tarball/
Disallow: /copilot/

User-agent: baidu
crawl-delay: 1

User-agent: *
Disallow: /*/*/pulse
Disallow: /*/commits/*?author
Disallow: /*.git$
Disallow: /search$
Disallow: /*q=
Allow: /*?tab=achievements&achievement=*
Disallow: /copilot/
"#,
        );

        assert_eq!(robots.groups.len(), 3);
        assert_eq!(robots.groups[0].user_agents, ["bingbot"]);
        assert_eq!(robots.groups[1].user_agents, ["baidu"]);
        assert_eq!(robots.groups[1].crawl_delay, Some(Duration::from_secs(1)));

        let baidu = robots.rules_for("baidu");
        assert_eq!(baidu.crawl_delay(), Some(Duration::from_secs(1)));

        let generic = robots.rules_for("some crawler");
        assert!(!generic.is_allowed("/owner/repo/pulse"));
        assert!(!generic.is_allowed("/repo.git"));
        assert!(!generic.is_allowed("/search"));
        assert!(!generic.is_allowed("/search?q=rust"));
        assert!(generic.is_allowed("/user?tab=achievements&achievement=pair-extraordinaire"));
        assert!(!generic.is_allowed("/copilot/"));
    }
}
