use crate::headers::x_robots_tag::rule::Rule;
use rama_core::error::OpaqueError;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    bot_name: Option<String>, // or `rama_ua::UserAgent` ???
    indexing_rule: Rule,
}

impl std::fmt::Display for Element {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.bot_name {
            None => write!(f, "{}", self.indexing_rule),
            Some(bot) => write!(f, "{}: {}", bot, self.indexing_rule),
        }
    }
}

impl FromStr for Element {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (bot_name, indexing_rule) = match Rule::from_str(s) {
            Ok(rule) => (None, Ok(rule)),
            Err(e) => match *s.split(":").map(str::trim).collect::<Vec<_>>().as_slice() {
                [bot_name, rule] => (Some(bot_name.to_owned()), rule.parse()),
                [bot_name, rule_name, rule_value] => (
                    Some(bot_name.to_owned()),
                    [rule_name, rule_value][..].try_into(),
                ),
                _ => (None, Err(e)),
            },
        };
        match indexing_rule {
            Ok(indexing_rule) => Ok(Element {
                bot_name,
                indexing_rule,
            }),
            Err(_) => Err(OpaqueError::from_display(
                "Failed to parse XRobotsTagElement",
            )),
        }
    }
}
