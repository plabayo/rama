use crate::headers::util::csv::{fmt_comma_delimited, split_csv_str};
use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag::rule::Rule;
use rama_core::error::OpaqueError;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    bot_name: Option<HeaderValueString>,
    indexing_rules: Vec<Rule>,
}

impl Element {
    pub fn new() -> Self {
        Self {
            bot_name: None,
            indexing_rules: Vec::new(),
        }
    }

    pub fn with_bot_name(bot_name: HeaderValueString) -> Self {
        Self {
            bot_name: Some(bot_name),
            indexing_rules: Vec::new(),
        }
    }

    pub fn add_indexing_rule(&mut self, indexing_rule: Rule) {
        self.indexing_rules.push(indexing_rule);
    }

    pub fn bot_name(&self) -> Option<&HeaderValueString> {
        self.bot_name.as_ref()
    }

    pub fn indexing_rules(&self) -> &[Rule] {
        &self.indexing_rules
    }
}

impl std::fmt::Display for Element {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.bot_name() {
            None => fmt_comma_delimited(f, self.indexing_rules().iter()),
            Some(bot) => {
                write!(f, "{bot}: ")?;
                fmt_comma_delimited(f, self.indexing_rules().iter())
            }
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
