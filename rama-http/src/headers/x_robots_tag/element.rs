use crate::headers::util::csv::{fmt_comma_delimited, split_csv_str};
use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag::rule::Rule;
use rama_core::error::{ErrorContext, OpaqueError};
use regex::Regex;
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
        let regex = Regex::new(r"^\s*([^:]+?):\s*(.+)$")
            .context("Failed to compile a regular expression")?;

        let mut bot_name = None;
        let mut rules_str = s;

        if let Some(captures) = regex.captures(s) {
            let bot_name_candidate = captures
                .get(1)
                .context("Failed to capture the target bot name")?
                .as_str()
                .trim();
            
            if bot_name_candidate.parse::<Rule>().is_err() {
                bot_name = HeaderValueString::from_string(bot_name_candidate.to_owned());
                rules_str = captures
                    .get(2)
                    .context("Failed to capture the indexing rules")?
                    .as_str()
                    .trim();
            }
        }

        let indexing_rules = split_csv_str(rules_str)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse the indexing rules")?;

        Ok(Self {
            bot_name,
            indexing_rules,
        })
    }
}
