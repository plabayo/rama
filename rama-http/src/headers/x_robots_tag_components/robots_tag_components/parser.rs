use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag_components::RobotsTag;
use rama_core::error::OpaqueError;
use std::str::FromStr;

pub(in crate::headers) struct Parser<'a> {
    remaining: Option<&'a str>,
}

impl<'a> Parser<'a> {
    pub(in crate::headers) fn new(remaining: &'a str) -> Self {
        Self {
            remaining: Some(remaining.trim()),
        }
    }
}

impl<'a> Iterator for Parser<'_> {
    type Item = Result<RobotsTag, OpaqueError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut remaining = self.remaining?;

        let bot_name = match Self::parse_bot_name(&mut remaining) {
            Ok(bot_name) => bot_name,
            Err(e) => return Some(Err(e)),
        };

        let mut builder = RobotsTag::builder().bot_name(bot_name);

        while let Some((field, rest)) = remaining.split_once(',') {
            let field = field.trim();
            if field.is_empty() {
                continue;
            }

            match builder.add_field(field) {
                Ok(_) => {
                    remaining = rest.trim();
                }
                Err(e) if e.to_string().contains("not a valid robots tag field") => {
                    self.remaining = Some(remaining.trim());
                    return Some(builder.build());
                }
                Err(e) => return Some(Err(e)),
            }
        }

        Some(builder.build())
    }
}

impl Parser<'_> {
    fn parse_bot_name(remaining: &mut &str) -> Result<Option<HeaderValueString>, OpaqueError> {
        if let Some((bot_name_candidate, rest)) = remaining.split_once(':') {
            if !RobotsTag::is_valid_field_name(bot_name_candidate) {
                *remaining = rest.trim();
                return match HeaderValueString::from_str(bot_name_candidate) {
                    Ok(bot) => Ok(Some(bot)),
                    Err(e) => Err(OpaqueError::from_std(e)),
                };
            }
        }

        Ok(None)
    }
}
