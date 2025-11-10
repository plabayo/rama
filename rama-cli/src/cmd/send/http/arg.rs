use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::{HeaderValue, proto::h1::Http1HeaderName},
};

use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct HttpHeader {
    pub name: Http1HeaderName,
    pub value: HeaderValue,
}

impl FromStr for HttpHeader {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (raw_name, raw_value) = s
            .split_once(':')
            .context("split header string on colon (':')")?;

        Ok(Self {
            name: raw_name.parse().context("parse raw http header name")?,
            value: raw_value
                .trim_start()
                .parse()
                .context("parse raw http header value")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_header() {
        for (input, raw_name, raw_value) in [
            (
                "Content-Type: application/json",
                "Content-Type",
                "application/json",
            ),
            ("x-MAGIC-Header:       poof", "x-MAGIC-Header", "poof"),
            ("DNT: 1", "DNT", "1"),
            ("user-agent:    rama", "user-agent", "rama"),
        ] {
            let HttpHeader { name, value } = input.parse().unwrap();
            assert_eq!(name.as_str(), raw_name);
            assert_eq!(std::str::from_utf8(value.as_bytes()).unwrap(), raw_value);
        }
    }
}
