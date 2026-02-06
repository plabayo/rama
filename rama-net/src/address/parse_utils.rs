use rama_core::error::{BoxError, ErrorExt};
use std::net::{IpAddr, Ipv6Addr};

pub(crate) fn split_port_from_str(s: &str) -> Result<(&str, u16), BoxError> {
    if let Some(colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        match s[colon + 1..].parse() {
            Ok(port) => Ok((&s[..colon], port)),
            Err(err) => Err(err.context("parse port as u16")),
        }
    } else {
        Err(BoxError::from("missing port"))
    }
}

pub(crate) fn try_to_parse_str_to_ip(value: &str) -> Option<IpAddr> {
    if value.starts_with('[') || value.ends_with(']') {
        let value = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))?;
        Some(IpAddr::V6(value.parse::<Ipv6Addr>().ok()?))
    } else {
        value.parse::<IpAddr>().ok()
    }
}
