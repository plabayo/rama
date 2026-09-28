//! Internal helper shared by COEP and COOP header impls.
//!
//! Both headers carry the same wire shape: a single token, optionally
//! followed by RFC 8941 parameters. The only standardised parameter
//! across both is `report-to` (naming a Reporting-Endpoints entry), so
//! we parse just that one and ignore anything else — staying lenient
//! the way browsers do.

use std::borrow::Cow;
use std::fmt::{self, Write as _};

use rama_core::telemetry::tracing;

pub(super) struct SingleTokenWithReportTo<'a> {
    pub(super) token: &'a str,
    pub(super) report_to: Option<Cow<'static, str>>,
}

/// Parse `token [; report-to=<sf-string>] [; ignored=...]*` syntax.
///
/// Returns `None` on a structurally invalid input (empty token, dangling
/// equals, missing parameter name, malformed sf-string). Unknown parameter
/// names are silently dropped, as browsers do.
pub(super) fn parse_single_token_with_report_to(raw: &str) -> Option<SingleTokenWithReportTo<'_>> {
    let mut parts = split_parameters(raw);
    let token = parts.next().map(str::trim).filter(|t| !t.is_empty())?;
    let mut report_to: Option<Cow<'static, str>> = None;
    for raw_param in parts {
        let param = raw_param.trim();
        if param.is_empty() {
            continue;
        }
        let (name, raw_value) = param.split_once('=')?;
        if name.trim().eq_ignore_ascii_case("report-to") {
            let raw_value = raw_value.trim();
            // tolerate the unquoted token form too, as browsers do
            let value = if raw_value.starts_with('"') {
                parse_sf_string(raw_value)?
            } else if raw_value.contains('"') {
                // a bare token cannot hold a quote
                return None;
            } else {
                raw_value.to_owned()
            };
            if value.is_empty() {
                return None;
            }
            report_to = Some(Cow::Owned(value));
        }
    }
    Some(SingleTokenWithReportTo { token, report_to })
}

/// Split on `;` outside sf-strings.
fn split_parameters(raw: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(raw);
    std::iter::from_fn(move || {
        let s = rest.take()?;
        // `;` is ASCII, so byte offsets around it are char boundaries
        match unquoted_semicolon(s.as_bytes()) {
            Some(idx) => {
                rest = s.get(idx.saturating_add(1)..);
                s.get(..idx)
            }
            None => Some(s),
        }
    })
}

fn unquoted_semicolon(bytes: &[u8]) -> Option<usize> {
    let mut in_string = false;
    let mut escaped = false;
    bytes.iter().position(|&b| {
        if escaped {
            escaped = false;
            return false;
        }
        match b {
            b'\\' if in_string => {
                escaped = true;
                false
            }
            b'"' => {
                in_string = !in_string;
                false
            }
            b';' => !in_string,
            _ => false,
        }
    })
}

/// Decode one complete RFC 8941 §4.2.5 sf-string, quotes included.
fn parse_sf_string(raw: &str) -> Option<String> {
    let body = raw.strip_prefix('"')?;
    if let Some(plain) = body.strip_suffix('"')
        && plain
            .bytes()
            .all(|b| matches!(b, b' '..=b'~') && b != b'"' && b != b'\\')
    {
        return Some(plain.to_owned());
    }
    let mut chars = body.chars();
    let mut value = String::with_capacity(body.len());
    loop {
        match chars.next()? {
            '\\' => match chars.next()? {
                escaped @ ('"' | '\\') => value.push(escaped),
                _ => return None,
            },
            '"' => return chars.as_str().is_empty().then_some(value),
            c @ ' '..='~' => value.push(c),
            _ => return None,
        }
    }
}

/// Emit `<token>` or `<token>; report-to="<endpoint>"` (always
/// quoted on serialise, matching the canonical sf-string form).
pub(super) fn format_single_token_with_report_to(
    f: &mut fmt::Formatter<'_>,
    token: &str,
    report_to: Option<&str>,
) -> fmt::Result {
    f.write_str(token)?;
    let Some(endpoint) = report_to else {
        return Ok(());
    };
    // an sf-string only holds printable ASCII; drop reporting, not the policy
    if !endpoint.bytes().all(|b| matches!(b, b' '..=b'~')) {
        tracing::debug!("drop report-to endpoint that is not a valid sf-string");
        return Ok(());
    }
    f.write_str("; report-to=\"")?;
    if endpoint.contains(['"', '\\']) {
        for c in endpoint.chars() {
            if matches!(c, '"' | '\\') {
                f.write_char('\\')?;
            }
            f.write_char(c)?;
        }
    } else {
        f.write_str(endpoint)?;
    }
    f.write_char('"')
}
