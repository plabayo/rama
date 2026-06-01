//! Internal helper shared by COEP and COOP header impls.
//!
//! Both headers carry the same wire shape: a single token, optionally
//! followed by RFC 8941 parameters. The only standardised parameter
//! across both is `report-to` (naming a Reporting-Endpoints entry), so
//! we parse just that one and ignore anything else — staying lenient
//! the way browsers do.

use std::borrow::Cow;
use std::fmt;

pub(super) struct SingleTokenWithReportTo<'a> {
    pub(super) token: &'a str,
    pub(super) report_to: Option<Cow<'static, str>>,
}

/// Parse `token [; report-to=<sf-string>] [; ignored=...]*` syntax.
///
/// Returns `None` on a structurally invalid input (empty token, dangling
/// equals, missing parameter name). Unknown parameter names are
/// silently dropped — same behaviour browsers exhibit when an unknown
/// param appears on a recognised header.
pub(super) fn parse_single_token_with_report_to(raw: &str) -> Option<SingleTokenWithReportTo<'_>> {
    let mut parts = raw.split(';');
    let token = parts.next().map(str::trim).filter(|t| !t.is_empty())?;
    let mut report_to: Option<Cow<'static, str>> = None;
    for raw_param in parts {
        let param = raw_param.trim();
        if param.is_empty() {
            continue;
        }
        let mut eq = param.splitn(2, '=');
        let name = eq.next()?.trim();
        let raw_value = eq.next()?.trim();
        if name.eq_ignore_ascii_case("report-to") {
            // RFC 8941 sf-string is double-quoted; tolerate the
            // unquoted token form too since browsers do.
            let value = if let Some(stripped) = raw_value
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
            {
                stripped.to_owned()
            } else {
                raw_value.to_owned()
            };
            // Treat an empty endpoint as a malformed parameter rather
            // than a meaningful value.
            if value.is_empty() {
                return None;
            }
            report_to = Some(Cow::Owned(value));
        }
        // Unknown params: silently drop.
    }
    Some(SingleTokenWithReportTo { token, report_to })
}

/// Emit `<token>` or `<token>; report-to="<endpoint>"` (always
/// quoted on serialise, matching the canonical sf-string form).
pub(super) fn format_single_token_with_report_to(
    f: &mut fmt::Formatter<'_>,
    token: &str,
    report_to: Option<&str>,
) -> fmt::Result {
    f.write_str(token)?;
    if let Some(endpoint) = report_to {
        write!(f, "; report-to=\"{endpoint}\"")?;
    }
    Ok(())
}
