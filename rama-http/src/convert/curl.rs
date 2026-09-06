//! Convert HTTP requests with or without their payload into a valid curl
//! command.
//!
//! Proxy export reads the middleware-visible
//! [`ProxyRoute`]. Compose
//! [`ProxyRoutesLayer`][rama_net::client::ProxyRoutesLayer] after all proxy
//! route selectors and before exporting when inputs may carry an ordered route
//! plan.

use std::borrow::Cow;
use std::fmt::{self, Write};
use std::process::{Command, Stdio};

use base64::Engine as _;

use crate::header::ACCEPT_ENCODING;
use crate::headers::{HeaderEncode, ProxyAuthorization};
use crate::{HeaderName, Method, Version};

use rama_core::bytes::Bytes;
use rama_http_types::HttpRequestParts;
use rama_net::client::ProxyRoute;
use rama_net::mode::{ConnectIpMode, DnsResolveIpMode};
use rama_net::uri::Uri;
use rama_net::user::ProxyCredential;
use rama_net::{AuthorityInputExt, ProtocolInputExt};

/// Policies used while converting an HTTP request into curl arguments.
///
/// The default favors faithful request replay without requiring shell-specific
/// helper programs: methods and HTTP versions are explicit, an explicit `Host`
/// is preserved, curl manages body framing, and encoded responses are
/// decompressed when the request contains `Accept-Encoding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct CurlExportOptions {
    response_decompression: bool,
    http_version: bool,
    explicit_method: bool,
    preserve_host_header: bool,
    preserve_framing_headers: bool,
    proxy_tunnel: bool,
    script_compatibility: CurlScriptCompatibility,
}

impl CurlExportOptions {
    /// Options favoring faithful request replay and curl-only command strings.
    pub const fn faithful() -> Self {
        Self {
            response_decompression: true,
            http_version: true,
            explicit_method: true,
            preserve_host_header: true,
            preserve_framing_headers: false,
            proxy_tunnel: false,
            script_compatibility: CurlScriptCompatibility::CrossPlatform,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable curl's `--proxytunnel` option for HTTP(S) proxies.
        pub fn proxy_tunnel(mut self, enabled: bool) -> Self {
            self.proxy_tunnel = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable curl's automatic response decompression.
        pub fn response_decompression(mut self, enabled: bool) -> Self {
            self.response_decompression = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable communicating the request's recorded HTTP version to curl.
        ///
        /// HTTP/0.9 only permits matching responses; HTTPS HTTP/2 remains negotiated.
        pub fn http_version(mut self, enabled: bool) -> Self {
            self.http_version = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable always rendering the request method explicitly.
        ///
        /// Methods that curl would otherwise change because a body is present are
        /// still rendered explicitly when this option is disabled.
        pub fn explicit_method(mut self, enabled: bool) -> Self {
            self.explicit_method = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable preserving an explicit `Host` header.
        pub fn host_header(mut self, enabled: bool) -> Self {
            self.preserve_host_header = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable preserving `Content-Length` and `Transfer-Encoding`.
        ///
        /// Disabled by default because curl should normally derive framing from the
        /// selected body source.
        pub fn framing_headers(mut self, enabled: bool) -> Self {
            self.preserve_framing_headers = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Select the compatibility target used when rendering a command string.
        ///
        /// This option does not affect the shell-independent [`Command`] APIs.
        pub fn script_compatibility(
            mut self,
            compatibility: CurlScriptCompatibility,
        ) -> Self {
            self.script_compatibility = compatibility;
            self
        }
    }
}

impl Default for CurlExportOptions {
    fn default() -> Self {
        Self::faithful()
    }
}

/// Compatibility target for an exported curl command string.
///
/// This controls shell syntax and whether a self-contained script may use
/// platform-specific facilities to preserve arbitrary payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CurlScriptCompatibility {
    /// Emit a pure curl invocation without shell-specific helper programs.
    ///
    /// "Cross-platform" refers to executable dependencies: shell quoting itself
    /// is not universal. Select a concrete target when its syntax matters, or
    /// use the [`Command`] APIs to avoid a shell entirely.
    ///
    /// Inline payloads must be UTF-8 and cannot contain NUL. Use
    /// [`CurlScriptPayloadMode::Stdin`] or [`CurlScriptPayloadMode::File`] for
    /// arbitrary bytes.
    #[default]
    CrossPlatform,
    /// Target a Unix shell and embed inline payload bytes through `base64`.
    Unix,
    /// Target PowerShell and embed inline payload bytes through a temporary file.
    PowerShell,
}

/// How a request payload is referenced by an exported curl command string.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CurlScriptPayloadMode {
    /// Embed the payload in the exported script.
    ///
    /// With [`CurlScriptCompatibility::CrossPlatform`], this uses `--data-raw`
    /// and rejects NUL or invalid UTF-8. Platform-specific targets can use
    /// their native facilities to embed arbitrary bytes losslessly.
    #[default]
    Inline,
    /// Read exact payload bytes from stdin using `--data-binary @-`.
    Stdin,
    /// Read exact payload bytes from a caller-managed sidecar file.
    File(String),
}

impl CurlScriptPayloadMode {
    /// Create a sidecar-file payload mode for the given command-visible path.
    pub fn file(path: impl Into<String>) -> Self {
        Self::File(path.into())
    }
}

/// Create a `curl` command string for the given [`HttpRequestParts`].
pub fn cmd_string_for_request_parts(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
) -> String {
    cmd_string_for_request_parts_with_options(parts, CurlExportOptions::default())
}

/// Create a `curl` command string using explicit export policies.
pub fn cmd_string_for_request_parts_with_options(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
    options: CurlExportOptions,
) -> String {
    let mut cmd = CurlScriptWriter::new(
        curl_script_program(options.script_compatibility),
        options.script_compatibility,
    );
    write_curl_command_for_request_parts(&mut cmd, parts, CurlPayload::None, options);
    cmd.finish()
}

/// Create a pure `curl` command string for the given request and inline payload.
///
/// This function refuses payloads that cannot be represented losslessly as a
/// command-line argument. Use [`prepare_cmd_for_request_parts_and_payload`] for
/// arbitrary bytes without a shell, or use
/// [`try_cmd_string_for_request_parts_and_payload_with_options`] to select a
/// platform-specific script target or external payload source.
pub fn try_cmd_string_for_request_parts_and_payload(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
    payload: &Bytes,
) -> Result<String, CurlPayloadRequiresStdin> {
    try_cmd_string_for_request_parts_and_payload_with_options(
        parts,
        payload,
        CurlExportOptions::default(),
        &CurlScriptPayloadMode::default(),
    )
}

/// Create a curl command string using explicit request and payload policies.
pub fn try_cmd_string_for_request_parts_and_payload_with_options(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
    payload: &Bytes,
    options: CurlExportOptions,
    payload_mode: &CurlScriptPayloadMode,
) -> Result<String, CurlPayloadRequiresStdin> {
    let (prefix, payload_source, suffix) = match (payload.is_empty(), payload_mode) {
        (true, _) => (
            Cow::Borrowed(curl_script_program(options.script_compatibility)),
            CurlPayload::None,
            None,
        ),
        (false, CurlScriptPayloadMode::Stdin) => (
            Cow::Borrowed(curl_script_program(options.script_compatibility)),
            CurlPayload::Stdin,
            None,
        ),
        (false, CurlScriptPayloadMode::File(path)) => (
            Cow::Borrowed(curl_script_program(options.script_compatibility)),
            CurlPayload::File(path.as_str()),
            None,
        ),
        (false, CurlScriptPayloadMode::Inline) => match options.script_compatibility {
            CurlScriptCompatibility::CrossPlatform => {
                if payload.contains(&0) || std::str::from_utf8(payload).is_err() {
                    return Err(CurlPayloadRequiresStdin);
                }
                (Cow::Borrowed("curl"), CurlPayload::Inline(payload), None)
            }
            CurlScriptCompatibility::Unix => {
                if !payload.contains(&0) && std::str::from_utf8(payload).is_ok() {
                    (Cow::Borrowed("curl"), CurlPayload::Inline(payload), None)
                } else {
                    let mut prefix = "printf %s ".to_owned();
                    write_unix_shell_single_quoted(
                        &mut prefix,
                        base64::engine::general_purpose::STANDARD.encode(payload),
                    );
                    // `-d` is supported by GNU, BSD/macOS and BusyBox base64.
                    prefix.push_str(" | base64 -d | curl");
                    (Cow::Owned(prefix), CurlPayload::Stdin, None)
                }
            }
            CurlScriptCompatibility::PowerShell => {
                if !payload.contains(&0) && std::str::from_utf8(payload).is_ok() {
                    (
                        Cow::Borrowed(curl_script_program(CurlScriptCompatibility::PowerShell)),
                        CurlPayload::Inline(payload),
                        None,
                    )
                } else {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
                    let prefix = format!(
                        "$__ramaCurlPayload = [IO.Path]::GetTempFileName(); try {{ \
                     [IO.File]::WriteAllBytes($__ramaCurlPayload, \
                     [Convert]::FromBase64String('{encoded}')); {}",
                        curl_script_program(CurlScriptCompatibility::PowerShell),
                    );
                    (
                        Cow::Owned(prefix),
                        CurlPayload::PowerShellTempFile,
                        Some(" } finally { Remove-Item -LiteralPath $__ramaCurlPayload }"),
                    )
                }
            }
        },
    };
    let mut cmd = CurlScriptWriter::new(prefix, options.script_compatibility);
    write_curl_command_for_request_parts(&mut cmd, parts, payload_source, options);
    let mut cmd = cmd.finish();
    if let Some(suffix) = suffix {
        cmd.push_str(suffix);
    }
    Ok(cmd)
}

/// Create a `curl` [`Command`] for the given [`HttpRequestParts`].
pub fn cmd_for_request_parts(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
) -> Command {
    cmd_for_request_parts_with_options(parts, CurlExportOptions::default())
}

/// Create a `curl` [`Command`] using explicit export policies.
pub fn cmd_for_request_parts_with_options(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
    options: CurlExportOptions,
) -> Command {
    let mut cmd = Command::new("curl");
    write_curl_command_for_request_parts(&mut cmd, parts, CurlPayload::None, options);
    cmd
}

/// Create a `curl` [`Command`] for the given [`HttpRequestParts`] and payload bytes.
///
/// Invalid UTF-8 is replaced lossily for backwards compatibility. Prefer
/// [`prepare_cmd_for_request_parts_and_payload`] for arbitrary body bytes.
pub fn cmd_for_request_parts_and_payload(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
    payload: &Bytes,
) -> Command {
    cmd_for_request_parts_and_payload_with_options(parts, payload, CurlExportOptions::default())
}

/// Create a `curl` [`Command`] with an inline payload and explicit policies.
pub fn cmd_for_request_parts_and_payload_with_options(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
    payload: &Bytes,
    options: CurlExportOptions,
) -> Command {
    let mut cmd = Command::new("curl");
    write_curl_command_for_request_parts(&mut cmd, parts, CurlPayload::Inline(payload), options);
    cmd
}

/// A `curl` process command together with bytes that must be written to its stdin.
///
/// This representation keeps arbitrary request bodies out of process arguments,
/// which cannot contain NUL bytes. It is shell-independent and cross-platform.
#[must_use]
pub struct PreparedCurlCommand {
    command: Command,
    stdin: Option<Bytes>,
}

impl PreparedCurlCommand {
    /// Return the configured `curl` process command.
    pub fn command(&self) -> &Command {
        &self.command
    }

    /// Return the configured `curl` process command mutably.
    pub fn command_mut(&mut self) -> &mut Command {
        &mut self.command
    }

    /// Return bytes that must be written to the spawned child's stdin.
    pub fn stdin(&self) -> Option<&Bytes> {
        self.stdin.as_ref()
    }

    /// Split into the process command and its optional stdin payload.
    pub fn into_parts(self) -> (Command, Option<Bytes>) {
        (self.command, self.stdin)
    }
}

/// Prepare a shell-independent `curl` command that receives its payload on stdin.
///
/// Non-empty payloads are represented as `--data-binary @-`; callers must write
/// [`PreparedCurlCommand::stdin`] to the spawned child's piped stdin.
pub fn prepare_cmd_for_request_parts_and_payload(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
    payload: &Bytes,
) -> PreparedCurlCommand {
    prepare_cmd_for_request_parts_and_payload_with_options(
        parts,
        payload,
        CurlExportOptions::default(),
    )
}

/// Prepare a shell-independent curl command using explicit export policies.
pub fn prepare_cmd_for_request_parts_and_payload_with_options(
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
    payload: &Bytes,
    options: CurlExportOptions,
) -> PreparedCurlCommand {
    let mut command = Command::new("curl");
    let stdin = if payload.is_empty() {
        write_curl_command_for_request_parts(&mut command, parts, CurlPayload::None, options);
        None
    } else {
        command.stdin(Stdio::piped());
        write_curl_command_for_request_parts(&mut command, parts, CurlPayload::Stdin, options);
        Some(payload.clone())
    };
    PreparedCurlCommand { command, stdin }
}

/// Error returned when the selected script policies cannot embed a payload
/// losslessly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurlPayloadRequiresStdin;

impl fmt::Display for CurlPayloadRequiresStdin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("curl payload requires stdin, a file, or a platform-specific target")
    }
}

impl std::error::Error for CurlPayloadRequiresStdin {}

#[derive(Clone, Copy)]
enum CurlPayload<'a> {
    None,
    Inline(&'a Bytes),
    Stdin,
    File(&'a str),
    PowerShellTempFile,
}

fn curl_script_program(compatibility: CurlScriptCompatibility) -> &'static str {
    match compatibility {
        CurlScriptCompatibility::PowerShell => {
            "& (Get-Command curl -CommandType Application).Source"
        }
        CurlScriptCompatibility::CrossPlatform | CurlScriptCompatibility::Unix => "curl",
    }
}

impl CurlPayload<'_> {
    fn is_non_empty(self) -> bool {
        match self {
            Self::None => false,
            Self::Inline(payload) => !payload.is_empty(),
            Self::Stdin | Self::File(_) | Self::PowerShellTempFile => true,
        }
    }
}

struct CurlScriptWriter {
    output: String,
    compatibility: CurlScriptCompatibility,
}

impl CurlScriptWriter {
    fn new(output: impl Into<String>, compatibility: CurlScriptCompatibility) -> Self {
        Self {
            output: output.into(),
            compatibility,
        }
    }

    fn finish(self) -> String {
        self.output
    }

    fn write_separator(&mut self) {
        match self.compatibility {
            CurlScriptCompatibility::PowerShell => {
                _ = write!(self.output, " `{}  ", rama_utils::str::NATIVE_NEWLINE);
            }
            CurlScriptCompatibility::CrossPlatform | CurlScriptCompatibility::Unix => {
                _ = write!(self.output, " \\{}  ", rama_utils::str::NATIVE_NEWLINE);
            }
        }
    }

    fn write_quoted(&mut self, value: impl fmt::Display) {
        match self.compatibility {
            CurlScriptCompatibility::PowerShell => {
                write_powershell_single_quoted(&mut self.output, value);
            }
            CurlScriptCompatibility::CrossPlatform | CurlScriptCompatibility::Unix => {
                write_unix_shell_single_quoted(&mut self.output, value);
            }
        }
    }
}

trait CurlCommandWriter {
    fn write_uri(&mut self, uri: Uri) -> &mut Self;
    fn write_single(&mut self, one: impl fmt::Display) -> &mut Self;
    fn write_tuple(
        &mut self,
        one: impl fmt::Display,
        two: impl fmt::Display,
        quote_value: bool,
    ) -> &mut Self;
    fn write_header(&mut self, key: HeaderName, value: Cow<'_, str>) -> &mut Self;
}

impl CurlCommandWriter for Command {
    // `Command::arg` passes each value as a distinct argv element straight to
    // the curl process (no shell), so values must NOT be quoted: any surrounding
    // quotes would become literal bytes of the argument. This is the dual of the
    // script writer below, which builds shell text and therefore must quote.
    fn write_uri(&mut self, uri: Uri) -> &mut Self {
        self.arg(uri.to_string())
    }

    fn write_single(&mut self, one: impl fmt::Display) -> &mut Self {
        self.arg(one.to_string())
    }

    fn write_tuple(
        &mut self,
        one: impl fmt::Display,
        two: impl fmt::Display,
        _quote_value: bool,
    ) -> &mut Self {
        // `quote_value` only governs shell-text quoting; argv needs none.
        self.arg(one.to_string()).arg(two.to_string())
    }

    fn write_header(&mut self, key: HeaderName, value: Cow<'_, str>) -> &mut Self {
        self.arg("-H").arg(format!("{key}: {value}"))
    }
}

impl CurlCommandWriter for CurlScriptWriter {
    fn write_uri(&mut self, uri: Uri) -> &mut Self {
        self.output.push(' ');
        self.write_quoted(uri);
        self
    }

    fn write_single(&mut self, one: impl fmt::Display) -> &mut Self {
        self.write_separator();
        _ = write!(self.output, "{one}");
        self
    }

    fn write_tuple(
        &mut self,
        one: impl fmt::Display,
        two: impl fmt::Display,
        quote_value: bool,
    ) -> &mut Self {
        self.write_separator();
        _ = write!(self.output, "{one} ");
        if quote_value {
            self.write_quoted(two);
        } else {
            _ = write!(self.output, "{two}");
        }
        self
    }

    fn write_header(&mut self, key: HeaderName, value: Cow<'_, str>) -> &mut Self {
        self.write_separator();
        self.output.push_str("-H ");
        self.write_quoted(format_args!("{key}: {value}"));
        self
    }
}

fn write_unix_shell_single_quoted(out: &mut String, value: impl fmt::Display) {
    struct ShellSingleQuoted<'a>(&'a mut String);

    impl fmt::Write for ShellSingleQuoted<'_> {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let mut start = 0;
            for (idx, ch) in value.char_indices() {
                if ch == '\'' {
                    self.0.push_str(&value[start..idx]);
                    self.0.push_str("'\\''");
                    start = idx + ch.len_utf8();
                }
            }
            self.0.push_str(&value[start..]);
            Ok(())
        }
    }

    out.push('\'');
    _ = write!(&mut ShellSingleQuoted(out), "{value}");
    out.push('\'');
}

fn write_powershell_single_quoted(out: &mut String, value: impl fmt::Display) {
    struct PowerShellSingleQuoted<'a>(&'a mut String);

    impl fmt::Write for PowerShellSingleQuoted<'_> {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let mut start = 0;
            for (idx, ch) in value.char_indices() {
                if ch == '\'' {
                    self.0.push_str(&value[start..idx]);
                    self.0.push_str("''");
                    start = idx + ch.len_utf8();
                }
            }
            self.0.push_str(&value[start..]);
            Ok(())
        }
    }

    out.push('\'');
    _ = write!(&mut PowerShellSingleQuoted(out), "{value}");
    out.push('\'');
}

fn write_curl_command_for_request_parts(
    writer: &mut impl CurlCommandWriter,
    parts: &(impl HttpRequestParts + AuthorityInputExt + ProtocolInputExt),
    payload: CurlPayload<'_>,
    options: CurlExportOptions,
) {
    let mut uri = parts.uri().clone();
    // Origin-form requests carry only a path; reconstruct the full URL for curl
    // from the request context's authority (+ scheme). Requests that already
    // carry an authority (absolute- or authority-form) are rendered as-is.
    if uri.authority().is_none()
        && let Some(authority) = parts.authority()
    {
        let protocol = parts.protocol();
        uri.set_authority(authority.without_default_port_for(protocol).into());
        if uri.scheme().is_none()
            && let Some(protocol) = protocol
        {
            uri.set_scheme(protocol.clone());
        }
    }
    writer.write_uri(uri);

    if options.response_decompression && parts.headers().contains_key(ACCEPT_ENCODING) {
        writer.write_single("--compressed");
    }

    if parts.method() == Method::HEAD {
        // Unlike `-X HEAD`, `--head` also tells curl not to wait for a response
        // body that a conforming HEAD server will never send.
        writer.write_single("--head");
    } else if options.explicit_method || parts.method() != Method::GET || payload.is_non_empty() {
        writer.write_tuple("-X", parts.method(), false);
    }

    if options.http_version {
        match parts.version() {
            Version::HTTP_09 => {
                writer.write_single("--http0.9");
            }
            Version::HTTP_10 => {
                writer.write_single("--http1.0");
            }
            Version::HTTP_11 => {
                writer.write_single("--http1.1");
            }
            Version::HTTP_2 => {
                writer.write_single("--http2-prior-knowledge");
            }
            Version::HTTP_3 => {
                writer.write_single("--http3-only");
            }
        }
    }

    if let Some(route) = parts.extensions().get_ref::<ProxyRoute>()
        && let Some(proxy_addr) = route.proxy_address()
    {
        writer.write_tuple("-x", proxy_addr, true);
        if options.proxy_tunnel
            && proxy_addr
                .protocol
                .as_ref()
                .is_none_or(|protocol| protocol.is_http())
        {
            writer.write_single("--proxytunnel");
        }
        if let Some(ProxyCredential::Bearer(bearer)) = &proxy_addr.credential
            && let Some(value) = ProxyAuthorization(bearer.clone()).encode_to_value()
        {
            let s_value = String::from_utf8_lossy(value.as_bytes());
            writer.write_tuple(
                "--proxy-header",
                format_args!("{}: {s_value}", crate::header::PROXY_AUTHORIZATION),
                true,
            );
        }
    }

    match (
        parts.extensions().get_ref::<DnsResolveIpMode>(),
        parts.extensions().get_ref::<ConnectIpMode>(),
    ) {
        (Some(DnsResolveIpMode::SingleIpV4), _)
        | (
            None | Some(DnsResolveIpMode::DualPreferIpV4 | DnsResolveIpMode::Dual),
            Some(ConnectIpMode::Ipv4),
        ) => {
            // force ipv4
            writer.write_single("-4");
        }
        (Some(DnsResolveIpMode::SingleIpV6), _)
        | (
            None | Some(DnsResolveIpMode::DualPreferIpV4 | DnsResolveIpMode::Dual),
            Some(ConnectIpMode::Ipv6),
        ) => {
            // force ipv6
            writer.write_single("-6");
        }
        _ => (), // nothing that can be done
    }

    for (key, value) in parts.headers().ordered_iter() {
        let skip_header = match key.standard() {
            Some(crate::header::StandardHeader::Host) => !options.preserve_host_header,
            Some(
                crate::header::StandardHeader::ContentLength
                | crate::header::StandardHeader::TransferEncoding,
            ) => !options.preserve_framing_headers,
            _ => false,
        };
        if skip_header {
            // Let curl derive the authority and body framing from the URL and
            // selected payload source; replaying captured framing can conflict.
            continue;
        }

        let s_value = String::from_utf8_lossy(value.as_bytes());
        writer.write_header(key.clone(), s_value);
    }

    match payload {
        CurlPayload::Inline(payload) if !payload.is_empty() => {
            writer.write_tuple(
                "--data-raw",
                String::from_utf8_lossy(payload.as_ref()),
                true,
            );
        }
        CurlPayload::Stdin => {
            writer.write_tuple("--data-binary", "@-", true);
        }
        CurlPayload::File(path) => {
            writer.write_tuple("--data-binary", format_args!("@{path}"), true);
        }
        CurlPayload::PowerShellTempFile => {
            writer.write_tuple("--data-binary", "('@' + $__ramaCurlPayload)", false);
        }
        CurlPayload::None | CurlPayload::Inline(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use rama_net::Protocol;
    use rama_net::address::{HostWithPort, ProxyAddress};
    use rama_net::client::ProxyRoute;
    use rama_net::user::credentials::{basic, bearer};

    use crate::body::util::BodyExt;
    use crate::layer::har;

    use super::*;

    #[tokio::test]
    async fn test_cmd_string_for_request_parts_from_har() {
        struct TestCase {
            description: &'static str,
            input_har_request: &'static str,
            expected_cmd_string: String,
        }

        for test_case in [
            TestCase {
                description: "GET example.com",
                input_har_request: r##"{
    "bodySize": 0,
    "method": "GET",
    "url": "https://example.com/",
    "httpVersion": "HTTP/2",
    "headers": [
        {
            "name": "Host",
            "value": "example.com"
        },
        {
            "name": "User-Agent",
            "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0"
        },
        {
            "name": "Accept",
            "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        },
        {
            "name": "Accept-Language",
            "value": "en-US,en;q=0.5"
        },
        {
            "name": "Accept-Encoding",
            "value": "gzip, deflate, br, zstd"
        },
        {
            "name": "Sec-GPC",
            "value": "1"
        },
        {
            "name": "Upgrade-Insecure-Requests",
            "value": "1"
        },
        {
            "name": "Connection",
            "value": "keep-alive"
        },
        {
            "name": "Sec-Fetch-Dest",
            "value": "document"
        },
        {
            "name": "Sec-Fetch-Mode",
            "value": "navigate"
        },
        {
            "name": "Sec-Fetch-Site",
            "value": "none"
        },
        {
            "name": "Sec-Fetch-User",
            "value": "?1"
        },
        {
            "name": "Priority",
            "value": "u=0, i"
        },
        {
            "name": "Pragma",
            "value": "no-cache"
        },
        {
            "name": "Cache-Control",
            "value": "no-cache"
        }
    ],
    "cookies": [],
    "queryString": [],
    "headersSize": 504
}"##,
                expected_cmd_string: format!(
                    r##"curl 'https://example.com/' \{NL}  --compressed \{NL}  -X GET \{NL}  --http2-prior-knowledge \{NL}  -H 'Host: example.com' \{NL}  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0' \{NL}  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \{NL}  -H 'Accept-Language: en-US,en;q=0.5' \{NL}  -H 'Accept-Encoding: gzip, deflate, br, zstd' \{NL}  -H 'Sec-GPC: 1' \{NL}  -H 'Upgrade-Insecure-Requests: 1' \{NL}  -H 'Connection: keep-alive' \{NL}  -H 'Sec-Fetch-Dest: document' \{NL}  -H 'Sec-Fetch-Mode: navigate' \{NL}  -H 'Sec-Fetch-Site: none' \{NL}  -H 'Sec-Fetch-User: ?1' \{NL}  -H 'Priority: u=0, i' \{NL}  -H 'Pragma: no-cache' \{NL}  -H 'Cache-Control: no-cache'"##,
                    NL = rama_utils::str::NATIVE_NEWLINE
                ),
            },
            TestCase {
                description: "POST form request for ramaproxy FP",
                input_har_request: r##"{
    "bodySize": 19,
    "method": "POST",
    "url": "https://fp.ramaproxy.org/form",
    "httpVersion": "HTTP/2",
    "headers": [
    {
        "name": "Host",
        "value": "fp.ramaproxy.org"
    },
    {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0"
    },
    {
        "name": "Accept",
        "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    },
    {
        "name": "Accept-Language",
        "value": "en-US,en;q=0.5"
    },
    {
        "name": "Accept-Encoding",
        "value": "gzip, deflate, br, zstd"
    },
    {
        "name": "Content-Type",
        "value": "application/x-www-form-urlencoded"
    },
    {
        "name": "Content-Length",
        "value": "19"
    },
    {
        "name": "Origin",
        "value": "https://fp.ramaproxy.org"
    },
    {
        "name": "Sec-GPC",
        "value": "1"
    },
    {
        "name": "Connection",
        "value": "keep-alive"
    },
    {
        "name": "Referer",
        "value": "https://fp.ramaproxy.org/report"
    },
    {
        "name": "Cookie",
        "value": "rama-fp=ready"
    },
    {
        "name": "Upgrade-Insecure-Requests",
        "value": "1"
    },
    {
        "name": "Sec-Fetch-Dest",
        "value": "document"
    },
    {
        "name": "Sec-Fetch-Mode",
        "value": "navigate"
    },
    {
        "name": "Sec-Fetch-Site",
        "value": "same-origin"
    },
    {
        "name": "Sec-Fetch-User",
        "value": "?1"
    },
    {
        "name": "Priority",
        "value": "u=0, i"
    },
    {
        "name": "Pragma",
        "value": "no-cache"
    },
    {
        "name": "Cache-Control",
        "value": "no-cache"
    },
    {
        "name": "TE",
        "value": "trailers"
    }
    ],
    "cookies": [
    {
        "name": "rama-fp",
        "value": "ready"
    }
    ],
    "queryString": [],
    "headersSize": 689,
    "postData": {
    "mimeType": "application/x-www-form-urlencoded",
    "params": [
        {
        "name": "source",
        "value": "web"
        },
        {
        "name": "rating",
        "value": "3"
        }
    ],
    "text": "source=web&rating=3"
    }
}"##,
                expected_cmd_string: format!(
                    r##"curl 'https://fp.ramaproxy.org/form' \{NL}  --compressed \{NL}  -X POST \{NL}  --http2-prior-knowledge \{NL}  -H 'Host: fp.ramaproxy.org' \{NL}  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0' \{NL}  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \{NL}  -H 'Accept-Language: en-US,en;q=0.5' \{NL}  -H 'Accept-Encoding: gzip, deflate, br, zstd' \{NL}  -H 'Content-Type: application/x-www-form-urlencoded' \{NL}  -H 'Origin: https://fp.ramaproxy.org' \{NL}  -H 'Sec-GPC: 1' \{NL}  -H 'Connection: keep-alive' \{NL}  -H 'Referer: https://fp.ramaproxy.org/report' \{NL}  -H 'Cookie: rama-fp=ready' \{NL}  -H 'Upgrade-Insecure-Requests: 1' \{NL}  -H 'Sec-Fetch-Dest: document' \{NL}  -H 'Sec-Fetch-Mode: navigate' \{NL}  -H 'Sec-Fetch-Site: same-origin' \{NL}  -H 'Sec-Fetch-User: ?1' \{NL}  -H 'Priority: u=0, i' \{NL}  -H 'Pragma: no-cache' \{NL}  -H 'Cache-Control: no-cache' \{NL}  -H 'TE: trailers' \{NL}  --data-raw 'source=web&rating=3'"##,
                    NL = rama_utils::str::NATIVE_NEWLINE
                ),
            },
        ] {
            // put input together
            let har_request: har::spec::Request = serde_json::from_str(test_case.input_har_request)
                .unwrap_or_else(|err| {
                    panic!(
                        "expect testcase '{}' har request to deserialize: {err}",
                        test_case.description
                    )
                });
            let request: crate::Request = har_request.try_into().unwrap_or_else(|err| {
                panic!(
                    "expect testcase '{}' har request to convert into a http request: {err}",
                    test_case.description
                )
            });

            let (parts, body) = request.into_parts();
            let payload = body.collect().await.unwrap().to_bytes();

            let cmd_string = if payload.is_empty() {
                cmd_string_for_request_parts(&parts)
            } else {
                try_cmd_string_for_request_parts_and_payload(&parts, &payload).unwrap()
            };

            assert_eq!(
                test_case.expected_cmd_string, cmd_string,
                "testcase '{}'",
                test_case.description
            );
        }
    }

    #[test]
    fn test_cmd_string_for_request_with_http_proxy_no_auth() {
        let (parts, _) = crate::Request::builder()
            .uri(Uri::parse_authority_form("example.com").unwrap())
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            protocol: None,
            address: HostWithPort::local_ipv4(8080),
            credential: None,
        }));

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  -X GET \{NL}  --http1.1 \{NL}  -x '127.0.0.1:8080'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn proxy_tunnel_option_is_emitted_only_for_http_proxies() {
        for (proxy, expected) in [
            ("http://proxy.example:8080", true),
            ("https://proxy.example:8443", true),
            ("socks5://proxy.example:1080", false),
        ] {
            let (parts, _) = crate::Request::builder()
                .uri("http://origin.example/path")
                .body(())
                .unwrap()
                .into_parts();
            parts
                .extensions
                .insert(ProxyRoute::Proxy(proxy.parse::<ProxyAddress>().unwrap()));

            let command = cmd_string_for_request_parts_with_options(
                &parts,
                CurlExportOptions::default().with_proxy_tunnel(true),
            );
            assert_eq!(command.contains("--proxytunnel"), expected, "{command}");
        }
    }

    #[test]
    fn test_cmd_string_for_request_with_ipv4_preference() {
        let (parts, _) = crate::Request::builder()
            .uri(Uri::parse_authority_form("example.com").unwrap())
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(DnsResolveIpMode::SingleIpV4);

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  -X GET \{NL}  --http1.1 \{NL}  -4"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_with_ipv6_preference() {
        let (parts, _) = crate::Request::builder()
            .uri(Uri::parse_authority_form("example.com").unwrap())
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(DnsResolveIpMode::SingleIpV6);

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  -X GET \{NL}  --http1.1 \{NL}  -6"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_with_http_proxy_with_auth_basic_only_username() {
        let (parts, _) = crate::Request::builder()
            .uri(Uri::parse_authority_form("example.com").unwrap())
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            protocol: None,
            address: HostWithPort::local_ipv4(8080),
            credential: Some(ProxyCredential::Basic(basic!("john"))),
        }));

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  -X GET \{NL}  --http1.1 \{NL}  -x 'john@127.0.0.1:8080'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_with_http_proxy_with_auth_basic() {
        let (parts, _) = crate::Request::builder()
            .uri(Uri::parse_authority_form("example.com").unwrap())
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            protocol: None,
            address: HostWithPort::local_ipv4(8080),
            credential: Some(ProxyCredential::Basic(basic!("john", "secret"))),
        }));

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  -X GET \{NL}  --http1.1 \{NL}  -x 'john:secret@127.0.0.1:8080'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        )
    }

    #[test]
    fn test_cmd_string_for_request_with_http_proxy_with_auth_bearer() {
        let (parts, _) = crate::Request::builder()
            .uri(Uri::parse_authority_form("example.com").unwrap())
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            protocol: None,
            address: HostWithPort::local_ipv4(8080),
            credential: Some(ProxyCredential::Bearer(bearer!("abc123"))),
        }));

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  -X GET \{NL}  --http1.1 \{NL}  -x '127.0.0.1:8080' \{NL}  --proxy-header 'proxy-authorization: Bearer abc123'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_with_socks5_proxy() {
        let (parts, _) = crate::Request::builder()
            .version(Version::HTTP_3)
            .uri(Uri::parse_authority_form("example.com").unwrap())
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            protocol: Some(Protocol::SOCKS5),
            address: HostWithPort::local_ipv4(8080),
            credential: Some(ProxyCredential::Basic(basic!("user", "pass"))),
        }));

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  -X GET \{NL}  --http3-only \{NL}  -x 'socks5://user:pass@127.0.0.1:8080'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_shell_escapes_quoted_values() {
        let (parts, _) = crate::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/")
            .header("x-test", "a'b")
            .body(())
            .unwrap()
            .into_parts();

        let payload = Bytes::from_static(b"source='web'&rating=3");
        let s = try_cmd_string_for_request_parts_and_payload(&parts, &payload).unwrap();

        assert_eq!(
            s,
            format!(
                r##"curl 'https://example.com/' \{NL}  -X POST \{NL}  --http1.1 \{NL}  -H 'x-test: a'\''b' \{NL}  --data-raw 'source='\''web'\''&rating=3'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_get_with_payload_preserves_method() {
        let (parts, _) = crate::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/search")
            .body(())
            .unwrap()
            .into_parts();

        let s = try_cmd_string_for_request_parts_and_payload(
            &parts,
            &Bytes::from_static(br#"{"query":"rama"}"#),
        )
        .unwrap();

        assert_eq!(
            s,
            format!(
                r##"curl 'https://example.com/search' \{NL}  -X GET \{NL}  --http1.1 \{NL}  --data-raw '{{"query":"rama"}}'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_try_cmd_string_rejects_payloads_that_require_stdin() {
        let (parts, _) = crate::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/upload")
            .body(())
            .unwrap()
            .into_parts();

        assert_eq!(
            try_cmd_string_for_request_parts_and_payload(
                &parts,
                &Bytes::from_static(b"invalid: \xff"),
            ),
            Err(CurlPayloadRequiresStdin),
        );
        assert_eq!(
            try_cmd_string_for_request_parts_and_payload(
                &parts,
                &Bytes::from_static(b"contains\0nul"),
            ),
            Err(CurlPayloadRequiresStdin),
        );

        let text = Bytes::from_static(b"source=web&rating=3");
        assert!(
            try_cmd_string_for_request_parts_and_payload(&parts, &text)
                .unwrap()
                .contains("--data-raw 'source=web&rating=3'")
        );
    }

    #[test]
    fn test_default_export_options_are_faithful_and_configurable() {
        assert_eq!(CurlExportOptions::default(), CurlExportOptions::faithful());

        let (parts, _) = crate::Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_2)
            .uri("https://example.com/path")
            .header("accept-encoding", "gzip")
            .header("host", "virtual.example")
            .header("content-length", "7")
            .header("transfer-encoding", "chunked")
            .body(())
            .unwrap()
            .into_parts();

        let faithful = cmd_string_for_request_parts(&parts);
        assert!(faithful.contains("-X GET"));
        assert!(faithful.contains("--http2-prior-knowledge"));
        assert!(faithful.contains("host: virtual.example"));
        assert!(faithful.contains("--compressed"));
        assert!(!faithful.contains("content-length:"));
        assert!(!faithful.contains("transfer-encoding:"));

        let mut customized_options = CurlExportOptions::default()
            .with_response_decompression(false)
            .with_http_version(false)
            .with_explicit_method(false);
        customized_options
            .set_host_header(false)
            .set_framing_headers(true);
        let customized = cmd_string_for_request_parts_with_options(&parts, customized_options);
        assert!(!customized.contains("--compressed"));
        assert!(!customized.contains("-X GET"));
        assert!(!customized.contains("--http2-prior-knowledge"));
        assert!(!customized.contains("host: virtual.example"));
        assert!(customized.contains("content-length: 7"));
        assert!(customized.contains("transfer-encoding: chunked"));
    }

    #[test]
    fn test_script_payload_modes_cover_stdin_and_file() {
        let (parts, _) = crate::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/upload")
            .body(())
            .unwrap()
            .into_parts();
        let payload = Bytes::from_static(b"\0\xfftail\n");
        let options = CurlExportOptions::default();

        let stdin = try_cmd_string_for_request_parts_and_payload_with_options(
            &parts,
            &payload,
            options,
            &CurlScriptPayloadMode::Stdin,
        )
        .unwrap();
        assert!(stdin.starts_with("curl "));
        assert!(stdin.contains("--data-binary '@-'"));
        assert!(!stdin.contains("base64"));

        let file = try_cmd_string_for_request_parts_and_payload_with_options(
            &parts,
            &payload,
            options,
            &CurlScriptPayloadMode::file("flow's body.bin"),
        )
        .unwrap();
        assert!(file.starts_with("curl "));
        assert!(file.contains("--data-binary '@flow'\\''s body.bin'"));
        assert!(!file.contains("base64"));
    }

    #[test]
    fn test_unix_compatibility_embeds_inline_payload_as_base64() {
        let (parts, _) = crate::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/upload")
            .body(())
            .unwrap()
            .into_parts();
        let payload = Bytes::from_static(b"\0\xfftail\n");
        let unix = try_cmd_string_for_request_parts_and_payload_with_options(
            &parts,
            &payload,
            CurlExportOptions::default().with_script_compatibility(CurlScriptCompatibility::Unix),
            &CurlScriptPayloadMode::Inline,
        )
        .unwrap();
        assert!(unix.starts_with("printf %s 'AP90YWlsCg==' | base64 -d | curl "));
        assert!(unix.contains("--data-binary '@-'"));
        assert!(!unix.contains('\u{fffd}'));
    }

    #[test]
    fn test_platform_scripts_keep_text_payloads_readable() {
        let (parts, _) = crate::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/upload")
            .body(())
            .unwrap()
            .into_parts();
        let payload = Bytes::from_static(b"plain text");

        for compatibility in [
            CurlScriptCompatibility::Unix,
            CurlScriptCompatibility::PowerShell,
        ] {
            let script = try_cmd_string_for_request_parts_and_payload_with_options(
                &parts,
                &payload,
                CurlExportOptions::default().with_script_compatibility(compatibility),
                &CurlScriptPayloadMode::Inline,
            )
            .unwrap();
            assert!(script.contains("--data-raw 'plain text'"));
            assert!(!script.contains("base64"));
            assert!(!script.contains("GetTempFileName"));
        }
    }

    #[test]
    fn test_head_uses_curl_head_mode_instead_of_custom_method() {
        let (parts, _) = crate::Request::builder()
            .method(Method::HEAD)
            .uri("https://example.com/health")
            .body(())
            .unwrap()
            .into_parts();

        let script = cmd_string_for_request_parts(&parts);
        assert!(script.contains("--head"));
        assert!(!script.contains("-X HEAD"));

        let command = cmd_for_request_parts(&parts);
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|arg| arg == "--head"));
        assert!(!args.windows(2).any(|args| args == ["-X", "HEAD"]));
    }

    #[test]
    fn test_powershell_compatibility_uses_native_syntax_and_exact_payload() {
        let (parts, _) = crate::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/a'b")
            .header("x-test", "a'b")
            .body(())
            .unwrap()
            .into_parts();
        let payload = Bytes::from_static(b"\0\xfftail\n");
        let powershell = try_cmd_string_for_request_parts_and_payload_with_options(
            &parts,
            &payload,
            CurlExportOptions::default()
                .with_script_compatibility(CurlScriptCompatibility::PowerShell),
            &CurlScriptPayloadMode::Inline,
        )
        .unwrap();

        assert!(powershell.starts_with(
            "$__ramaCurlPayload = [IO.Path]::GetTempFileName(); try { \
             [IO.File]::WriteAllBytes($__ramaCurlPayload, \
             [Convert]::FromBase64String('AP90YWlsCg==')); \
             & (Get-Command curl -CommandType Application).Source 'https://example.com/a''b'"
        ));
        assert!(powershell.contains(&format!(
            " `{}  -H 'x-test: a''b'",
            rama_utils::str::NATIVE_NEWLINE
        )));
        assert!(powershell.contains("--data-binary ('@' + $__ramaCurlPayload)"));
        assert!(powershell.ends_with(" } finally { Remove-Item -LiteralPath $__ramaCurlPayload }"));
        assert!(!powershell.contains('\u{fffd}'));
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_compatibility_round_trips_exact_bytes() {
        let (parts, _) = crate::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/upload")
            .body(())
            .unwrap()
            .into_parts();
        let payload = Bytes::from_static(b"\0\xfftail\n");
        let curl = try_cmd_string_for_request_parts_and_payload_with_options(
            &parts,
            &payload,
            CurlExportOptions::default().with_script_compatibility(CurlScriptCompatibility::Unix),
            &CurlScriptPayloadMode::Inline,
        )
        .unwrap();
        let dir = rama_utils::fs::tempdir().unwrap();
        let body_path = dir.path().join("body.bin");

        // Shadow curl so the opt-in Unix pipeline can be tested without making
        // a network request.
        let script = format!("curl() {{ cat > \"$CAPTURED_BODY\"; }}\n{curl}");
        let output = Command::new("sh")
            .arg("-c")
            .arg(script)
            .env("CAPTURED_BODY", &body_path)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "generated command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(std::fs::read(body_path).unwrap(), payload);
    }

    #[test]
    fn test_prepared_cmd_streams_arbitrary_payload_without_a_shell() {
        let (parts, _) = crate::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/upload")
            .body(())
            .unwrap()
            .into_parts();
        let payload = Bytes::from_static(b"\0\xfftail\n");

        let prepared = prepare_cmd_for_request_parts_and_payload(&parts, &payload);
        assert_eq!(prepared.command().get_program(), "curl");
        assert_eq!(prepared.stdin(), Some(&payload));

        let args: Vec<String> = prepared
            .command()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "-X" && pair[1] == "GET"),
            "GET must remain explicit for a streamed payload, got {args:?}",
        );
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "--data-binary" && pair[1] == "@-"),
            "stdin payload must use curl's byte-preserving input, got {args:?}",
        );
        assert!(
            args.iter().all(|arg| !arg.contains('\u{fffd}')),
            "payload bytes must never be converted lossily, got {args:?}",
        );
    }

    #[test]
    fn test_cmd_string_for_request_shell_escapes_uri() {
        // A single quote is a valid RFC 3986 sub-delim and reaches the URI
        // writer verbatim, so it must be shell-escaped like any other value.
        let (parts, _) = crate::Request::builder()
            .uri("http://example.com/a'b?x=y'z")
            .body(())
            .unwrap()
            .into_parts();

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'http://example.com/a'\''b?x=y'\''z' \{NL}  -X GET \{NL}  --http1.1"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_for_request_passes_unquoted_argv() {
        // The `Command` path executes curl directly (no shell), so values must
        // be passed as bare argv elements: surrounding shell quotes would become
        // literal bytes of the argument and break curl.
        let (parts, _) = crate::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/path?q=a'b")
            .header("x-test", "a'b")
            .body(())
            .unwrap()
            .into_parts();

        let cmd = cmd_for_request_parts_and_payload(&parts, &Bytes::from_static(b"source='web'"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        // URI, header value and --data-raw payload are all unquoted argv elements.
        assert!(
            args.contains(&"https://example.com/path?q=a'b".to_owned()),
            "uri must be a bare argv element, got {args:?}",
        );
        assert!(
            args.contains(&"x-test: a'b".to_owned()),
            "header must be a bare argv element, got {args:?}",
        );
        assert!(
            args.contains(&"source='web'".to_owned()),
            "payload must be a bare argv element, got {args:?}",
        );
        // No argv element should be wrapped in literal shell quotes.
        assert!(
            !args
                .iter()
                .any(|a| a.starts_with('\'') && a.ends_with('\'')),
            "no argv element may be shell-quoted, got {args:?}",
        );
    }

    #[test]
    fn test_cmd_for_get_with_payload_preserves_method() {
        let (parts, _) = crate::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/search")
            .body(())
            .unwrap()
            .into_parts();

        let cmd = cmd_for_request_parts_and_payload(&parts, &Bytes::from_static(b"query=rama"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(
            args.windows(2)
                .any(|pair| pair == ["-X".to_owned(), "GET".to_owned()]),
            "GET must stay explicit when curl receives a payload, got {args:?}",
        );
    }
}
