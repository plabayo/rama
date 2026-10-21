use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorExt as _},
    json::path::JsonPath,
    net::{Protocol, address::ProxyAddress, user::Basic},
    tls::boring::client::BoringRequestedTrustAnchors,
    ua::profile::model::runtime_hints::RequestInitiator,
    utils::str::NonEmptyStr,
};

use clap::Args;
use std::{convert::Infallible, path::PathBuf, str::FromStr};

use super::uri::parse_user_uri;

pub mod http;

mod arg;
mod layer;
mod next;

pub async fn run(cfg: SendCommand) -> Result<(), BoxError> {
    let following = next::following_requests(&cfg)?;
    // The last request selects the protocol; earlier --next requests are HTTP.
    let last = following.last().unwrap_or(&cfg.req);
    if last.uri.is_empty() {
        return Err(BoxError::from_static_str("empty URI is not valid"));
    }

    let uri = parse_user_uri(&last.uri)?;
    let scheme = uri.scheme().cloned().unwrap_or(Protocol::HTTP);

    let is_ws = scheme.is_ws();
    // file:// and data: are served by client layers, so they take the
    // same path as http and get all its output handling
    if scheme.is_http() || is_ws || scheme == Protocol::FILE || scheme == Protocol::DATA {
        return http::run(cfg, following, is_ws).await;
    }
    Err(BoxError::from_static_str("scheme is not supported")
        .context_str_field("scheme", scheme.as_str()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EmulationProfiles {
    Embedded,
    File(PathBuf),
}

impl FromStr for EmulationProfiles {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(if value == "@embedded" {
            Self::Embedded
        } else {
            Self::File(value.into())
        })
    }
}

#[derive(Debug, Args)]
/// send (client) request (default cmd)
pub struct SendCommand {
    #[arg(short = 'L', long)]
    /// (HTTP) If the server reports that the requested page has moved to a different location
    /// (indicated with a Location: header and a 3XX response code),
    /// this option makes curl redo the request to the new place.
    /// If used together with --show-headers, headers from all requested pages are shown.
    ///
    /// Limit the amount of redirects to follow by using the --max-redirs option.
    location: bool,

    #[arg(long, default_value_t = false)]
    /// (HTTP) Like --location, but allows credentials to be forwarded to redirected hosts.
    location_trusted: bool,

    #[arg(long, default_value_t = 50)]
    /// (HTTP) the maximum number of redirects to follow (set to -1 to put no limit)
    max_redirs: isize,

    #[arg(long, default_value_t = false)]
    /// (HTTP) Return an error on server errors where the HTTP response code is 400 or greater). In normal cases when an HTTP server fails to deliver a document, it returns an HTML document stating so (which often also describes why and more). This option allows curl to output and save that content but also to return error 22.
    fail: bool,

    #[arg(long, short = 'x')]
    /// Upstream proxy to use. NO_PROXY still applies. Without this option,
    /// scheme-specific and all-protocol proxy environment variables are tried
    /// before operating-system settings.
    proxy: Option<ProxyAddress>,

    #[arg(long, short = 'U')]
    /// upstream proxy user credentials to use (or overwrite)
    proxy_user: Option<Basic>,

    #[arg(long, default_value_t = false)]
    /// Disable automatic credentials on plaintext HTTP requests forwarded to
    /// an HTTP(S) proxy. Explicit Proxy-Authorization headers are preserved.
    no_proxy_forward_auth: bool,

    #[arg(long = "proxytunnel", default_value_t = false)]
    /// Use HTTP CONNECT even for plaintext HTTP requests sent through an
    /// HTTP(S) proxy. This does not encrypt the tunneled origin traffic.
    proxy_tunnel: bool,

    #[arg(short = 'k', long)]
    /// (HTTP) skip Tls certificate verification
    insecure: bool,

    #[arg(long)]
    /// PEM CA bundle used to verify the destination server instead of system roots.
    /// With --platform-verifier the bundle is trusted in addition to the system.
    /// Does not change HTTPS proxy trust.
    cacert: Option<PathBuf>,

    #[arg(long, conflicts_with = "insecure")]
    /// (TLS) verify the destination server with the operating system's
    /// certificate verifier instead of a snapshot of its root store.
    /// Platforms without one verify against the native roots.
    platform_verifier: bool,

    #[arg(long, value_parser = arg::requested_trust_anchors)]
    /// Advertise current requested trust-anchor IDs as comma-separated hexadecimal values.
    /// An empty value advertises an empty list. This does not configure certificate trust.
    tls_requested_trust_anchors: Option<BoringRequestedTrustAnchors>,

    #[arg(long)]
    /// same as `--insecure` but for tls proxies
    proxy_insecure: bool,

    #[arg(long)]
    /// (TLS) the desired MAX tls version to use
    ///
    /// Can be set together with one of the TLS version
    /// flags to enforce a specific TLS version: --tlsv1.0,
    /// --tlsv1.1, --tlsv1.2, --tlsv1.3
    tls_max: Option<arg::TlsVersion>,

    #[arg(long = "tlsv1.0", default_value_t = false)]
    /// (TLS) Force rama to use TLS version 1.0 or later when connecting to a remote TLS server.
    tls_v10: bool,

    #[arg(long = "tlsv1.1", default_value_t = false)]
    /// (TLS) Force rama to use TLS version 1.1 or later when connecting to a remote TLS server.
    tls_v11: bool,

    #[arg(long = "tlsv1.2", default_value_t = false)]
    /// (TLS) Force rama to use TLS version 1.2 or later when connecting to a remote TLS server.
    tls_v12: bool,

    #[arg(long = "tlsv1.3", default_value_t = false)]
    /// (TLS) Force rama to use TLS version 1.3 or later when connecting to a remote TLS server.
    tls_v13: bool,

    #[arg(long, short = 'm')]
    /// Set the maximum time in seconds that you allow each transfer to take.
    /// Prevents your batch jobs from hanging for hours due to slow networks or links going down.
    ///
    /// This option accepts decimal values.
    max_time: Option<f64>,

    #[arg(long)]
    /// Maximum time in seconds that you allow rama's connection to take.
    /// This only limits the connection phase, so if rama connects within the given period it continues -
    /// if not it exits.
    ///
    /// This option accepts decimal values
    ///  The decimal value needs to be provided using a dot (.) as decimal separator -
    /// not the local version even if it might be using another separator.
    ///
    /// The connection phase is considered complete when the DNS lookup and requested TCP,
    /// TLS or QUIC handshakes are done.
    connect_timeout: Option<f64>,

    #[arg(short = 'i', long)]
    /// (HTTP) Show response headers in the output. HTTP response headers can include
    /// things like server name, cookies, date of the document, HTTP version and more.
    ///
    /// For request headers use the `-v` / `--verbose` flag.
    show_headers: bool,

    #[arg(long, short = 'v')]
    /// print verbose output, alias for --all --print hHbB
    verbose: bool,

    #[arg(long)]
    /// do not send request but instead print equivalent curl command
    curl: bool,

    #[arg(long, short = 'o')]
    /// Write output to the given file instead of stdout
    output: Option<PathBuf>,

    #[arg(long, value_name = "FILE")]
    /// (HTTP/WebSocket) Record the complete exchange to this HAR file.
    har: Option<PathBuf>,

    #[arg(long, requires = "har")]
    /// Preserve sensitive headers such as Authorization, Cookie and Set-Cookie in the HAR file.
    /// By default these headers are removed from recordings.
    har_preserve_sensitive: bool,

    #[arg(long = "select-json", value_name = "JSONPATH")]
    /// Select JSON response values with JSONPath and print each match on its own line.
    select_json: Vec<JsonPath>,

    #[arg(
        long,
        value_name = "JSON_FILE",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "@embedded"
    )]
    /// Emulate the provided User-Agent using Rama's embedded profiles.
    ///
    /// Pass `--emulate=profiles.json` to use a custom exported profile database.
    /// A random profile is selected when no User-Agent header is defined.
    emulate: Option<EmulationProfiles>,

    #[arg(
        long,
        value_name = "HEX64",
        requires = "emulate",
        requires = "emulate_connection_key",
        requires = "emulate_request_key"
    )]
    /// Fix the captured-profile selection seed. Each coordinate is 32 bytes in hexadecimal.
    emulate_seed: Option<arg::EmulationHex>,

    #[arg(
        long,
        value_name = "HEX64",
        requires = "emulate",
        requires = "emulate_seed",
        requires = "emulate_request_key"
    )]
    /// Fix the logical connection draw key. Each coordinate is 32 bytes in hexadecimal.
    emulate_connection_key: Option<arg::EmulationHex>,

    #[arg(
        long,
        value_name = "HEX64",
        requires = "emulate",
        requires = "emulate_seed",
        requires = "emulate_connection_key"
    )]
    /// Fix the logical request draw key. Each coordinate is 32 bytes in hexadecimal.
    emulate_request_key: Option<arg::EmulationHex>,

    #[arg(long = "http0.9")]
    /// (HTTP) force http_version to http/0.9
    ///
    /// Mutually exclusive with --http1.0, --http1.1, --http2, --http3
    http_09: bool,

    #[arg(long = "http1.0")]
    /// (HTTP) force http_version to http/1.0
    ///
    /// Mutually exclusive with --http1.0, --http1.1, --http2, --http3
    http_10: bool,

    #[arg(long = "http1.1")]
    /// (HTTP) force http_version to http/1.1
    ///
    /// Mutually exclusive with --http0.9, --http1.0, --http2, --http3
    http_11: bool,

    #[arg(long = "http2")]
    /// (HTTP) force http_version to http/2
    ///
    /// Mutually exclusive with --http0.9, --http1.0, --http1.1, --http3
    http_2: bool,

    #[arg(long = "http3")]
    /// (HTTP) require HTTP/3 over QUIC for an HTTPS origin.
    ///
    /// Fails if HTTP/3 cannot be established; does not fall back to HTTP/1 or HTTP/2.
    /// With --alt-svc and no forced version, HTTP/3 can be selected from advertisements.
    ///
    /// Mutually exclusive with --http0.9, --http1.0, --http1.1, --http2
    http_3: bool,

    #[arg(long)]
    /// (HTTP) learn and use advertised alternative services for this command.
    ///
    /// Keeps advertisements in memory only, including across redirects. Explicit
    /// HTTP version flags still apply. Disabled by default.
    alt_svc: bool,

    #[arg(long, short = '4')]
    /// Use IPv4 addresses only when resolving hostnames, and not for example try IPv6.
    ipv4: bool,

    #[arg(long, short = '6')]
    /// Use IPv6 addresses only when resolving hostnames, and not for example try IPv4.
    ///
    /// Your resolver may respond to an IPv6-only resolve request by
    /// returning IPv6 addresses that contain "mapped" IPv4 addresses
    /// for compatibility purposes. macOS is known to do this.
    ipv6: bool,

    #[arg(long, value_name = "[host]|:[port]:addr[,addr]...")]
    /// Provide custom address(es) to overwrite the DNS with.
    ///
    /// - if Host is empty or equal to `*` it will resolve _any_ host to the given Ips
    /// - if Port is empty or equal to `*` it will use the dns overwrites for any port
    /// - at least one Ip address is required (ipv4/ipv6), multiple are allowed as well
    ///
    /// Using this, you can make the requests(s) use a specified address and
    /// prevent the otherwise normally resolved address to be used.
    resolve: Option<arg::ResolveArg>,

    #[arg(long)]
    /// (HTTP Proxy) Extra header to include in the request when sending HTTP to a proxy.
    ///
    /// You may specify any number of extra headers.
    /// This is the equivalent option to --header but is for proxy communication
    /// only like in CONNECT requests when you want a separate header sent to the proxy
    /// to what is sent to the actual remote host.
    proxy_header: Vec<http::arg::HttpHeader>,

    #[arg(long)]
    /// Output trace (log) output to the given file.
    trace: Option<PathBuf>,

    #[arg(long, value_delimiter = ',')]
    /// (WebSocket) sub protocols to use
    subprotocol: Option<Vec<NonEmptyStr>>,

    #[arg(long)]
    /// (HTTP) With --next, write only the last response; earlier ones are read and discarded.
    last_response_only: bool,

    #[command(flatten)]
    req: RequestArgs,
}

#[derive(Debug, Args)]
/// The options of one request; `--next` starts the next request's options.
struct RequestArgs {
    #[arg(required = true)]
    /// Request URI, scheme indicates protocol to be used, http assumed by default.
    uri: String,

    #[arg(long, short = 'X')]
    /// (HTTP) Change the method to use when starting the transfer.
    request: Option<String>,

    #[arg(long, short = 'd')]
    /// (HTTP) Post data exactly as specified with no extra processing whatsoever.
    ///
    /// If you start the data with the letter @, the rest should be a filename. "@-"
    /// makes rama read the data from stdin.
    ///
    /// The default content-type sent to the server is application/x-www-form-urlencoded.
    /// If you want the data to be treated as arbitrary binary data by the server then
    /// set the content-type to octet-stream: -H "Content-Type: application/octet-stream"
    /// or use --binary flag. There is also the --json flag for -H "Content-Type: application/json".
    /// An explicit Content-Type header takes precedence over these defaults.
    ///
    /// If this option is used several times, the ones following the first append data.
    ///
    /// --data-binary can be used several times in a command line
    data: Option<Vec<String>>,

    #[arg(long, default_value_t = false)]
    /// (HTTP) Shorthand to specify the content-type as -H "Content-Type: application/json".
    json: bool,

    #[arg(long, default_value_t = false)]
    /// (HTTP) Shorthand to specify the content-type as -H "Content-Type: application/octet-stream".
    binary: bool,

    #[arg(long, short = 'F')]
    /// (HTTP) Send a `multipart/form-data` part.
    ///
    /// Each `-F` flag adds one part. Spec syntax (compatible with curl `-F`
    /// and httpie):
    ///
    ///   name=value                              text part
    ///   name=@path                              file upload (mime guessed)
    ///   name=@-                                 file upload from stdin
    ///   name=<path                              file content as text part
    ///   name=<-                                 text part from stdin
    ///
    /// Optional modifiers, separated by `;`:
    ///
    ///   ;type=mime/sub      override the part's Content-Type
    ///   ;filename=name      override the filename
    ///
    /// Example:
    ///
    ///   --form-data 'avatar=@./photo.png;type=image/png;filename=me.png'
    ///
    /// Mutually exclusive with --data, --json, --binary.
    form_data: Option<Vec<String>>,

    #[arg(long, short = 'u')]
    /// (HTTP) client authentication: `USER[:PASS]` | TOKEN,
    /// if basic and no password is given it will be promped
    user: Option<String>,

    #[arg(long, short = 'H')]
    /// (HTTP) Extra header to include in information sent.
    /// When used within an HTTP request, it is added to the regular request headers.
    ///
    /// Some HTTP-based protocols such as websocket will add the
    /// headers required for that protocol automatically if not yet defined.
    header: Vec<http::arg::HttpHeader>,

    /// Request flow to replay: navigate, fetch, xhr, form, or ws.
    /// WebSocket URIs select ws automatically when emulation is enabled.
    #[arg(long)]
    emulate_initiator: Option<RequestInitiator>,

    #[arg(long, value_name = "HEX64")]
    /// Pin the exact stored connection variant. Each coordinate is 32 bytes in hexadecimal.
    emulate_connection_variant: Option<arg::EmulationHex>,

    #[arg(long, value_name = "HEX64")]
    /// Pin the exact stored request variant. Each coordinate is 32 bytes in hexadecimal.
    emulate_request_variant: Option<arg::EmulationHex>,

    #[arg(long)]
    /// Send this request as the one that opened its captured connection, so the
    /// connection's captured startup (such as HTTP/3 bootstrap state) applies to it.
    emulate_connection_bootstrap: bool,

    #[arg(long = "next", num_args = 1.., allow_hyphen_values = true, value_name = "ARGS")]
    /// (HTTP) Send another request afterwards on the same client, like curl's --next.
    ///
    /// What follows are that request's own options and URI: -X, -d, --json, --binary,
    /// -F, -u, -H, --emulate-initiator, --emulate-connection-variant,
    /// --emulate-request-variant and --emulate-connection-bootstrap. Nothing else is
    /// inherited from earlier requests; every other option is set once, before the
    /// first --next. Requests run in order and reuse connections where they can; every
    /// response is written in order (see --last-response-only), and --fail applies to
    /// each of them.
    ///
    /// Example: `rama https://example.com/ --next -X POST -d x=1 https://example.com/api`
    next: Vec<String>,
}
