use rama::{
    error::{BoxError, OpaqueError},
    net::{address::ProxyAddress, user::Basic},
    utils::str::{NonEmptyStr, starts_with_ignore_ascii_case},
};

use clap::Args;
use std::path::PathBuf;

pub mod http;

mod arg;
mod layer;

pub async fn run(cfg: SendCommand) -> Result<(), BoxError> {
    if cfg.uri.is_empty() {
        return Err(OpaqueError::from_display("empty URI is not valid").into_boxed());
    }

    let uri_scheme_raw = cfg
        .uri
        .split_once("://")
        .map(|t| t.0.trim())
        .unwrap_or("http");

    if ["http", "https", "ws", "wss"]
        .into_iter()
        .any(|scheme| uri_scheme_raw.eq_ignore_ascii_case(scheme))
    {
        let is_ws = starts_with_ignore_ascii_case(uri_scheme_raw.as_bytes(), b"ws");
        http::run(cfg, is_ws).await
    } else {
        Err(
            OpaqueError::from_display(format!("scheme '{uri_scheme_raw}' is not supported"))
                .into_boxed(),
        )
    }
}

#[derive(Debug, Args)]
/// send (client) request (default cmd)
pub struct SendCommand {
    #[arg(required = true)]
    /// Request URI, scheme indicates protocol to be used, http assumed by default.
    uri: String,

    #[arg(short = 'L', long)]
    /// (HTTP) If the server reports that the requested page has moved to a different location
    /// (indicated with a Location: header and a 3XX response code),
    /// this option makes curl redo the request to the new place.
    /// If used together with --show-headers, headers from all requested pages are shown.
    ///
    /// Limit the amount of redirects to follow by using the --max-redirs option.
    location: bool,

    #[arg(long, default_value_t = 50)]
    /// (HTTP) the maximum number of redirects to follow (set to -1 to put no limit)
    max_redirs: isize,

    #[arg(long, default_value_t = false)]
    /// (HTTP) Return an error on server errors where the HTTP response code is 400 or greater). In normal cases when an HTTP server fails to deliver a document, it returns an HTML document stating so (which often also describes why and more). This option allows curl to output and save that content but also to return error 22.
    fail: bool,

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

    #[arg(long, short = 'x')]
    /// upstream proxy to use (can also be specified using PROXY env variable)
    proxy: Option<ProxyAddress>,

    #[arg(long, short = 'U')]
    /// upstream proxy user credentials to use (or overwrite)
    proxy_user: Option<Basic>,

    #[arg(long, short = 'u')]
    /// (HTTP) client authentication: `USER[:PASS]` | TOKEN,
    /// if basic and no password is given it will be promped
    user: Option<String>,

    #[arg(short = 'k', long)]
    /// (HTTP) skip Tls certificate verification
    insecure: bool,

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

    #[arg(long)]
    /// emulate the provided user-agent
    ///
    /// (or a random one if no user-agent header is defined)
    emulate: bool,

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
    /// (HTTP) force http_version to http/3
    ///
    /// Mutually exclusive with --http0.9, --http1.0, --http1.1, --http2
    http_3: bool,

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

    #[arg(long, short = 'H')]
    /// (HTTP) Extra header to include in information sent.
    /// When used within an HTTP request, it is added to the regular request headers.
    ///
    /// Some HTTP-based protocols such as websocket will add the
    /// headers required for that protocol automatically if not yet defined.
    header: Vec<http::arg::HttpHeader>,

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
}
