#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// URL Schemes supported by `rama`.
///
/// This is used to determine the protocol of an incoming request,
/// and to ensure the entire chain can work with a sanatized scheme,
/// rather than having to deal with the raw string.
///
/// Please [file an issue or open a PR][repo] if you need more schemes.
/// When doing so please provide sufficient motivation and ensure
/// it has no unintended consequences.
///
/// [repo]: https://github.com/plabayo/rama
pub enum Scheme {
    /// The `http` scheme.
    Http,
    /// The `https` scheme.
    Https,
    /// The `ws` scheme.
    ///
    /// (Websocket over HTTP)
    /// <https://tools.ietf.org/html/rfc6455>
    Ws,
    /// The `wss` scheme.
    ///
    /// (Websocket over HTTPS)
    /// <https://tools.ietf.org/html/rfc6455>
    Wss,
}
