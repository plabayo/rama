use rama_core::Context;
use rama_http_types::Request;

#[cfg(any(feature = "rustls", feature = "boring"))]
mod tls_alpn;
// #[cfg(any(feature = "rustls", feature = "boring"))]
// pub use tls_alpn::HttpALPNModifier;

/// Trait that can be implemented to augment a HttpConnector
/// Just In Time (JIT). Right after establishing a "transport" connection,
/// but prior to actually establishing the application-layer http connection.
///
/// This allows one to adapt the http [`Request`] and [`Context`] based
/// on previous (runtime) configurations or agreed upon information
/// from underlying layers.
///
/// Some common use cases are adapting http version based on TLS' ALPN,
/// or emulating a User-Agent's http request in harmony with all the other layers.
pub trait HttpModifier<State, Body>: Send + Sync + 'static {
    type Error: Send + Sync + 'static;

    fn modify_http(
        &self,
        ctx: &mut Context<State>,
        req: &mut Request<Body>,
    ) -> Result<(), Self::Error>;
}

impl<State, Body, F, Error> HttpModifier<State, Body> for F
where
    F: Fn(&mut Context<State>, &mut Request<Body>) -> Result<(), Error> + Send + Sync + 'static,
    Error: Send + Sync + 'static,
{
    type Error = Error;

    fn modify_http(
        &self,
        ctx: &mut Context<State>,
        req: &mut Request<Body>,
    ) -> Result<(), Self::Error> {
        (self)(ctx, req)
    }
}
