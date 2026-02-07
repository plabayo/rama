use std::time::Duration;

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    telemetry::tracing,
};
use rama_http::{HeaderMap, HeaderValue, Request};
use rama_utils::macros::define_inner_service_accessors;

use crate::{TimeoutExpired, metadata::GRPC_TIMEOUT_HEADER};

#[derive(Debug, Clone)]
/// A timeout [`Layer`] for timeout support in Grpc stacks.
pub struct GrpcTimeoutLayer {
    server_timeout: Option<Duration>,
}

impl GrpcTimeoutLayer {
    /// Create a new [`GrpcTimeoutLayer`]
    pub fn new(server_timeout: impl Into<Option<Duration>>) -> Self {
        Self {
            server_timeout: server_timeout.into(),
        }
    }
}

impl<S> Layer<S> for GrpcTimeoutLayer {
    type Service = GrpcTimeout<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        GrpcTimeout::new(inner, self.server_timeout)
    }
}

#[derive(Debug, Clone)]
/// A timeout [`Service`] for timeout support in Grpc stacks.
pub struct GrpcTimeout<S> {
    inner: S,
    server_timeout: Option<Duration>,
}

impl<S> GrpcTimeout<S> {
    /// Create a new [`GrpcTimeout`]
    pub fn new(inner: S, server_timeout: impl Into<Option<Duration>>) -> Self {
        Self {
            inner,
            server_timeout: server_timeout.into(),
        }
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody> Service<Request<ReqBody>> for GrpcTimeout<S>
where
    S: Service<Request<ReqBody>>,
    S::Error: Into<BoxError>,
    ReqBody: Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let client_timeout = try_parse_grpc_timeout(req.headers()).unwrap_or_else(|e| {
            tracing::trace!("Error parsing `grpc-timeout` header {:?}", e);
            None
        });

        // Use the shorter of the two durations, if either are set
        let maybe_timeout = match (client_timeout, self.server_timeout) {
            (None, None) => None,
            (Some(dur), None) | (None, Some(dur)) => Some(dur),
            (Some(header), Some(server)) => {
                let shorter_duration = std::cmp::min(header, server);
                Some(shorter_duration)
            }
        };

        if let Some(timeout) = maybe_timeout {
            tokio::time::timeout(timeout, self.inner.serve(req))
                .await
                .map_err(|_| TimeoutExpired(()))?
        } else {
            self.inner.serve(req).await
        }
        .into_box_error()
    }
}

/// Tries to parse the `grpc-timeout` header if it is present. If we fail to parse, returns
/// the value we attempted to parse.
///
/// Follows the [gRPC over HTTP2 spec](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md).
fn try_parse_grpc_timeout(
    headers: &HeaderMap<HeaderValue>,
) -> Result<Option<Duration>, &HeaderValue> {
    let Some(val) = headers.get(GRPC_TIMEOUT_HEADER) else {
        return Ok(None);
    };

    let (timeout_value, timeout_unit) = val
        .to_str()
        .map_err(|_| val)
        .and_then(|s| if s.is_empty() { Err(val) } else { Ok(s) })?
        // `HeaderValue::to_str` only returns `Ok` if the header contains ASCII so this
        // `split_at` will never panic from trying to split in the middle of a character.
        // See https://docs.rs/http/1/http/header/struct.HeaderValue.html#method.to_str
        //
        // `len - 1` also wont panic since we just checked `s.is_empty`.
        .split_at(val.len() - 1);

    // gRPC spec specifies `TimeoutValue` will be at most 8 digits
    // Caping this at 8 digits also prevents integer overflow from ever occurring
    if timeout_value.len() > 8 {
        return Err(val);
    }

    let timeout_value: u64 = timeout_value.parse().map_err(|_| val)?;

    let duration = match timeout_unit {
        // Hours
        "H" => Duration::from_hours(timeout_value),
        // Minutes
        "M" => Duration::from_mins(timeout_value),
        // Seconds
        "S" => Duration::from_secs(timeout_value),
        // Milliseconds
        "m" => Duration::from_millis(timeout_value),
        // Microseconds
        "u" => Duration::from_micros(timeout_value),
        // Nanoseconds
        "n" => Duration::from_nanos(timeout_value),
        _ => return Err(val),
    };

    Ok(Some(duration))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    // Helper function to reduce the boiler plate of our test cases
    fn setup_map_try_parse(val: Option<&str>) -> Result<Option<Duration>, HeaderValue> {
        let mut hm = HeaderMap::new();
        if let Some(v) = val {
            let hv = HeaderValue::from_str(v).unwrap();
            hm.insert(GRPC_TIMEOUT_HEADER, hv);
        };

        try_parse_grpc_timeout(&hm).map_err(|e| e.clone())
    }

    #[test]
    fn test_hours() {
        let parsed_duration = setup_map_try_parse(Some("3H")).unwrap().unwrap();
        assert_eq!(Duration::from_secs(3 * 60 * 60), parsed_duration);
    }

    #[test]
    fn test_minutes() {
        let parsed_duration = setup_map_try_parse(Some("1M")).unwrap().unwrap();
        assert_eq!(Duration::from_secs(60), parsed_duration);
    }

    #[test]
    fn test_seconds() {
        let parsed_duration = setup_map_try_parse(Some("42S")).unwrap().unwrap();
        assert_eq!(Duration::from_secs(42), parsed_duration);
    }

    #[test]
    fn test_milliseconds() {
        let parsed_duration = setup_map_try_parse(Some("13m")).unwrap().unwrap();
        assert_eq!(Duration::from_millis(13), parsed_duration);
    }

    #[test]
    fn test_microseconds() {
        let parsed_duration = setup_map_try_parse(Some("2u")).unwrap().unwrap();
        assert_eq!(Duration::from_micros(2), parsed_duration);
    }

    #[test]
    fn test_nanoseconds() {
        let parsed_duration = setup_map_try_parse(Some("82n")).unwrap().unwrap();
        assert_eq!(Duration::from_nanos(82), parsed_duration);
    }

    #[test]
    fn test_header_not_present() {
        let parsed_duration = setup_map_try_parse(None).unwrap();
        assert!(parsed_duration.is_none());
    }

    #[test]
    #[should_panic(expected = "82f")]
    fn test_invalid_unit() {
        // "f" is not a valid TimeoutUnit
        setup_map_try_parse(Some("82f")).unwrap().unwrap();
    }

    #[test]
    #[should_panic(expected = "123456789H")]
    fn test_too_many_digits() {
        // gRPC spec states TimeoutValue will be at most 8 digits
        setup_map_try_parse(Some("123456789H")).unwrap().unwrap();
    }

    #[test]
    #[should_panic(expected = "oneH")]
    fn test_invalid_digits() {
        // gRPC spec states TimeoutValue will be at most 8 digits
        setup_map_try_parse(Some("oneH")).unwrap().unwrap();
    }

    #[quickcheck]
    fn fuzz(header_value: HeaderValueGen) -> bool {
        let header_value = header_value.0;

        // this just shouldn't panic
        let _ = setup_map_try_parse(Some(&header_value));

        true
    }

    /// Newtype to implement `Arbitrary` for generating `String`s that are valid `HeaderValue`s.
    #[derive(Clone, Debug)]
    struct HeaderValueGen(String);

    impl Arbitrary for HeaderValueGen {
        fn arbitrary(g: &mut Gen) -> Self {
            let max = g.choose(&(1..70).collect::<Vec<_>>()).copied().unwrap();
            Self(gen_string(g, 0, max))
        }
    }

    // copied from https://github.com/hyperium/http/blob/master/tests/header_map_fuzz.rs
    fn gen_string(g: &mut Gen, min: usize, max: usize) -> String {
        let bytes: Vec<_> = (min..max)
            .map(|_| {
                // Chars to pick from
                g.choose(b"ABCDEFGHIJKLMNOPQRSTUVabcdefghilpqrstuvwxyz----")
                    .copied()
                    .unwrap()
            })
            .collect();

        String::from_utf8(bytes).unwrap()
    }
}
