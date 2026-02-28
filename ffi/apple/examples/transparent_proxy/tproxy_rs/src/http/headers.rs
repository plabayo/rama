use rama::{
    http::{
        HeaderName, HeaderValue,
        headers::{HeaderEncode, TypedHeader},
    },
    telemetry::tracing,
};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct XRamaTransparentProxyObservedHeader;

impl XRamaTransparentProxyObservedHeader {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }
}

impl TypedHeader for XRamaTransparentProxyObservedHeader {
    fn name() -> &'static HeaderName {
        static NAME: HeaderName = HeaderName::from_static("x-rama-tproxy-observed");
        &NAME
    }
}

impl HeaderEncode for XRamaTransparentProxyObservedHeader {
    fn encode<E: Extend<rama::http::HeaderValue>>(&self, values: &mut E) {
        values.extend([
            HeaderValue::try_from(format!("seen-by-{}", std::process::id())).unwrap_or_else(
                |err| {
                    tracing::warn!("failed to create proxy observed header: {err}");
                    HeaderValue::from_static("seen")
                },
            ),
        ]);
    }
}
