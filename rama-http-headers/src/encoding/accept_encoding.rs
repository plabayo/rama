use super::SupportedEncodings;
use rama_http_types::HeaderValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptEncoding {
    gzip: bool,
    deflate: bool,
    br: bool,
    zstd: bool,
}

impl AcceptEncoding {
    #[must_use]
    pub fn maybe_to_header_value(self) -> Option<HeaderValue> {
        let accept = match (self.gzip(), self.deflate(), self.br(), self.zstd()) {
            (true, true, true, false) => "gzip,deflate,br",
            (true, true, false, false) => "gzip,deflate",
            (true, false, true, false) => "gzip,br",
            (true, false, false, false) => "gzip",
            (false, true, true, false) => "deflate,br",
            (false, true, false, false) => "deflate",
            (false, false, true, false) => "br",
            (true, true, true, true) => "zstd,gzip,deflate,br",
            (true, true, false, true) => "zstd,gzip,deflate",
            (true, false, true, true) => "zstd,gzip,br",
            (true, false, false, true) => "zstd,gzip",
            (false, true, true, true) => "zstd,deflate,br",
            (false, true, false, true) => "zstd,deflate",
            (false, false, true, true) => "zstd,br",
            (false, false, false, true) => "zstd",
            (false, false, false, false) => return None,
        };
        Some(HeaderValue::from_static(accept))
    }

    pub fn set_gzip(&mut self, enable: bool) {
        self.gzip = enable;
    }

    #[must_use]
    pub fn with_gzip(mut self, enable: bool) -> Self {
        self.gzip = enable;
        self
    }

    pub fn set_deflate(&mut self, enable: bool) {
        self.deflate = enable;
    }

    #[must_use]
    pub fn with_deflate(mut self, enable: bool) -> Self {
        self.deflate = enable;
        self
    }

    pub fn set_br(&mut self, enable: bool) {
        self.br = enable;
    }

    #[must_use]
    pub fn with_br(mut self, enable: bool) -> Self {
        self.br = enable;
        self
    }

    pub fn set_zstd(&mut self, enable: bool) {
        self.zstd = enable;
    }

    #[must_use]
    pub fn with_zstd(mut self, enable: bool) -> Self {
        self.zstd = enable;
        self
    }
}

impl SupportedEncodings for AcceptEncoding {
    fn gzip(&self) -> bool {
        self.gzip
    }

    fn deflate(&self) -> bool {
        self.deflate
    }

    fn br(&self) -> bool {
        self.br
    }

    fn zstd(&self) -> bool {
        self.zstd
    }
}

impl Default for AcceptEncoding {
    fn default() -> Self {
        Self {
            gzip: true,
            deflate: true,
            br: true,
            zstd: true,
        }
    }
}
