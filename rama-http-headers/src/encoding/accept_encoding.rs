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
    pub fn new_gzip() -> Self {
        Self {
            gzip: true,
            deflate: false,
            br: false,
            zstd: false,
        }
    }

    #[must_use]
    pub fn new_deflate() -> Self {
        Self {
            gzip: false,
            deflate: true,
            br: false,
            zstd: false,
        }
    }

    #[must_use]
    pub fn new_br() -> Self {
        Self {
            gzip: false,
            deflate: false,
            br: true,
            zstd: false,
        }
    }

    #[must_use]
    pub fn new_zstd() -> Self {
        Self {
            gzip: false,
            deflate: false,
            br: false,
            zstd: true,
        }
    }

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

    rama_utils::macros::generate_set_and_with! {
        pub fn gzip(mut self, enable: bool) -> Self {
            self.gzip = enable;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn deflate(mut self, enable: bool) -> Self {
            self.deflate = enable;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn br(mut self, enable: bool) -> Self {
            self.br = enable;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn zstd(mut self, enable: bool) -> Self {
            self.zstd = enable;
            self
        }
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
