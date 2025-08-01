use std::cell::RefCell;
use std::fmt::{self, Write};
use std::str;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use httpdate::HttpDate;
use rama_http_types::HeaderValue;

// "Sun, 06 Nov 1994 08:49:37 GMT".len()
pub(crate) const DATE_VALUE_LENGTH: usize = 29;

pub(crate) fn extend(dst: &mut Vec<u8>) {
    CACHED.with(|cache| {
        dst.extend_from_slice(cache.borrow().buffer());
    })
}

pub(crate) fn update() {
    CACHED.with(|cache| {
        cache.borrow_mut().check();
    })
}

pub(crate) fn update_and_header_value() -> HeaderValue {
    CACHED.with(|cache| {
        let mut cache = cache.borrow_mut();
        cache.check();
        cache.header_value.clone()
    })
}

struct CachedDate {
    bytes: [u8; DATE_VALUE_LENGTH],
    pos: usize,
    header_value: HeaderValue,
    next_update: SystemTime,
}

thread_local!(static CACHED: RefCell<CachedDate> = RefCell::new(CachedDate::new()));

impl CachedDate {
    fn new() -> Self {
        let mut cache = Self {
            bytes: [0; DATE_VALUE_LENGTH],
            pos: 0,
            header_value: HeaderValue::from_static(""),
            next_update: SystemTime::now(),
        };
        cache.update(cache.next_update);
        cache
    }

    fn buffer(&self) -> &[u8] {
        &self.bytes[..]
    }

    fn check(&mut self) {
        let now = SystemTime::now();
        if now > self.next_update {
            self.update(now);
        }
    }

    fn update(&mut self, now: SystemTime) {
        let nanos = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();

        self.render(now);

        self.next_update = now + Duration::new(1, 0) - Duration::from_nanos(nanos as u64);
    }

    fn render(&mut self, now: SystemTime) {
        self.pos = 0;
        let _ = write!(self, "{}", HttpDate::from(now));
        debug_assert!(self.pos == DATE_VALUE_LENGTH);
        self.render_http2();
    }

    fn render_http2(&mut self) {
        self.header_value = HeaderValue::from_bytes(self.buffer())
            .expect("Date format should be valid HeaderValue");
    }
}

impl fmt::Write for CachedDate {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let len = s.len();
        self.bytes[self.pos..self.pos + len].copy_from_slice(s.as_bytes());
        self.pos += len;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_len() {
        assert_eq!(DATE_VALUE_LENGTH, "Sun, 06 Nov 1994 08:49:37 GMT".len());
    }
}
