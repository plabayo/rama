#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::black_box;
use rama::{bytes::BytesMut, net::uri::Uri};

struct BytesMutWriter<'a>(&'a mut BytesMut);

impl core::fmt::Write for BytesMutWriter<'_> {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

fn main() {
    divan::main();
}

const URI_SHAPES: &[&str] = &[
    "http://proxy-target.example:8080/api/v1/items/123?include=metadata&format=json",
    "http://[2001:db8::8]:8080/resource?q=1",
    "http://proxy-target.example",
    "https://user:secret@proxy-target.example/a%2Fb?next=%2Fhome",
];

fn uri(shape: usize) -> Uri {
    URI_SHAPES[shape].parse().unwrap()
}

fn write_previous_http_absolute_form(
    uri: &Uri,
    writer: &mut impl core::fmt::Write,
) -> core::fmt::Result {
    writer.write_str(uri.scheme().unwrap().as_str())?;
    writer.write_str(":")?;
    if let Some(authority) = uri.authority() {
        writer.write_str("//")?;
        authority.write_address_with_port(writer, uri.port())?;
    }
    if let Some(path) = uri.path().filter(|path| !path.is_empty()) {
        write!(writer, "{path}")?;
    } else {
        writer.write_str("/")?;
    }
    if let Some(query) = uri.query() {
        write!(writer, "?{query}")?;
    }
    Ok(())
}

/// HTTP/1 forward-proxy request-target hot path.
#[divan::bench(args = [0_usize, 1, 2, 3], sample_count = 100)]
fn http_absolute_direct(bencher: divan::Bencher, shape: usize) {
    let uri = uri(shape);
    let mut output = BytesMut::with_capacity(128);
    bencher.bench_local(|| {
        output.clear();
        black_box(&uri)
            .write_http_absolute_form(&mut output)
            .unwrap();
        black_box(output.as_ref());
        output.len()
    });
}

/// The formatter-based implementation used before the HTTP-specific writer
/// gained a direct encoded-byte path. It intentionally produces identical
/// bytes, including stripping userinfo and normalizing an empty path to `/`.
#[divan::bench(args = [0_usize, 1, 2, 3], sample_count = 100)]
fn absolute_fmt_projection(bencher: divan::Bencher, shape: usize) {
    let uri = uri(shape);
    let mut output = BytesMut::with_capacity(128);
    bencher.bench_local(|| {
        output.clear();
        let mut writer = BytesMutWriter(&mut output);
        write_previous_http_absolute_form(black_box(&uri), &mut writer).unwrap();
        black_box(output.as_ref());
        output.len()
    });
}
