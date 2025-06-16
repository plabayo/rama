#[cfg(fuzzing)]
pub mod fuzz_logic {
    use crate::h2::hpack;
    use rama_core::bytes::BytesMut;
    use rama_http_types::header::HeaderName;
    use std::io::Cursor;

    pub fn fuzz_hpack(data_: &[u8]) {
        let mut decoder_ = hpack::Decoder::new(0);
        let mut buf = BytesMut::new();
        buf.extend(data_);
        let _dec_res = decoder_.decode(&mut Cursor::new(&mut buf), |_h| {});

        if let Ok(s) = std::str::from_utf8(data_) {
            if let Ok(h) = rama_http_types::Method::from_bytes(s.as_bytes()) {
                let m_ = hpack::Header::Method(h);
                let mut encoder = hpack::Encoder::new(0, 0);
                let _res = encode(&mut encoder, vec![m_]);
            }
        }
    }

    fn encode(e: &mut hpack::Encoder, hdrs: Vec<hpack::Header<Option<HeaderName>>>) -> BytesMut {
        let mut dst = BytesMut::with_capacity(1024);
        e.encode(&mut hdrs.into_iter(), &mut dst);
        dst
    }
}
