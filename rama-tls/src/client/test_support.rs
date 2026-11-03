//! Synthetic record fixtures shared by parser and routing regressions.

pub(crate) fn record(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x16, 3, 1];
    out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(crate) fn fragments(message: &[u8], chunk_size: usize) -> Vec<u8> {
    message.chunks(chunk_size).flat_map(record).collect()
}

pub(crate) fn hello(padding: usize) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    let mut extensions = vec![
        0, 0, 0, 10, 0, 8, 0, 0, 5, b'x', b'.', b'c', b'o', b'm', 0, 16, 0, 5, 0, 3, 2, b'h', b'2',
        0, 13, 0, 4, 0, 2, 4, 3,
    ];
    extensions.extend_from_slice(&[0, 21]);
    extensions.extend_from_slice(&u16::try_from(padding).unwrap().to_be_bytes());
    extensions.resize(extensions.len() + padding, 0);
    body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut message = vec![1];
    message.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    message
}
