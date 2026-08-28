use rama_utils::byte_set::{set_ascii_alphanum, set_each};

const HTTP_TOKEN_BYTES: [bool; 256] =
    set_each(set_ascii_alphanum([false; 256]), b"!#$%&'*+-.^_`|~");

#[inline]
pub(crate) const fn is_http_token_byte(byte: u8) -> bool {
    HTTP_TOKEN_BYTES[byte as usize]
}
