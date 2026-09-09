use super::*;

use rama_core::{futures::stream, stream::io::StreamReader};
#[tokio::test]
async fn streamed_search_matches_native_display_across_unicode_boundaries() {
    let mut text = "x".repeat(rama_utils::octets::kib(16) - 1);
    text.push_str("🙂\"\n\0'\u{200d}İΣabcabcabd");
    let mut binary = text.as_bytes().to_vec();
    binary.extend_from_slice(&[0xff, 0xaa]);
    for data in [text.as_bytes(), binary.as_slice(), b"", b"a'b\nc"] {
        for needle in [
            "🙂",
            "\\n",
            "\\u{200d}",
            "'",
            "İΣ",
            "abcabd",
            "0x78",
            "ffaa",
            "missing",
            "\"",
            "",
        ] {
            assert_eq!(
                matches_reader(data, needle).await.unwrap(),
                matches_display(&rama_utils::fmt::utf8_or_hex(data), needle),
                "{needle:?}"
            );
        }
    }
}

#[tokio::test]
async fn small_reads_preserve_unicode_and_binary_search_semantics() {
    for data in [
        "🙂é\nİΣ".as_bytes(),
        b"abc\xf0\x9f",
        b"abc\xf0\x9f\xffxyz",
        b"\xffabc\x00",
    ] {
        for size in 1..=4 {
            for needle in ["🙂", "é", "\\n", "İΣ", "0x", "FF", "f09f", "abc", "missing"] {
                let reader =
                    StreamReader::new(stream::iter(data.chunks(size).map(Ok::<_, std::io::Error>)));
                assert_eq!(
                    matches_reader(reader, needle).await.unwrap(),
                    matches_display(&rama_utils::fmt::utf8_or_hex(data), needle),
                    "chunk={size}, needle={needle:?}, data={data:?}",
                );
            }
        }
    }
}
