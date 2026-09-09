use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use super::*;

struct Counted<'a> {
    bytes: &'a [u8],
    fills: usize,
}

impl AsyncRead for Counted<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        panic!("buffered form parser must consume filled slices");
    }
}

impl AsyncBufRead for Counted<'_> {
    fn poll_fill_buf(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        let this = self.get_mut();
        this.fills += 1;
        Poll::Ready(Ok(this.bytes))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        this.bytes = &this.bytes[amount..];
    }
}

#[tokio::test]
async fn form_parser_polls_per_buffer_instead_of_per_byte() {
    let source = "a=%F0%9F%99%82".to_owned() + &"x".repeat(CHUNK * 8);
    let mut reader = Counted {
        bytes: source.as_bytes(),
        fills: 0,
    };
    let mut output = Vec::new();
    write_params(&mut output, &mut reader).await.unwrap();
    assert!(reader.fills < 20, "{} buffer polls", reader.fills);
    #[derive(serde::Deserialize)]
    struct Param {
        name: String,
        value: String,
    }
    let params: Vec<Param> = serde_json::from_slice(&output).unwrap();
    assert_eq!(params[0].name, "a");
    assert_eq!(params[0].value, "🙂".to_owned() + &"x".repeat(CHUNK * 8));
}

#[tokio::test]
async fn streamed_form_parameters_match_serde_decoding() {
    for bytes in [
        b"name=one&name=two&bare&=empty-name&&trailing=".as_slice(),
        b"x=a+b%26c%3Dd&unicode=%F0%9F%99%82&escaped=%00%22%5C",
        b"bad=%GG%2%&lossy=%FF%F0%9F&equals=a=b=c",
    ] {
        let expected: Vec<(String, String)> = serde_html_form::from_bytes(bytes).unwrap();
        for capacity in 1..=5 {
            let mut output = Vec::new();
            write_params(
                &mut output,
                tokio::io::BufReader::with_capacity(capacity, bytes),
            )
            .await
            .unwrap();
            let actual: Vec<crate::layer::har::spec::PostParam> =
                serde_json::from_slice(&output).unwrap();
            assert_eq!(actual.len(), expected.len());
            for (actual, (name, value)) in actual.iter().zip(&expected) {
                assert_eq!(&*actual.name, name);
                assert_eq!(actual.value.as_deref(), Some(value.as_str()));
            }
        }
    }
}
