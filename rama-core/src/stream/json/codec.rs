use bytes::{Buf, BufMut};
use rama_error::{BoxError, ErrorContext as _};
use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;

use super::engine::NdjsonEngine;
use crate::{bytes::BytesMut, stream::json::ParseConfig};

/// NDJson encoder.
pub struct JsonEncoder<T> {
    written: bool,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> JsonEncoder<T> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            written: false,
            _phantom: PhantomData,
        }
    }
}

impl<T> JsonEncoder<T> {
    #[must_use]
    /// Use [`JsonEncoder::new`] for new streams.
    /// This constructor can be used if you wish to start
    /// the strema with a newline because you are continuing
    /// to write to a stream where you left of.
    pub fn new_continued() -> Self {
        Self {
            written: true,
            _phantom: PhantomData,
        }
    }
}

impl<T> Clone for JsonEncoder<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for JsonEncoder<T> {}

impl<T> Default for JsonEncoder<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Serialize> crate::stream::codec::Encoder<T> for JsonEncoder<T> {
    type Error = BoxError;

    fn encode(&mut self, data: T, buf: &mut BytesMut) -> Result<(), Self::Error> {
        if self.written {
            buf.put_u8(b'\n');
        }
        let result = serde_json::to_writer(buf.writer(), &data)
            .context("serde-json write data to buffer")
            .into_box_error();
        self.written = true;
        result
    }
}

/// NDJson decoder decoding ndjson stream of bytes
/// into json objects.
pub struct JsonDecoder<T> {
    engine: NdjsonEngine<T>,
}

impl<T> JsonDecoder<T> {
    /// Creates a new fallible NDJSON decoder with default [`ParseConfig`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: NdjsonEngine::new(),
        }
    }

    /// Creates a new fallible NDJSON decoder with the given
    /// [`ParseConfig`] to control its behavior.
    ///
    /// See [`ParseConfig`] for more details.
    #[must_use]
    pub fn new_with_config(config: ParseConfig) -> Self {
        Self {
            engine: NdjsonEngine::with_config(config),
        }
    }
}

impl<T> Default for JsonDecoder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: DeserializeOwned> crate::stream::codec::Decoder for JsonDecoder<T> {
    type Item = T;
    type Error = BoxError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // If we already buffered parsed values, return them first.
        if let Some(result) = self.engine.pop() {
            return Ok(Some(result.context("json-deserialize next value")?));
        }

        // DO NOT finalize here on empty src; just ask FramedRead to read more.
        if !src.is_empty() {
            self.engine.input(&src);
            src.advance(src.len());
        }

        match self.engine.pop() {
            Some(result) => Ok(Some(result.context("json-deserialize next value")?)),
            None => Ok(None),
        }
    }

    // If your trait has a dedicated EOF hook, implement it like this:
    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !src.is_empty() {
            self.engine.input(&src);
            src.advance(src.len());
        }
        self.engine.finalize();

        if let Some(result) = self.engine.pop() {
            return Ok(Some(result.context("json-deserialize next value")?));
        }
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use ahash::{HashSet, HashSetExt as _};

    use super::*;
    use crate::stream::codec::{Decoder as _, Encoder as _};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Item {
        id: u32,
        name: String,
    }

    #[test]
    fn encode_single_value_no_leading_newline() -> Result<(), BoxError> {
        let mut enc: JsonEncoder<u32> = JsonEncoder::new();
        let mut buf = BytesMut::new();

        enc.encode(42, &mut buf)?;

        let s = std::str::from_utf8(&buf)?;
        assert_eq!(s, "42"); // no newline
        Ok(())
    }

    #[test]
    fn encode_multiple_values_separated_by_newline_without_trailing_newline() -> Result<(), BoxError>
    {
        let mut enc: JsonEncoder<u32> = JsonEncoder::new();
        let mut buf = BytesMut::new();

        enc.encode(1, &mut buf)?;
        enc.encode(2, &mut buf)?;
        enc.encode(3, &mut buf)?;

        let bytes = buf.as_ref();
        // must be "1\n2\n3" with no trailing newline
        assert_eq!(bytes, b"1\n2\n3");
        assert_ne!(bytes.last().copied(), Some(b'\n'));
        Ok(())
    }

    #[test]
    fn roundtrip_structs_encode_then_decode_all() -> Result<(), BoxError> {
        let mut enc: JsonEncoder<Item> = JsonEncoder::new();
        let mut buf = BytesMut::new();

        let input = vec![
            Item {
                id: 1,
                name: "alice".to_owned(),
            },
            Item {
                id: 2,
                name: "bob".to_owned(),
            },
            Item {
                id: 3,
                name: "carol".to_owned(),
            },
        ];

        for it in &input {
            enc.encode(it.clone(), &mut buf)?;
        }

        let mut dec: JsonDecoder<Item> = JsonDecoder::new();
        let mut out = Vec::new();

        // First call will feed the entire buffer into the engine and return the first item
        if let Some(first) = dec.decode(&mut buf)? {
            out.push(first);
        }

        // Subsequent calls will keep popping from the engine even if src is now empty
        while let Some(next) = dec.decode(&mut buf)? {
            out.push(next);
        }

        if let Some(next) = dec.decode_eof(&mut buf)? {
            out.push(next);
        }

        assert_eq!(out, input);
        Ok(())
    }

    #[test]
    fn decode_incremental_streaming_chunks() -> Result<(), BoxError> {
        // Prepare an NDJSON stream
        let mut enc: JsonEncoder<Item> = JsonEncoder::new();
        let mut full = BytesMut::new();

        let items = vec![
            Item {
                id: 10,
                name: "ten".into(),
            },
            Item {
                id: 20,
                name: "twenty".into(),
            },
            Item {
                id: 30,
                name: "thirty".into(),
            },
        ];
        for it in &items {
            enc.encode(it.clone(), &mut full)?;
        }

        // Split into irregular chunks to mimic a real stream
        let all_bytes = full.freeze();
        let split_points = [1, 7, 13, all_bytes.len()]; // arbitrary cut points
        let mut chunks = Vec::new();
        let mut start = 0;
        for &end in &split_points {
            chunks.push(all_bytes.slice(start..end));
            start = end;
        }

        // Feed chunks one by one
        let mut dec: JsonDecoder<Item> = JsonDecoder::new();
        let mut collected = Vec::new();
        let mut staging = BytesMut::new();

        for chunk in chunks {
            staging.extend_from_slice(&chunk);
            // Try to drain as many items as available after each chunk
            while let Some(item) = dec.decode(&mut staging)? {
                collected.push(item);
            }
        }

        if let Ok(Some(next)) = dec.decode_eof(&mut staging) {
            collected.push(next);
        }

        assert_eq!(collected, items);
        Ok(())
    }

    #[test]
    fn decode_reports_error_for_malformed_json_line() {
        let mut dec: JsonDecoder<serde_json::Value> = JsonDecoder::new();
        let mut buf = BytesMut::from(&b"{not valid json}\n{\"ok\": true}\n"[..]);

        // First decode should error because the first line is invalid
        let err = dec
            .decode(&mut buf)
            .expect_err("expected an error for malformed json");
        let msg = format!("{err}");
        // The error is wrapped with context in the decoder
        assert!(msg.contains("json-deserialize next value"));

        // After an error, you can still try to keep decoding
        // The engine has consumed the input already, so call decode again to pop any next valid item
        let next = dec
            .decode(&mut buf)
            .expect("second decode should not error");
        // Depending on engine behavior, it may or may not yield the second value after the failed one
        // We only assert that it is either Some(valid) or None, but it must not be an error
        if let Some(val) = next {
            assert_eq!(val, serde_json::json!({"ok": true}));
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    #[allow(dead_code)]
    struct OrderEvent {
        item: String,
        quantity: u32,
        prepaid: bool,
    }

    #[test]
    fn decode_order_events() {
        let inputs = [
            r#"{"item":"Apple Watch Series 9","quantity":2,"prepaid":true}"#,
            concat!("\n", r#"{"item":"extra item","quantity":0,"prepaid":true}"#),
            concat!(
                "\n",
                r#"{"item":"Gaming Mousepad XL","quantity":1,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Noise Cancelling Headphones","quantity":3,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Ergonomic Chair","quantity":1,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"extra item","quantity":6,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"LED Monitor 27\"","quantity":4,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Smartphone Stand","quantity":6,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Mechanical Keyboard","quantity":2,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"extra item","quantity":12,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Laptop Sleeve 15.6\"","quantity":3,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"USB-C Docking Station","quantity":1,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Wireless Presenter","quantity":1,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"extra item","quantity":18,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Foldable Desk Lamp","quantity":5,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Portable SSD 1TB","quantity":2,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Webcam Cover Slide","quantity":10,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"extra item","quantity":24,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Bluetooth Speaker","quantity":2,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Fitness Tracker Band","quantity":4,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Laser Pointer","quantity":1,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"extra item","quantity":30,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Conference Mic","quantity":2,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Noise-Absorbing Panels","quantity":12,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Desk Organizer Set","quantity":1,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"extra item","quantity":36,"prepaid":true}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Whiteboard Eraser Pack","quantity":6,"prepaid":false}"#
            ),
            concat!(
                "\n",
                r#"{"item":"Travel Power Adapter","quantity":2,"prepaid":true}"#
            ),
        ];

        let mut event_count = 0;
        let mut unique_events = HashSet::new();
        let mut dec: JsonDecoder<OrderEvent> = JsonDecoder::new();

        for input in inputs {
            let mut buf = BytesMut::from(input);
            while !buf.is_empty() {
                if let Some(event) = dec.decode(&mut buf).unwrap() {
                    unique_events.insert(event.item);
                    event_count += 1;
                }
            }
        }
        while let Some(event) = dec.decode_eof(&mut Default::default()).unwrap() {
            unique_events.insert(event.item);
            event_count += 1;
        }
        assert_eq!(28, event_count);
        assert_eq!(22, unique_events.len());
    }

    #[test]
    fn decode_order_events_random_chunks() {
        let raw_input = [
            r##"{"item":"Apple Watch Series 9","quantity":2,"prepaid":true}"##,
            r##"{"item":"extra item","quantity":0,"prepaid":true}"##,
            r##"{"item":"Gaming Mousepad XL","quantity":1,"prepaid":false}"##,
            r##"{"item":"Noise Cancelling Headphones","quantity":3,"prepaid":true}"##,
            r##"{"item":"Ergonomic Chair","quantity":1,"prepaid":true}"##,
            r##"{"item":"extra item","quantity":6,"prepaid":false}"##,
            r##"{"item":"LED Monitor 27\"","quantity":4,"prepaid":false}"##,
            r##"{"item":"Smartphone Stand","quantity":6,"prepaid":false}"##,
            r##"{"item":"Mechanical Keyboard","quantity":2,"prepaid":true}"##,
            r##"{"item":"extra item","quantity":12,"prepaid":true}"##,
            r##"{"item":"Laptop Sleeve 15.6\"","quantity":3,"prepaid":false}"##,
            r##"{"item":"USB-C Docking Station","quantity":1,"prepaid":true}"##,
            r##"{"item":"Wireless Presenter","quantity":1,"prepaid":false}"##,
            r##"{"item":"extra item","quantity":18,"prepaid":false}"##,
            r##"{"item":"Foldable Desk Lamp","quantity":5,"prepaid":true}"##,
            r##"{"item":"Portable SSD 1TB","quantity":2,"prepaid":true}"##,
            r##"{"item":"Webcam Cover Slide","quantity":10,"prepaid":false}"##,
            r##"{"item":"extra item","quantity":24,"prepaid":true}"##,
            r##"{"item":"Bluetooth Speaker","quantity":2,"prepaid":false}"##,
            r##"{"item":"Fitness Tracker Band","quantity":4,"prepaid":true}"##,
            r##"{"item":"Laser Pointer","quantity":1,"prepaid":false}"##,
            r##"{"item":"extra item","quantity":30,"prepaid":false}"##,
            r##"{"item":"Conference Mic","quantity":2,"prepaid":true}"##,
            r##"{"item":"Noise-Absorbing Panels","quantity":12,"prepaid":false}"##,
            r##"{"item":"Desk Organizer Set","quantity":1,"prepaid":true}"##,
            r##"{"item":"extra item","quantity":36,"prepaid":true}"##,
            r##"{"item":"Whiteboard Eraser Pack","quantity":6,"prepaid":false}"##,
            r##"{"item":"Travel Power Adapter","quantity":2,"prepaid":true}"##,
        ]
        .join("\n");

        // try it 32 times...
        for _ in 0..32 {
            let max = raw_input.len();
            let mut begin = 0;

            let mut event_count = 0;
            let mut unique_events = HashSet::new();
            let mut dec: JsonDecoder<OrderEvent> = JsonDecoder::new();

            while begin < max {
                let end = rand::random_range(begin..=max);
                let mut buf = BytesMut::from(&raw_input[begin..end]);
                while !buf.is_empty() {
                    if let Some(event) = dec.decode(&mut buf).unwrap() {
                        unique_events.insert(event.item);
                        event_count += 1;
                    }
                }
                begin = end;
            }

            while let Some(event) = dec.decode_eof(&mut Default::default()).unwrap() {
                unique_events.insert(event.item);
                event_count += 1;
            }

            assert_eq!(28, event_count);
            assert_eq!(22, unique_events.len());
        }
    }
}
