use rama_json::capture::{CaptureHandler, CapturedValue, JsonCapturer};
use rama_json::path::JsonPath;
use rama_json::{JsonError, JsonErrorKind};
use rama_utils::octets::mib;
use serde_json::{Value, json};

const BOOKSTORE: &[u8] = br#"{
  "store": {
    "book": [
      {
        "category": "reference",
        "author": "Nigel Rees",
        "title": "Sayings of the Century",
        "price": 8.95
      },
      {
        "category": "fiction",
        "author": "Evelyn Waugh",
        "title": "Sword of Honour",
        "price": 12.99
      },
      {
        "category": "fiction",
        "author": "Herman Melville",
        "title": "Moby Dick",
        "isbn": "0-553-21311-3",
        "price": 8.99
      },
      {
        "category": "fiction",
        "author": "J. R. R. Tolkien",
        "title": "The Lord of the Rings",
        "isbn": "0-395-19395-8",
        "price": 22.99
      }
    ],
    "bicycle": {
      "color": "red",
      "price": 19.95
    }
  }
}"#;

#[derive(Debug, Default)]
struct Values {
    values: Vec<Value>,
}

impl CaptureHandler for Values {
    fn handle_capture(&mut self, value: CapturedValue<'_>) -> Result<(), JsonError> {
        self.values.push(value.deserialize()?);
        Ok(())
    }
}

#[test]
fn rfc9535_bookstore_examples_supported_by_streaming_matcher() -> Result<(), JsonError> {
    let cases = [
        (
            "$.store.book[*].author",
            json!([
                "Nigel Rees",
                "Evelyn Waugh",
                "Herman Melville",
                "J. R. R. Tolkien"
            ]),
        ),
        (
            "$..author",
            json!([
                "Nigel Rees",
                "Evelyn Waugh",
                "Herman Melville",
                "J. R. R. Tolkien"
            ]),
        ),
        (
            "$.store.*",
            json!([
                [
                    {
                        "category": "reference",
                        "author": "Nigel Rees",
                        "title": "Sayings of the Century",
                        "price": 8.95
                    },
                    {
                        "category": "fiction",
                        "author": "Evelyn Waugh",
                        "title": "Sword of Honour",
                        "price": 12.99
                    },
                    {
                        "category": "fiction",
                        "author": "Herman Melville",
                        "title": "Moby Dick",
                        "isbn": "0-553-21311-3",
                        "price": 8.99
                    },
                    {
                        "category": "fiction",
                        "author": "J. R. R. Tolkien",
                        "title": "The Lord of the Rings",
                        "isbn": "0-395-19395-8",
                        "price": 22.99
                    }
                ],
                {
                    "color": "red",
                    "price": 19.95
                }
            ]),
        ),
        ("$..price", json!([8.95, 12.99, 8.99, 22.99, 19.95])),
        (
            "$..book[2]",
            json!([
                {
                    "category": "fiction",
                    "author": "Herman Melville",
                    "title": "Moby Dick",
                    "isbn": "0-553-21311-3",
                    "price": 8.99
                }
            ]),
        ),
        ("$..book[0,1].author", json!(["Nigel Rees", "Evelyn Waugh"])),
        ("$..book[:2].author", json!(["Nigel Rees", "Evelyn Waugh"])),
    ];

    for (selector, expected) in cases {
        assert_eq!(select_values(selector)?, expected, "{selector}");
    }
    Ok(())
}

#[test]
fn rfc9535_filter_examples_are_rejected_explicitly() {
    let err = "$.store.book[?(@.price < 10)]"
        .parse::<JsonPath>()
        .unwrap_err();
    assert!(matches!(
        err.kind(),
        JsonErrorKind::UnsupportedJsonPath("filter selectors")
    ));
}

fn select_values(selector: &str) -> Result<Value, JsonError> {
    let path = selector.parse::<JsonPath>()?;
    let selectors = [path];
    let mut capturer = JsonCapturer::new(selectors, mib(8), Values::default());
    capturer.write(BOOKSTORE)?;
    capturer.end()?;
    Ok(Value::Array(capturer.into_handler().values))
}
