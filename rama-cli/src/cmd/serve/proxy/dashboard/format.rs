use std::fmt::{self, Write as _};

use rama::http::HeaderValue;

use super::*;

pub(super) fn display(value: impl fmt::Display) -> impl IntoHtml {
    join_display([value], "")
}

pub(super) fn uppercase(value: &str) -> impl fmt::Display + '_ {
    rama::utils::fmt::display_fn(move |f: &mut fmt::Formatter<'_>| {
        for ch in value.chars() {
            f.write_char(ch.to_ascii_uppercase())?;
        }
        Ok(())
    })
}

pub(super) fn render_each(values: impl IntoIterator<Item = impl IntoHtml>) -> impl IntoHtml {
    move |output: &mut String| {
        for value in values {
            value.escape_and_write(output);
        }
    }
}

pub(super) fn header_preview(value: &HeaderValue) -> impl fmt::Display + '_ {
    let bytes = value.as_bytes();
    let limit = std::str::from_utf8(bytes)
        .map(|text| {
            text.char_indices()
                .nth(4096)
                .map_or(bytes.len(), |(index, _)| index)
        })
        .unwrap_or(bytes.len().min(kib(4)));
    rama::utils::fmt::display_fn(move |f: &mut fmt::Formatter<'_>| {
        // Header values remain borrowed; only the final HTML buffer is allocated.
        match std::str::from_utf8(bytes) {
            Ok(text) => f.write_str(&text[..text.floor_char_boundary(limit)])?,
            Err(_) => write!(f, "{}", rama::utils::fmt::hex(&bytes[..limit]))?,
        }
        if limit < bytes.len() {
            f.write_str("…")?;
        }
        Ok(())
    })
}
