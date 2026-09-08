use super::*;

pub(super) fn display(value: impl std::fmt::Display) -> impl IntoHtml {
    join_display([value], "")
}

pub(super) fn render_each(values: impl IntoIterator<Item = impl IntoHtml>) -> impl IntoHtml {
    move |output: &mut String| {
        for value in values {
            value.escape_and_write(output);
        }
    }
}

pub(super) fn header_preview(value: &rama::http::HeaderValue) -> impl std::fmt::Display + '_ {
    let bytes = value.as_bytes();
    let limit = std::str::from_utf8(bytes)
        .map(|text| {
            text.char_indices()
                .nth(4096)
                .map_or(bytes.len(), |(index, _)| index)
        })
        .unwrap_or(bytes.len().min(4096));
    rama::utils::fmt::display_fn(move |f: &mut std::fmt::Formatter<'_>| {
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
