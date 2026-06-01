//! Shared XML serialization helpers.

use quick_xml::{
    Writer,
    events::{BytesCData, BytesEnd, BytesStart, BytesText, Event},
};

/// Error type for XML write operations.
#[derive(Debug)]
pub(super) struct XmlWriteError(quick_xml::Error);

impl std::fmt::Display for XmlWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "xml write error: {}", self.0)
    }
}

impl std::error::Error for XmlWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<quick_xml::Error> for XmlWriteError {
    fn from(e: quick_xml::Error) -> Self {
        Self(e)
    }
}

impl From<std::io::Error> for XmlWriteError {
    fn from(e: std::io::Error) -> Self {
        Self(quick_xml::Error::from(e))
    }
}

pub(super) fn write_text_elem<W: std::io::Write>(
    w: &mut Writer<W>,
    name: &str,
    value: &str,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new(name)))?;
    // If the body carries markup-significant characters (`<` or `&`), emit
    // as one or more CDATA sections rather than escaped entities. Both
    // forms parse back to the same string, but CDATA stays close to the
    // wire shape typical publishers emit (e.g. RSS `<description>`
    // carrying inline HTML, which most readers expect to find verbatim).
    // For plain text — the common case for titles, links, dates — the
    // path stays the cheap `BytesText` escape.
    if value.contains('<') || value.contains('&') {
        write_cdata_escaped(w, value)?;
    } else {
        w.write_event(Event::Text(BytesText::new(value)))?;
    }
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

pub(super) fn write_opt_text_elem<W: std::io::Write>(
    w: &mut Writer<W>,
    name: &str,
    value: Option<&str>,
) -> Result<(), XmlWriteError> {
    if let Some(v) = value {
        write_text_elem(w, name, v)?;
    }
    Ok(())
}

/// Write `content` as one or more CDATA sections, splitting at every `]]>`
/// occurrence so the resulting XML is well-formed for any input.
///
/// XML forbids the literal `]]>` token inside a `<![CDATA[ … ]]>` section
/// (it would close the section early). The standard workaround is to break the
/// CDATA at each occurrence: emit `<![CDATA[…]]]]><![CDATA[>…]]>` so the
/// `]]` lands at the end of one section and the `>` at the start of the next.
/// Concatenating the text content of both sections yields the original string.
pub(super) fn write_cdata_escaped<W: std::io::Write>(
    w: &mut Writer<W>,
    content: &str,
) -> Result<(), XmlWriteError> {
    let mut start = 0usize;
    while let Some(rel) = content[start..].find("]]>") {
        let split = start + rel + 2; // include "]]" in the head; ">" starts the next CDATA
        w.write_event(Event::CData(BytesCData::new(&content[start..split])))?;
        start = split;
    }
    w.write_event(Event::CData(BytesCData::new(&content[start..])))?;
    Ok(())
}
