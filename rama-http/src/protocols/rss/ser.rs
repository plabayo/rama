//! Shared XML serialization helpers.

use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};

/// Error type for XML write operations.
#[derive(Debug)]
pub struct XmlWriteError(quick_xml::Error);

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
    w.write_event(Event::Text(BytesText::new(value)))?;
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
