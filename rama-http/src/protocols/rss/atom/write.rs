use quick_xml::{
    Writer,
    events::{BytesCData, BytesEnd, BytesStart, BytesText, Event},
};

use super::super::ext_write;
use super::super::ser::{XmlWriteError, write_opt_text_elem, write_text_elem};
use super::types::{
    AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomLink, AtomPerson, AtomText,
};

pub(super) fn write_atom_feed<W: std::io::Write>(
    w: &mut Writer<W>,
    feed: &AtomFeed,
) -> Result<(), XmlWriteError> {
    let mut feed_tag = BytesStart::new("feed");
    feed_tag.push_attribute(("xmlns", "http://www.w3.org/2005/Atom"));

    let needs_itunes = feed.extensions.itunes.is_some()
        || feed.entries.iter().any(|e| e.extensions.itunes.is_some());
    let needs_podcast = feed.extensions.podcast.is_some()
        || feed.entries.iter().any(|e| e.extensions.podcast.is_some());
    let needs_dc = feed.extensions.dublin_core.is_some()
        || feed
            .entries
            .iter()
            .any(|e| e.extensions.dublin_core.is_some());
    let needs_media = feed.entries.iter().any(|e| e.extensions.media.is_some());

    if needs_itunes {
        feed_tag.push_attribute(("xmlns:itunes", "http://www.itunes.com/dtds/podcast-1.0.dtd"));
    }
    if needs_podcast {
        feed_tag.push_attribute(("xmlns:podcast", "https://podcastindex.org/namespace/1.0"));
    }
    if needs_dc {
        feed_tag.push_attribute(("xmlns:dc", "http://purl.org/dc/elements/1.1/"));
    }
    if needs_media {
        feed_tag.push_attribute(("xmlns:media", "http://search.yahoo.com/mrss/"));
    }

    w.write_event(Event::Start(feed_tag))?;

    write_text_elem(w, "id", &feed.id)?;
    write_atom_text(w, "title", &feed.title)?;
    write_text_elem(w, "updated", &feed.updated.to_string())?;

    for author in &feed.authors {
        write_atom_person(w, "author", author)?;
    }
    for link in &feed.links {
        write_atom_link(w, link)?;
    }
    for cat in &feed.categories {
        write_atom_category(w, cat)?;
    }
    for contrib in &feed.contributors {
        write_atom_person(w, "contributor", contrib)?;
    }
    if let Some(generator) = &feed.generator {
        let mut tag = BytesStart::new("generator");
        if let Some(uri) = &generator.uri {
            tag.push_attribute(("uri", uri.as_str()));
        }
        if let Some(ver) = &generator.version {
            tag.push_attribute(("version", ver.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&generator.value)))?;
        w.write_event(Event::End(BytesEnd::new("generator")))?;
    }
    write_opt_text_elem(w, "icon", feed.icon.as_deref())?;
    write_opt_text_elem(w, "logo", feed.logo.as_deref())?;
    if let Some(rights) = &feed.rights {
        write_atom_text(w, "rights", rights)?;
    }
    if let Some(subtitle) = &feed.subtitle {
        write_atom_text(w, "subtitle", subtitle)?;
    }

    if let Some(itunes) = &feed.extensions.itunes {
        ext_write::write_itunes_feed(w, itunes)?;
    }
    if let Some(podcast) = &feed.extensions.podcast {
        ext_write::write_podcast_feed(w, podcast)?;
    }
    if let Some(dc) = &feed.extensions.dublin_core {
        ext_write::write_dc_feed_fields(w, dc)?;
    }

    for entry in &feed.entries {
        write_atom_entry(w, entry)?;
    }

    w.write_event(Event::End(BytesEnd::new("feed")))?;
    Ok(())
}

pub(in super::super) fn write_atom_entry<W: std::io::Write>(
    w: &mut Writer<W>,
    entry: &AtomEntry,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new("entry")))?;

    write_text_elem(w, "id", &entry.id)?;
    write_atom_text(w, "title", &entry.title)?;
    write_text_elem(w, "updated", &entry.updated.to_string())?;

    for author in &entry.authors {
        write_atom_person(w, "author", author)?;
    }
    for link in &entry.links {
        write_atom_link(w, link)?;
    }
    if let Some(summary) = &entry.summary {
        write_atom_text(w, "summary", summary)?;
    }
    if let Some(content) = &entry.content {
        write_atom_content(w, content)?;
    }
    for cat in &entry.categories {
        write_atom_category(w, cat)?;
    }
    for contrib in &entry.contributors {
        write_atom_person(w, "contributor", contrib)?;
    }
    if let Some(published) = &entry.published {
        write_text_elem(w, "published", &published.to_string())?;
    }
    if let Some(rights) = &entry.rights {
        write_atom_text(w, "rights", rights)?;
    }
    if let Some(source) = &entry.source {
        w.write_event(Event::Start(BytesStart::new("source")))?;
        write_opt_text_elem(w, "id", source.id.as_deref())?;
        if let Some(title) = &source.title {
            write_atom_text(w, "title", title)?;
        }
        if let Some(updated) = &source.updated {
            write_text_elem(w, "updated", &updated.to_string())?;
        }
        w.write_event(Event::End(BytesEnd::new("source")))?;
    }

    if let Some(dc) = &entry.extensions.dublin_core {
        ext_write::write_dc_item_fields(w, dc)?;
    }
    if let Some(itunes) = &entry.extensions.itunes {
        ext_write::write_itunes_item(w, itunes)?;
    }
    if let Some(podcast) = &entry.extensions.podcast {
        ext_write::write_podcast_item(w, podcast)?;
    }
    if let Some(media) = &entry.extensions.media {
        ext_write::write_media_item(w, media)?;
    }

    w.write_event(Event::End(BytesEnd::new("entry")))?;
    Ok(())
}

fn write_atom_content<W: std::io::Write>(
    w: &mut Writer<W>,
    content: &AtomContent,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new("content");
    if let Some(src) = &content.src {
        tag.push_attribute(("src", src.as_str()));
        tag.push_attribute(("type", content.value.value()));
        w.write_event(Event::Empty(tag))?;
    } else {
        tag.push_attribute(("type", content.value.type_attr()));
        w.write_event(Event::Start(tag))?;
        write_atom_text_body(w, &content.value)?;
        w.write_event(Event::End(BytesEnd::new("content")))?;
    }
    Ok(())
}

fn write_atom_text<W: std::io::Write>(
    w: &mut Writer<W>,
    name: &str,
    text: &AtomText,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new(name);
    tag.push_attribute(("type", text.type_attr()));
    w.write_event(Event::Start(tag))?;
    write_atom_text_body(w, text)?;
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

fn write_atom_text_body<W: std::io::Write>(
    w: &mut Writer<W>,
    text: &AtomText,
) -> Result<(), XmlWriteError> {
    match text {
        AtomText::Text(s) => {
            w.write_event(Event::Text(BytesText::new(s)))?;
        }
        AtomText::Html(s) => {
            w.write_event(Event::CData(BytesCData::new(s)))?;
        }
        AtomText::Xhtml(s) => {
            // RFC 4287 §3.1.1.3: xhtml content is a single XHTML-namespaced
            // <div> whose children are real markup, emitted verbatim. Guard
            // against malformed input so we never emit a broken document.
            if !xhtml_well_formed(s) {
                return Err(XmlWriteError::from(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "atom xhtml content is not well-formed XML",
                )));
            }
            let mut div = BytesStart::new("div");
            div.push_attribute(("xmlns", "http://www.w3.org/1999/xhtml"));
            w.write_event(Event::Start(div))?;
            w.write_event(Event::Text(BytesText::from_escaped(s.as_str())))?;
            w.write_event(Event::End(BytesEnd::new("div")))?;
        }
    }
    Ok(())
}

/// Returns `true` if `fragment` is balanced, well-formed XML, so it is safe to
/// embed verbatim inside an Atom `type="xhtml"` `<div>`.
fn xhtml_well_formed(fragment: &str) -> bool {
    let wrapped = format!("<x>{fragment}</x>");
    let mut reader = quick_xml::Reader::from_str(&wrapped);
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => return true,
            Err(_) => return false,
            Ok(_) => {}
        }
    }
}

fn write_atom_person<W: std::io::Write>(
    w: &mut Writer<W>,
    tag_name: &str,
    person: &AtomPerson,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new(tag_name)))?;
    write_text_elem(w, "name", &person.name)?;
    write_opt_text_elem(w, "email", person.email.as_deref())?;
    write_opt_text_elem(w, "uri", person.uri.as_deref())?;
    w.write_event(Event::End(BytesEnd::new(tag_name)))?;
    Ok(())
}

fn write_atom_link<W: std::io::Write>(
    w: &mut Writer<W>,
    link: &AtomLink,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new("link");
    tag.push_attribute(("href", link.href.as_str()));
    if let Some(rel) = &link.rel {
        tag.push_attribute(("rel", rel.as_str()));
    }
    if let Some(type_) = &link.type_ {
        tag.push_attribute(("type", type_.as_str()));
    }
    if let Some(lang) = &link.hreflang {
        tag.push_attribute(("hreflang", lang.as_str()));
    }
    if let Some(title) = &link.title {
        tag.push_attribute(("title", title.as_str()));
    }
    if let Some(len) = link.length {
        tag.push_attribute(("length", len.to_string().as_str()));
    }
    w.write_event(Event::Empty(tag))?;
    Ok(())
}

fn write_atom_category<W: std::io::Write>(
    w: &mut Writer<W>,
    cat: &AtomCategory,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new("category");
    tag.push_attribute(("term", cat.term.as_str()));
    if let Some(scheme) = &cat.scheme {
        tag.push_attribute(("scheme", scheme.as_str()));
    }
    if let Some(label) = &cat.label {
        tag.push_attribute(("label", label.as_str()));
    }
    w.write_event(Event::Empty(tag))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::super::types::{AtomContent, AtomEntry, AtomFeed, AtomLink, AtomPerson, AtomText};

    #[test]
    fn builder_enforces_all_required_fields() {
        let ts = Timestamp::now();
        let feed = AtomFeed::builder()
            .updated(ts)
            .id("urn:uuid:test")
            .title("Test Feed")
            .build();
        assert_eq!(feed.id, "urn:uuid:test");
        assert_eq!(feed.title, AtomText::Text("Test Feed".into()));
        assert_eq!(feed.updated, ts);
    }

    #[test]
    fn feed_serializes_to_valid_xml() {
        let ts = Timestamp::now();
        let feed = AtomFeed::builder()
            .id("https://example.com/feed")
            .title("My Blog")
            .updated(ts)
            .author(AtomPerson::new("Author"))
            .link(AtomLink::alternate("https://example.com"))
            .entry(
                AtomEntry::new("https://example.com/1", "Post 1", ts)
                    .with_content(AtomContent::html("<p>Hello</p>")),
            )
            .build();

        let xml = feed.to_string();
        assert!(xml.contains("<?xml"));
        assert!(xml.contains(r#"xmlns="http://www.w3.org/2005/Atom""#));
        assert!(xml.contains("<id>https://example.com/feed</id>"));
        assert!(xml.contains("My Blog"));
        assert!(xml.contains("<entry>"));
        assert!(xml.contains("Post 1"));
    }

    #[test]
    fn atom_text_preserves_type() {
        let text = AtomText::html("<b>bold</b>");
        assert_eq!(text.type_attr(), "html");
        assert_eq!(text.value(), "<b>bold</b>");
    }

    #[test]
    fn xhtml_malformed_content_errors() {
        let ts = Timestamp::UNIX_EPOCH;
        let bad = AtomFeed::builder()
            .id("urn:f")
            .title("T")
            .updated(ts)
            .entry(AtomEntry::new("urn:1", "E", ts).with_content(AtomContent {
                value: AtomText::xhtml("<p>broken"),
                src: None,
            }))
            .build();
        bad.to_xml()
            .expect_err("malformed xhtml should fail to serialize");

        let ok = AtomFeed::builder()
            .id("urn:f")
            .title("T")
            .updated(ts)
            .entry(AtomEntry::new("urn:1", "E", ts).with_content(AtomContent {
                value: AtomText::xhtml("<p>ok</p>"),
                src: None,
            }))
            .build();
        ok.to_xml().expect("valid xhtml should serialize");
    }

    #[test]
    fn xhtml_content_wrapped_in_namespaced_div() {
        let ts = Timestamp::UNIX_EPOCH;
        let feed = AtomFeed::builder()
            .id("urn:f")
            .title("T")
            .updated(ts)
            .entry(AtomEntry::new("urn:1", "E", ts).with_content(AtomContent {
                value: AtomText::xhtml("<p>hi</p>"),
                src: None,
            }))
            .build();
        let xml = feed.to_string();
        assert!(
            xml.contains(
                r#"<content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml"><p>hi</p></div></content>"#
            ),
            "{xml}"
        );
    }
}
