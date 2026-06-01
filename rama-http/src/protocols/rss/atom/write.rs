use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};

use super::names::elem;
use super::read::AtomHeader;
use super::types::{
    AtomCategory, AtomContent, AtomEntry, AtomLink, AtomPerson, AtomText, AtomTextKind,
};
use crate::protocols::rss::feed_ext::names::{attr, content};
use crate::protocols::rss::feed_ext::write as ext_write;
use crate::protocols::rss::ns;
use crate::protocols::rss::ser::{
    XmlWriteError, write_cdata_escaped, write_opt_text_elem, write_text_elem,
};

/// Open `<feed>` and emit all feed-level metadata + extension blocks. Stops
/// just before entries so the caller can stream them in.
///
/// Always declares the well-known extension namespaces (`itunes`, `podcast`,
/// `dc`, `media`); see the comment in [`crate::protocols::rss::rss2::write_rss2_channel_open`]
/// for why.
pub(in crate::protocols::rss) fn write_atom_feed_open<W: std::io::Write>(
    w: &mut Writer<W>,
    header: &AtomHeader,
) -> Result<(), XmlWriteError> {
    let mut feed_tag = BytesStart::new(elem::FEED);
    ns::push_xmlns_atom_default(&mut feed_tag);
    ns::push_xmlns_itunes(&mut feed_tag);
    ns::push_xmlns_podcast(&mut feed_tag);
    ns::push_xmlns_dc(&mut feed_tag);
    ns::push_xmlns_media(&mut feed_tag);
    ns::push_xmlns_content(&mut feed_tag);
    ns::push_xmlns_psc(&mut feed_tag);

    w.write_event(Event::Start(feed_tag))?;

    write_text_elem(w, elem::ID, &header.id)?;
    write_atom_text(w, elem::TITLE, &header.title)?;
    write_text_elem(w, elem::UPDATED, &header.updated.to_string())?;

    for author in &header.authors {
        write_atom_person(w, elem::AUTHOR, author)?;
    }
    for link in &header.links {
        write_atom_link(w, link)?;
    }
    for cat in &header.categories {
        write_atom_category(w, cat)?;
    }
    for contrib in &header.contributors {
        write_atom_person(w, elem::CONTRIBUTOR, contrib)?;
    }
    if let Some(generator) = &header.generator {
        let mut tag = BytesStart::new(elem::GENERATOR);
        if let Some(uri) = &generator.uri {
            tag.push_attribute((attr::URI, uri.as_str()));
        }
        if let Some(ver) = &generator.version {
            tag.push_attribute((attr::VERSION, ver.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&generator.value)))?;
        w.write_event(Event::End(BytesEnd::new(elem::GENERATOR)))?;
    }
    write_opt_text_elem(w, elem::ICON, header.icon.as_deref())?;
    write_opt_text_elem(w, elem::LOGO, header.logo.as_deref())?;
    if let Some(rights) = &header.rights {
        write_atom_text(w, elem::RIGHTS, rights)?;
    }
    if let Some(subtitle) = &header.subtitle {
        write_atom_text(w, elem::SUBTITLE, subtitle)?;
    }

    if let Some(itunes) = &header.extensions.itunes {
        ext_write::write_itunes_feed(w, itunes)?;
    }
    if let Some(podcast) = &header.extensions.podcast {
        ext_write::write_podcast_feed(w, podcast)?;
    }
    if let Some(dc) = &header.extensions.dublin_core {
        ext_write::write_dc_feed_fields(w, dc)?;
    }

    Ok(())
}

/// Close `</feed>`. Pairs with [`write_atom_feed_open`].
pub(in crate::protocols::rss) fn write_atom_feed_close<W: std::io::Write>(
    w: &mut Writer<W>,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::End(BytesEnd::new(elem::FEED)))?;
    Ok(())
}

pub(in crate::protocols::rss) fn write_atom_entry<W: std::io::Write>(
    w: &mut Writer<W>,
    entry: &AtomEntry,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new(elem::ENTRY)))?;

    write_text_elem(w, elem::ID, &entry.id)?;
    write_atom_text(w, elem::TITLE, &entry.title)?;
    write_text_elem(w, elem::UPDATED, &entry.updated.to_string())?;

    for author in &entry.authors {
        write_atom_person(w, elem::AUTHOR, author)?;
    }
    for link in &entry.links {
        write_atom_link(w, link)?;
    }
    if let Some(summary) = &entry.summary {
        write_atom_text(w, elem::SUMMARY, summary)?;
    }
    if let Some(content) = &entry.content {
        write_atom_content(w, content)?;
    }
    for cat in &entry.categories {
        write_atom_category(w, cat)?;
    }
    for contrib in &entry.contributors {
        write_atom_person(w, elem::CONTRIBUTOR, contrib)?;
    }
    if let Some(published) = &entry.published {
        write_text_elem(w, elem::PUBLISHED, &published.to_string())?;
    }
    if let Some(rights) = &entry.rights {
        write_atom_text(w, elem::RIGHTS, rights)?;
    }
    if let Some(source) = &entry.source {
        w.write_event(Event::Start(BytesStart::new(elem::SOURCE)))?;
        write_opt_text_elem(w, elem::ID, source.id.as_deref())?;
        if let Some(title) = &source.title {
            write_atom_text(w, elem::TITLE, title)?;
        }
        if let Some(updated) = &source.updated {
            write_text_elem(w, elem::UPDATED, &updated.to_string())?;
        }
        w.write_event(Event::End(BytesEnd::new(elem::SOURCE)))?;
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
    if let Some(chapters) = &entry.extensions.podlove {
        ext_write::write_podlove_chapters(w, chapters)?;
    }
    // Atom has native <content>, so <content:encoded> is rare in Atom
    // feeds — but the parser fills the field if the input carries it
    // (mixed feeds happen), so the writer must round-trip it through.
    if let Some(c) = &entry.extensions.content
        && let Some(encoded) = &c.encoded
    {
        w.write_event(Event::Start(BytesStart::new(content::ENCODED_TAG)))?;
        write_cdata_escaped(w, encoded)?;
        w.write_event(Event::End(BytesEnd::new(content::ENCODED_TAG)))?;
    }

    w.write_event(Event::End(BytesEnd::new(elem::ENTRY)))?;
    Ok(())
}

fn write_atom_content<W: std::io::Write>(
    w: &mut Writer<W>,
    content: &AtomContent,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new(elem::CONTENT);
    if let Some(src) = &content.src {
        // Out-of-line content: the MIME type lives in `out_of_line_type`;
        // we fall back to the inline kind ("text"/"html"/"xhtml") if the
        // caller didn't set one, so misuse can never produce a malformed
        // `type=` attribute.
        tag.push_attribute((attr::SRC, src.as_str()));
        let mime = content
            .out_of_line_type
            .as_deref()
            .unwrap_or_else(|| content.value.kind.type_attr());
        tag.push_attribute((attr::TYPE, mime));
        w.write_event(Event::Empty(tag))?;
    } else {
        tag.push_attribute((attr::TYPE, content.value.kind.type_attr()));
        w.write_event(Event::Start(tag))?;
        write_atom_text_body(w, &content.value)?;
        w.write_event(Event::End(BytesEnd::new(elem::CONTENT)))?;
    }
    Ok(())
}

fn write_atom_text<W: std::io::Write>(
    w: &mut Writer<W>,
    name: &str,
    text: &AtomText,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new(name);
    tag.push_attribute((attr::TYPE, text.kind.type_attr()));
    w.write_event(Event::Start(tag))?;
    write_atom_text_body(w, text)?;
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

fn write_atom_text_body<W: std::io::Write>(
    w: &mut Writer<W>,
    text: &AtomText,
) -> Result<(), XmlWriteError> {
    let s = text.value.as_str();
    match text.kind {
        AtomTextKind::Text => {
            w.write_event(Event::Text(BytesText::new(s)))?;
        }
        AtomTextKind::Html => {
            write_cdata_escaped(w, s)?;
        }
        AtomTextKind::Xhtml => {
            // RFC 4287 §3.1.1.3: xhtml content is a single XHTML-namespaced
            // <div> whose children are real markup, emitted verbatim. Guard
            // against malformed input so we never emit a broken document.
            if !xhtml_well_formed(s) {
                return Err(XmlWriteError::from(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "atom xhtml content is not well-formed XML",
                )));
            }
            let mut div = BytesStart::new(elem::DIV);
            div.push_attribute(("xmlns", ns::XHTML_NS));
            w.write_event(Event::Start(div))?;
            w.write_event(Event::Text(BytesText::from_escaped(s)))?;
            w.write_event(Event::End(BytesEnd::new(elem::DIV)))?;
        }
    }
    Ok(())
}

/// Returns `true` if `fragment` is balanced, well-formed XML *and* contains
/// only the event kinds permitted inside an Atom `type="xhtml"` `<div>`
/// (per RFC 4287 §3.1.1.3): elements, text, CDATA, and comments. Document-
/// level constructs — XML declaration, DOCTYPE, and processing instructions —
/// are not legal inside a content element and would produce invalid XML if
/// emitted verbatim, so they are rejected here even though `quick-xml`'s
/// tokenizer accepts them.
///
/// Validates depth-counted in-place; no allocation. (Earlier versions
/// wrapped the fragment in a synthetic `<x>…</x>` so it would parse as a
/// single rooted document — that allocation is unnecessary, we just need
/// to assert depth ends at zero.)
fn xhtml_well_formed(fragment: &str) -> bool {
    let mut reader = quick_xml::Reader::from_str(fragment);
    let mut depth: i32 = 0;
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => return depth == 0,
            Ok(Event::Start(_)) => depth += 1,
            Ok(Event::End(_)) => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Ok(Event::Empty(_) | Event::Text(_) | Event::CData(_) | Event::Comment(_)) => {}
            Ok(Event::Decl(_) | Event::DocType(_) | Event::PI(_)) | Err(_) => return false,
        }
    }
}

fn write_atom_person<W: std::io::Write>(
    w: &mut Writer<W>,
    tag_name: &str,
    person: &AtomPerson,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new(tag_name)))?;
    write_text_elem(w, elem::NAME, &person.name)?;
    write_opt_text_elem(w, elem::EMAIL, person.email.as_deref())?;
    write_opt_text_elem(w, elem::URI, person.uri.as_deref())?;
    w.write_event(Event::End(BytesEnd::new(tag_name)))?;
    Ok(())
}

fn write_atom_link<W: std::io::Write>(
    w: &mut Writer<W>,
    link: &AtomLink,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new(elem::LINK);
    tag.push_attribute((attr::HREF, link.href.as_str()));
    if let Some(rel) = &link.rel {
        tag.push_attribute((attr::REL, rel.as_str()));
    }
    if let Some(type_) = &link.type_ {
        tag.push_attribute((attr::TYPE, type_.as_str()));
    }
    if let Some(lang) = &link.hreflang {
        tag.push_attribute((attr::HREFLANG, lang.as_str()));
    }
    if let Some(title) = &link.title {
        tag.push_attribute((attr::TITLE, title.as_str()));
    }
    if let Some(len) = link.length {
        tag.push_attribute((attr::LENGTH, len.to_string().as_str()));
    }
    w.write_event(Event::Empty(tag))?;
    Ok(())
}

fn write_atom_category<W: std::io::Write>(
    w: &mut Writer<W>,
    cat: &AtomCategory,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new(elem::CATEGORY);
    tag.push_attribute((attr::TERM, cat.term.as_str()));
    if let Some(scheme) = &cat.scheme {
        tag.push_attribute((attr::SCHEME, scheme.as_str()));
    }
    if let Some(label) = &cat.label {
        tag.push_attribute((attr::LABEL, label.as_str()));
    }
    w.write_event(Event::Empty(tag))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use crate::protocols::rss::atom::types::{
        AtomContent, AtomEntry, AtomFeed, AtomLink, AtomPerson, AtomText,
    };

    #[test]
    fn builder_enforces_all_required_fields() {
        let ts = Timestamp::now();
        let feed = AtomFeed::builder()
            .updated(ts)
            .id("urn:uuid:test")
            .title("Test Feed")
            .build();
        assert_eq!(feed.id, "urn:uuid:test");
        assert_eq!(feed.title, AtomText::text("Test Feed"));
        assert_eq!(feed.updated, ts);
    }

    #[tokio::test]
    async fn feed_serializes_to_valid_xml() {
        let ts = Timestamp::now();
        let feed = AtomFeed::builder()
            .id("https://example.com/feed")
            .title("My Blog")
            .updated(ts)
            .with_author(AtomPerson::new("Author"))
            .with_link(AtomLink::alternate("https://example.com"))
            .with_entry(
                AtomEntry::new("https://example.com/1", "Post 1", ts)
                    .with_content(AtomContent::html("<p>Hello</p>")),
            )
            .build();

        let xml_bytes = feed.to_xml().await.expect("serialize");
        let xml = String::from_utf8(xml_bytes).expect("utf-8");
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
        assert_eq!(text.kind.type_attr(), "html");
        assert_eq!(text.value, "<b>bold</b>");
    }

    #[tokio::test]
    async fn xhtml_malformed_content_errors() {
        let ts = Timestamp::UNIX_EPOCH;
        let bad = AtomFeed::builder()
            .id("urn:f")
            .title("T")
            .updated(ts)
            .with_entry(AtomEntry::new("urn:1", "E", ts).with_content(AtomContent {
                value: AtomText::xhtml("<p>broken"),
                src: None,
                out_of_line_type: None,
            }))
            .build();
        bad.to_xml()
            .await
            .expect_err("malformed xhtml should fail to serialize");

        let ok = AtomFeed::builder()
            .id("urn:f")
            .title("T")
            .updated(ts)
            .with_entry(AtomEntry::new("urn:1", "E", ts).with_content(AtomContent {
                value: AtomText::xhtml("<p>ok</p>"),
                src: None,
                out_of_line_type: None,
            }))
            .build();
        ok.to_xml().await.expect("valid xhtml should serialize");
    }

    #[tokio::test]
    async fn xhtml_content_wrapped_in_namespaced_div() {
        let ts = Timestamp::UNIX_EPOCH;
        let feed = AtomFeed::builder()
            .id("urn:f")
            .title("T")
            .updated(ts)
            .with_entry(AtomEntry::new("urn:1", "E", ts).with_content(AtomContent {
                value: AtomText::xhtml("<p>hi</p>"),
                src: None,
                out_of_line_type: None,
            }))
            .build();
        let xml_bytes = feed.to_xml().await.expect("serialize");
        let xml = String::from_utf8(xml_bytes).expect("utf-8");
        assert!(
            xml.contains(
                r#"<content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml"><p>hi</p></div></content>"#
            ),
            "{xml}"
        );
    }
}
