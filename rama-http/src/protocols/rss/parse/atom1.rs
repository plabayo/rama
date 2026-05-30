//! Atom 1.0 event-loop parser plus `capture_xhtml_subtree` — the helper that
//! re-emits the inner XML of an `Atom type="xhtml"` text construct so xhtml
//! content round-trips with its markup intact (RFC 4287 §3.1.1.3).
//!
//! `parse_atom` returns `(AtomFeed, saw_root)` so the caller in [`super`]
//! can decide whether a document without a `<feed>` root should be rejected.

use jiff::Timestamp;
use quick_xml::{NsReader, events::Event};
use rama_core::telemetry::tracing;

use super::super::atom::{
    AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomGenerator, AtomLink, AtomPerson,
    AtomSource, AtomText,
};
use super::super::ext_parse::{FeedExtAcc, ItemExtAcc, Ns, classify_ns};
use super::FeedParseError;
use super::helpers::{
    atom_category_from_attrs, atom_link_from_attrs, attr_value, make_atom_text, parse_rfc3339_lax,
};

/// Consume events until the matching End of the caller's currently-open
/// element, returning the inner XML as a `String`. Used by the Atom parser to
/// capture `type="xhtml"` text constructs, which are subtrees rather than
/// flat text.
///
/// Per RFC 4287 §3.1.1.3 the inner content is wrapped in a single XHTML-
/// namespaced `<div>`; if the very first child Start is a `<div>` we drop its
/// open/close tags from the captured output so callers can write it back
/// through the standard xhtml writer (which adds the wrapping div again).
fn capture_xhtml_subtree(reader: &mut NsReader<&[u8]>) -> Result<String, FeedParseError> {
    let mut captured = Vec::<u8>::new();
    let mut depth: i32 = 0;
    let mut saw_wrapper = false;
    {
        let mut writer = quick_xml::Writer::new(&mut captured);
        loop {
            let ev = reader
                .read_resolved_event()
                .map_err(|e| FeedParseError::new(format!("xhtml capture: {e}")))?;
            match ev {
                (_, Event::Start(e)) => {
                    if depth == 0 && !saw_wrapper && e.local_name().as_ref() == b"div" {
                        // wrapping XHTML <div> — don't emit, just enter
                        saw_wrapper = true;
                        depth += 1;
                    } else {
                        depth += 1;
                        writer
                            .write_event(Event::Start(e))
                            .map_err(|e| FeedParseError::new(format!("xhtml write: {e}")))?;
                    }
                }
                (_, Event::End(e)) => {
                    if depth == 0 {
                        // End of the outer element — done.
                        return String::from_utf8(captured).map_err(|err| {
                            FeedParseError::new(format!("xhtml inner is not utf-8: {err}"))
                        });
                    }
                    depth -= 1;
                    if depth == 0 && saw_wrapper {
                        // closing the wrapper div — skip it
                    } else {
                        writer
                            .write_event(Event::End(e))
                            .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?;
                    }
                }
                (_, Event::Empty(e)) => writer
                    .write_event(Event::Empty(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
                (_, Event::Text(e)) => writer
                    .write_event(Event::Text(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
                (_, Event::CData(e)) => writer
                    .write_event(Event::CData(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
                (_, Event::Comment(e)) => writer
                    .write_event(Event::Comment(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
                (_, Event::Eof) => {
                    return Err(FeedParseError::new("unexpected EOF in xhtml content"));
                }
                // Drop document-level constructs (DOCTYPE / PI / Decl) — these
                // are not legal inside Atom xhtml content.
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Atom parser
// ---------------------------------------------------------------------------

pub(crate) fn parse_atom(input: &str, strict: bool) -> Result<(AtomFeed, bool), FeedParseError> {
    let mut reader = NsReader::from_str(input);
    reader.config_mut().trim_text(true);

    let mut saw_root = false;

    // Feed state
    let mut feed_id = String::new();
    let mut feed_title = AtomText::text("");
    let mut feed_updated = Timestamp::UNIX_EPOCH;
    // True iff `<updated>` was seen *and* parsed as a valid RFC 3339 timestamp.
    // Used by strict mode to reject both missing and unparseable values.
    let mut feed_updated_parsed = false;
    let mut feed_authors: Vec<AtomPerson> = Vec::new();
    let mut feed_contributors: Vec<AtomPerson> = Vec::new();
    let mut feed_links: Vec<AtomLink> = Vec::new();
    let mut feed_categories: Vec<AtomCategory> = Vec::new();
    let mut feed_generator: Option<AtomGenerator> = None;
    let mut feed_icon: Option<String> = None;
    let mut feed_logo: Option<String> = None;
    let mut feed_rights: Option<AtomText> = None;
    let mut feed_subtitle: Option<AtomText> = None;
    let mut entries: Vec<AtomEntry> = Vec::new();
    let mut feed_acc = FeedExtAcc::default();

    // Entry state
    let mut in_entry = false;
    let mut in_author = false;
    let mut in_feed_author = false;
    let mut in_contributor = false;
    let mut in_feed_contributor = false;
    let mut in_source = false;
    let mut current_entry_id = String::new();
    let mut current_entry_id_set = false;
    let mut current_entry_title = AtomText::text("");
    let mut current_entry_title_set = false;
    let mut current_entry_updated = Timestamp::UNIX_EPOCH;
    let mut current_entry_updated_parsed = false;
    let mut current_entry_authors: Vec<AtomPerson> = Vec::new();
    let mut current_entry_contributors: Vec<AtomPerson> = Vec::new();
    let mut current_entry_links: Vec<AtomLink> = Vec::new();
    let mut current_entry_categories: Vec<AtomCategory> = Vec::new();
    let mut current_entry_summary: Option<AtomText> = None;
    let mut current_entry_content: Option<AtomContent> = None;
    let mut current_entry_published: Option<Timestamp> = None;
    let mut current_entry_rights: Option<AtomText> = None;
    let mut current_entry_source: Option<AtomSource> = None;
    let mut entry_acc = ItemExtAcc::default();

    // Shared sub-element state
    let mut current_author = AtomPerson::new("");
    let mut current_contributor = AtomPerson::new("");
    let mut current_source = AtomSource {
        id: None,
        title: None,
        updated: None,
    };
    let mut pending_generator: Option<AtomGenerator> = None;
    let mut current_content_type = String::from("text");
    let mut current_title_type = String::from("text");
    let mut current_summary_type = String::from("text");
    let mut current_subtitle_type = String::from("text");
    let mut current_rights_type = String::from("text");

    let mut text_buf = String::new();
    // Tracks `<x>` minus `</x>` so we can flag truncated documents at EOF.
    let mut depth: i32 = 0;

    loop {
        match reader.read_resolved_event() {
            Ok((rr, Event::Start(e))) => {
                depth += 1;
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                text_buf.clear();

                let consumed = if in_entry {
                    entry_acc.on_start(ns, local, &e)
                } else {
                    feed_acc.on_start(ns, local, &e)
                };
                if consumed {
                    continue;
                }

                if ns != Ns::Atom {
                    continue;
                }

                // Typed-text elements (RFC 4287 §3.1) with type="xhtml" are
                // *subtrees*, not flat text. Capture the inner markup here so
                // we don't lose it in the text-accumulator path. The capture
                // also consumes the matching End event, so the normal End
                // handler never sees this element.
                if matches!(
                    local,
                    "title" | "summary" | "content" | "rights" | "subtitle"
                ) && attr_value(&e, b"type").as_deref() == Some("xhtml")
                {
                    let which = local.to_owned();
                    let scope_in_entry = in_entry;
                    let scope_in_source = in_source;
                    drop(e);
                    drop(rr);
                    let xhtml_inner = capture_xhtml_subtree(&mut reader)?;
                    // capture_xhtml_subtree consumed the outer End event too,
                    // so balance the depth counter for it (we already
                    // incremented for the outer Start above).
                    depth -= 1;
                    let value = AtomText::Xhtml(xhtml_inner);
                    match (which.as_str(), scope_in_source, scope_in_entry) {
                        ("title", true, _) => current_source.title = Some(value),
                        ("title", false, true) => {
                            current_entry_title = value;
                            current_entry_title_set = true;
                        }
                        ("title", false, false) => feed_title = value,
                        ("summary", _, true) => current_entry_summary = Some(value),
                        ("content", _, true) => {
                            current_entry_content = Some(AtomContent { value, src: None });
                        }
                        ("rights", _, true) => current_entry_rights = Some(value),
                        ("rights", _, false) => feed_rights = Some(value),
                        ("subtitle", _, false) => feed_subtitle = Some(value),
                        _ => {}
                    }
                    continue;
                }

                match local {
                    "feed" => saw_root = true,
                    "entry" => {
                        in_entry = true;
                        current_entry_id = String::new();
                        current_entry_id_set = false;
                        current_entry_title = AtomText::text("");
                        current_entry_title_set = false;
                        current_entry_updated = Timestamp::UNIX_EPOCH;
                        current_entry_updated_parsed = false;
                        current_entry_authors = Vec::new();
                        current_entry_contributors = Vec::new();
                        current_entry_links = Vec::new();
                        current_entry_categories = Vec::new();
                        current_entry_summary = None;
                        current_entry_content = None;
                        current_entry_published = None;
                        current_entry_rights = None;
                        current_entry_source = None;
                        entry_acc = ItemExtAcc::default();
                    }
                    // RFC 4287 §4.2.11: `<source>` carries the entry's
                    // *origin* feed's metadata. Its child elements must not
                    // leak into the enclosing entry's collections — anything
                    // we don't model (author/contributor/link/category/etc.)
                    // is dropped while `in_source`.
                    "author" if !in_source => {
                        current_author = AtomPerson::new("");
                        if in_entry {
                            in_author = true;
                        } else {
                            in_feed_author = true;
                        }
                    }
                    "contributor" if !in_source => {
                        current_contributor = AtomPerson::new("");
                        if in_entry {
                            in_contributor = true;
                        } else {
                            in_feed_contributor = true;
                        }
                    }
                    "source" if in_entry && !in_source => {
                        in_source = true;
                        current_source = AtomSource {
                            id: None,
                            title: None,
                            updated: None,
                        };
                    }
                    "link" if !in_source => {
                        let link = atom_link_from_attrs(&e);
                        if in_entry {
                            current_entry_links.push(link);
                        } else {
                            feed_links.push(link);
                        }
                    }
                    "category" if !in_source => {
                        let cat = atom_category_from_attrs(&e);
                        if in_entry {
                            current_entry_categories.push(cat);
                        } else {
                            feed_categories.push(cat);
                        }
                    }
                    "title" => {
                        current_title_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "summary" => {
                        current_summary_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "content" => {
                        current_content_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "subtitle" => {
                        current_subtitle_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "rights" => {
                        current_rights_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "generator" if !in_source => {
                        pending_generator = Some(AtomGenerator {
                            value: String::new(),
                            uri: attr_value(&e, b"uri"),
                            version: attr_value(&e, b"version"),
                        });
                    }
                    _ => {}
                }
            }
            Ok((rr, Event::Empty(e))) => {
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                let consumed = if in_entry {
                    entry_acc.on_empty(ns, local, &e)
                } else {
                    feed_acc.on_empty(ns, local, &e)
                };
                if consumed {
                    continue;
                }

                if ns != Ns::Atom {
                    continue;
                }
                match local {
                    "link" if !in_source => {
                        let link = atom_link_from_attrs(&e);
                        if in_entry {
                            current_entry_links.push(link);
                        } else {
                            feed_links.push(link);
                        }
                    }
                    "category" if !in_source => {
                        let cat = atom_category_from_attrs(&e);
                        if in_entry {
                            current_entry_categories.push(cat);
                        } else {
                            feed_categories.push(cat);
                        }
                    }
                    "content" if in_entry && !in_source => {
                        // Out-of-line content: <content src=".." type=".."/>
                        if let Some(src) = attr_value(&e, b"src") {
                            let type_ = attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                            current_entry_content = Some(AtomContent {
                                value: AtomText::Text(type_),
                                src: Some(src),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Ok((_, Event::Text(e))) => match e.unescape() {
                Ok(t) => text_buf.push_str(&t),
                Err(err) => {
                    if strict {
                        return Err(FeedParseError::new(format!("invalid text content: {err}")));
                    }
                    // See parse_rss2's matching branch — preserve raw bytes so
                    // surrounding text isn't lost to a stray entity.
                    tracing::debug!("atom unescape error (lenient): {err}");
                    text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                }
            },
            Ok((_, Event::CData(e))) => match std::str::from_utf8(e.as_ref()) {
                Ok(t) => text_buf.push_str(t),
                Err(err) => {
                    if strict {
                        return Err(FeedParseError::new(format!("invalid CDATA: {err}")));
                    }
                    tracing::debug!("atom CDATA utf8 error (lenient): {err}");
                    text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                }
            },
            Ok((rr, Event::End(e))) => {
                depth -= 1;
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                let text = std::mem::take(&mut text_buf);

                if in_author && ns == Ns::Atom {
                    match local {
                        "name" => current_author.name = text,
                        "email" => current_author.email = Some(text),
                        "uri" => current_author.uri = Some(text),
                        "author" => {
                            current_entry_authors
                                .push(std::mem::replace(&mut current_author, AtomPerson::new("")));
                            in_author = false;
                        }
                        _ => {}
                    }
                } else if in_feed_author && ns == Ns::Atom {
                    match local {
                        "name" => current_author.name = text,
                        "email" => current_author.email = Some(text),
                        "uri" => current_author.uri = Some(text),
                        "author" => {
                            feed_authors
                                .push(std::mem::replace(&mut current_author, AtomPerson::new("")));
                            in_feed_author = false;
                        }
                        _ => {}
                    }
                } else if in_contributor && ns == Ns::Atom {
                    match local {
                        "name" => current_contributor.name = text,
                        "email" => current_contributor.email = Some(text),
                        "uri" => current_contributor.uri = Some(text),
                        "contributor" => {
                            current_entry_contributors.push(std::mem::replace(
                                &mut current_contributor,
                                AtomPerson::new(""),
                            ));
                            in_contributor = false;
                        }
                        _ => {}
                    }
                } else if in_feed_contributor && ns == Ns::Atom {
                    match local {
                        "name" => current_contributor.name = text,
                        "email" => current_contributor.email = Some(text),
                        "uri" => current_contributor.uri = Some(text),
                        "contributor" => {
                            feed_contributors.push(std::mem::replace(
                                &mut current_contributor,
                                AtomPerson::new(""),
                            ));
                            in_feed_contributor = false;
                        }
                        _ => {}
                    }
                } else if in_source && ns == Ns::Atom {
                    match local {
                        "id" => current_source.id = Some(text),
                        "title" => {
                            current_source.title = Some(make_atom_text(&current_title_type, text));
                        }
                        "updated" => current_source.updated = parse_rfc3339_lax(&text),
                        "source" => {
                            current_entry_source = Some(std::mem::replace(
                                &mut current_source,
                                AtomSource {
                                    id: None,
                                    title: None,
                                    updated: None,
                                },
                            ));
                            in_source = false;
                        }
                        _ => {}
                    }
                } else if in_entry {
                    let Some(text) = entry_acc.on_end(ns, local, text) else {
                        continue;
                    };
                    if ns != Ns::Atom {
                        continue;
                    }
                    match local {
                        "id" => {
                            current_entry_id = text;
                            current_entry_id_set = true;
                        }
                        "title" => {
                            current_entry_title = make_atom_text(&current_title_type, text);
                            current_entry_title_set = true;
                        }
                        "updated" => {
                            if let Some(ts) = parse_rfc3339_lax(&text) {
                                current_entry_updated = ts;
                                current_entry_updated_parsed = true;
                            }
                        }
                        "published" => current_entry_published = parse_rfc3339_lax(&text),
                        "summary" => {
                            current_entry_summary =
                                Some(make_atom_text(&current_summary_type, text));
                        }
                        "content" => {
                            let at = make_atom_text(&current_content_type, text);
                            current_entry_content = Some(AtomContent {
                                value: at,
                                src: None,
                            });
                        }
                        "rights" => {
                            current_entry_rights = Some(make_atom_text(&current_rights_type, text));
                        }
                        "entry" => {
                            if strict {
                                if !current_entry_id_set || current_entry_id.is_empty() {
                                    return Err(FeedParseError::new(
                                        "Atom entry missing required <id>",
                                    ));
                                }
                                if !current_entry_title_set {
                                    return Err(FeedParseError::new(
                                        "Atom entry missing required <title>",
                                    ));
                                }
                                if !current_entry_updated_parsed {
                                    return Err(FeedParseError::new(
                                        "Atom entry missing or unparseable <updated>",
                                    ));
                                }
                            }
                            let entry = AtomEntry {
                                id: std::mem::take(&mut current_entry_id),
                                title: std::mem::replace(
                                    &mut current_entry_title,
                                    AtomText::text(""),
                                ),
                                updated: current_entry_updated,
                                authors: std::mem::take(&mut current_entry_authors),
                                content: current_entry_content.take(),
                                links: std::mem::take(&mut current_entry_links),
                                summary: current_entry_summary.take(),
                                categories: std::mem::take(&mut current_entry_categories),
                                contributors: std::mem::take(&mut current_entry_contributors),
                                published: current_entry_published.take(),
                                rights: current_entry_rights.take(),
                                source: current_entry_source.take(),
                                extensions: std::mem::take(&mut entry_acc).finish(),
                            };
                            entries.push(entry);
                            in_entry = false;
                        }
                        _ => {}
                    }
                } else {
                    let Some(text) = feed_acc.on_end(ns, local, text) else {
                        continue;
                    };
                    if ns != Ns::Atom {
                        continue;
                    }
                    match local {
                        "id" => feed_id = text,
                        "title" => {
                            feed_title = make_atom_text(&current_title_type, text);
                        }
                        "updated" => {
                            if let Some(ts) = parse_rfc3339_lax(&text) {
                                feed_updated = ts;
                                feed_updated_parsed = true;
                            }
                        }
                        "subtitle" => {
                            feed_subtitle = Some(make_atom_text(&current_subtitle_type, text));
                        }
                        "rights" => {
                            feed_rights = Some(make_atom_text(&current_rights_type, text));
                        }
                        "logo" => feed_logo = Some(text),
                        "icon" => feed_icon = Some(text),
                        "generator" => {
                            if let Some(mut g) = pending_generator.take() {
                                g.value = text;
                                feed_generator = Some(g);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok((_, Event::Eof)) => {
                if depth > 0 {
                    return Err(FeedParseError::new(format!(
                        "truncated feed: {depth} unclosed element(s) at end of input"
                    )));
                }
                break;
            }
            Err(e) => {
                // See parse_rss2: XML errors are surfaced in both modes so a
                // truncated document doesn't masquerade as a successful parse.
                tracing::debug!("atom parse xml error: {e}");
                return Err(FeedParseError::new(format!("xml error: {e}")));
            }
            _ => {}
        }
    }

    if strict {
        if feed_id.is_empty() {
            return Err(FeedParseError::new("Atom feed missing required <id>"));
        }
        if feed_title.value().is_empty() {
            return Err(FeedParseError::new("Atom feed missing required <title>"));
        }
        if !feed_updated_parsed {
            return Err(FeedParseError::new(
                "Atom feed missing or unparseable <updated>",
            ));
        }
    }

    Ok((
        AtomFeed {
            id: feed_id,
            title: feed_title,
            updated: feed_updated,
            authors: feed_authors,
            links: feed_links,
            categories: feed_categories,
            contributors: feed_contributors,
            generator: feed_generator,
            icon: feed_icon,
            logo: feed_logo,
            rights: feed_rights,
            subtitle: feed_subtitle,
            entries,
            extensions: feed_acc.finish(),
        },
        saw_root,
    ))
}
