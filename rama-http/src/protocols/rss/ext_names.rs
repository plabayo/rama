//! Element names used by the extension parsers and writers.
//!
//! The parser ([`super::ext_parse`]) sees *local* names (the prefix is
//! stripped after namespace resolution); the writer ([`super::ext_write`])
//! emits the prefix-qualified form. Both forms are driven from one
//! [`decl_ext!`] invocation per namespace so a typo can't silently desync
//! the two sides.
//!
//! For each declared element `Foo` the macro emits two `&str` constants:
//! `Foo` (the local name, used in parser `match` arms) and `Foo_TAG` (the
//! prefixed name, used in writer `BytesStart::new` / `write_*_text_elem`).
//!
//! See [`super::ns`] for the namespace URIs themselves.

/// Per-namespace name table. The first argument is the prefix; each
/// subsequent line is `IDENT => "local-name"`.
macro_rules! decl_ext {
    ($prefix:literal, $($name:ident => $local:literal),+ $(,)?) => {
        rama_utils::macros::paste! {
            $(
                // `super::super` from inside the per-namespace module reaches
                // the `protocols::rss` module — the consts are usable by
                // ext_parse + ext_write but don't leak further.
                pub(in super::super) const $name: &str = $local;
                pub(in super::super) const [<$name _TAG>]: &str =
                    concat!($prefix, ":", $local);
            )+
        }
    };
}

/// iTunes podcast namespace (`http://www.itunes.com/dtds/podcast-1.0.dtd`).
pub(super) mod itunes {
    decl_ext! { "itunes",
        TITLE        => "title",
        AUTHOR       => "author",
        SUBTITLE     => "subtitle",
        SUMMARY      => "summary",
        IMAGE        => "image",
        CATEGORY     => "category",
        DURATION     => "duration",
        EXPLICIT     => "explicit",
        EPISODE      => "episode",
        SEASON       => "season",
        EPISODE_TYPE => "episodeType",
        KEYWORDS     => "keywords",
        BLOCK        => "block",
        COMPLETE     => "complete",
        TYPE         => "type",
        NEW_FEED_URL => "new-feed-url",
        OWNER        => "owner",
        NAME         => "name",
        EMAIL        => "email",
    }
}

/// Podcasting 2.0 namespace (`https://podcastindex.org/namespace/1.0`).
pub(super) mod podcast {
    decl_ext! { "podcast",
        GUID        => "guid",
        LOCKED      => "locked",
        FUNDING     => "funding",
        MEDIUM      => "medium",
        LICENSE     => "license",
        PERSON      => "person",
        LOCATION    => "location",
        TRAILER     => "trailer",
        REMOTE_ITEM => "remoteItem",
        TRANSCRIPT  => "transcript",
        CHAPTERS    => "chapters",
        SOUNDBITE   => "soundbite",
        SEASON      => "season",
        EPISODE     => "episode",
    }
}

/// Media RSS namespace (`http://search.yahoo.com/mrss/`).
pub(super) mod media {
    decl_ext! { "media",
        CONTENT     => "content",
        TITLE       => "title",
        DESCRIPTION => "description",
        THUMBNAIL   => "thumbnail",
        KEYWORDS    => "keywords",
        RATING      => "rating",
    }
}

/// Dublin Core namespace (`http://purl.org/dc/elements/1.1/`). Fields are
/// flat — same set on item-level and feed-level.
pub(super) mod dc {
    decl_ext! { "dc",
        TITLE       => "title",
        CREATOR     => "creator",
        SUBJECT     => "subject",
        DESCRIPTION => "description",
        PUBLISHER   => "publisher",
        CONTRIBUTOR => "contributor",
        DATE        => "date",
        TYPE        => "type",
        FORMAT      => "format",
        IDENTIFIER  => "identifier",
        SOURCE      => "source",
        LANGUAGE    => "language",
        RELATION    => "relation",
        COVERAGE    => "coverage",
        RIGHTS      => "rights",
    }
}

/// `content:encoded` namespace (`http://purl.org/rss/1.0/modules/content/`).
/// The only element we read from this namespace is `encoded`.
pub(super) mod content {
    decl_ext! { "content",
        ENCODED => "encoded",
    }
}
