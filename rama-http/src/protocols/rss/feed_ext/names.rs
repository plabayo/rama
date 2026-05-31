//! Element and attribute names used by the RSS / Atom parsers and writers.
//!
//! Two flavours of constants live here:
//!
//! * **Per-namespace element names** (in [`itunes`] / [`podcast`] / [`media`]
//!   / [`dc`] / [`content`]). Parser sees *local* names (the prefix is
//!   stripped after namespace resolution); writer emits the prefix-qualified
//!   form. The [`decl_ext!`] macro drives both from one source per element,
//!   producing `FOO` (local) + `FOO_TAG` (prefixed).
//! * **Attribute names** (in [`attr`]). XML attributes aren't
//!   namespace-qualified in the feeds we handle, so one bare `&str` per name
//!   serves both parser ([`super::parse_util::attr_value`] takes `&str` now)
//!   and writer (quick-xml `push_attribute` takes `&str` for the key).
//!
//! See [`super::ns`] for the namespace URIs themselves.

/// Per-namespace name table. The first argument is the prefix; each
/// subsequent line is `IDENT => "local-name"`.
macro_rules! decl_ext {
    ($prefix:literal, $($name:ident => $local:literal),+ $(,)?) => {
        rama_utils::macros::paste! {
            $(
                // From inside the per-namespace module (e.g. `itunes`):
                // super = itunes, super² = names, super³ = feed_ext, super⁴ = rss.
                // The consts need to be usable by the per-format readers and
                // writers under `super::rss2` / `super::atom`, but should not
                // leak past the rss module.
                pub(in super::super::super::super) const $name: &str = $local;
                pub(in super::super::super::super) const [<$name _TAG>]: &str =
                    concat!($prefix, ":", $local);
            )+
        }
    };
}

/// iTunes podcast namespace (`http://www.itunes.com/dtds/podcast-1.0.dtd`).
pub(in super::super) mod itunes {
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
pub(in super::super) mod podcast {
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
pub(in super::super) mod media {
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
pub(in super::super) mod dc {
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
pub(in super::super) mod content {
    decl_ext! { "content",
        ENCODED => "encoded",
    }
}

/// XML attribute names used across the RSS / Atom parsers + writers. None of
/// these are namespace-qualified in real-world feeds (the host element's
/// namespace governs), so one bare `&str` constant per name serves both
/// sides.
pub(in super::super) mod attr {
    macro_rules! decl_attr {
        ($($name:ident => $lit:literal),+ $(,)?) => {
            $(
                pub(in super::super::super::super) const $name: &str = $lit;
            )+
        };
    }
    decl_attr! {
        // Core RSS / Atom attributes
        URL          => "url",
        HREF         => "href",
        TYPE         => "type",
        REL          => "rel",
        HREFLANG     => "hreflang",
        TITLE        => "title",
        LENGTH       => "length",
        URI          => "uri",
        VERSION      => "version",
        SRC          => "src",
        DOMAIN       => "domain",
        IS_PERMALINK => "isPermaLink",
        TERM         => "term",
        SCHEME       => "scheme",
        LABEL        => "label",
        LANGUAGE     => "language",
        PUB_DATE     => "pubDate",
        NAME         => "name",

        // Extension attributes
        MEDIUM       => "medium",
        DURATION     => "duration",
        WIDTH        => "width",
        HEIGHT       => "height",
        FILE_SIZE    => "fileSize",
        BITRATE      => "bitrate",
        ROLE         => "role",
        GROUP        => "group",
        IMG          => "img",
        GEO          => "geo",
        OSM          => "osm",
        SEASON       => "season",
        DISPLAY      => "display",
        START_TIME   => "startTime",
        TEXT         => "text",
        FEED_GUID    => "feedGuid",
        ITEM_GUID    => "itemGuid",
        FEED_URL     => "feedUrl",
    }
}
