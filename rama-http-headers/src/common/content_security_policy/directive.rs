use std::fmt;

use rama_utils::macros::enums::enum_builder;

use super::source_list::SourceList;

enum_builder! {
    /// Names of the CSP directives this crate knows about. Unknown
    /// directives round-trip through the `Unknown(String)` variant.
    @String
    pub enum DirectiveName {
        /// Fallback source-list for fetch directives that don't have
        /// their own entry. The closest thing CSP has to a global lock.
        DefaultSrc => "default-src",
        /// Where executable script may be fetched / inlined from.
        ScriptSrc => "script-src",
        /// `script-src` restricted to `<script>` element loads only.
        ScriptSrcElem => "script-src-elem",
        /// `script-src` restricted to inline event handlers / `javascript:`
        /// URIs only.
        ScriptSrcAttr => "script-src-attr",
        /// Where stylesheets may be fetched / inlined from.
        StyleSrc => "style-src",
        /// `style-src` restricted to `<style>` / `<link rel=stylesheet>` loads.
        StyleSrcElem => "style-src-elem",
        /// `style-src` restricted to inline `style="…"` attributes.
        StyleSrcAttr => "style-src-attr",
        /// Where images may be fetched from.
        ImgSrc => "img-src",
        /// Where fonts may be fetched from.
        FontSrc => "font-src",
        /// Where the protected resource may open XHR / fetch / WebSocket
        /// / EventSource connections.
        ConnectSrc => "connect-src",
        /// Where audio / video may be fetched from.
        MediaSrc => "media-src",
        /// Where `<object>` / `<embed>` / `<applet>` may be fetched from.
        ObjectSrc => "object-src",
        /// Where `<frame>` / `<iframe>` documents may be fetched from.
        FrameSrc => "frame-src",
        /// Who may embed the protected resource in a frame. Note:
        /// nonces/hashes/`'unsafe-inline'` are NOT valid here.
        FrameAncestors => "frame-ancestors",
        /// Fallback for `frame-src` + `worker-src` (legacy).
        ChildSrc => "child-src",
        /// Where workers (`Worker`, `SharedWorker`, `ServiceWorker`)
        /// may be fetched from.
        WorkerSrc => "worker-src",
        /// Where the page manifest may be fetched from.
        ManifestSrc => "manifest-src",
        /// Where the browser is permitted to prefetch resources from.
        PrefetchSrc => "prefetch-src",
        /// Permissible form submission targets.
        FormAction => "form-action",
        /// Permissible values for the `<base href>` element.
        BaseUri => "base-uri",
        /// Restrict the URLs the document may navigate to (CSP3 draft;
        /// limited browser support).
        NavigateTo => "navigate-to",
        /// Endpoint to POST violation reports to (deprecated in favour
        /// of `report-to`, but still the most widely supported).
        ReportUri => "report-uri",
        /// Reporting-API group name to deliver violation reports to.
        ReportTo => "report-to",
        /// Apply HTML5 iframe-sandbox flags to the protected resource
        /// itself.
        Sandbox => "sandbox",
        /// Force-rewrite all `http:` subresource URLs to `https:`.
        /// Valueless.
        UpgradeInsecureRequests => "upgrade-insecure-requests",
        /// Block all mixed-content loads (legacy precursor to
        /// `upgrade-insecure-requests`). Valueless.
        BlockAllMixedContent => "block-all-mixed-content",
        /// Restrict which sink-types require a Trusted Type.
        RequireTrustedTypesFor => "require-trusted-types-for",
        /// Whitelist of Trusted-Types policy names.
        TrustedTypes => "trusted-types",
    }
}

/// One CSP directive — a `(name, source-list)` pair. Render via
/// [`fmt::Display`] for the wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub name: DirectiveName,
    pub sources: SourceList,
}

impl fmt::Display for Directive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sources.as_slice().is_empty() {
            self.name.fmt(f)
        } else {
            write!(f, "{} {}", self.name, self.sources)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_directive_names_round_trip() {
        for known in [
            "default-src",
            "script-src",
            "frame-ancestors",
            "upgrade-insecure-requests",
            "require-trusted-types-for",
        ] {
            let d: DirectiveName = known.into();
            assert_eq!(d.as_str(), known);
            // The strict parser agrees with `From<&str>` for known names.
            assert!(DirectiveName::strict_parse(known).is_some());
        }
    }

    #[test]
    fn unknown_directive_name_falls_through_to_unknown() {
        let d: DirectiveName = "experimental-thing".into();
        assert!(matches!(d, DirectiveName::Unknown(ref s) if s == "experimental-thing"));
        assert_eq!(d.as_str(), "experimental-thing");
        // Strict parser rejects unknowns.
        assert!(DirectiveName::strict_parse("experimental-thing").is_none());
    }

    #[test]
    fn directive_display_with_sources() {
        let d = Directive {
            name: DirectiveName::DefaultSrc,
            sources: SourceList::self_origin(),
        };
        assert_eq!(d.to_string(), "default-src 'self'");
    }

    #[test]
    fn directive_display_valueless() {
        let d = Directive {
            name: DirectiveName::UpgradeInsecureRequests,
            sources: SourceList::empty(),
        };
        assert_eq!(d.to_string(), "upgrade-insecure-requests");
    }
}
