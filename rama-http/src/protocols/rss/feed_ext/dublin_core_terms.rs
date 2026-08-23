//! DCMI Metadata Terms relationship extension (<http://purl.org/dc/terms/>).
//!
//! This module models the complete family of resource-relationship properties:
//! the general [`DublinCoreTerms::relation`] property, its refinements, and the
//! [`DublinCoreTerms::source`] relationship. DCMI recommends or requires
//! non-literal resource values for these terms, so Rama exposes them as typed
//! [`Uri`] values. Every property is repeatable.

use rama_net::uri::Uri;

macro_rules! define_dublin_core_terms {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq)]
        pub struct $name {
            /// A related resource.
            pub relation: Vec<Uri>,
            /// An established standard to which the described resource conforms.
            pub conforms_to: Vec<Uri>,
            /// A substantially equivalent resource in another format.
            pub has_format: Vec<Uri>,
            /// A resource that is substantially equivalent but in another format.
            pub is_format_of: Vec<Uri>,
            /// A resource included physically or logically in the described resource.
            pub has_part: Vec<Uri>,
            /// A resource that physically or logically includes the described resource.
            pub is_part_of: Vec<Uri>,
            /// A version, edition, or adaptation of the described resource.
            pub has_version: Vec<Uri>,
            /// A resource of which the described resource is a version, edition, or adaptation.
            pub is_version_of: Vec<Uri>,
            /// A resource referenced, cited, or otherwise pointed to by the described resource.
            pub references: Vec<Uri>,
            /// A resource that references, cites, or otherwise points to the described resource.
            pub is_referenced_by: Vec<Uri>,
            /// A resource supplanted, displaced, or superseded by the described resource.
            pub replaces: Vec<Uri>,
            /// A resource that supplants, displaces, or supersedes the described resource.
            pub is_replaced_by: Vec<Uri>,
            /// A resource required by the described resource for its function, delivery, or coherence.
            pub requires: Vec<Uri>,
            /// A resource that requires the described resource for its function, delivery, or coherence.
            pub is_required_by: Vec<Uri>,
            /// A related resource from which the described resource is derived.
            pub source: Vec<Uri>,
        }

        impl $name {
            /// Returns `true` when no relationship values are present.
            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.relation.is_empty()
                    && self.conforms_to.is_empty()
                    && self.has_format.is_empty()
                    && self.is_format_of.is_empty()
                    && self.has_part.is_empty()
                    && self.is_part_of.is_empty()
                    && self.has_version.is_empty()
                    && self.is_version_of.is_empty()
                    && self.references.is_empty()
                    && self.is_referenced_by.is_empty()
                    && self.replaces.is_empty()
                    && self.is_replaced_by.is_empty()
                    && self.requires.is_empty()
                    && self.is_required_by.is_empty()
                    && self.source.is_empty()
            }
        }
    };
}

define_dublin_core_terms! {
    /// DCMI Metadata Terms relationship fields for a feed item or Atom entry.
    DublinCoreTerms
}

define_dublin_core_terms! {
    /// DCMI Metadata Terms relationship fields at RSS channel or Atom feed level.
    DublinCoreTermsFeed
}
