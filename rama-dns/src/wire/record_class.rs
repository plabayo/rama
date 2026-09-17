use rama_utils::macros::enums::enum_builder;

enum_builder! {
    /// A DNS resource-record class from the IANA DNS CLASSes registry.
    ///
    /// Internet traffic uses [`RecordClass::IN`] almost exclusively; the
    /// remaining values appear in query-only classes and in dynamic-update
    /// prerequisites. Unassigned, private-use, and future values are retained
    /// by [`RecordClass::Unknown`].
    ///
    /// This list reflects a snapshot of the [IANA DNS CLASSes registry] taken
    /// on 2026-09-16.
    ///
    /// [IANA DNS CLASSes registry]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
    #[non_exhaustive]
    #[allow(clippy::upper_case_acronyms)]
    @U16
    pub enum RecordClass {
        /// Provides the reserved class-zero marker, never for ordinary records.
        Reserved => 0,
        /// Identifies the Internet class.
        IN => 1,
        /// Identifies the Chaos class.
        CH => 3,
        /// Identifies the Hesiod class.
        HS => 4,
        /// Requires, in an update prerequisite, that records be absent.
        NONE => 254,
        /// Matches records of any class in a query.
        ANY => 255,
        /// Reserves class 65535 for future standards action.
        ReservedMax => 65535,
    }
}
