use rama_utils::macros::enums::enum_builder;

enum_builder! {
    /// A DNS response code (RCODE) from the IANA DNS RCODEs registry.
    ///
    /// The message header carries only the low four bits; EDNS(0) and TSIG
    /// widen the field by supplying the upper bits, so values above 15 only
    /// occur once those extensions have been read. Unassigned and private-use
    /// values are retained by [`ResponseCode::Unknown`].
    ///
    /// This list reflects a snapshot of the [IANA DNS RCODEs registry] taken on
    /// 2026-09-16, restricted to the values that fit the octet this enum
    /// stores. The registry reserves everything up to 65535 for future use.
    ///
    /// [IANA DNS RCODEs registry]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
    #[non_exhaustive]
    #[allow(clippy::upper_case_acronyms)]
    @U8
    pub enum ResponseCode {
        /// Reports that no error occurred.
        NoError => 0,
        /// Reports that the server could not interpret the query.
        FormErr => 1,
        /// Reports a failure that prevented the server from answering.
        ServFail => 2,
        /// Reports that the queried name does not exist.
        NXDomain => 3,
        /// Reports that the server does not implement the requested query.
        NotImp => 4,
        /// Reports that policy prevented the server from answering.
        Refused => 5,
        /// Reports that a name exists that the update required to be absent.
        YXDomain => 6,
        /// Reports that an RRset exists that the update required to be absent.
        YXRRSet => 7,
        /// Reports that an RRset the update required to be present is absent.
        NXRRSet => 8,
        /// Reports an unauthorized update, or a server not authoritative for
        /// the zone.
        NotAuth => 9,
        /// Reports a name outside the zone named in the update.
        NotZone => 10,
        /// Reports a DSO-TYPE that the server does not implement.
        DSOTYPENI => 11,
        /// Reports an unsupported EDNS version, and a bad TSIG signature.
        ///
        /// The registry assigns this value twice: `BADVERS` for EDNS and
        /// `BADSIG` for TSIG. Which one applies follows from the extension
        /// that carried the code.
        BADVERS => 16,
        /// Reports a key not recognized by the server.
        BADKEY => 17,
        /// Reports a signature outside its validity window.
        BADTIME => 18,
        /// Reports a bad TKEY mode.
        BADMODE => 19,
        /// Reports a duplicate key name.
        BADNAME => 20,
        /// Reports an algorithm that the server does not support.
        BADALG => 21,
        /// Reports a truncated TSIG message authentication code.
        BADTRUNC => 22,
        /// Reports a bad or missing server cookie.
        BADCOOKIE => 23,
    }
}
