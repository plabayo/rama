use rama_utils::macros::enums::enum_builder;

enum_builder! {
    /// A DNS resource-record type from the IANA DNS Parameters registry.
    ///
    /// Assigned values are represented explicitly. Unassigned, private-use,
    /// and future values are retained by [`RecordType::Unknown`].
    ///
    /// This list reflects a snapshot of the [IANA Resource Record (RR) TYPEs
    /// registry] taken on 2026-08-28.
    ///
    /// [IANA Resource Record (RR) TYPEs registry]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    #[non_exhaustive]
    #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
    @U16
    pub enum RecordType {
        /// Provides the reserved type-zero marker, never for ordinary records.
        Reserved => 0,
        /// Maps a name to an IPv4 host address.
        A => 1,
        /// Names an authoritative server for a zone.
        NS => 2,
        /// Names an obsolete mail destination superseded by MX.
        MD => 3,
        /// Names an obsolete mail forwarder superseded by MX.
        MF => 4,
        /// Gives the canonical name for an alias.
        CNAME => 5,
        /// Describes a zone's authority and synchronization metadata.
        SOA => 6,
        /// Names an experimental mailbox domain.
        MB => 7,
        /// Names an experimental mail-group member.
        MG => 8,
        /// Names an experimental mailbox rename target.
        MR => 9,
        /// Carries experimental opaque data without defined semantics.
        NULL => 10,
        /// Describes well-known services available at an IPv4 address.
        WKS => 11,
        /// Points one DNS name to another.
        PTR => 12,
        /// Describes a host's CPU and operating system.
        HINFO => 13,
        /// Provides mailbox or mailing-list administration information.
        MINFO => 14,
        /// Selects mail exchange servers by preference.
        MX => 15,
        /// Carries one or more text strings.
        TXT => 16,
        /// Identifies a domain's responsible person.
        RP => 17,
        /// Locates an AFS or DCE database server.
        AFSDB => 18,
        /// Carries an X.25 PSDN address.
        X25 => 19,
        /// Carries an ISDN address and optional subaddress.
        ISDN => 20,
        /// Selects an intermediate host through which packets should route.
        RT => 21,
        /// Carries a deprecated OSI NSAP address.
        NSAP => 22,
        /// Provides a deprecated reverse mapping for an OSI NSAP address.
        NSAP_PTR => 23,
        /// Carries a legacy DNS security signature.
        SIG => 24,
        /// Carries a legacy DNS security key.
        KEY => 25,
        /// Maps between X.400 and RFC 822 mail addresses.
        PX => 26,
        /// Carries geographical position coordinates.
        GPOS => 27,
        /// Maps a name to an IPv6 host address.
        AAAA => 28,
        /// Describes a geographical location and its precision.
        LOC => 29,
        /// Carries an obsolete DNSSEC next-domain proof.
        NXT => 30,
        /// Carries a Nimrod endpoint identifier.
        EID => 31,
        /// Carries a Nimrod locator.
        NIMLOC => 32,
        /// Selects service endpoints by priority, weight, port, and target.
        SRV => 33,
        /// Carries an ATM network address.
        ATMA => 34,
        /// Carries naming-authority rewrite and delegation rules.
        NAPTR => 35,
        /// Selects a key-exchange server by preference.
        KX => 36,
        /// Publishes certificates and certificate revocation lists.
        CERT => 37,
        /// Carries an obsolete chained IPv6 address superseded by AAAA.
        A6 => 38,
        /// Aliases an entire DNS name subtree.
        DNAME => 39,
        /// Carries experimental kitchen-sink data.
        SINK => 40,
        /// Represents the EDNS pseudo-record and its options.
        OPT => 41,
        /// Carries an address-prefix list.
        APL => 42,
        /// Publishes a DNSSEC delegation signer digest.
        DS => 43,
        /// Publishes an SSH host-key fingerprint.
        SSHFP => 44,
        /// Publishes IPsec gateway and public-key information.
        IPSECKEY => 45,
        /// Carries a DNSSEC signature over an RRset.
        RRSIG => 46,
        /// Authenticates DNSSEC denial of existence and covered record types.
        NSEC => 47,
        /// Publishes a DNSSEC zone public key.
        DNSKEY => 48,
        /// Associates a DNS name with a DHCP client identity.
        DHCID => 49,
        /// Authenticates denial of existence using hashed owner names.
        NSEC3 => 50,
        /// Publishes a zone's NSEC3 hashing parameters.
        NSEC3PARAM => 51,
        /// Publishes a TLS certificate association for DANE.
        TLSA => 52,
        /// Publishes an S/MIME certificate association.
        SMIMEA => 53,
        /// Publishes Host Identity Protocol identities and rendezvous servers.
        HIP => 55,
        /// Publishes descriptive zone-status text.
        NINFO => 56,
        /// Publishes application keys for encrypted DNS data.
        RKEY => 57,
        /// Links adjacent entries in DNSSEC trust-anchor history.
        TALINK => 58,
        /// Requests that a parent publish a child-selected DS record.
        CDS => 59,
        /// Publishes a child DNSKEY for conversion into a parent DS record.
        CDNSKEY => 60,
        /// Publishes an OpenPGP public key.
        OPENPGPKEY => 61,
        /// Communicates child-to-parent DNS synchronization data.
        CSYNC => 62,
        /// Publishes a digest over zone data.
        ZONEMD => 63,
        /// Publishes a general-purpose service binding.
        SVCB => 64,
        /// Publishes an HTTP-specific service binding.
        HTTPS => 65,
        /// Discovers endpoints for DNS delegation synchronization.
        DSYNC => 66,
        /// Publishes a Hierarchical Host Identity Tag's verification material.
        HHIT => 67,
        /// Publishes unmanned-aircraft Broadcast Remote Identification data.
        BRID => 68,
        /// Carries a value coded by a UNECE Recommendation.
        UNECE => 69,
        /// Carries a value coded by an ISO standard.
        ISO => 70,
        /// Carries obsolete Sender Policy Framework policy data.
        SPF => 99,
        /// Retains the IANA-reserved UINFO code point.
        UINFO => 100,
        /// Retains the IANA-reserved UID code point.
        UID => 101,
        /// Retains the IANA-reserved GID code point.
        GID => 102,
        /// Retains the IANA-reserved UNSPEC code point.
        UNSPEC => 103,
        /// Publishes an Identifier-Locator Network Protocol node identifier.
        NID => 104,
        /// Publishes a 32-bit Identifier-Locator Network Protocol locator.
        L32 => 105,
        /// Publishes a 64-bit Identifier-Locator Network Protocol locator.
        L64 => 106,
        /// Selects Identifier-Locator Network Protocol locators by preference.
        LP => 107,
        /// Publishes an IEEE EUI-48 address.
        EUI48 => 108,
        /// Publishes an IEEE EUI-64 address.
        EUI64 => 109,
        /// Signals NXDOMAIN in compact authenticated denial responses.
        NXNAME => 128,
        /// Negotiates transaction authentication keys.
        TKEY => 249,
        /// Authenticates a DNS transaction message.
        TSIG => 250,
        /// Requests an incremental zone transfer.
        IXFR => 251,
        /// Requests a complete zone transfer.
        AXFR => 252,
        /// Requests mailbox-related MB, MG, or MR records.
        MAILB => 253,
        /// Requests obsolete mail-agent records superseded by MX.
        MAILA => 254,
        /// Requests some or all available record types.
        ANY => 255,
        /// Publishes a service URI with priority and weight.
        URI => 256,
        /// Restricts which certification authorities may issue certificates.
        CAA => 257,
        /// Publishes Application Visibility and Control data.
        AVC => 258,
        /// Publishes Digital Object Architecture data.
        DOA => 259,
        /// Discovers an Automatic Multicast Tunneling relay.
        AMTRELAY => 260,
        /// Publishes resolver information as key-value pairs.
        RESINFO => 261,
        /// Publishes a public wallet address.
        WALLET => 262,
        /// Publishes a Bundle Protocol convergence-layer adapter.
        CLA => 263,
        /// Publishes a Bundle Protocol node number.
        IPN => 264,
        /// Publishes DNSSEC trust-authority information.
        TA => 32768,
        /// Publishes obsolete DNSSEC lookaside-validation anchors.
        DLV => 32769,
        /// Reserves type 65535 for future standards action.
        ReservedMax => 65535,
    }
}
