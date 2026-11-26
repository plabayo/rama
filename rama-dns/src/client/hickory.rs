//! dns using the [`hickory_resolver`] crate

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

pub use hickory_resolver as resolver;
#[cfg(any(target_family = "unix", target_os = "windows"))]
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::{
    ResolverBuilder, TokioResolver,
    config::{CLOUDFLARE, GOOGLE, QUAD9, ResolverConfig},
    net::{DnsError, NetError, runtime::TokioRuntimeProvider},
    proto::op::ResponseCode,
    proto::rr::{
        Name, RData, RecordType as HickoryRecordType,
        rdata::{A, AAAA},
    },
    proto::serialize::binary::{BinEncodable, BinEncoder},
};

use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    futures::Stream,
};
use rama_core::{futures::async_stream::stream_fn, telemetry::tracing};
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;

use super::resolver::{
    DnsAddressResolver, DnsCnameResolver, DnsResolver, DnsServiceBindingResolver, DnsTxtResolver,
    ServiceBindingRecord,
};
use crate::wire::{AlpnList, SvcParam, SvcParamKey};
use crate::wire::{Name as WireName, ServiceBinding, Txt};
use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;

#[derive(Debug, Clone)]
/// DNS Resolver using the [`hickory_resolver`] crate
pub struct HickoryDnsResolver(Arc<TokioResolver>);

/// Rama defined overwrites of HickoryDNS [`ResolverOpts`].
///
/// [`ResolverOpts`]: self::resolver::config::ResolverOpts
pub fn default_resolver_opts() -> self::resolver::config::ResolverOpts {
    let mut opts = self::resolver::config::ResolverOpts::default();
    opts.cache_size = 32_000;
    opts.timeout = Duration::from_secs(3);
    opts.num_concurrent_reqs = std::thread::available_parallelism()
        .map(|n| (n.get() / 2).clamp(2, 8))
        .unwrap_or(2);
    opts.try_tcp_on_error = true;
    opts
}

impl HickoryDnsResolver {
    #[inline]
    /// Construct a [`HickoryDnsBuilder`] used to build
    /// a custom [`HickoryDnsResolver`] instead of one of the predefined
    /// (fallible) constructors.
    #[must_use]
    pub fn builder() -> HickoryDnsBuilder {
        HickoryDnsBuilder::default()
    }

    #[inline]
    /// Construct a new non-shared [`HickoryDnsResolver`] instance using Google's nameservers.
    ///
    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google).
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS.
    ///
    /// To use the system configuration see: [`Self::try_new_system`].
    pub fn try_new_google() -> Result<Self, BoxError> {
        tracing::trace!("create HickoryDnsResolver resolver using default google config");
        Self::builder()
            .with_config(ResolverConfig::udp_and_tcp(&GOOGLE))
            .try_build()
    }

    #[inline]
    /// Construct a new non-shared [`HickoryDnsResolver`] instance using Cloudflare's nameservers.
    ///
    /// Creates a default configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare).
    ///
    /// Please see: <https://www.cloudflare.com/dns/>
    ///
    /// To use the system configuration see: [`Self::try_new_system`].
    pub fn try_new_cloudflare() -> Result<Self, BoxError> {
        tracing::trace!("create HickoryDnsResolver resolver using default cloudflare config");
        Self::builder()
            .with_config(ResolverConfig::udp_and_tcp(&CLOUDFLARE))
            .try_build()
    }

    #[inline]
    /// Construct a new non-shared [`HickoryDnsResolver`] instance using Quad9's nameservers.
    ///
    /// Creates a configuration, using `9.9.9.9`, `149.112.112.112` and `2620:fe::fe`, `2620:fe::fe:9`,
    /// the "secure" variants of the quad9 settings (thank you, Quad9).
    ///
    /// Please see: <https://www.quad9.net/faq/>
    ///
    /// To use the system configuration see: [`Self::try_new_system`].
    pub fn try_new_quad9() -> Result<Self, BoxError> {
        tracing::trace!("create HickoryDnsResolver resolver using default quad9 config");
        Self::builder()
            .with_config(ResolverConfig::udp_and_tcp(&QUAD9))
            .try_build()
    }

    #[cfg(any(target_family = "unix", target_os = "windows"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_family = "unix", target_os = "windows"))))]
    /// Construct a new [`HickoryDnsResolver`] with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    pub fn try_new_system() -> Result<Self, BoxError> {
        Self::try_new_system_with_options(default_resolver_opts())
    }

    #[cfg(any(target_family = "unix", target_os = "windows"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_family = "unix", target_os = "windows"))))]
    /// Construct a new [`HickoryDnsResolver`] with the system configuration,
    /// and provided (resolver) options...
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    pub fn try_new_system_with_options(options: ResolverOpts) -> Result<Self, BoxError> {
        tracing::trace!("try to create HickoryDnsResolver resolver using system config");
        Self::try_new_with_builder(
            TokioResolver::builder_tokio()
                .context("build async dns resolver with system conf")
                .inspect_err(|err| {
                    tracing::debug!(
                        "failed to create HickoryDnsResolver resolver using system config: {err:?}"
                    )
                })?
                .with_options(options),
        )
    }

    #[inline(always)]
    fn try_new_with_builder(
        builder: ResolverBuilder<TokioRuntimeProvider>,
    ) -> Result<Self, BoxError> {
        let resolver = builder
            .build()
            .context("build rsolver from provided builder")?;
        // NOTE: in future this central loc can be used
        // to do any optimizations or sanitizations if ever required
        Ok(resolver.into())
    }
}

impl From<TokioResolver> for HickoryDnsResolver {
    fn from(value: TokioResolver) -> Self {
        Self(Arc::new(value))
    }
}

#[derive(Debug, Clone)]
/// Used to [`build`][`Self::try_build`] a [`HickoryDnsResolver`] instance.
pub struct HickoryDnsBuilder {
    config: Option<self::resolver::config::ResolverConfig>,
    options: Option<self::resolver::config::ResolverOpts>,
}

impl Default for HickoryDnsBuilder {
    #[inline(always)]
    fn default() -> Self {
        Self {
            config: None,
            options: Some(default_resolver_opts()),
        }
    }
}

impl HickoryDnsBuilder {
    generate_set_and_with! {
        /// Define the [`ResolverConfig`][`config::ResolverConfig`] used.
        pub fn config(mut self, config: Option<self::resolver::config::ResolverConfig>) -> Self {
            self.config = config;
            self
        }
    }

    generate_set_and_with! {
        /// Define the [`ResolverOpts`][`config::ResolverOpts`] used.
        #[must_use]
        pub fn options(mut self, options: Option<self::resolver::config::ResolverOpts>) -> Self {
            self.options = options;
            self
        }
    }

    /// Build a [`HickoryDnsResolver`] instance, consuming [`self`].
    ///
    /// [`Clone`] the [`HickoryDnsBuilder`] prior to calling this method in case you
    /// still need the builder afterwards.
    pub fn try_build(self) -> Result<HickoryDnsResolver, BoxError> {
        let mut resolver_builder = TokioResolver::builder_with_config(
            self.config.unwrap_or_else(|| {
                self::resolver::config::ResolverConfig::udp_and_tcp(&CLOUDFLARE)
            }),
            TokioRuntimeProvider::default(),
        );
        if let Some(options) = self.options {
            *resolver_builder.options_mut() = options;
        }
        HickoryDnsResolver::try_new_with_builder(resolver_builder)
    }
}

macro_rules! try_or_yield {
    ($yielder:ident, $expr:expr, $ctx:literal $(,$field_name:literal = $field_value:ident)*) => {
        match $expr {
            Ok(v) => v,
            Err(err) => {
                $yielder.yield_item(Err(err).context($ctx)$(.context_debug_field($field_name, $field_value))*).await;
                return;
            }
        }
    };
}

impl DnsAddressResolver for HickoryDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_ {
        stream_fn(async |mut yielder| {
            let name = try_or_yield!(
                yielder,
                name_from_domain(domain),
                "lookup_ipv4: create name from domain"
            );
            let lookup = try_or_yield!(
                yielder,
                self.0.ipv4_lookup(name.clone()).await,
                "resolve A record(s) for name",
                "name" = name
            );
            for ip in lookup
                .answers()
                .iter()
                .map(|a| &a.data)
                .filter_map(|data| match data {
                    RData::A(A(ip)) => Some(*ip),
                    _ => None,
                })
            {
                yielder.yield_item(Ok(ip)).await;
            }
        })
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_ {
        stream_fn(async |mut yielder| {
            let name = try_or_yield!(
                yielder,
                name_from_domain(domain),
                "lookup_ipv6: reate name from domain"
            );
            let lookup = try_or_yield!(
                yielder,
                self.0.ipv6_lookup(name.clone()).await,
                "resolve AAAA record(s) for name",
                "name" = name
            );
            for ip in lookup
                .answers()
                .iter()
                .map(|a| &a.data)
                .filter_map(|data| match data {
                    RData::AAAA(AAAA(ip)) => Some(*ip),
                    _ => None,
                })
            {
                yielder.yield_item(Ok(ip)).await;
            }
        })
    }
}

impl DnsTxtResolver for HickoryDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        stream_fn(async |mut yielder| {
            let name = try_or_yield!(
                yielder,
                name_from_domain(domain),
                "lookup_txt: create name from domain"
            );
            let lookup = try_or_yield!(
                yielder,
                self.0.txt_lookup(name.clone()).await,
                "resolve TXT record(s) for name",
                "name" = name
            );
            for txt in lookup
                .answers()
                .iter()
                .map(|a| &a.data)
                .filter_map(|data| match data {
                    RData::TXT(txt) => Some(txt),
                    _ => None,
                })
            {
                match decode_hickory_txt(txt) {
                    Ok(txt) => yielder.yield_item(Ok(txt)).await,
                    Err(err) => {
                        yielder.yield_item(Err(err)).await;
                        return;
                    }
                }
            }
        })
    }
}

impl DnsCnameResolver for HickoryDnsResolver {
    type Error = BoxError;

    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<WireName, Self::Error>> + Send + '_ {
        stream_fn(async move |mut yielder| {
            let name = try_or_yield!(
                yielder,
                name_from_domain(domain),
                "lookup CNAME: create name from domain"
            );
            let lookup = try_or_yield!(
                yielder,
                self.0.lookup(name.clone(), HickoryRecordType::CNAME).await,
                "resolve CNAME record(s) for name",
                "name" = name
            );
            for cname in lookup
                .answers()
                .iter()
                .filter_map(|answer| match &answer.data {
                    RData::CNAME(cname) => Some(cname),
                    _ => None,
                })
            {
                match decode_hickory_name(cname) {
                    Ok(cname) => yielder.yield_item(Ok(cname)).await,
                    Err(err) => {
                        yielder.yield_item(Err(err)).await;
                        return;
                    }
                }
            }
        })
    }
}

fn decode_hickory_txt(value: &hickory_resolver::proto::rr::rdata::TXT) -> Result<Txt, BoxError> {
    Txt::try_from_strings(value.txt_data.iter().map(AsRef::<[u8]>::as_ref))
        .context("validate Hickory TXT RDATA")
}

fn decode_hickory_name(value: &impl BinEncodable) -> Result<WireName, BoxError> {
    let mut wire = Vec::new();
    value
        .emit(&mut BinEncoder::new(&mut wire))
        .context("encode Hickory DNS name")?;
    WireName::from_wire_bytes(&Bytes::from(wire)).context("validate Hickory DNS name")
}

impl DnsServiceBindingResolver for HickoryDnsResolver {
    type Error = BoxError;

    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
        self.lookup_service_bindings(domain, HickoryRecordType::SVCB)
    }

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
        self.lookup_service_bindings(domain, HickoryRecordType::HTTPS)
    }
}

impl DnsResolver for HickoryDnsResolver {}

impl HickoryDnsResolver {
    fn lookup_service_bindings(
        &self,
        domain: Domain,
        record_type: HickoryRecordType,
    ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
        stream_fn(async move |mut yielder| {
            let name = try_or_yield!(
                yielder,
                name_from_domain(domain),
                "lookup service binding: create name from domain"
            );
            let lookup = match self.0.lookup(name.clone(), record_type).await {
                Ok(lookup) => lookup,
                // Hickory also uses NoRecordsFound for referrals. Only terminal
                // negative answers establish that this RRset is empty.
                Err(NetError::Dns(DnsError::NoRecordsFound(records)))
                    if records.response_code == ResponseCode::NXDomain
                        || (records.response_code == ResponseCode::NoError
                            && (records.soa.is_some() || records.ns.is_none())) =>
                {
                    return;
                }
                Err(error) => {
                    yielder
                        .yield_item(
                            Err(error)
                                .context("resolve service binding record(s) for name")
                                .context_debug_field("name", name),
                        )
                        .await;
                    return;
                }
            };
            let bindings = decode_hickory_records(record_type, lookup.answers());
            let bindings = match bindings {
                Ok(bindings) => bindings,
                Err(err) => {
                    yielder.yield_item(Err(err)).await;
                    return;
                }
            };
            for binding in bindings {
                yielder.yield_item(Ok(binding)).await;
            }
        })
    }
}

fn decode_hickory_records(
    record_type: HickoryRecordType,
    records: &[hickory_resolver::proto::rr::Record],
) -> Result<Vec<ServiceBindingRecord>, BoxError> {
    records
        .iter()
        .filter_map(|record| {
            decode_hickory_rdata(record_type, &record.data).map(|binding| {
                Ok(ServiceBindingRecord {
                    owner: decode_hickory_name(&record.name)?,
                    binding: binding?,
                })
            })
        })
        .collect()
}

#[cfg(test)]
fn decode_hickory_rrset<'a>(
    record_type: HickoryRecordType,
    records: impl IntoIterator<Item = &'a RData>,
) -> Result<Vec<ServiceBinding>, BoxError> {
    records
        .into_iter()
        .filter_map(|data| decode_hickory_rdata(record_type, data))
        .collect()
}

fn decode_hickory_rdata(
    record_type: HickoryRecordType,
    data: &RData,
) -> Option<Result<ServiceBinding, BoxError>> {
    match (record_type, data) {
        (HickoryRecordType::SVCB, RData::SVCB(svcb)) => Some(decode_hickory_service_binding(svcb)),
        (HickoryRecordType::HTTPS, RData::HTTPS(https)) => {
            Some(decode_hickory_service_binding(&https.0))
        }
        _ => None,
    }
}

fn decode_hickory_service_binding(
    value: &hickory_resolver::proto::rr::rdata::SVCB,
) -> Result<ServiceBinding, BoxError> {
    let target = decode_hickory_name(&value.target_name)?;
    let mut params = Vec::with_capacity(value.svc_params.len());
    for (key, value) in &value.svc_params {
        let key = SvcParamKey::from(u16::from(*key));
        let param = match value {
            SvcParamValue::Mandatory(keys) => SvcParam::Mandatory(
                keys.0
                    .iter()
                    .map(|key| SvcParamKey::from(u16::from(*key)))
                    .collect(),
            ),
            SvcParamValue::Alpn(protocols) => SvcParam::Alpn(
                AlpnList::from_protocols(protocols.0.iter().map(String::as_str))
                    .ok_or_else(|| BoxError::from_static_str("invalid Hickory ALPN value"))?,
            ),
            SvcParamValue::NoDefaultAlpn => SvcParam::NoDefaultAlpn,
            SvcParamValue::Port(port) => SvcParam::Port(*port),
            SvcParamValue::Ipv4Hint(hints) => {
                SvcParam::Ipv4Hint(hints.0.iter().map(|ip| ip.0).collect())
            }
            SvcParamValue::Ipv6Hint(hints) => {
                SvcParam::Ipv6Hint(hints.0.iter().map(|ip| ip.0).collect())
            }
            SvcParamValue::EchConfigList(config) => {
                SvcParam::Ech(Bytes::copy_from_slice(&config.0))
            }
            SvcParamValue::Unknown(value) => SvcParam::Unknown {
                key,
                value: Bytes::copy_from_slice(&value.0),
            },
        };
        if param.key() != key {
            return Err(BoxError::from_static_str(
                "Hickory service parameter key/value mismatch",
            ));
        }
        params.push(param);
    }
    ServiceBinding::from_parts(value.svc_priority, target, params)
        .context("validate Hickory service binding")
}

fn name_from_domain(domain: Domain) -> Result<Name, BoxError> {
    let is_fqdn = domain.is_fqdn();
    let mut name = Name::from_utf8(domain).context("try to consume a Domain as a Dns Name")?;
    name.set_fqdn(is_fqdn);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::rdata::{
        CNAME, HTTPS, SVCB, TXT,
        svcb::{SvcParamKey, SvcParamValue},
    };
    use hickory_resolver::proto::rr::{
        Record,
        rdata::svcb::{Alpn, EchConfigList, IpHint, Mandatory, Unknown},
    };
    use rama_core::futures::StreamExt as _;
    use std::iter;

    #[tokio::test]
    async fn negative_service_binding_answers_are_empty_but_lookup_failures_propagate() {
        let resolver = HickoryDnsResolver::builder()
            .with_config(ResolverConfig::from_name_servers(vec![]))
            .try_build()
            .unwrap();
        // Hickory synthesizes NODATA for non-address queries under localhost
        // and NXDOMAIN under invalid, even with no upstream servers.
        for name in ["test.localhost.", "test.invalid."] {
            let domain = Domain::from_static(name);
            assert!(
                std::pin::pin!(resolver.lookup_https(domain.clone()))
                    .next()
                    .await
                    .is_none()
            );
            assert!(
                std::pin::pin!(resolver.lookup_svcb(domain))
                    .next()
                    .await
                    .is_none()
            );
        }
        let errors = resolver.lookup_https(Domain::from_static("example.org."));
        std::pin::pin!(errors).next().await.unwrap().unwrap_err();
    }

    #[test]
    fn typed_service_binding_matches_wire_validation_for_every_parameter() {
        let record = SVCB::new(
            1,
            Name::from_ascii("target.example.").unwrap(),
            vec![
                (
                    SvcParamKey::Mandatory,
                    SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Alpn, SvcParamKey::Port])),
                ),
                (
                    SvcParamKey::Alpn,
                    SvcParamValue::Alpn(Alpn(vec!["h3".into(), "h2".into()])),
                ),
                (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn),
                (SvcParamKey::Port, SvcParamValue::Port(8443)),
                (
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::LOCALHOST)])),
                ),
                (
                    SvcParamKey::EchConfigList,
                    SvcParamValue::EchConfigList(EchConfigList(vec![0, 4, 0xfe, 0x0d, 0, 0])),
                ),
                (
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(Ipv6Addr::LOCALHOST)])),
                ),
                (
                    SvcParamKey::Unknown(100),
                    SvcParamValue::Unknown(Unknown(vec![1, 2, 3])),
                ),
            ],
        );
        let typed = decode_hickory_service_binding(&record).unwrap();
        let mut wire = Vec::new();
        record.emit(&mut BinEncoder::new(&mut wire)).unwrap();
        assert_eq!(typed, ServiceBinding::parse_rdata(&wire).unwrap());
    }

    #[test]
    fn typed_service_binding_rejects_invalid_provider_constructed_values() {
        let cases = vec![
            vec![(SvcParamKey::Port, SvcParamValue::NoDefaultAlpn)],
            vec![(
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec![String::new()])),
            )],
            vec![(
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["x".repeat(256)])),
            )],
            vec![(
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Mandatory])),
            )],
            vec![(
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![])),
            )],
            vec![(
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(vec![0, 0])),
            )],
            vec![(
                SvcParamKey::Port,
                SvcParamValue::Unknown(Unknown(vec![0, 80])),
            )],
            vec![
                (SvcParamKey::Port, SvcParamValue::Port(443)),
                (SvcParamKey::Port, SvcParamValue::Port(8443)),
            ],
            vec![(
                SvcParamKey::Unknown(100),
                SvcParamValue::Unknown(Unknown(vec![0; 65535])),
            )],
        ];
        for params in cases {
            decode_hickory_service_binding(&SVCB::new(1, Name::root(), params)).unwrap_err();
        }
    }

    #[test]
    fn service_binding_uses_returned_owner_after_cname() {
        let records = [
            Record::from_rdata(
                Name::from_ascii("query.example.").unwrap(),
                60,
                RData::CNAME(CNAME(Name::from_ascii("owner.example.").unwrap())),
            ),
            Record::from_rdata(
                Name::from_ascii("owner.example.").unwrap(),
                60,
                RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), vec![]))),
            ),
        ];
        let decoded = decode_hickory_records(HickoryRecordType::HTTPS, &records).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].owner.to_string(), "owner.example.");
        assert!(decoded[0].binding.target().is_root());
    }

    #[test]
    fn txt_bridge_preserves_record_boundaries_and_validates_input() {
        let strings = [b"first".as_slice(), b"".as_slice(), b"\x00\xff".as_slice()];
        let value = TXT::try_new(strings.into_iter()).expect("valid TXT record");
        let txt = decode_hickory_txt(&value).expect("valid TXT record");
        assert_eq!(txt.iter().collect::<Vec<_>>(), strings);

        let mut invalid = TXT::try_new(iter::empty::<&[u8]>()).expect("empty TXT record");
        decode_hickory_txt(&invalid).expect_err("TXT RDATA requires one string");
        // The constructor refuses such a string; the field does not.
        invalid.txt_data = Box::new([vec![0; 256].into_boxed_slice()]);
        decode_hickory_txt(&invalid).expect_err("TXT string is limited to 255 octets");
    }

    #[test]
    fn cname_bridge_preserves_dns_name_semantics() {
        let cname = CNAME(Name::from_ascii("Alias.Example.").expect("valid name"));
        let decoded = decode_hickory_name(&cname).expect("valid CNAME");
        assert_eq!(decoded.as_wire(), b"\x05Alias\x07Example\0");
        assert_eq!(decoded.to_string(), "Alias.Example.");
    }

    #[test]
    fn test_box_hickory_system_dns_resolver() {
        // The system DNS configuration is environment-dependent: macOS
        // routinely advertises link-local nameservers with a zone id
        // (e.g. `fe80::1%en0`), which `hickory-resolver` cannot parse,
        // and other hosts may carry entries hickory rejects for similar
        // reasons. Treat construction failure as an environment issue
        // rather than a code regression — the boxing path itself is
        // covered by `test_box_hickory_cloudflare_dns_resolver`. We
        // still exercise the boxing path here when the host config is
        // parseable.
        match HickoryDnsResolver::try_new_system() {
            Ok(resolver) => {
                _ = resolver.into_box_dns_resolver();
            }
            Err(err) => {
                eprintln!(
                    "skipping system-config check: cannot build resolver from host config: {err}"
                );
            }
        }
    }

    #[test]
    fn test_box_hickory_cloudflare_dns_resolver() {
        _ = HickoryDnsResolver::try_new_cloudflare()
            .unwrap()
            .into_box_dns_resolver();
    }

    #[test]
    fn service_binding_bridge_supports_svcb_and_https() {
        let svcb = RData::SVCB(SVCB::new(
            1,
            Name::root(),
            vec![(SvcParamKey::Port, SvcParamValue::Port(8443))],
        ));
        let binding = decode_hickory_rdata(HickoryRecordType::SVCB, &svcb)
            .expect("matching type")
            .expect("valid SVCB");
        assert_eq!(binding.priority(), 1);
        assert_eq!(binding.port(), Some(8443));

        let https = RData::HTTPS(HTTPS(SVCB::new(
            2,
            Name::from_ascii("svc.example.").expect("valid name"),
            vec![(SvcParamKey::Port, SvcParamValue::Port(443))],
        )));
        let binding = decode_hickory_rdata(HickoryRecordType::HTTPS, &https)
            .expect("matching type")
            .expect("valid HTTPS");
        assert_eq!(binding.priority(), 2);
        assert_eq!(binding.port(), Some(443));
        assert_eq!(
            binding.target().to_domain().expect("domain").as_str(),
            "svc.example."
        );
        assert!(decode_hickory_rdata(HickoryRecordType::HTTPS, &svcb).is_none());
        assert!(decode_hickory_rdata(HickoryRecordType::SVCB, &https).is_none());
    }

    #[test]
    fn service_binding_bridge_applies_rama_validation() {
        let invalid = SVCB::new(
            1,
            Name::root(),
            vec![(SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn)],
        );
        let err = decode_hickory_service_binding(&invalid).expect_err("ALPN is required");
        assert!(
            err.to_string().contains("validate Hickory service binding"),
            "got: {err}"
        );
    }

    #[test]
    fn service_binding_bridge_rejects_a_complete_malformed_rrset() {
        let valid = RData::SVCB(SVCB::new(
            1,
            Name::root(),
            vec![(SvcParamKey::Port, SvcParamValue::Port(8443))],
        ));
        let malformed = RData::SVCB(SVCB::new(
            1,
            Name::root(),
            vec![(SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn)],
        ));

        decode_hickory_rrset(HickoryRecordType::SVCB, [&valid, &malformed])
            .expect_err("one malformed record invalidates the complete RRset");
    }
}
