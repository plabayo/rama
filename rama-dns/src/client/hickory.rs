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
    net::runtime::TokioRuntimeProvider,
    proto::rr::{
        Name, RData, RecordType as HickoryRecordType,
        rdata::{A, AAAA},
    },
    proto::serialize::binary::{BinEncodable, BinEncoder},
};

use rama_core::{
    bytes::Bytes,
    error::{BoxError, ErrorContext},
    futures::Stream,
};
use rama_core::{futures::async_stream::stream_fn, telemetry::tracing};
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsServiceBindingResolver, DnsTxtResolver};
use crate::wire::{ServiceBinding, Txt};

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

fn decode_hickory_txt(value: &hickory_resolver::proto::rr::rdata::TXT) -> Result<Txt, BoxError> {
    Txt::try_from_strings(value.txt_data.iter().map(AsRef::<[u8]>::as_ref))
        .context("validate Hickory TXT RDATA")
}

impl DnsServiceBindingResolver for HickoryDnsResolver {
    type Error = BoxError;

    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, BoxError>> + Send + '_ {
        self.lookup_service_bindings(domain, HickoryRecordType::SVCB)
    }

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, BoxError>> + Send + '_ {
        self.lookup_service_bindings(domain, HickoryRecordType::HTTPS)
    }
}

impl DnsResolver for HickoryDnsResolver {}

impl HickoryDnsResolver {
    fn lookup_service_bindings(
        &self,
        domain: Domain,
        record_type: HickoryRecordType,
    ) -> impl Stream<Item = Result<ServiceBinding, BoxError>> + Send + '_ {
        stream_fn(async move |mut yielder| {
            let name = try_or_yield!(
                yielder,
                name_from_domain(domain),
                "lookup service binding: create name from domain"
            );
            let lookup = try_or_yield!(
                yielder,
                self.0.lookup(name.clone(), record_type).await,
                "resolve service binding record(s) for name",
                "name" = name
            );
            let bindings = decode_hickory_rrset(
                record_type,
                lookup.answers().iter().map(|answer| &answer.data),
            );
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
            Some(decode_hickory_service_binding(https))
        }
        _ => None,
    }
}

fn decode_hickory_service_binding(value: &impl BinEncodable) -> Result<ServiceBinding, BoxError> {
    let mut rdata = Vec::new();
    // A fresh encoder has no name-compression state, so TargetName is emitted
    // in the uncompressed RDATA form required by the shared wire parser.
    value
        .emit(&mut BinEncoder::new(&mut rdata))
        .context("encode Hickory service binding RDATA")?;
    let rdata = Bytes::from(rdata);
    ServiceBinding::parse_rdata_bytes(&rdata).context("validate Hickory service binding RDATA")
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
        HTTPS, SVCB, TXT,
        svcb::{SvcParamKey, SvcParamValue},
    };

    #[test]
    fn txt_bridge_preserves_record_boundaries_and_validates_input() {
        let value = TXT::from_bytes(vec![b"first", b"", b"\x00\xff"]);
        let txt = decode_hickory_txt(&value).expect("valid TXT record");
        assert_eq!(
            txt.iter().collect::<Vec<_>>(),
            [b"first".as_slice(), b"".as_slice(), b"\x00\xff".as_slice()],
        );

        decode_hickory_txt(&TXT::from_bytes(Vec::new()))
            .expect_err("TXT RDATA requires one string");
        let oversized = vec![0; 256];
        decode_hickory_txt(&TXT::from_bytes(vec![&oversized]))
            .expect_err("TXT string is limited to 255 octets");
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
