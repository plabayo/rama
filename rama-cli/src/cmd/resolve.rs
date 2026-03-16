#![allow(clippy::print_stdout)]

use std::{
    env::home_dir,
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use clap::{ArgAction, Args};
use hickory_resolver::{proto::xfer::Protocol, system_conf};
use rama::{
    dns::client::{
        HickoryDnsResolver,
        hickory::{
            self,
            resolver::config::{NameServerConfig, ResolverConfig},
        },
        resolver::{DnsAddressResolver, DnsTxtResolver, HappyEyeballAddressResolverExt},
    },
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::Extensions,
    futures::StreamExt,
    net::{
        address::Domain,
        mode::{ConnectIpMode, DnsResolveIpMode},
    },
    telemetry::tracing,
};

pub async fn run(cfg: ResolveCommand) -> Result<(), BoxError> {
    match cfg.trace.as_deref() {
        Some(path) => crate::trace::init_tracing_file(path),
        None => crate::trace::init_tracing_file(
            &home_dir()
                .context("fetch home dir")?
                .join(".rama")
                .join("resolve.log"),
        ),
    }?;

    let domain = cfg.domain()?;
    let record_type = cfg.record_type()?;
    let (dns_config, dns_options) = build_dns_config_and_options(&cfg)?;

    let resolver = HickoryDnsResolver::builder()
        .with_config(dns_config)
        .with_options(dns_options)
        .build();

    maybe_emit_resolver_config(&resolver, &cfg)?;

    match record_type {
        Some(RecordType::A) => {
            println!("Resolving A for domain: {domain}");
            let mut results = std::pin::pin!(resolver.lookup_ipv4(domain));
            let mut addresses_found = 0;
            while let Some(result) = results.next().await {
                match result {
                    Ok(ip) => {
                        addresses_found += 1;
                        println!("* {ip}");
                    }
                    Err(err) => tracing::debug!("error while resolving A record: {err:?}"),
                }
            }
            if addresses_found == 0 {
                return Err(BoxError::from("failed to resolve domain into any A record"));
            }
        }
        Some(RecordType::AAAA) => {
            println!("Resolving AAAA for domain: {domain}");
            let mut results = std::pin::pin!(resolver.lookup_ipv6(domain));
            let mut addresses_found = 0;
            while let Some(result) = results.next().await {
                match result {
                    Ok(ip) => {
                        addresses_found += 1;
                        println!("* {ip}");
                    }
                    Err(err) => tracing::debug!("error while resolving AAAA record: {err:?}"),
                }
            }
            if addresses_found == 0 {
                return Err(BoxError::from(
                    "failed to resolve domain into any AAAA record",
                ));
            }
        }
        Some(RecordType::TXT) => {
            println!("Resolving TXT for domain: {domain}");
            let mut results = std::pin::pin!(resolver.lookup_txt(domain));
            let mut records_found = 0;
            while let Some(result) = results.next().await {
                match result {
                    Ok(data) => {
                        records_found += 1;
                        match std::str::from_utf8(data.as_ref()) {
                            Ok(s) => println!("* {s}"),
                            Err(_) => println!("* 0x{:X?}", data.as_ref()),
                        }
                    }
                    Err(err) => tracing::debug!("error while resolving TXT record: {err:?}"),
                }
            }
            if records_found == 0 {
                return Err(BoxError::from(
                    "failed to resolve domain into any TXT record",
                ));
            }
        }
        Some(RecordType::Unknown(variant)) => {
            return Err(BoxError::from("unknown record type").context_field("value", variant));
        }
        None => {
            println!("Resolving IP for domain: {domain}");
            let mut extensions = Extensions::new();
            let dns_mode = match (cfg.ipv4_only, cfg.ipv6_only) {
                (true, false) => DnsResolveIpMode::SingleIpV4,
                (false, true) => DnsResolveIpMode::SingleIpV6,
                _ => DnsResolveIpMode::Dual,
            };
            let connect_mode = match (cfg.ipv4_only, cfg.ipv6_only) {
                (true, false) => ConnectIpMode::Ipv4,
                (false, true) => ConnectIpMode::Ipv6,
                _ => ConnectIpMode::Dual,
            };
            extensions.insert(dns_mode);
            extensions.insert(connect_mode);

            let mut results = std::pin::pin!(
                resolver
                    .happy_eyeballs_resolver(domain)
                    .with_extensions(&extensions)
                    .lookup_ip()
            );

            let mut addresses_found = 0;
            while let Some(result) = results.next().await {
                match result {
                    Ok(ip) => {
                        addresses_found += 1;
                        println!("* {ip}");
                    }
                    Err(err) => tracing::debug!("error while resolving IP record: {err:?}"),
                }
            }
            if addresses_found == 0 {
                return Err(BoxError::from(
                    "failed to resolve domain into any IP address",
                ));
            }
        }
    }

    Ok(())
}

fn build_dns_config_and_options(
    cfg: &ResolveCommand,
) -> Result<(ResolverConfig, hickory::resolver::config::ResolverOpts), BoxError> {
    let (mut dns_config, mut dns_options) = if cfg.name_servers.is_empty() {
        system_conf::read_system_conf()
            .map_err(BoxError::from)
            .unwrap_or_else(|err| {
                tracing::debug!("failed to read system DNS configuration: {err:?}");
                (
                    ResolverConfig::cloudflare(),
                    hickory::default_resolver_opts(),
                )
            })
    } else {
        (ResolverConfig::new(), hickory::default_resolver_opts())
    };

    apply_options(cfg, &mut dns_options)?;

    if cfg.name_servers.is_empty() {
        dns_config = rewrite_name_servers(&dns_config, cfg)?;
    } else {
        for name_server in &cfg.name_servers {
            dns_config.add_name_server(name_server.to_name_server_config(cfg.port, cfg.tcp)?);
        }
    }

    Ok((dns_config, dns_options))
}

fn apply_options(
    cfg: &ResolveCommand,
    dns_options: &mut hickory::resolver::config::ResolverOpts,
) -> Result<(), BoxError> {
    if cfg.ipv4_only && cfg.ipv6_only {
        return Err(BoxError::from(
            "IPv4-only and IPv6-only transport cannot be requested at the same time",
        ));
    }

    if let Some(timeout_secs) = cfg.timeout_secs {
        dns_options.timeout = Duration::from_secs(timeout_secs);
    }

    if let Some(attempts) = cfg.tries {
        dns_options.attempts = attempts;
    }

    if cfg.edns0 {
        dns_options.edns0 = true;
    }

    if cfg.dnssec {
        dns_options.validate = true;
        dns_options.edns0 = true;
    }

    if cfg.no_recurse {
        dns_options.recursion_desired = false;
    }

    if cfg.tcp {
        dns_options.try_tcp_on_error = true;
    }

    Ok(())
}

fn rewrite_name_servers(
    dns_config: &ResolverConfig,
    cfg: &ResolveCommand,
) -> Result<ResolverConfig, BoxError> {
    let name_servers = dns_config
        .name_servers()
        .iter()
        .cloned()
        .map(|mut server| {
            if let Some(port) = cfg.port {
                server.socket_addr = SocketAddr::new(server.socket_addr.ip(), port);
            }
            if cfg.tcp {
                server.protocol = Protocol::Tcp;
            }
            server
        })
        .collect::<Vec<_>>();

    Ok(ResolverConfig::from_parts(
        dns_config.domain().cloned(),
        dns_config.search().to_vec(),
        name_servers,
    ))
}

fn maybe_emit_resolver_config(
    resolver: &HickoryDnsResolver,
    cfg: &ResolveCommand,
) -> Result<(), BoxError> {
    if !cfg.print_config && cfg.config_out.is_none() {
        return Ok(());
    }

    let rendered = serde_json::to_string_pretty(&resolver.config())
        .context("serialize resolver configuration as pretty json")?;

    if cfg.print_config {
        println!("{rendered}");
    }

    if let Some(path) = cfg.config_out.as_ref() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent directory for config output: {path:?}"))?;
        }
        fs::write(path, rendered.as_bytes())
            .with_context(|| format!("write resolver configuration to: {path:?}"))?;
    }

    Ok(())
}

rama::utils::macros::enums::enum_builder! {
    #[allow(clippy::upper_case_acronyms)]
    @String
    enum RecordType {
        A => "A",
        AAAA => "AAAA",
        TXT => "TXT",
    }
}

#[derive(Debug, Clone)]
struct NameServerArg {
    ip: IpAddr,
    port: Option<u16>,
}

impl NameServerArg {
    fn to_name_server_config(
        &self,
        default_port: Option<u16>,
        tcp: bool,
    ) -> Result<NameServerConfig, BoxError> {
        let port = self.port.or(default_port).unwrap_or(53);
        let protocol = if tcp { Protocol::Tcp } else { Protocol::Udp };
        Ok(NameServerConfig::new(
            SocketAddr::new(self.ip, port),
            protocol,
        ))
    }
}

impl FromStr for NameServerArg {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = s.parse::<SocketAddr>() {
            return Ok(Self {
                ip: socket_addr.ip(),
                port: Some(socket_addr.port()),
            });
        }

        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self { ip, port: None });
        }

        Err(BoxError::from("invalid nameserver address").context_field("value", s.to_owned()))
    }
}

#[derive(Debug, Args)]
/// resolve (DNS) queries
pub struct ResolveCommand {
    #[arg(required = false)]
    /// domain to query
    domain: Option<Domain>,

    #[arg(required = false)]
    /// type of record to resolve, when omitted IPs are resolved using happy eyeballs
    record_type: Option<RecordType>,

    #[arg(short = 'q', long = "name")]
    /// explicit query name, useful in dig-like form
    query_name: Option<Domain>,

    #[arg(short = 't', long = "type")]
    /// explicit query type (A, AAAA, TXT)
    query_type: Option<RecordType>,

    #[arg(short = '4', action = ArgAction::SetTrue)]
    /// use IPv4 DNS transport and IPv4 happy-eyeballs resolution only
    ipv4_only: bool,

    #[arg(short = '6', action = ArgAction::SetTrue)]
    /// use IPv6 DNS transport and IPv6 happy-eyeballs resolution only
    ipv6_only: bool,

    #[arg(short = 'p', long)]
    /// DNS server port to use, defaults to 53
    port: Option<u16>,

    #[arg(long = "nameserver", value_name = "IP[:PORT]")]
    /// one or more upstream nameservers to query instead of the system defaults
    name_servers: Vec<NameServerArg>,

    #[arg(long, action = ArgAction::SetTrue)]
    /// prefer TCP queries for upstream DNS servers
    tcp: bool,

    #[arg(long = "time")]
    /// query timeout in seconds
    timeout_secs: Option<u64>,

    #[arg(long = "tries")]
    /// number of DNS query attempts
    tries: Option<usize>,

    #[arg(long, action = ArgAction::SetTrue)]
    /// enable EDNS0 support
    edns0: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    /// enable DNSSEC validation
    dnssec: bool,

    #[arg(long = "no-recurse", action = ArgAction::SetTrue)]
    /// disable the recursion desired bit
    no_recurse: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    /// print the resolver config as pretty json to stdout
    print_config: bool,

    #[arg(long, value_name = "PATH")]
    /// write the resolver config as pretty json to a file
    config_out: Option<PathBuf>,

    /// define custom path to trace to, by default logging happens to $HOME/.rama/resolve.log
    #[arg(long)]
    trace: Option<PathBuf>,
}

impl ResolveCommand {
    fn domain(&self) -> Result<Domain, BoxError> {
        match (&self.domain, &self.query_name) {
            (Some(domain), None) | (None, Some(domain)) => Ok(domain.clone()),
            (Some(_), Some(_)) => Err(BoxError::from(
                "domain cannot be provided both positionally and via --name",
            )),
            (None, None) => Err(BoxError::from(
                "domain is required either positionally or via --name",
            )),
        }
    }

    fn record_type(&self) -> Result<Option<RecordType>, BoxError> {
        match (&self.record_type, &self.query_type) {
            (Some(record_type), None) | (None, Some(record_type)) => Ok(Some(record_type.clone())),
            (None, None) => Ok(None),
            (Some(_), Some(_)) => Err(BoxError::from(
                "record type cannot be provided both positionally and via --type",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nameserver_arg_ip_without_port() {
        let value = NameServerArg::from_str("1.1.1.1").expect("parse nameserver");
        assert_eq!(value.ip, IpAddr::from([1, 1, 1, 1]));
        assert_eq!(value.port, None);
    }

    #[test]
    fn parse_nameserver_arg_socket_addr() {
        let value = NameServerArg::from_str("1.1.1.1:5353").expect("parse nameserver");
        assert_eq!(value.ip, IpAddr::from([1, 1, 1, 1]));
        assert_eq!(value.port, Some(5353));
    }

    #[test]
    fn resolve_command_prefers_single_domain_source() {
        let cmd = ResolveCommand {
            domain: Some(Domain::from_static("example.com")),
            record_type: None,
            query_name: Some(Domain::from_static("example.org")),
            query_type: None,
            ipv4_only: false,
            ipv6_only: false,
            port: None,
            name_servers: Vec::new(),
            tcp: false,
            timeout_secs: None,
            tries: None,
            edns0: false,
            dnssec: false,
            no_recurse: false,
            print_config: false,
            config_out: None,
            trace: None,
        };

        assert!(cmd.domain().is_err());
    }

    #[test]
    fn resolve_command_defaults_to_happy_eyeballs_when_type_is_absent() {
        let cmd = ResolveCommand {
            domain: Some(Domain::from_static("example.com")),
            record_type: None,
            query_name: None,
            query_type: None,
            ipv4_only: false,
            ipv6_only: false,
            port: None,
            name_servers: Vec::new(),
            tcp: false,
            timeout_secs: None,
            tries: None,
            edns0: false,
            dnssec: false,
            no_recurse: false,
            print_config: false,
            config_out: None,
            trace: None,
        };

        assert!(cmd.record_type().expect("resolve type").is_none());
    }
}
