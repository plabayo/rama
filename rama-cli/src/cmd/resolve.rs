#![allow(clippy::print_stdout)]

use std::{env::home_dir, path::PathBuf};

use rama::{
    dns::client::{
        GlobalDnsResolver,
        resolver::{DnsAddressResolver, DnsTxtResolver},
    },
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    futures::StreamExt,
    net::address::Domain,
    telemetry::tracing,
};

use clap::Args;

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

    let resolver = GlobalDnsResolver::default();
    let rt = cfg.record_type.unwrap_or_default();
    println!("Resolving {rt:?} for domain: {}...", cfg.domain);

    match rt {
        RecordType::A => {
            let results = resolver.lookup_ipv4(cfg.domain).collect::<Vec<_>>().await;
            let mut addresses_found = 0;
            for result in results {
                match result {
                    Ok(ip) => {
                        addresses_found += 1;
                        println!("* {ip}")
                    }
                    Err(err) => tracing::debug!("error while resolving A record: {err:?}"),
                }
            }
            if addresses_found == 0 {
                return Err(BoxError::from("failed to resolve domain into any A record"));
            }
        }
        RecordType::AAAA => {
            let results = resolver.lookup_ipv6(cfg.domain).collect::<Vec<_>>().await;
            let mut addresses_found = 0;
            for result in results {
                match result {
                    Ok(ip) => {
                        addresses_found += 1;
                        println!("* {ip}")
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
        RecordType::TXT => {
            let results = resolver.lookup_txt(cfg.domain).collect::<Vec<_>>().await;
            let mut addresses_found = 0;
            for result in results {
                match result {
                    Ok(data) => {
                        addresses_found += 1;
                        match std::str::from_utf8(data.as_ref()) {
                            Ok(s) => println!("* {s}"),
                            Err(_) => println!("* 0x{:X?}", data.as_ref()),
                        }
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
        RecordType::Unknown(variant) => {
            return Err(BoxError::from("unknown record type").context_field("value", variant));
        }
    }

    Ok(())
}

rama::utils::macros::enums::enum_builder! {
    #[allow(clippy::upper_case_acronyms)]
    #[derive(Default)]
    @String
    enum RecordType {
        #[default]
        A => "A",
        AAAA => "AAAA",
        TXT => "TXT",
    }
}

#[derive(Debug, Args)]
/// resolve (DNS) queries
pub struct ResolveCommand {
    #[arg(required = true)]
    /// domain to query
    domain: Domain,

    #[arg(required = false)]
    /// type of record to resolve, defaults to 'A' records
    record_type: Option<RecordType>,

    /// define custom path to trace to, by default logging happens to $HOME/.rama/resolve.log
    #[arg(long)]
    trace: Option<PathBuf>,
}
