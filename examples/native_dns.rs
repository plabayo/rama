//! Resolve one or more domains using Rama's native DNS support.
//!
//! - On Apple platforms this example uses `AppleDnsResolver`.
//! - On Windows platforms this example uses `WindowsDnsResolver`.
//! - On other platforms it exits successfully after printing
//!   that the example is Apple/Windows only for now.
//!
//! ```sh
//! cargo run --example native_dns --features=dns -- localhost
//! cargo run --example native_dns --features=dns -- A localhost example.com
//! cargo run --example native_dns --features=dns -- TXT example.com
//! ```

use tracing_subscriber::{
    EnvFilter, filter::LevelFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _,
};

use rama::{error::BoxError, telemetry::tracing};

#[cfg(any(target_vendor = "apple", target_os = "windows"))]
use ::{
    rama::{
        dns::client::{
            resolver::{
                DnsAddressResolver as _, DnsTxtResolver as _, HappyEyeballAddressResolverExt,
            },
        },
        error::ErrorContext as _,
        futures::StreamExt as _,
        net::address::Domain,
    },
    std::str::FromStr,
    tokio::task::JoinSet,
};

#[cfg(target_vendor =  "apple")]
use rama::dns::client::AppleDnsResolver as NativeDnsResolver;

#[cfg(target_os =  "windows")]
use rama::dns::client::WindowsDnsResolver as NativeDnsResolver;

#[derive(Debug, Clone, Copy)]
enum RecordType {
    A,
    Aaaa,
    Txt,
    Dual,
}

impl RecordType {
    fn from_cli_arg(arg: &str) -> Option<Self> {
        if arg.eq_ignore_ascii_case("A") {
            Some(Self::A)
        } else if arg.eq_ignore_ascii_case("AAAA") {
            Some(Self::Aaaa)
        } else if arg.eq_ignore_ascii_case("TXT") {
            Some(Self::Txt)
        } else {
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        print_usage();
        std::process::exit(1);
    }

    let record_type = RecordType::from_cli_arg(&args[0]).unwrap_or(RecordType::Dual);
    if !matches!(record_type, RecordType::Dual) {
        args.remove(0);
    }

    if args.is_empty() {
        print_usage();
        std::process::exit(1);
    }

    #[cfg(any(target_vendor = "apple", target_os = "windows"))]
    {
        let resolver = NativeDnsResolver::new();
        let domains = args
            .into_iter()
            .map(|arg| Domain::from_str(&arg))
            .collect::<Result<Vec<_>, _>>()?;

        let mut join_set = JoinSet::new();
        for domain in domains {
            let resolver = resolver.clone();
            join_set.spawn(async move { resolve_domain(&resolver, record_type, domain).await });
        }

        while let Some(result) = join_set.join_next().await {
            result
                .context("wait for resolve task")?
                .context("resolve")?;
        }
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
    {
        let _ = record_type;
        let _ = args;
        println!("native_dns example is Apple/Windows only for now");
    }

    Ok(())
}

fn print_usage() {
    eprintln!("usage: native_dns [A|AAAA|TXT] <domain> [domain...]");
}

#[cfg(any(target_vendor = "apple", target_os = "windows"))]
async fn resolve_domain(
    resolver: &NativeDnsResolver,
    record_type: RecordType,
    domain: Domain,
) -> Result<(), BoxError> {
    match record_type {
        RecordType::A => {
            let mut stream = std::pin::pin!(resolver.lookup_ipv4(domain.clone()));
            while let Some(result) = stream.next().await {
                println!("{domain}\tA\t{}", result?);
            }
        }
        RecordType::Aaaa => {
            let mut stream = std::pin::pin!(resolver.lookup_ipv6(domain.clone()));
            while let Some(result) = stream.next().await {
                println!("{domain}\tAAAA\t{}", result?);
            }
        }
        RecordType::Txt => {
            let mut stream = std::pin::pin!(resolver.lookup_txt(domain.clone()));
            while let Some(result) = stream.next().await {
                let txt = result?;
                println!("{domain}\tTXT\t{}", String::from_utf8_lossy(&txt));
            }
        }
        RecordType::Dual => {
            let mut stream =
                std::pin::pin!(resolver.happy_eyeballs_resolver(domain.clone()).lookup_ip());
            while let Some(result) = stream.next().await {
                println!("{domain}\tIP\t{}", result?);
            }
        }
    }

    Ok(())
}
