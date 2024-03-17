use clap::Parser;

pub mod service;

/// a fingerprinting service for ramae                   
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "rama-fp")]
#[command(about = "a fingerprinting service for rama", long_about = None)]
struct Cli {
    /// the interface to listen on
    #[arg(short, long, default_value = "127.0.0.1")]
    interface: String,

    /// the port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// the port to listen on for the TLS service
    #[arg(short, long, default_value = "8443")]
    secure_port: u16,
    /// http version to serve FP Service from
    #[arg(long, default_value = "auto")]
    http_version: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    service::run(service::Config {
        interface: args.interface,
        port: args.port,
        secure_port: args.secure_port,
        http_version: args.http_version,
    })
    .await
}
