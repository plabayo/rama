use clap::Parser;

pub mod service;

/// a fingerprinting service for ramae                   
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "rama-fp")]
#[command(about = "a fingerprinting service for rama", long_about = None)]
struct Cli {
    /// the port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// the port to listen on for health checks
    #[arg(long, default_value = "9999")]
    health_port: u16,

    /// the interface to listen on
    #[arg(short, long, default_value = "127.0.0.1")]
    interface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    service::run(args.interface, args.port, args.health_port).await
}
