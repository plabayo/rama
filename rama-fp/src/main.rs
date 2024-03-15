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

    /// the address to listen on
    #[arg(short, long, default_value = "127.0.0.1")]
    address: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let address = format!("{}:{}", args.address, args.port);

    service::run(address).await
}
