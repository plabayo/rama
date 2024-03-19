use clap::{Parser, Subcommand};

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

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand, Default)]
enum Commands {
    /// Run the regular FP Server
    #[default]
    Run,

    /// Run an echo server
    Echo,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command.unwrap_or_default() {
        Commands::Run => {
            service::run(service::Config {
                interface: args.interface,
                port: args.port,
                secure_port: args.secure_port,
                http_version: args.http_version,
            })
            .await?;
        }
        Commands::Echo => {
            service::echo(service::Config {
                interface: args.interface,
                port: args.port,
                secure_port: args.secure_port,
                http_version: args.http_version,
            })
            .await?;
        }
    }

    Ok(())
}
