use clap::{Args, Parser, Subcommand};
use rama::error::BoxError;

pub mod service;

#[derive(Debug, Parser)]
#[command(name = "rama-fp")]
#[command(bin_name = "rama-fp")]
#[command(version, about, long_about = None)]
struct Cli {
    /// the interface to listen on
    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    interface: String,

    /// the port to listen on
    #[arg(long, short = 'p', default_value_t = 8080)]
    port: u16,

    /// the port to listen on for the TLS service
    #[arg(long, short = 's', default_value_t = 8443)]
    secure_port: u16,

    /// the port to listen on for the TLS service
    #[arg(long, short = 't', default_value_t = 9091)]
    prometheus_port: u16,

    /// http version to serve FP Service from
    #[arg(long, default_value = "auto")]
    http_version: String,

    /// serve as an HaProxy
    #[arg(long, short = 'f')]
    ha_proxy: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Run(RunSubCommand),
    Echo(EchoSubCommand),
}

impl Default for Commands {
    fn default() -> Self {
        Commands::Run(RunSubCommand {})
    }
}

#[derive(Debug, Args)]
/// Run the regular FP Server
struct RunSubCommand;

#[derive(Debug, Args)]
/// Run an echo server
struct EchoSubCommand;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Cli::parse();

    match args.command.unwrap_or_default() {
        Commands::Run(_) => {
            service::run(service::Config {
                interface: args.interface,
                port: args.port,
                secure_port: args.secure_port,
                prometheus_port: args.prometheus_port,
                http_version: args.http_version,
                ha_proxy: args.ha_proxy,
            })
            .await?;
        }
        Commands::Echo(_) => {
            service::echo(service::Config {
                interface: args.interface,
                port: args.port,
                secure_port: args.secure_port,
                prometheus_port: args.prometheus_port,
                http_version: args.http_version,
                ha_proxy: args.ha_proxy,
            })
            .await?;
        }
    }

    Ok(())
}
