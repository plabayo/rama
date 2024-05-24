use argh::FromArgs;
use rama::error::BoxError;

pub mod service;

#[derive(Debug, FromArgs)]
/// a fingerprinting service for rama
struct Cli {
    /// the interface to listen on
    #[argh(option, short = 'i', default = "String::from(\"127.0.0.1\")")]
    interface: String,

    /// the port to listen on
    #[argh(option, short = 'p', default = "8080")]
    port: u16,

    /// the port to listen on for the TLS service
    #[argh(option, short = 's', default = "8443")]
    secure_port: u16,

    /// the port to listen on for the TLS service
    #[argh(option, short = 't', default = "9091")]
    prometheus_port: u16,

    /// http version to serve FP Service from
    #[argh(option, default = "String::from(\"auto\")")]
    http_version: String,

    /// serve as an HaProxy
    #[argh(switch, short = 'f')]
    ha_proxy: bool,

    #[argh(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand)]
enum Commands {
    Run(RunSubCommand),
    Echo(EchoSubCommand),
}

impl Default for Commands {
    fn default() -> Self {
        Commands::Run(RunSubCommand {})
    }
}

#[derive(FromArgs, Debug)]
/// Run the regular FP Server
#[argh(subcommand, name = "run")]
struct RunSubCommand {}

#[derive(FromArgs, Debug)]
/// Run an echo server
#[argh(subcommand, name = "echo")]
struct EchoSubCommand {}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args: Cli = argh::from_env();

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
