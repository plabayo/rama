use argh::FromArgs;
use rama::error::BoxError;

mod echo;
use echo::CliCommandEcho;

mod http;
use http::CliCommandHttp;

mod proxy;
use proxy::CliCommandProxy;

mod ip;
use ip::CliCommandIp;

#[derive(Debug, FromArgs)]
/// rama cli to move and transform netwrok packets
///
/// https://ramaproxy.org
struct Cli {
    #[argh(subcommand)]
    cmds: CliCommands,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum CliCommands {
    Echo(CliCommandEcho),
    Http(CliCommandHttp),
    Proxy(CliCommandProxy),
    Ip(CliCommandIp),
    Version(CliCommandVersion),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "version")]
/// print the version information
struct CliCommandVersion {}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli: Cli = argh::from_env();

    match cli.cmds {
        CliCommands::Echo(cfg) => echo::run(cfg).await,
        CliCommands::Http(cfg) => http::run(cfg).await,
        CliCommands::Proxy(cfg) => proxy::run(cfg).await,
        CliCommands::Ip(cfg) => ip::run(cfg).await,
        CliCommands::Version(_) => {
            println!("{}", rama::utils::info::VERSION);
            Ok(())
        }
    }
}
