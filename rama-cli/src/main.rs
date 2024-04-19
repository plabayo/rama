use argh::FromArgs;

#[derive(Debug, FromArgs)]
/// a distortion proxy cli
struct Cli {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _: Cli = argh::from_env();
    Ok(())
}
