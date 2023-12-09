use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum Commands {
    Generate,
}

impl Commands {
    pub async fn run(&self) -> anyhow::Result<()> {
        match self {
            Commands::Generate => generate().await,
        }
    }
}

pub async fn generate() -> anyhow::Result<()> {
    Err(anyhow::anyhow!("not implemented"))
}
