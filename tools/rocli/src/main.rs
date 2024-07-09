extern crate base64;
extern crate rand;

use rust_rsi::verify_token;
use clap::{Parser, Subcommand};
use error::RocliError;
use subcmds::{make_endorsements, make_refvals, make_corim};
use tools::{read_yaml, write_json, dump_json, read_bytes};
use tags::Config;
use rand::Rng;

mod tags;
mod tools;
mod subcmds;
mod error;
mod conv;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output file or none for writing to screen
    #[arg(short, long)]
    output: Option<String>,

    /// Path to config file
    #[arg(short, long)]
    config: String,

    /// Path to cca token with claims to parse
    #[arg(short, long)]
    token: String,

    /// Randomize tag identifier
    #[arg(short, long)]
    rand_tag_id: bool,

    #[command(subcommand)]
    command: Commands
}

#[derive(Debug, Subcommand)]
enum Commands {
    Endorsements {
        /// Path to Cpak public PEM
        #[arg(short, long)]
        cpak: Vec<String>,

        /// Type of the provided key
        #[arg(short, long)]
        cpak_type: Vec<String>
    },

    Refvals { },

    Corim {}
}

fn main() -> Result<(), RocliError> {
    let cli = Args::parse();

    let mut config: Config = read_yaml(cli.config)?;
    if cli.rand_tag_id {
        config.tag_identity.id = uuid::Uuid::from_bytes(
            rand::thread_rng().gen::<[u8; 16]>()
        );
    }

    let token = verify_token(read_bytes(cli.token)?.as_slice(), None)?;

    let comid = match cli.command {
        Commands::Endorsements { cpak, cpak_type } => make_endorsements(cpak, cpak_type, token, config)?,
        Commands::Refvals { } => make_refvals(token, config)?,
        Commands::Corim { } => make_corim(token, config)?
    };

    if let Some(path) = cli.output {
        write_json(comid, path)?;
    } else {
        let encoded = dump_json(comid)?;
        println!("{}", encoded);
    }

    Ok(())
}
