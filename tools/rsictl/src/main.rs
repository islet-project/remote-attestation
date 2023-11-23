mod resolver;
mod subcmds;
mod tools;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli
{
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands
{
    /// Prints RSI ABI version
    Version,
    /// Gets given measurement
    MeasurRead(subcmds::MeasurReadArgs),
    /// Extends given measurement
    MeasurExtend(subcmds::MeasurExtendArgs),
    /// Gets attestation token
    Attest(subcmds::AttestArgs),
    /// Verifies and prints the token from a file
    Verify(subcmds::VerifyArgs),
    /// Verifies and prints the platform token from a file
    VerifyPlatform(subcmds::VerifyPlatformArgs),
    /// Verifies and prints the token from a file using kvm-test C code
    VerifyC(subcmds::VerifyCArgs),
    /// Connect to server using ratls protocol
    RaTLS(subcmds::RaTLSArgs),
}

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let cli = Cli::parse();

    match &cli.command {
        Commands::Version => subcmds::version()?,
        Commands::MeasurRead(args) => subcmds::measur_read(args)?,
        Commands::MeasurExtend(args) => subcmds::measur_extend(args)?,
        Commands::Attest(args) => subcmds::attest(args)?,
        Commands::Verify(args) => subcmds::verify(args)?,
        Commands::VerifyPlatform(args) => subcmds::verify_platform(args)?,
        Commands::VerifyC(args) => subcmds::verify_c(args)?,
        Commands::RaTLS(args) => subcmds::ratls(args)?,
    };

    Ok(())
}
