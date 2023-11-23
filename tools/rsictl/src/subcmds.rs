use crate::{resolver, tools};
use clap::Args;
use ratls::RaTlsClient;
use std::{io::Write, sync::Arc};


pub(crate) type GenericResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) fn version() -> GenericResult
{
    let version = rust_rsi::abi_version()?;
    println!("{}.{}", version.0, version.1);
    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct MeasurReadArgs
{
    /// index to read, must be 0-4
    #[arg(short = 'n', long,
          value_parser = clap::value_parser!(u32).range(0..=4))]
    index: u32,

    /// filename to write the measurement, none for stdout hexdump
    #[arg(short, long)]
    output: Option<String>,
}

pub(crate) fn measur_read(args: &MeasurReadArgs) -> GenericResult
{
    let data = rust_rsi::measurement_read(args.index)?;

    match &args.output {
        Some(f) => tools::file_write(f, &data)?,
        None => tools::hexdump(&data, 8, None),
    }

    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct MeasurExtendArgs
{
    /// index to extend, must be 1-4
    #[arg(short = 'n', long,
          value_parser = clap::value_parser!(u32).range(1..=4))]
    index: u32,

    /// length of random data to use (1-64)
    #[arg(short, long, default_value_t = rust_rsi::MAX_MEASUR_LEN.into(),
          value_parser = clap::value_parser!(u32).range(1..=rust_rsi::MAX_MEASUR_LEN.into()))]
    random: u32,

    /// filename to extend the measurement with (1-64 bytes), none to use random
    #[arg(short, long)]
    input: Option<String>,
}

pub(crate) fn measur_extend(args: &MeasurExtendArgs) -> GenericResult
{
    let data = match &args.input {
        None => tools::random_data(args.random as usize),
        Some(f) => tools::file_read(f)?,
    };

    if data.is_empty() || data.len() > rust_rsi::MAX_MEASUR_LEN as usize {
        return Err("Data must be within 1-64 bytes range".into());
    }

    rust_rsi::measurement_extend(args.index, &data)?;

    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct AttestArgs
{
    /// filename with the challange (64 bytes), none to use random
    #[arg(short, long)]
    input: Option<String>,

    /// filename to write the token to, none to verify & print
    #[arg(short, long)]
    output: Option<String>,

    /// filename with a CPAK public key, used only when verifying
    #[arg(short, long)]
    key: Option<String>,
}

pub(crate) fn attest(args: &AttestArgs) -> GenericResult
{
    let challenge = match &args.input {
        None => tools::random_data(rust_rsi::CHALLENGE_LEN as usize),
        Some(f) => tools::file_read(f)?,
    };

    if challenge.len() != rust_rsi::CHALLENGE_LEN as usize {
        return Err("Challange needs to be exactly 64 bytes".into());
    }

    // try_into: &Vec<u8> -> &[u8,64]
    let token = rust_rsi::attestation_token(&challenge.try_into().unwrap())?;

    match &args.output {
        Some(f) => tools::file_write(f, &token)?,
        None => match &args.key {
            Some(f) => tools::verify_print(&token, Some(tools::file_read(f)?.as_slice()))?,
            None => tools::verify_print(&token, None)?,
        },
    }

    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct VerifyArgs
{
    /// filename with the token to verify
    #[arg(short, long)]
    input: String,

    /// filename with a CPAK public key
    #[arg(short, long)]
    key: Option<String>,
}

pub(crate) fn verify(args: &VerifyArgs) -> GenericResult
{
    let token = tools::file_read(&args.input)?;

    match &args.key {
        Some(f) => tools::verify_print(&token, Some(tools::file_read(f)?.as_slice()))?,
        None => tools::verify_print(&token, None)?,
    }

    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct VerifyPlatformArgs
{
    /// filename with the extracted platform token to verify
    #[arg(short, long)]
    input: String,

    /// filename with the public cpak
    #[arg(short, long)]
    key: String,
}

pub(crate) fn verify_platform(args: &VerifyPlatformArgs) -> GenericResult
{
    let token = tools::file_read(&args.input)?;
    let key = tools::file_read(&args.key)?;
    tools::verify_print_platform(&token, &key)?;
    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct VerifyCArgs
{
    /// filename with the token to verify
    #[arg(short, long)]
    input: String,
}

pub(crate) fn verify_c(args: &VerifyCArgs) -> GenericResult
{
    let token = tools::file_read(&args.input)?;
    tools::verify_print_c(&token)?;
    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct RaTLSArgs
{
    /// Path to root CA cert
    #[arg(short, long)]
    root_ca: String,

    /// Url to ratls server
    #[arg(short = 'u', long, default_value = "localhost:1337")]
    server_url: String,

    /// Server name, overriden if server is attested
    #[clap(short = 'n', long, default_value = "localhost")]
    server_name: String,
}

pub(crate) fn ratls(args: &RaTLSArgs) -> GenericResult
{
    ratls::init_logger();

    let client = RaTlsClient::new(ratls::ClientMode::AttestedClient {
        client_token_resolver: Arc::new(resolver::IoctlTokenResolver()),
        root_ca_path: args.root_ca.to_string()
    })?;

    let mut connection = client.connect(args.server_url.to_string(), args.server_name.to_string())?;
    println!("Connection established");
    write!(connection.stream(), "GIT")?;
    println!("Work finished, exiting");

    Ok(())
}
