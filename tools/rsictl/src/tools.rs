use rand::{distributions::Standard, Rng};
use std::{
    fs::File,
    io::{Read, Write},
};
use rust_rsi::{RSI_SEALING_KEY_FLAGS_KEY, RSI_SEALING_KEY_FLAGS_REALM_ID, RSI_SEALING_KEY_FLAGS_RIM, RSI_SEALING_KEY_FLAGS_SVN};

use crate::subcmds::SealingKeyFlags;

pub(crate) fn file_read(filename: &str) -> std::io::Result<Vec<u8>>
{
    let mut buf = Vec::<u8>::with_capacity(64);
    File::open(filename)?.read_to_end(&mut buf)?;
    buf.shrink_to_fit();
    Ok(buf)
}

pub(crate) fn file_write(filename: &str, data: &[u8]) -> std::io::Result<()>
{
    File::create(filename)?.write_all(data)
}

pub(crate) fn hexdump(data: &[u8], line: usize, header: Option<&str>)
{
    if let Some(h) = header {
        println!("{}", h);
    }
    let mut cur = 0;
    while cur < data.len() {
        let line_len = std::cmp::min(line, data.len() - cur);
        println!("{:02X?}", &data[cur..cur + line_len]);
        cur += line_len;
    }
}

pub(crate) fn random_data(len: usize) -> Vec<u8>
{
    let rng = rand::thread_rng();
    rng.sample_iter(&Standard).take(len).collect()
}

pub(crate) fn verify_print(token: &[u8], key: Option<&[u8]>) -> Result<(), rust_rsi::TokenError>
{
    let token = rust_rsi::verify_token(token, key)?;
    rust_rsi::print_token(&token);
    Ok(())
}

pub(crate) fn verify_print_platform(token: &[u8], key: &[u8]) -> Result<(), rust_rsi::TokenError>
{
    let token = rust_rsi::verify_token_platform(token, Some(key))?;
    rust_rsi::print_token_platform(&token);
    Ok(())
}

impl From<&SealingKeyFlags> for u64 {
    fn from(value: &SealingKeyFlags) -> Self {
        match value {
            SealingKeyFlags::Key => RSI_SEALING_KEY_FLAGS_KEY,
            SealingKeyFlags::Rim => RSI_SEALING_KEY_FLAGS_RIM,
            SealingKeyFlags::RealmId => RSI_SEALING_KEY_FLAGS_REALM_ID
        }
    }
}

pub(crate) fn read_sealing_key(flags: &Vec<SealingKeyFlags>, svn: Option<u64>) -> Result<[u8; 32], rust_rsi::NixError>
{
    let flags = flags.iter()
        .fold(0u64, |a, b| a | u64::from(b));

    let (flags, svn) = match svn {
        Some(svn) => (flags | RSI_SEALING_KEY_FLAGS_SVN, svn),
        None => (flags, 0u64)
    };

    rust_rsi::sealing_key(flags, svn)
}
