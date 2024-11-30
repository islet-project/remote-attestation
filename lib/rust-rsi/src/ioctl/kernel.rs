/*
 * This file must match kernel API.
 *
 * This includes rsi.h from the rsi module and eventually some internals from
 * the upstream kernel like the version split below.
 */

mod internal
{
    use super::{RsiMeasurement, RsiAttestation, RsiSealingKey, RsiRealmMetadata};

    // TODO: These should be hex
    nix::ioctl_read!(abi_version, b'x', 190u8, u64);
    nix::ioctl_readwrite_buf!(measurement_read, b'x', 192u8, RsiMeasurement);
    nix::ioctl_write_buf!(measurement_extend, b'x', 193u8, RsiMeasurement);
    nix::ioctl_readwrite_buf!(attestation_token, b'x', 194u8, RsiAttestation);
    nix::ioctl_readwrite_buf!(sealing_key, b'x', 200u8, RsiSealingKey);
    nix::ioctl_read_buf!(realm_metadata, b'x', 201u8, RsiRealmMetadata);
}


pub const MAX_MEASUR_LEN: u16 = 0x40;
pub const CHALLENGE_LEN:  u16 = 0x40;
pub const GRANULE_LEN:  u16 = 0x1000;


// should be pub(super) but nix leaks the type through pub ioctl definitions
#[repr(C)]
pub struct RsiMeasurement
{
    pub(super) index: u32,
    pub(super) data_len: u32,
    pub(super) data: [u8; MAX_MEASUR_LEN as usize],
}

impl RsiMeasurement
{
    pub(super) fn new_empty(index: u32) -> Self
    {
        Self { index, data_len: 0, data: [0; MAX_MEASUR_LEN as usize] }
    }

    pub(super) fn new_from_data(index: u32, src: &[u8]) -> Self
    {
        // panic on wrong size here to avoid obscured panic below
        assert!(!src.is_empty() && src.len() <= MAX_MEASUR_LEN as usize);

        let mut data = [0u8; MAX_MEASUR_LEN as usize];
        data[..src.len()].copy_from_slice(src);
        Self { index, data_len: src.len().try_into().unwrap(), data }
    }
}

// should be pub(super) but nix leaks the type through pub ioctl definitions
#[repr(C)]
pub struct RsiAttestation
{
    pub(super) challenge: [u8; CHALLENGE_LEN as usize],
    pub(super) token_len: u64,
    pub(super) token: *mut u8,
}

impl RsiAttestation
{
    pub(super) fn new(src: &[u8; CHALLENGE_LEN as usize], token_len: u64) -> Self
    {
        Self { challenge: src.clone(), token_len, token: std::ptr::null_mut() }
    }
}

pub const RSI_SEALING_KEY_FLAGS_KEY:      u64 = 1 << 0;
pub const RSI_SEALING_KEY_FLAGS_RIM:      u64 = 1 << 1;
pub const RSI_SEALING_KEY_FLAGS_REALM_ID: u64 = 1 << 2;
pub const RSI_SEALING_KEY_FLAGS_SVN:      u64 = 1 << 3;
pub(super) const RSI_SEALING_KEY_FLAGS_MASK:     u64 = 0x0F;

#[repr(C)]
pub struct RsiSealingKey
{
    pub(super) flags: u64,
    pub(super) svn: u64,
    pub(super) realm_sealing_key: [u8; 32]
}

impl RsiSealingKey
{
    pub(super) fn new(flags: u64, svn: u64) -> Self
    {
        Self { flags: flags & RSI_SEALING_KEY_FLAGS_MASK, svn, realm_sealing_key: [0u8; 32] }
    }
}

#[repr(C)]
pub struct RsiRealmMetadata
{
    pub(super) metadata: [u8;  GRANULE_LEN as usize]
}

impl RsiRealmMetadata
{
    pub(super) fn new() -> Self {
        Self { metadata: [0u8; GRANULE_LEN as usize] }
    }
}

pub(super) const fn abi_version_get_major(version: u64) -> u32
{
    ((version & 0x7FFF0000) >> 16) as u32
}

pub(super) const fn abi_version_get_minor(version: u64) -> u32
{
    (version & 0xFFFF) as u32
}

pub(super) fn abi_version(fd: i32, data: *mut u64) -> nix::Result<()>
{
    unsafe { internal::abi_version(fd, data) }.map(|_| ())
}

pub(super) fn measurement_read(fd: i32, data: &mut [RsiMeasurement]) -> nix::Result<()>
{
    unsafe { internal::measurement_read(fd, data) }.map(|_| ())
}

pub(super) fn measurement_extend(fd: i32, data: &[RsiMeasurement]) -> nix::Result<()>
{
    unsafe { internal::measurement_extend(fd, data) }.map(|_| ())
}

pub(super) fn attestation_token(fd: i32, data: &mut [RsiAttestation]) -> nix::Result<()>
{
    unsafe { internal::attestation_token(fd, data) }.map(|_| ())
}

pub(super) fn sealing_key(fd: i32, data: &mut [RsiSealingKey]) -> nix::Result<()>
{
    unsafe { internal::sealing_key(fd, data) }.map(|_| ())
}

pub(super) fn realm_metadata(fd: i32, data: &mut [RsiRealmMetadata]) -> nix::Result<()>
{
    unsafe { internal::realm_metadata(fd, data) }.map(|_| ())
}
