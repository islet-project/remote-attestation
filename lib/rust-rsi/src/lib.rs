mod ioctl;
mod token;


pub use ioctl::kernel::MAX_MEASUR_LEN;
pub use ioctl::kernel::CHALLENGE_LEN;
pub use ioctl::kernel::GRANULE_LEN;
pub use ioctl::kernel::RSI_SEALING_KEY_FLAGS_KEY;
pub use ioctl::kernel::RSI_SEALING_KEY_FLAGS_RIM;
pub use ioctl::kernel::RSI_SEALING_KEY_FLAGS_REALM_ID;
pub use ioctl::kernel::RSI_SEALING_KEY_FLAGS_SVN;

pub use ioctl::abi_version;
pub use ioctl::attestation_token;
pub use ioctl::measurement_extend;
pub use ioctl::measurement_read;
pub use ioctl::sealing_key;
pub use ioctl::realm_metadata;
pub use nix::Error as NixError;

pub use token::AttestationClaims;
pub use token::TokenError;
pub use token::verifier::verify_token;
pub use token::verifier::verify_token_platform;
pub use token::dumper::print_token;
pub use token::dumper::print_token_platform;

pub use token::parser::PlatClaims;
pub use token::parser::PlatSwComponent;
pub use token::parser::RealmClaims;
pub use token::CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS;
