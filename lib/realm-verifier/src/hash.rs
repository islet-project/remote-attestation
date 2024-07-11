use std::str::FromStr;

pub const HASH_ALGO_SHA256_STR: &'static str = "sha-256";
pub const HASH_ALGO_SHA512_STR: &'static str = "sha-512";

#[derive(Debug)]
pub struct HashAlgo {
    name: String,
    len: usize,
}

impl HashAlgo {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl FromStr for HashAlgo {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            HASH_ALGO_SHA256_STR => Ok(HashAlgo {name: s.to_string(), len: 32}),
            HASH_ALGO_SHA512_STR => Ok(HashAlgo {name: s.to_string(), len: 64}),
            _ => Err("Unrecognized hash algorithm"),
        }
    }
}
