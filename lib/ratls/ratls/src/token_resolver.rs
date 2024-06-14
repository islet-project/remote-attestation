use std::fmt::Debug;

use crate::{error::RaTlsError, tools::read_file};

pub trait InternalTokenResolver: Debug + Send + Sync {
    fn resolve(&self, challenge: &[u8]) -> Result<Vec<u8>, RaTlsError>;
}

#[derive(Debug)]
pub struct TokenFromFile(Vec<u8>);

impl TokenFromFile {
    pub fn from_path(path: impl AsRef<str>) -> Result<Self, RaTlsError> {
        Ok(Self(read_file(path)?))
    }
}

impl InternalTokenResolver for TokenFromFile {
    fn resolve(&self, _challenge: &[u8]) -> Result<Vec<u8>, RaTlsError> {
        Ok(self.0.clone())
    }
}
