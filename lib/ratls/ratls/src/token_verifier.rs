use std::{fmt::Debug, sync::Arc};
use log::error;
use crate::error::RaTlsError;

pub trait InternalTokenVerifier: Debug + Send + Sync {
    fn verify(&self, token: &[u8]) -> Result<(), RaTlsError>;
}

#[derive(Debug)]
pub struct SkipVerification;

impl InternalTokenVerifier for SkipVerification {
    fn verify(&self, _cert: &[u8]) -> Result<(), RaTlsError> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct ChainVerifier {
    verifiers: Vec<Arc<dyn InternalTokenVerifier>>
}

impl ChainVerifier {
    pub fn new(verifiers: Vec<Arc<dyn InternalTokenVerifier>>) -> Self {
        Self {
            verifiers
        }
    }
}
impl InternalTokenVerifier for ChainVerifier {
    fn verify(&self, cert: &[u8]) -> Result<(), RaTlsError> {
        for verifier in self.verifiers.iter() {
            verifier.verify(cert).inspect_err(|e| error!("Verification failed: {:?}", e))?;
        }

        Ok(())
    }
}
