use std::{fs::File, io::Read};
use std::io::BufReader;
use rustls::{Certificate, PrivateKey, RootCertStore};
use sha2::{Digest, Sha512};

use crate::error::RaTlsError;

pub(crate) fn load_certificates_from_pem(path: &str) -> std::io::Result<Vec<Certificate>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)?;

    Ok(certs.into_iter().map(Certificate).collect())
}

pub(crate) fn load_private_key_from_file(path: &str) -> Result<PrivateKey, RaTlsError> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;

    match keys.len() {
        0 => Err(RaTlsError::PrivateKeyParsingError(format!("No PKCS8-encoded private key found in {path}"))),
        1 => Ok(PrivateKey(keys.remove(0))),
        _ => Err(RaTlsError::PrivateKeyParsingError(format!("More than one PKCS8-encoded private key found in {path}"))),
    }
}

pub(crate) fn load_root_cert_store(path: impl AsRef<str>) -> Result<RootCertStore, RaTlsError> {
    let root_ca = load_certificates_from_pem(path.as_ref())?;
    let mut root_store = RootCertStore::empty();

    for cert in root_ca.into_iter() {
        root_store.add(&cert)?;
    }

    Ok(root_store)
}

pub(crate) fn hash_realm_challenge(challenge: &[u8], der_public_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(challenge);
    hasher.update(der_public_key);
    hasher.finalize()[..].to_vec()
}

pub(crate) fn read_file(path: impl AsRef<str>) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path.as_ref())?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

pub fn init_logger() {
    env_logger::init();
}
