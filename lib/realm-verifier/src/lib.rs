mod parser;

pub mod hash;
pub use parser::json as parser_json;

use log::{debug, error};
use ratls::{InternalTokenVerifier, RaTlsError};
use rust_rsi::{verify_token, RealmClaims, CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS};
use tinyvec::ArrayVec;
use hash::HashAlgo;

pub const MAX_MEASUREMENT_SIZE: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct MeasurementValue {
    value: ArrayVec<[u8; MAX_MEASUREMENT_SIZE]>,
}

impl MeasurementValue {
    pub fn init(len: usize) -> Self {
        let mut av = ArrayVec::new();
        av.resize(len, 0);
        Self {
            value: av
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut[u8] {
        self.value.as_mut_slice()
    }
}

#[derive(Debug)]
pub struct RealmMeasurements {
    pub initial: MeasurementValue,
    pub extensible: Vec<[MeasurementValue; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS]>,
    pub hash_algo: HashAlgo,
}

#[derive(Debug)]
pub struct RealmVerifier {
    reference_measurements: RealmMeasurements,
}

fn eq_msg<T: PartialEq<U>, U>(lhs: T, rhs: U, msg: &str) -> bool {
    match lhs == rhs {
        true => {
            debug!("{} match", msg);
            true
        }
        false => {
            error!("{} do not match", msg);
            false
        }
    }
}

impl RealmVerifier {
    pub fn init(reference_measurements: RealmMeasurements) -> Self {
        debug!("Reference values: {:?}", reference_measurements);
        Self {
            reference_measurements,
        }
    }

    fn check_rim(&self, rim: &[u8]) -> bool {
        eq_msg(self.reference_measurements.initial.as_slice(), rim, "RIM")
    }

    fn check_rems(&self, rems: &[Vec<u8>]) -> bool {
        if rems.len() != CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS {
            error!("Wrong count of REMs: is ({}), should be ({})",
                   rems.len(), CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS);
            return false;
        }
        for reference_rems in &self.reference_measurements.extensible {
            let mut match_count = 0;
            for (i, rem) in rems.iter().enumerate() {
                if reference_rems[i].as_slice() == rem {
                    match_count += 1;
                }
            }
            if match_count == reference_rems.len() {
                debug!("REMs match");
                return true;
            }
        }
        error!("Could not find matching reference REMs");
        return false;
    }

    fn check_hash_algo(&self, hash_algo: &str) -> bool {
        eq_msg(self.reference_measurements.hash_algo.name(),
               hash_algo, "Hash algorithm")
    }
}

impl InternalTokenVerifier for RealmVerifier {
    fn verify(&self, token: &[u8]) -> Result<(), RaTlsError> {
        let attestation_claims = verify_token(token, None)
            .map_err(|e| RaTlsError::GenericTokenVerifierError(e.into()))?;
        let claims = RealmClaims::from_raw_claims(
            &attestation_claims.realm_claims.token_claims,
            &attestation_claims.realm_claims.measurement_claims,
        )
        .map_err(|e| RaTlsError::GenericTokenVerifierError(e.into()))?;
        debug!("{:?}", claims);
        debug!("token rim: {}", hex::encode(&claims.rim));
        for (rem_idx, rem) in claims.rems.iter().enumerate() {
            debug!("token rem[{}]: {}", rem_idx, hex::encode(&rem));
        }

        match self.check_rim(&claims.rim)
            && self.check_rems(&claims.rems)
            && self.check_hash_algo(&claims.hash_algo)
        {
            true => Ok(()),
            false => Err(RaTlsError::GenericTokenVerifierError(
                "Token measurements do not match reference values".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::{BufReader, Read}};
    use super::*;

    #[test]
    fn verify_token() {
        let mut token = Vec::<u8>::with_capacity(128);
        File::open("tests/token.bin").unwrap().read_to_end(&mut token).unwrap();
        token.shrink_to_fit();

        let file = File::open("tests/realm.json").unwrap();
        let reader = BufReader::new(file);

        let reference_json: serde_json::Value = serde_json::from_reader(reader).unwrap();
        let reference_values_json = reference_json["realm"]["reference-values"].clone();

        let reference_values = crate::parser_json::parse_value(reference_values_json).unwrap();
        let verifier = RealmVerifier::init(reference_values);

        let verification_result = verifier.verify(&token);

        verification_result.unwrap();
    }
}
