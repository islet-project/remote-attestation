pub mod parser;

use log::{debug, error};
use ratls::{InternalTokenVerifier, RaTlsError};
use rust_rsi::{verify_token, RealmClaims, CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS};
use tinyvec::ArrayVec;

pub const MAX_MEASUREMENT_SIZE: usize = 64;

pub type MeasurementValue = ArrayVec<[u8; MAX_MEASUREMENT_SIZE]>;

#[derive(Debug)]
pub struct RealmMeasurements {
    pub initial: MeasurementValue,
    pub extensible: Vec<[MeasurementValue; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS]>,
}

#[derive(Debug)]
pub struct RealmVerifier {
    reference_measurements: RealmMeasurements,
}

impl RealmVerifier {
    pub fn init(reference_measurements: RealmMeasurements) -> Self {
        Self {
            reference_measurements,
        }
    }

    fn check_rim(&self, rim: &[u8]) -> bool {
        match self.reference_measurements.initial == rim {
            true => {
                debug!("RIM matches");
                true
            }
            false => {
                error!("RIM does not match");
                false
            }
        }
    }

    fn check_rems(&self, rems: &[Vec<u8>]) -> bool {
        for reference_rems in &self.reference_measurements.extensible {
            let mut match_count = 0;
            for (i, rem) in rems.iter().enumerate() {
                if reference_rems[i].to_vec() == *rem {
                    match_count += 1;
                }
            }
            if match_count == rems.len() {
                debug!("REMs match");
                return true;
            }
        }
        error!("Could not find matching reference REMs");
        return false;
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

        debug!("token rem[1]: {}", hex::encode(&claims.rems[1]));
        debug!("token rem[2]: {}", hex::encode(&claims.rems[2]));
        debug!("token rem[3]: {}", hex::encode(&claims.rems[3]));

        match self.check_rim(&claims.rim) && self.check_rems(&claims.rems) {
            true => Ok(()),
            false => Err(RaTlsError::GenericTokenVerifierError(
                "Token measurements do not match reference values".into(),
            )),
        }
    }
}
