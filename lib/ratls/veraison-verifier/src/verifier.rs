use crate::{error::VeraisonTokenVeriferError, structs::{NewSessionresponse, SessionState, VerificationResults}};
use ear::{Ear, TrustTier};
use log::{error, info};
use reqwest::blocking::Client;

use ratls::{InternalTokenVerifier, RaTlsError};

pub struct VeraisonTokenVerifer {
    host: String,
    client: Client,
    pubkey: String
}

impl VeraisonTokenVerifer {
    pub fn new(host: impl Into<String>, pubkey: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            client: Client::new(),
            pubkey: pubkey.into()
        }
    }

    fn verify_attestation_results(&self, results: String) -> Result<(), VeraisonTokenVeriferError> {
        let ear = Ear::from_jwt_jwk(&results.as_str(), ear::Algorithm::ES256, self.pubkey.as_bytes())?;

        for (name, appraisal) in ear.submods.into_iter() {
            if appraisal.status != TrustTier::Affirming {
                error!("Submod {} does not affirm", name);
                return Err(VeraisonTokenVeriferError::SubmoduleDoesNotAffirm(name));
            } else {
                info!("Submod {} affirms token", name);
            }
        }

        info!("Verification passed successfully");

        Ok(())
    }

    fn verify_token(&self, token: &[u8]) -> Result<(), VeraisonTokenVeriferError> {
        let response = self.client.post(self.host.clone() + "/challenge-response/v1/newSession")
            .header("Accept", "application/vnd.veraison.challenge-response-session+json")
            .query(&[("nonceSize", 32)])
            .send()?;

        let next_location = response.headers().get("Location")
            .ok_or(VeraisonTokenVeriferError::VeraisonDidntProvideNextLocation)?
            .clone();
        let session = response.json::<NewSessionresponse>()?;

        match session.status {
            SessionState::Waiting => {
                info!("Opened session with nonce {}", session.nonce);
            }
            _ => {
                error!("Failed to open session, session status: {:?}", session.status);
                return Err(VeraisonTokenVeriferError::FailedToOpenSession);
            }
        }

        let session_path = next_location.to_str().map_err(|_| VeraisonTokenVeriferError::LocationHeaderIsNotAString)?;

        let verification_results = self.client.post(self.host.clone() + "/challenge-response/v1/" + session_path)
            .header("Accept", "application/vnd.veraison.challenge-response-session+json")
            .header("Content-Type", "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0")
            .body(token.to_owned())
            .send()?
            .json::<VerificationResults>()?;

        info!("Got verification results from Veraison");

        self.client.delete(self.host.clone() + "/challenge-response/v1/" + session_path)
            .send()?;

        info!("Session {} deleted", session.nonce);

        self.verify_attestation_results(verification_results.result)
    }
}
impl InternalTokenVerifier for VeraisonTokenVerifer {
    fn verify(&self, token: &[u8]) -> Result<(), RaTlsError> {
        self.verify_token(token).map_err(|err| err.into())
    }
}
