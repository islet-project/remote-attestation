use crate::{error::VeraisonTokenVeriferError, structs::{NewSessionresponse, SessionState, VerificationResults}};
use ear::{Ear, TrustTier};
use log::{error, info, trace};
use reqwest::{blocking::Client, Certificate};
use base64::{Engine, engine::general_purpose::URL_SAFE as b64};

use ratls::{InternalTokenVerifier, RaTlsError};
use rust_rsi::{verify_token, RealmClaims};

#[derive(Debug)]
pub struct VeraisonTokenVerifer {
    host: String,
    pubkey: String,
    ca: Option<Certificate>
}

impl VeraisonTokenVerifer {
    pub fn new(host: impl Into<String>, pubkey: impl Into<String>, ca: Option<&[u8]>) -> Result<Self, VeraisonTokenVeriferError> {
        Ok(Self {
            host: host.into(),
            pubkey: pubkey.into(),
            ca: ca.map(|i| Certificate::from_der(i)).transpose()?
        })
    }

    fn verify_attestation_results(&self, results: String) -> Result<(), VeraisonTokenVeriferError> {
        let ear = Ear::from_jwt_jwk(&results.as_str(), ear::Algorithm::ES256, self.pubkey.as_bytes())?;
        trace!("Attestation results: {:#?}", ear.submods);

        for (name, appraisal) in ear.submods.into_iter() {
            if name == "CCA_REALM" {
                // TODO: we need to provision realms reference values to veraison to make it work
                continue;
            }

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
        let mut builder = Client::builder();

        if let Some(ca) = self.ca.as_ref() {
            builder = builder.add_root_certificate(ca.clone());
        } else {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build()?;

        let token_claims = verify_token(token, None)?;
        let realm_claims = RealmClaims::from_raw_claims(&token_claims.realm_claims.token_claims, &token_claims.realm_claims.measurement_claims)?;

        let response = client.post(self.host.clone() + "/challenge-response/v1/newSession")
            .header("Accept", "application/vnd.veraison.challenge-response-session+json")
            .query(&[("nonce", b64.encode(realm_claims.challenge))])
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

        let verification_results = client.post(self.host.clone() + "/challenge-response/v1/" + session_path)
            .header("Accept", "application/vnd.veraison.challenge-response-session+json")
            .header("Content-Type", "application/eat-collection; profile=\"http://arm.com/CCA-SSD/1.0.0\"")
            .body(token.to_owned())
            .send()?
            .json::<VerificationResults>()?;

        info!("Got verification results from Veraison");

        client.delete(self.host.clone() + "/challenge-response/v1/" + session_path)
            .send()?;

        info!("Session {} deleted", session.nonce);

        self.verify_attestation_results(verification_results.result)
    }
}

impl InternalTokenVerifier for VeraisonTokenVerifer {
    fn verify(&self, token: &[u8]) -> Result<(), RaTlsError> {
        std::thread::scope(|s| {
            s.spawn(move || {
                self.verify_token(token).map_err(|err| err.into())
            }).join().expect("Thread failed")
        })
    }
}
