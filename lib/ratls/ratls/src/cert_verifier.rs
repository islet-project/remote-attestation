use std::sync::Arc;
use log::{info, error};
use pkcs8::EncodePublicKey;
use rand::RngCore;
use base64::{Engine, engine::general_purpose::STANDARD as b64};
use rust_rsi::{verify_token, print_token, RealmClaims};
use x509_certificate::X509Certificate;
use crate::{token_verifier::InternalTokenVerifier, config::CCA_TOKEN_X509_EXT, tools::hash_realm_challenge};
use rustls::{server::{ClientCertVerifier, ClientCertVerified}, DistinguishedName, client::{ServerCertVerifier, ServerCertVerified}, Certificate, Error};


use crate::error::RaTlsError;

pub struct RaTlsCertVeryfier {
    token_verifier: Arc<dyn InternalTokenVerifier>,
    challenge: [u8; 64],
    root_subjects: Vec<DistinguishedName>
}

impl RaTlsCertVeryfier {
    pub fn from_token_verifier(token_verifier: Arc<dyn InternalTokenVerifier>) -> Self {
        let mut challenge = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut challenge);
        let root_subjects = vec![
            DistinguishedName::from(b64.encode(challenge).as_bytes().to_owned())
        ];

        Self { token_verifier, challenge, root_subjects}
    }

    pub fn b64_challenge(&self) -> String {
        b64.encode(self.challenge)
    }

    fn fetch_token<'a>(&self, cert: &'a X509Certificate) -> Result<&'a [u8], RaTlsError> {
        for ext in cert.iter_extensions() {
            if ext.id.0.as_ref() == CCA_TOKEN_X509_EXT.as_raw()?.as_slice() {
                return Ok(ext.value.as_slice().ok_or(RaTlsError::CannotExtractTokenFromExtension)?);
            }
        }
        error!("Token is missing in certificate");
        Err(RaTlsError::MissingTokenInCertificate)
    }

    fn verify_cert(&self, cert_der: &Certificate) -> Result<(), RaTlsError> {
        let cert = X509Certificate::from_der(cert_der.0.clone())?;
        let pubkey = cert.to_public_key_der()?;
        let raw_token = self.fetch_token(&cert)?;
        let token = verify_token(raw_token, None).map_err(|e| {error!("Token verification failed"); e})?;
        let realm_claims = RealmClaims::from_raw_claims(&token.realm_claims.token_claims, &token.realm_claims.measurement_claims)?;
        let hash = hash_realm_challenge(
            self.challenge.as_slice(),
            pubkey.as_bytes()
        );

        if hash != realm_claims.challenge {
            error!("Challenge mismatch, expected: {:?} and got {:?}", self.challenge, realm_claims.challenge);
            return Err(RaTlsError::InvalidChallenge);
        }

        info!("Received client CCA token:");
        print_token(&token);

        self.token_verifier.verify(raw_token).map_err(|e|{error!("Token verification failed"); e})
    }
}

impl ClientCertVerifier for RaTlsCertVeryfier {
    fn verify_client_cert(
            &self,
            end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _now: std::time::SystemTime,
        ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        match self.verify_cert(end_entity) {
            Ok(()) => Ok(ClientCertVerified::assertion()),
            Err(err) => Err(Error::InvalidCertificate(rustls::CertificateError::Other(Arc::new(err))))
        }
    }

    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.root_subjects
    }
}

impl ServerCertVerifier for RaTlsCertVeryfier {
    fn verify_server_cert(
            &self,
            end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        match self.verify_cert(end_entity) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(err) => Err(Error::InvalidCertificate(rustls::CertificateError::Other(Arc::new(err))))
        }
    }
}
