use log::{debug, info};
use rcgen::{CertificateParams, KeyPair, CustomExtension, Certificate as RcgenCert, date_time_ymd, DistinguishedName};
use rsa::RsaPrivateKey;
use rustls::{client::ResolvesClientCert, server::ResolvesServerCert, sign::{CertifiedKey, RsaSigningKey}, Certificate, PrivateKey};
use std::sync::Arc;
use rand::rngs::OsRng;
use pkcs8::{EncodePublicKey, EncodePrivateKey};
use crate::{error::RaTlsError, tools::hash_realm_challenge, config::CCA_TOKEN_X509_EXT};
use crate::token_resolver::InternalTokenResolver;
use base64::{Engine, engine::general_purpose::STANDARD as b64};

pub struct RaTlsCertResolver {
    token_resolver: Arc<dyn InternalTokenResolver>,
    private_key: RsaPrivateKey
}

impl RaTlsCertResolver {
    pub fn from_token_resolver(token_resolver: Arc<dyn InternalTokenResolver>) -> Result<Self, RaTlsError> {
        let key_size = 2048;

        info!("Generating RSA {}bit key.", key_size);
        let private_key = RsaPrivateKey::new(&mut OsRng, key_size)?;
        info!("Finished generating RSA key.");

        Ok(Self {
            token_resolver,
            private_key
        })
    }

    fn create_cert(&self, challenge: String) -> Result<Arc<CertifiedKey>, RaTlsError> {
        debug!("Received challenge {}", challenge);
        let realm_challenge = hash_realm_challenge(
            b64.decode(challenge)?.as_slice(),
            self.private_key
                .to_public_key()
                .to_public_key_der()?
                .as_bytes()
        );

        let token = self.token_resolver.resolve(&realm_challenge)?;
        let pkcs8_privkey = self.private_key.to_pkcs8_der()?;
        let privkey = PrivateKey(pkcs8_privkey.to_bytes().to_vec());
        let mut params = CertificateParams::default();
        params.key_pair = Some(KeyPair::try_from(pkcs8_privkey.as_bytes())?);
        params.not_before = date_time_ymd(2021, 05, 19);
        params.not_after = date_time_ymd(4096, 01, 01);
        params.distinguished_name = DistinguishedName::new();

        params.alg = &rcgen::PKCS_RSA_SHA256;
        params.custom_extensions.push(CustomExtension::from_oid_content(
            CCA_TOKEN_X509_EXT.as_vec::<u64>()?.as_slice(),
            token
        ));

        let der = RcgenCert::from_params(params)?.serialize_der()?;
        let cert = Certificate(der);
        let key = RsaSigningKey::new(&privkey)?;

        Ok(Arc::new(CertifiedKey {
            cert: vec![cert],
            key: Arc::new(key),
            ocsp: None,
            sct_list: None
        }))
    }
}

impl ResolvesClientCert for RaTlsCertResolver {
    fn has_certs(&self) -> bool {
        true
    }

    fn resolve(
            &self,
            acceptable_issuers: &[&[u8]],
            _sigschemes: &[rustls::SignatureScheme],
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {

        if acceptable_issuers.len() != 1 {
            return None;
        }

        if let Ok(challenge) = String::from_utf8(acceptable_issuers[0].to_owned()) {
            self.create_cert(challenge).ok()
        } else {
            None
        }
    }
}

impl ResolvesServerCert for RaTlsCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(challenge) = client_hello.server_name() {
            self.create_cert(challenge.to_owned()).ok()
        } else {
            None
        }
    }
}
