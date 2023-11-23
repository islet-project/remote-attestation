use p384::ecdsa::signature::Verifier;
use sha2::{Sha256, Digest, Sha384, Sha512};
use super::*;


enum SigningAlgorithm
{
    // sha256 + secp256r1/prime256v1/P-256
    ES256,
    // sha384 + secp384r1/P-384
    ES384,
    // sha512 + secp521r1/P-521
    ES512,
}

impl TryFrom<coset::Algorithm> for SigningAlgorithm
{
    type Error = TokenError;

    fn try_from(alg: coset::Algorithm) -> Result<Self, Self::Error>
    {
        match alg {
            coset::Algorithm::Assigned(coset::iana::Algorithm::ES256) => Ok(SigningAlgorithm::ES256),
            coset::Algorithm::Assigned(coset::iana::Algorithm::ES384) => Ok(SigningAlgorithm::ES384),
            coset::Algorithm::Assigned(coset::iana::Algorithm::ES512) => Ok(SigningAlgorithm::ES512),
            unknown => Err(TokenError::InvalidAlgorithm(Some(unknown))),
        }
    }
}

impl TryFrom<&str> for SigningAlgorithm
{
    type Error = TokenError;

    fn try_from(alg: &str) -> Result<Self, Self::Error>
    {
        match alg {
            "sha-256" => Ok(SigningAlgorithm::ES256),
            "sha-384" => Ok(SigningAlgorithm::ES384),
            "sha-512" => Ok(SigningAlgorithm::ES512),
            _ => Err(TokenError::InvalidTokenFormat("invalid hash algorithm")),
        }
    }
}

struct RustCryptoVerifier
{
    algorithm: SigningAlgorithm,
    key_public_raw: Vec<u8>,
}

impl RustCryptoVerifier
{
    fn new(algorithm: SigningAlgorithm, key_public: &[u8]) -> Self
    {
        Self {
            algorithm,
            key_public_raw: key_public.to_vec(),
        }
    }

    fn verify(&self, sig: &[u8], data: &[u8]) -> Result<(), TokenError>
    {
        match self.algorithm {
            SigningAlgorithm::ES256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_public_raw)?;
                let sig = p256::ecdsa::Signature::from_slice(sig)?;
                key.verify(data, &sig)?;
            },
            SigningAlgorithm::ES384 => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_public_raw)?;
                let sig = p384::ecdsa::Signature::from_slice(sig)?;
                key.verify(data, &sig)?;
            },
            SigningAlgorithm::ES512 => {
                // p521 from RustCrypto cannot do ecdsa
                return Err(TokenError::NotImplemented("p521 ecdsa"));
            },
        }
        Ok(())
    }
}

pub(crate) fn verify_coset_signature(cose: &CoseSign1, key_pub: &[u8], aad: &[u8]) -> Result<(), TokenError>
{
    if cose.protected.header.alg.is_none() {
        return Err(TokenError::InvalidAlgorithm(None));
    }
    let alg = cose.protected.header.alg.as_ref().unwrap().clone().try_into()?;
    let verifier = RustCryptoVerifier::new(alg, &key_pub);
    cose.verify_signature(aad, |sig, data| verifier.verify(sig, data))
}

pub(crate) fn verify_digest(data: &[u8], hash: &[u8], alg: &str) -> Result<(), TokenError>
{
    let algorithm = alg.try_into()?;

    let digest = match algorithm {
        SigningAlgorithm::ES256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        },
        SigningAlgorithm::ES384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        },
        SigningAlgorithm::ES512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        },
    };

    if digest != hash {
        return Err(TokenError::VerificationFailed("challenge verification failed"));
    }

    Ok(())
}
