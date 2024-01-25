use ratls::RaTlsError;
use std::fmt::Display;

#[derive(Debug)]
pub enum VeraisonTokenVeriferError {
    HTTPRequestError(reqwest::Error),
    FailedToOpenSession,
    VeraisonDidntProvideNextLocation,
    LocationHeaderIsNotAString,
    AttestationResultsVerificationError(ear::Error),
    SubmoduleDoesNotAffirm(String),
    TokenParsingError(rust_rsi::TokenError)
}

impl From<reqwest::Error> for VeraisonTokenVeriferError {
    fn from(value: reqwest::Error) -> Self {
        VeraisonTokenVeriferError::HTTPRequestError(value)
    }
}

impl From<ear::Error> for VeraisonTokenVeriferError {
    fn from(value: ear::Error) -> Self {
        Self::AttestationResultsVerificationError(value)
    }
}

impl From<rust_rsi::TokenError> for VeraisonTokenVeriferError {
    fn from(value: rust_rsi::TokenError) -> Self {
        Self::TokenParsingError(value)
    }
}

impl std::error::Error for VeraisonTokenVeriferError {}
impl Display for VeraisonTokenVeriferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VeraisonVerificationError")
    }
}

impl Into<RaTlsError> for VeraisonTokenVeriferError {
    fn into(self) -> RaTlsError {
        RaTlsError::GenericTokenVerifierError(Box::new(self))
    }
}
