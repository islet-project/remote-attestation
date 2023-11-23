use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum SessionState {
    #[serde(rename = "waiting")]
    Waiting,

    #[serde(rename = "processing")]
    Processing,

    #[serde(rename = "complete")]
    Complete,

    #[serde(rename = "failed")]
    Failed
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct NewSessionresponse {
    pub(crate) nonce: String,
    pub(crate) expiry: String,
    pub(crate) accept: Vec<String>,
    pub(crate) status: SessionState
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Evidence {
    #[serde(rename = "type")]
    pub(crate) ty: String,

    pub(crate) value: String
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct VerificationResults {
    pub(crate) nonce: String,
    pub(crate) expiry: String,
    pub(crate) accept: Vec<String>,
    pub(crate) status: SessionState,
    pub(crate) evidence: Evidence,
    pub(crate) result: String
}
