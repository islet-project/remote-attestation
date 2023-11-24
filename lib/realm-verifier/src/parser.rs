use std::fs;

use serde::Deserialize;
use serde_json::Result;

use log::error;

#[derive(Debug, Deserialize)]
pub struct Issuer {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct ReferenceValues {
    pub rim: String,
    pub rems: Vec<Vec<String>>,
    #[serde(rename = "hash-algo")]
    pub hash_algo: String,
}

#[derive(Debug, Deserialize)]
pub struct Realm {
    pub uuid: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "release-timestamp")]
    pub release_timestamp: String,
    #[serde(rename = "attestation-protocol")]
    pub attestation_protocol: String,
    pub port: u16,
    #[serde(rename = "reference-values")]
    pub reference_values: ReferenceValues,
}

#[derive(Debug, Deserialize)]
pub struct ReferenceJSON {
    pub version: String,
    pub issuer: Issuer,
    pub realm: Realm,
}

pub fn parse_reference_json(path: String) -> Result<ReferenceJSON> {
    let contents = fs::read_to_string(path)
        .map_err(|e| {
            error!("Failed to open reference json");
            e
        })
        .unwrap();

    serde_json::from_str(&contents)
}
