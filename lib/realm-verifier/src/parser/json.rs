use std::str::FromStr;

use rust_rsi::CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS;
use serde::{Deserialize, Serialize};

use crate::{HashAlgo, MeasurementValue, RealmMeasurements};

pub const REFERENCE_RIM: &'static str = "rim";
pub const REFERENCE_REMS: &'static str = "rems";
pub const REFERENCE_HASH_ALGO: &'static str = "hash-algo";

#[derive(Debug, Deserialize, Serialize)]
pub struct ReferenceValues {
    pub rim: String,
    pub rems: Vec<Vec<String>>,
    #[serde(rename = "hash-algo")]
    pub hash_algo: String,
}

impl TryFrom<ReferenceValues> for RealmMeasurements {
    type Error = &'static str;
    fn try_from(value: ReferenceValues) -> Result<Self, Self::Error> {
        let hash_algo = HashAlgo::from_str(&value.hash_algo)?;

        let required_len = hash_algo.len();
        let required_hex_len = 2 * required_len;

        if value.rim.len() < required_hex_len {
            return Err("Length of reference RIM value too short");
        }

        let mut rim = MeasurementValue::init(required_len);
        hex::decode_to_slice(value.rim, &mut rim.as_mut_slice()[..required_len])
            .map_err(|_| "Failed to decode RIM value")?;

        if value.rems.len() < 1 {
            return Err("No reference REMs");
        }
        let mut rems = Vec::with_capacity(value.rems.len());

        for mut reference_rems_set in value.rems {
            if reference_rems_set.len() != CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS {
                return Err("Wrong length of reference REMs set");
            }
            let mut rems_set = [
                MeasurementValue::init(required_len);
                CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS
            ];

            for (rem_idx, reference_rem) in reference_rems_set.iter_mut().enumerate() {
                if reference_rem.len() != required_hex_len {
                    return Err("Wrong length of reference REM value")
                }

                hex::decode_to_slice(
                    reference_rem,
                    &mut rems_set[rem_idx].as_mut_slice()[..required_len]
                ).map_err(|_| "Failed to decode reference REM value")?;
            }

            rems.push(rems_set);
        }

        Ok(Self {
            initial: rim,
            extensible: rems,
            hash_algo,
        })
    }
}

pub fn parse_value(value: serde_json::Value) -> Result<RealmMeasurements, &'static str> {
    let reference_values: ReferenceValues = match serde_json::from_value(value) {
        Ok(v) => v,
        Err(_) => {
            return Err("Failed to deserialize reference values");
        }
    };
    RealmMeasurements::try_from(reference_values)
}
