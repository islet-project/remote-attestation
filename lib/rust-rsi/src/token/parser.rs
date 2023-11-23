use super::*;


pub struct PlatClaims {
    pub challenge: Vec<u8>,
    pub verification_service: String,
    pub profile: String,
    pub instance_id: Vec<u8>,
    pub implementation_id: Vec<u8>,
    pub lifecycle: i64,
    pub configuration: Vec<u8>,
    pub hash_algo: String,
}

fn get_claim(key: u32, claims: &ClaimsMap) -> Result<ClaimData, TokenError> {
    if claims.contains_key(&key) {
        Ok(claims[&key].data.clone())
    } else {
        Err(TokenError::MissingPlatSwClaim(key))
    }
}

impl PlatClaims {
    pub fn from_raw_claims(claims: &ClaimsMap) -> Result<Self, TokenError> {
        Ok(Self {
            challenge: get_claim(CCA_PLAT_CHALLENGE, claims)?.try_into()?,
            verification_service: get_claim(CCA_PLAT_VERIFICATION_SERVICE, claims)?.try_into()?,
            profile: get_claim(CCA_PLAT_PROFILE, claims)?.try_into()?,
            instance_id: get_claim(CCA_PLAT_INSTANCE_ID, claims)?.try_into()?,
            implementation_id: get_claim(CCA_PLAT_IMPLEMENTATION_ID, claims)?.try_into()?,
            lifecycle: get_claim(CCA_PLAT_SECURITY_LIFECYCLE, claims)?.try_into()?,
            configuration: get_claim(CCA_PLAT_CONFIGURATION, claims)?.try_into()?,
            hash_algo: get_claim(CCA_PLAT_HASH_ALGO_ID, claims)?.try_into()?,
        })
    }
}

pub struct PlatSwComponent {
    pub ty: String,
    pub hash_algo: String,
    pub value: Vec<u8>,
    pub version: String,
    pub signer_id: Vec<u8>,
}

impl PlatSwComponent {
    pub fn from_raw_claims(
        claims: &ClaimsMap,
        plat_hash_algo: &String,
    ) -> Result<Self, TokenError> {
        Ok(Self {
            ty: get_claim(CCA_SW_COMP_TITLE, claims)?.try_into()?,
            hash_algo: match get_claim(CCA_SW_COMP_HASH_ALGORITHM, claims) {
                Ok(i) => i.try_into()?,
                Err(_) => plat_hash_algo.clone(),
            },
            value: get_claim(CCA_SW_COMP_MEASUREMENT_VALUE, claims)?.try_into()?,
            version: get_claim(CCA_SW_COMP_VERSION, claims)?.try_into()?,
            signer_id: get_claim(CCA_SW_COMP_SIGNER_ID, claims)?.try_into()?,
        })
    }
}

#[derive(Debug)]
pub struct RealmClaims {
    pub challenge: Vec<u8>,
    pub personalization_value: Vec<u8>,
    pub hash_algo: String,
    pub pub_key_hash_algo: String,
    pub pub_key: Vec<u8>,
    pub rim: Vec<u8>,
    pub rems: [Vec<u8>; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS],
}

impl RealmClaims {
    pub fn from_raw_claims(
        claims: &ClaimsMap,
        measurement_claims: &ClaimsMap,
    ) -> Result<Self, TokenError> {
        let mut rems: [Vec<u8>; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS] =
            <[Vec<u8>; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS]>::default();
        for i in 0..CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS {
            rems[i] = get_claim(i as u32, measurement_claims)?.try_into()?;
        }

        Ok(Self {
            challenge: get_claim(CCA_REALM_CHALLENGE, claims)?.try_into()?,
            personalization_value: get_claim(CCA_REALM_PERSONALIZATION_VALUE, claims)?
                .try_into()?,
            hash_algo: get_claim(CCA_REALM_HASH_ALGO_ID, claims)?.try_into()?,
            pub_key_hash_algo: get_claim(CCA_REALM_PUB_KEY_HASH_ALGO_ID, claims)?.try_into()?,
            pub_key: get_claim(CCA_REALM_PUB_KEY, claims)?.try_into()?,
            rim: get_claim(CCA_REALM_INITIAL_MEASUREMENT, claims)?.try_into()?,
            rems,
        })
    }
}
