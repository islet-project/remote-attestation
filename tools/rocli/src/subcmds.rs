use rust_rsi::{AttestationClaims, PlatClaims, PlatSwComponent};
use crate::tags::{Comid, Environment, AttesterVerificationKeys,
    VerificationKey, Triples, Config, ReferenceValue, Corim, Output, Measurement, TypeValue};
use crate::tools::read_string;
use crate::error::RocliError;

pub(crate) fn make_endorsements(cpak: Vec<String>, cpak_type: Vec<String>, token: AttestationClaims, config: Config) -> Result<Output, RocliError> {
    let plat_claims = PlatClaims::from_raw_claims(&token.platform_claims.token_claims)?;
    let mut keys = Vec::new();

    for (ty, val) in cpak_type.into_iter().zip(cpak.into_iter()){
        let key = read_string(val)?;
        keys.push(TypeValue { ty, val: key });
    }
    let mut envir: Environment = plat_claims.into();

    if let Some(env) = config.environment {
        envir.extend_from_config(env);
    }

    Ok(Output::comid(Comid {
        lang: config.lang,
        tag_identity: config.tag_identity,
        entities: config.entities.into_iter().map(|i| i.to_comid_entity()).collect(),

        triples: Triples::AttesterVerificationKeys(vec![
            AttesterVerificationKeys {
                environment: envir,
                verification_keys: keys
            }
        ])
    }))
}

pub(crate) fn make_refvals(token: AttestationClaims, config: Config) -> Result<Output, RocliError> {
    let plat_claims = PlatClaims::from_raw_claims(&token.platform_claims.token_claims)?;
    let mut measurements = token.platform_claims.sw_component_claims.iter()
        .filter(|sw_componenet| sw_componenet.present)
        .map(|sw_componenet| PlatSwComponent::from_raw_claims(
                &sw_componenet.claims, &plat_claims.hash_algo))
        .flatten()
        .map(|i| i.into())
        .collect::<Vec<_>>();
    measurements.push(Measurement::from(&plat_claims));
    let mut envir: Environment = plat_claims.into();

    if let Some(env) = config.environment {
        envir.extend_from_config(env);
    }

    Ok(Output::comid(Comid {
        lang: config.lang,
        tag_identity: config.tag_identity,
        entities: config.entities.into_iter().map(|i| i.to_comid_entity()).collect(),

        triples: Triples::ReferenceValues(vec![
            ReferenceValue {
                environment: envir,
                measurements: measurements
            }
        ])
    }))
}

pub(crate) fn make_corim(token: AttestationClaims, config: Config) -> Result<Output, RocliError> {
    let plat_claims = PlatClaims::from_raw_claims(&token.platform_claims.token_claims)?;

    if config.profiles.iter().find(|i| **i ==  plat_claims.profile).is_none() {
        return Err(RocliError::ProfileNotAllowed(plat_claims.profile))
    }

    Ok(Output::corim(Corim {
        corim_id: config.tag_identity.id,
        profiles: vec![plat_claims.profile],
        validity: config.validity,
        entities: config.entities.into_iter().map(|i| i.to_corim_entity()).collect()
    }))
}
