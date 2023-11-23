use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use rust_rsi::{PlatClaims, PlatSwComponent};
use crate::tags::{Class, TypeValue, Environment,
    Measurement, MeasurementKey, MeasurementKeyValue, MeasurementValue};

impl From<PlatClaims> for Environment {
    fn from(value: PlatClaims) -> Self {
        Self {
            class: Class {
                id: TypeValue {
                    ty: "psa.impl-id".to_string(),
                    val: b64.encode(value.implementation_id)
                },
                vendor: None,
                model: None
            },
            instance: TypeValue {
                ty: "ueid".to_string(),
                val: b64.encode(value.instance_id)
            }
        }
    }
}

impl From<PlatSwComponent> for Measurement {
    fn from(value: PlatSwComponent) -> Self {
        Self {
            key: MeasurementKey {
                ty: "psa.refval-id".to_owned(),
                value: MeasurementKeyValue::PsaRefValId {
                    label: value.ty,
                    version: value.version,
                    signer_id: b64.encode(value.signer_id)
                }
            },
            value: MeasurementValue::Digests(vec![
                format!("{}:{}", value.hash_algo, b64.encode(value.value.as_slice()))
            ])
        }
    }
}

impl From<&PlatClaims> for Measurement {
    fn from(value: &PlatClaims) -> Self {
        Self {
            key: MeasurementKey {
                ty: "cca.platform-config-id".to_owned(),
                value: MeasurementKeyValue::CcaPlatformConfigId("cfg v1.0.0".to_owned())
            },
            value: MeasurementValue::RawValue {
                ty: "bytes".to_owned(),
                value: b64.encode(value.configuration.clone())
            }
        }
    }
}
