use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Id {
    pub id: Uuid,
    pub version: usize
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Entity {
    pub name: String,
    pub regid: String,
    pub roles: Vec<String>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EntityConfig {
    pub name: String,
    pub regid: String,
    pub comid_roles: Vec<String>,
    pub corim_roles: Vec<String>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TypeValue {
    #[serde(rename = "type")]
    pub ty: String,

    #[serde(rename = "value")]
    pub val: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Class {
    pub id: TypeValue,
    pub vendor: Option<String>,
    pub model: Option<String>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Environment {
    pub class: Class,
    pub instance: TypeValue
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InstanceConfig {
    pub ty: Option<String>,
    pub id: Option<String>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EnvironmentConfig {
    pub impl_id: Option<String>,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub instance_id: Option<InstanceConfig>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VerificationKey {
    pub key: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AttesterVerificationKeys {
    pub environment: Environment,

    #[serde(rename = "verification-keys")]
    pub verification_keys: Vec<VerificationKey>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum MeasurementKeyValue {
    PsaRefValId {
        label: String,
        version: String,

        #[serde(rename = "signer-id")]
        signer_id: String,
    },

    CcaPlatformConfigId(String)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MeasurementKey {
    #[serde(rename = "type")]
    pub ty: String,
    pub value: MeasurementKeyValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CcaPlatformConfigIdValue {
    #[serde(rename = "raw-value")]
    raw_value: TypeValue
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum MeasurementValue {
    #[serde(rename = "digests")]
    Digests(Vec<String>),

    #[serde(rename = "raw-value")]
    RawValue {
        #[serde(rename = "type")]
        ty: String,

        value: String
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Measurement {
    pub key: MeasurementKey,
    pub value: MeasurementValue
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReferenceValue {
    pub environment: Environment,
    pub measurements: Vec<Measurement>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Triples {
    #[serde(rename = "attester-verification-keys")]
    AttesterVerificationKeys(Vec<AttesterVerificationKeys>),

    #[serde(rename = "reference-values")]
    ReferenceValues(Vec<ReferenceValue>)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Validity {
    #[serde(rename = "not-before")]
    not_before: DateTime<Utc>,

    #[serde(rename = "not-after")]
    not_after: DateTime<Utc>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Corim {
    #[serde(rename = "corim-id")]
    pub corim_id: Uuid,
    pub profiles: Vec<String>,
    pub validity: Validity,
    pub entities: Vec<Entity>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Comid {
    pub lang: String,

    #[serde(rename = "tag-identity")]
    pub tag_identity: Id,
    pub entities: Vec<Entity>,
    pub triples: Triples
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Output {
    comid(Comid),
    corim(Corim)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Config {
    pub lang: String,
    pub tag_identity: Id,
    pub entities: Vec<EntityConfig>,
    pub validity: Validity,
    pub profiles: Vec<String>,
    pub environment: Option<EnvironmentConfig>
}

impl Environment {
    pub fn extend_from_config(&mut self, config: EnvironmentConfig) {
        if let Some(v) = config.model { self.class.model = Some(v); }
        if let Some(v) = config.vendor { self.class.vendor = Some(v); }
        if let Some(v) = config.impl_id { self.class.id.val = v; }
        if let Some(v) = config.instance_id {
            if let Some(ty) = v.ty { self.instance.ty = ty; }
            if let Some(id) = v.id { self.instance.val = id; }
        }
    }
}

impl EntityConfig {
    pub fn to_corim_entity(self) -> Entity {
        Entity { name: self.name, regid: self.regid, roles: self.corim_roles }
    }

    pub fn to_comid_entity(self) -> Entity {
        Entity { name: self.name, regid: self.regid, roles: self.comid_roles }
    }
}
