#[allow(dead_code)]
#[derive(Debug)]
pub enum RocliError {
    IOFileError(std::io::Error),
    TokenError(rust_rsi::TokenError),
    YamlDeserializationError(serde_yaml::Error),
    JsonSerializationError(serde_json::Error),
    ProfileNotAllowed(String)
}

impl From<std::io::Error> for RocliError {
    fn from(value: std::io::Error) -> Self {
        Self::IOFileError(value)
    }
}

impl From<rust_rsi::TokenError> for RocliError {
    fn from(value: rust_rsi::TokenError) -> Self {
        Self::TokenError(value)
    }
}

impl From<serde_yaml::Error> for RocliError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::YamlDeserializationError(value)
    }
}

impl From<serde_json::Error> for RocliError {
    fn from(value: serde_json::Error) -> Self {
        Self::JsonSerializationError(value)
    }
}
