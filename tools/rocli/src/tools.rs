use serde::{de::DeserializeOwned, Serialize};
use std::{io::{BufReader, Read, BufWriter}, fs::File};

use crate::error::RocliError;


pub(crate) fn read_yaml<T: DeserializeOwned, F: AsRef<str>>(path: F) -> Result<T, RocliError> {
    Ok(serde_yaml::from_reader(
        BufReader::new(
            File::open(path.as_ref())?
        )
    )?)
}

pub(crate) fn read_string<F: AsRef<str>>(path: F) -> Result<String, std::io::Error> {
    let mut data = String::new();
    let mut file = File::open(path.as_ref())?;
    file.read_to_string(&mut data)?;
    Ok(data)
}

pub(crate) fn read_bytes<F: AsRef<str>>(path: F) -> Result<Vec<u8>, std::io::Error> {
    let mut data = Vec::new();
    let mut file = File::open(path.as_ref())?;
    file.read_to_end(&mut data)?;
    Ok(data)
}

pub(crate) fn write_json<T: Serialize, F: AsRef<str>>(obj: T, path: F) -> Result<(), RocliError> {
    serde_json::to_writer(
        BufWriter::new(
            File::create(path.as_ref())?
        ),
        &obj
    )?;

    Ok(())
}

pub(crate) fn dump_json<T: Serialize>(obj: T) -> Result<String, RocliError> {
    Ok(serde_json::to_string(&obj)?)
}
