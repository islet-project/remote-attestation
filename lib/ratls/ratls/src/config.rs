use lazy_static::lazy_static;
use simple_asn1::{OID, oid};

// This is random, if you know better please change this XD
lazy_static! {
    pub(crate) static ref CCA_TOKEN_X509_EXT: OID = oid!(1, 3, 3, 3, 7);
}
