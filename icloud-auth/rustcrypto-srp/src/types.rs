//! Additional SRP types.
use num_bigint::BigUint;
use std::fmt;

/// SRP authentication error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SrpAuthError {
    IllegalParameter(String),
    BadRecordMac(String),
}

impl fmt::Display for SrpAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrpAuthError::IllegalParameter(param) => {
                write!(f, "illegal_parameter: bad '{}' value", param)
            }
            SrpAuthError::BadRecordMac(param) => {
                write!(f, "bad_record_mac: incorrect '{}'  proof", param)
            }
        }
    }
}

/// Group used for SRP computations
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SrpGroup {
    /// A large safe prime (N = 2q+1, where q is prime)
    pub n: BigUint,
    /// A generator modulo N
    pub g: BigUint,
}

// #[cfg(test)]
// mod tests {
//     use crate::groups::G_1024;
//     use crate::utils::compute_k;
//     use sha1::Sha1;

//     #[test]
//     fn test_k_1024_sha1() {
//         let k = compute_k::<Sha1>(&G_1024).to_bytes_be();
//         assert_eq!(&k, include_bytes!("test/k_sha1_1024.bin"));
//     }
// }
