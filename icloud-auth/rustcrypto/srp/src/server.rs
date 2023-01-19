//! SRP server implementation
//!
//! # Usage
//! First receive user's username and public value `a_pub`, retrieve from a
//! database the salt and verifier for a given username. Generate `b` and public value `b_pub`.
//!
//!
//! ```rust
//! use crate::srp::groups::G_2048;
//! use sha2::Sha256; // Note: You should probably use a proper password KDF
//! # use crate::srp::server::SrpServer;
//! # fn get_client_request()-> (Vec<u8>, Vec<u8>) { (vec![], vec![])}
//! # fn get_user(_: &[u8])-> (Vec<u8>, Vec<u8>) { (vec![], vec![])}
//!
//! let server = SrpServer::<Sha256>::new(&G_2048);
//! let (username, a_pub) = get_client_request();
//! let (salt, v) = get_user(&username);
//! let mut b = [0u8; 64];
//! // rng.fill_bytes(&mut b);
//! let b_pub = server.compute_public_ephemeral(&b, &v);
//! ```
//!
//! Next send to user `b_pub` and `salt` from user record
//!
//! Next process the user response:
//!
//! ```rust
//! # let server = crate::srp::server::SrpServer::<sha2::Sha256>::new(&crate::srp::groups::G_2048);
//! # fn get_client_response() -> Vec<u8> { vec![1] }
//! # let b = [0u8; 64];
//! # let v = b"";
//!
//! let a_pub = get_client_response();
//! let verifier = server.process_reply(&b, v, &a_pub).unwrap();
//! ```
//!
//!
//! And finally receive user proof, verify it and send server proof in the
//! reply:
//!
//! ```rust
//! # let server = crate::srp::server::SrpServer::<sha2::Sha256>::new(&crate::srp::groups::G_2048);
//! # let verifier = server.process_reply(b"", b"", b"1").unwrap();
//! # fn get_client_proof()-> Vec<u8> { vec![26, 80, 8, 243, 111, 162, 238, 171, 208, 237, 207, 46, 46, 137, 44, 213, 105, 208, 84, 224, 244, 216, 103, 145, 14, 103, 182, 56, 242, 4, 179, 57] };
//! # fn send_proof(_: &[u8]) { };
//!
//! let client_proof = get_client_proof();
//! verifier.verify_client(&client_proof).unwrap();
//! send_proof(verifier.proof());
//! ```
//!
//!
//! `key` contains shared secret key between user and the server. You can extract shared secret
//! key using `key()` method.
//! ```rust
//! # let server = crate::srp::server::SrpServer::<sha2::Sha256>::new(&crate::srp::groups::G_2048);
//! # let verifier = server.process_reply(b"", b"", b"1").unwrap();
//!
//! verifier.key();
//!```
//!
use std::marker::PhantomData;

use digest::{Digest, Output};
use num_bigint::BigUint;
use subtle::ConstantTimeEq;

use crate::types::{SrpAuthError, SrpGroup};
use crate::utils::{compute_k, compute_m1, compute_m2, compute_u};

/// SRP server state
pub struct SrpServer<'a, D: Digest> {
    params: &'a SrpGroup,
    d: PhantomData<D>,
}

/// SRP server state after handshake with the client.
pub struct SrpServerVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
}

impl<'a, D: Digest> SrpServer<'a, D> {
    /// Create new server state.
    pub fn new(params: &'a SrpGroup) -> Self {
        Self {
            params,
            d: Default::default(),
        }
    }

    //  k*v + g^b % N
    pub fn compute_b_pub(&self, b: &BigUint, k: &BigUint, v: &BigUint) -> BigUint {
        let inter = (k * v) % &self.params.n;
        (inter + self.params.g.modpow(b, &self.params.n)) % &self.params.n
    }

    // <premaster secret> = (A * v^u) ^ b % N
    pub fn compute_premaster_secret(
        &self,
        a_pub: &BigUint,
        v: &BigUint,
        u: &BigUint,
        b: &BigUint,
    ) -> BigUint {
        // (A * v^u)
        let base = (a_pub * v.modpow(u, &self.params.n)) % &self.params.n;
        base.modpow(b, &self.params.n)
    }

    /// Get public ephemeral value for sending to the client.
    pub fn compute_public_ephemeral(&self, b: &[u8], v: &[u8]) -> Vec<u8> {
        self.compute_b_pub(
            &BigUint::from_bytes_be(b),
            &compute_k::<D>(self.params),
            &BigUint::from_bytes_be(v),
        )
        .to_bytes_be()
    }

    /// Process client reply to the handshake.
    /// b is a random value,
    /// v is the provided during initial user registration
    pub fn process_reply(
        &self,
        b: &[u8],
        v: &[u8],
        a_pub: &[u8],
        username: &[u8],
        salt: &[u8],
    ) -> Result<SrpServerVerifier<D>, SrpAuthError> {
        let b = BigUint::from_bytes_be(b);
        let v = BigUint::from_bytes_be(v);
        let a_pub = BigUint::from_bytes_be(a_pub);

        let k = compute_k::<D>(self.params);
        let b_pub = self.compute_b_pub(&b, &k, &v);

        // Safeguard against malicious A
        if &a_pub % &self.params.n == BigUint::default() {
            return Err(SrpAuthError::IllegalParameter("a_pub".to_owned()));
        }

        let u = compute_u::<D>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be());

        let key = self.compute_premaster_secret(&a_pub, &v, &u, &b);

        let m1 = compute_m1::<D>(
            &a_pub.to_bytes_be(),
            &b_pub.to_bytes_be(),
            &key.to_bytes_be(),
            username,
            salt,
            self.params,
        );

        let m2 = compute_m2::<D>(&a_pub.to_bytes_be(), &m1, &key.to_bytes_be());

        Ok(SrpServerVerifier {
            m1,
            m2,
            key: key.to_bytes_be(),
        })
    }
}

impl<D: Digest> SrpServerVerifier<D> {
    /// Get shared secret between user and the server. (do not forget to verify
    /// that keys are the same!)
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verification data for sending to the client.
    pub fn proof(&self) -> &[u8] {
        // TODO not Output
        self.m2.as_slice()
    }

    /// Process user proof of having the same shared secret.
    pub fn verify_client(&self, reply: &[u8]) -> Result<(), SrpAuthError> {
        if self.m1.ct_eq(reply).unwrap_u8() != 1 {
            // aka == 0
            Err(SrpAuthError::BadRecordMac("client".to_owned()))
        } else {
            Ok(())
        }
    }
}
