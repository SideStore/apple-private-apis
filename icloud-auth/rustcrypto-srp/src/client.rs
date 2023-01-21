//! SRP client implementation.
//!
//! # Usage
//! First create SRP client struct by passing to it SRP parameters (shared
//! between client and server).
//!
//! You can use SHA1 from SRP-6a, but it's highly recommended to use specialized
//! password hashing algorithm instead (e.g. PBKDF2, argon2 or scrypt).
//!
//! ```rust
//! use crate::srp::groups::G_2048;
//! use sha2::Sha256; // Note: You should probably use a proper password KDF
//! # use crate::srp::client::SrpClient;
//!
//! let client = SrpClient::<Sha256>::new(&G_2048);
//! ```
//!
//! Next send handshake data (username and `a_pub`) to the server and receive
//! `salt` and `b_pub`:
//!
//! ```rust
//! # let client = crate::srp::client::SrpClient::<sha2::Sha256>::new(&crate::srp::groups::G_2048);
//! # fn server_response()-> (Vec<u8>, Vec<u8>) { (vec![], vec![]) }
//!
//! let mut a = [0u8; 64];
//! // rng.fill_bytes(&mut a);
//! let a_pub = client.compute_public_ephemeral(&a);
//! let (salt, b_pub) = server_response();
//! ```
//!
//! Process the server response and create verifier instance.
//! process_reply can return error in case of malicious `b_pub`.
//!
//! ```rust
//! # let client = crate::srp::client::SrpClient::<sha2::Sha256>::new(&crate::srp::groups::G_2048);
//! # let a = [0u8; 64];
//! # let username = b"username";
//! # let password = b"password";
//! # let salt = b"salt";
//! # let b_pub = b"b_pub";
//!
//! let private_key = (username, password, salt);
//! let verifier = client.process_reply(&a, username, password, salt, b_pub);
//! ```
//!
//! Finally verify the server: first generate user proof,
//! send it to the server and verify server proof in the reply. Note that
//! `verify_server` method will return error in case of incorrect server reply.
//!
//! ```rust
//! # let client = crate::srp::client::SrpClient::<sha2::Sha256>::new(&crate::srp::groups::G_2048);
//! # let verifier = client.process_reply(b"", b"", b"", b"", b"1").unwrap();
//! # fn send_proof(_: &[u8]) -> Vec<u8> { vec![173, 202, 13, 26, 207, 73, 0, 46, 121, 238, 48, 170, 96, 146, 60, 49, 88, 76, 12, 184, 152, 76, 207, 220, 140, 205, 190, 189, 117, 6, 131, 63]   }
//!
//! let client_proof = verifier.proof();
//! let server_proof = send_proof(client_proof);
//! verifier.verify_server(&server_proof).unwrap();
//! ```
//!
//! `key` contains shared secret key between user and the server. You can extract shared secret
//! key using `key()` method.
//! ```rust
//! # let client = crate::srp::client::SrpClient::<sha2::Sha256>::new(&crate::srp::groups::G_2048);
//! # let verifier = client.process_reply(b"", b"", b"", b"", b"1").unwrap();
//!
//! verifier.key();
//!```
//!
//!
//! For user registration on the server first generate salt (e.g. 32 bytes long)
//! and get password verifier which depends on private key. Send username, salt
//! and password verifier over protected channel to protect against
//! Man-in-the-middle (MITM) attack for registration.
//!
//! ```rust
//! # let client = crate::srp::client::SrpClient::<sha2::Sha256>::new(&crate::srp::groups::G_2048);
//! # let username = b"username";
//! # let password = b"password";
//! # let salt = b"salt";
//! # fn send_registration_data(_: &[u8], _: &[u8], _: &[u8]) {}
//!
//! let pwd_verifier = client.compute_verifier(username, password, salt);
//! send_registration_data(username, salt, &pwd_verifier);
//! ```

use digest::{Digest, Output};
use num_bigint::BigUint;
use std::marker::PhantomData;
use subtle::ConstantTimeEq;

use crate::types::{SrpAuthError, SrpGroup};
use crate::utils::{compute_k, compute_m1, compute_m2, compute_u};

/// SRP client state before handshake with the server.
pub struct SrpClient<'a, D: Digest> {
    params: &'a SrpGroup,
    d: PhantomData<D>,
}

/// SRP client state after handshake with the server.
pub struct SrpClientVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
}

impl<'a, D: Digest> SrpClient<'a, D> {
    /// Create new SRP client instance.
    pub fn new(params: &'a SrpGroup) -> Self {
        Self {
            params,
            d: Default::default(),
        }
    }

    pub fn compute_a_pub(&self, a: &BigUint) -> BigUint {
        self.params.g.modpow(a, &self.params.n)
    }

    //  H(<username> | ":" | <raw password>)
    pub fn compute_identity_hash(username: &[u8], password: &[u8]) -> Output<D> {
        let mut d = D::new();
        d.update(username);
        d.update(b":");
        d.update(password);
        d.finalize()
    }

    // x = H(<salt> | H(<username> | ":" | <raw password>))
    pub fn compute_x(identity_hash: &[u8], salt: &[u8]) -> BigUint {
        let mut x = D::new();
        x.update(salt);
        x.update(identity_hash);
        BigUint::from_bytes_be(&x.finalize())
    }

    // (B - (k * g^x)) ^ (a + (u * x)) % N
    pub fn compute_premaster_secret(
        &self,
        b_pub: &BigUint,
        k: &BigUint,
        x: &BigUint,
        a: &BigUint,
        u: &BigUint,
    ) -> BigUint {
        // (k * g^x)
        let base = (k * (self.params.g.modpow(x, &self.params.n))) % &self.params.n;
        // Because we do operation in modulo N we can get: b_pub > base. That's not good. So we add N to b_pub to make sure.
        // B - kg^x
        let base = ((&self.params.n + b_pub) - &base) % &self.params.n;
        let exp = (u * x) + a;
        // S = (B - kg^x) ^ (a + ux)
        // or
        // S = base ^ exp
        base.modpow(&exp, &self.params.n)
    }

    // v = g^x % N
    pub fn compute_v(&self, x: &BigUint) -> BigUint {
        self.params.g.modpow(x, &self.params.n)
    }

    /// Get password verifier (v in RFC5054) for user registration on the server.
    pub fn compute_verifier(&self, username: &[u8], password: &[u8], salt: &[u8]) -> Vec<u8> {
        let identity_hash = Self::compute_identity_hash(username, password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);
        self.compute_v(&x).to_bytes_be()
    }

    /// Get public ephemeral value for handshaking with the server.
    /// g^a % N
    pub fn compute_public_ephemeral(&self, a: &[u8]) -> Vec<u8> {
        self.compute_a_pub(&BigUint::from_bytes_be(a)).to_bytes_be()
    }

    /// Process server reply to the handshake.
    /// a is a random value,
    /// username, password is supplied by the user
    /// salt and b_pub come from the server
    pub fn process_reply(
        &self,
        a: &[u8],
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub: &[u8],
    ) -> Result<SrpClientVerifier<D>, SrpAuthError> {
        let a = BigUint::from_bytes_be(a);
        // let a_pub = BigUint::from_bytes_be(&a_pub_bytes);
        let a_pub = Self::compute_a_pub(&self, &a);

        let b_pub = BigUint::from_bytes_be(b_pub);

        // Safeguard against malicious B
        if &b_pub % &self.params.n == BigUint::default() {
            return Err(SrpAuthError::IllegalParameter("b_pub".to_owned()));
        }

        let u = compute_u::<D>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be());
        let k = compute_k::<D>(self.params);
        let identity_hash = Self::compute_identity_hash(&[], password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);

        let key = self.compute_premaster_secret(&b_pub, &k, &x, &a, &u);
        let key = D::digest(key.to_bytes_be());

        let m1 = compute_m1::<D>(
            &a_pub.to_bytes_be(),
            &b_pub.to_bytes_be(),
            &key,
            username,
            salt,
            self.params,
        );

        let m2 = compute_m2::<D>(&a_pub.to_bytes_be(), &m1, &key);

        Ok(SrpClientVerifier {
            m1,
            m2,
            key: key.to_vec(),
        })
    }
}

impl<D: Digest> SrpClientVerifier<D> {
    /// Get shared secret key without authenticating server, e.g. for using with
    /// authenticated encryption modes. DO NOT USE this method without
    /// some kind of secure authentication
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verification data for sending to the server.
    pub fn proof(&self) -> &[u8] {
        self.m1.as_slice()
    }

    /// Verify server reply to verification data.
    pub fn verify_server(&self, reply: &[u8]) -> Result<(), SrpAuthError> {
        if self.m2.ct_eq(reply).unwrap_u8() != 1 {
            // aka == 0
            Err(SrpAuthError::BadRecordMac("server".to_owned()))
        } else {
            Ok(())
        }
    }
}
