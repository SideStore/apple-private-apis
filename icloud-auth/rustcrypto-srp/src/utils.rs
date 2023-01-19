use digest::{Digest, Output};
use num_bigint::BigUint;

use crate::types::SrpGroup;

// u = H(PAD(A) | PAD(B))
pub fn compute_u<D: Digest>(a_pub: &[u8], b_pub: &[u8]) -> BigUint {
    let mut u = D::new();
    u.update(a_pub);
    u.update(b_pub);
    BigUint::from_bytes_be(&u.finalize())
}

// k = H(N | PAD(g))
pub fn compute_k<D: Digest>(params: &SrpGroup) -> BigUint {
    let n = params.n.to_bytes_be();
    let g_bytes = params.g.to_bytes_be();
    let mut buf = vec![0u8; n.len()];
    let l = n.len() - g_bytes.len();
    buf[l..].copy_from_slice(&g_bytes);

    let mut d = D::new();
    d.update(&n);
    d.update(&buf);
    BigUint::from_bytes_be(d.finalize().as_slice())
}

// M1 = H(A, B, K) this doesn't follow the spec but apparently no one does for M1
// M1 should equal =  H(H(N) XOR H(g) | H(U) | s | A | B | K) according to the spec
pub fn compute_m1<D: Digest>(
    a_pub: &[u8],
    b_pub: &[u8],
    key: &[u8],
    username: &[u8],
    salt: &[u8],
    params: &SrpGroup,
) -> Output<D> {
    let n = params.n.to_bytes_be();
    let g_bytes = params.g.to_bytes_be();
    //pad g and n to the same length
    let mut g = vec![0; n.len() - g_bytes.len()];
    g.extend_from_slice(&g_bytes);

    // Compute the hash of n and g
    let mut g_hash = D::digest(&g);
    let n_hash = D::digest(&n);

    // XOR the hashes
    for i in 0..g_hash.len() {
        g_hash[i] ^= n_hash[i];
    }

    let mut d = D::new();
    d.update(&g_hash);
    d.update(D::digest(username));
    d.update(salt);
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize()
}

// M2 = H(A, M1, K)
pub fn compute_m2<D: Digest>(a_pub: &[u8], m1: &Output<D>, key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(&a_pub);
    d.update(&m1);
    d.update(&key);
    d.finalize()
}
