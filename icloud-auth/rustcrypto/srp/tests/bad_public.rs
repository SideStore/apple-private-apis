use num_bigint::BigUint;
use num_traits::identities::Zero;
use sha1::Sha1;
use srp::client::SrpClient;
use srp::groups::G_1024;
use srp::server::SrpServer;

#[test]
#[should_panic]
fn bad_a_pub() {
    let server = SrpServer::<Sha1>::new(&G_1024);
    server
        .process_reply(b"", b"", &BigUint::zero().to_bytes_be())
        .unwrap();
}

#[test]
#[should_panic]
fn bad_b_pub() {
    let client = SrpClient::<Sha1>::new(&G_1024);
    client
        .process_reply(b"", b"", b"", b"", &BigUint::zero().to_bytes_be())
        .unwrap();
}
