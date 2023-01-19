use rand::RngCore;
use sha2::Sha256;
use srp::client::SrpClient;

use srp::groups::G_2048;
use srp::server::SrpServer;

fn auth_test(true_pwd: &[u8], auth_pwd: &[u8]) {
    let mut rng = rand::rngs::OsRng;
    let username = b"alice";

    // Client instance creation
    let client = SrpClient::<Sha256>::new(&G_2048);

    // Begin Registration

    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let verifier = client.compute_verifier(username, true_pwd, &salt);

    // Client sends username and verifier and salt to the Server for storage

    // Registration Ends

    // Begin Authentication

    // User sends username

    // Server instance creation
    let server = SrpServer::<Sha256>::new(&G_2048);

    // Server retrieves verifier, salt and computes a public B value
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    let (salt, b_pub) = (&salt, server.compute_public_ephemeral(&b, &verifier));

    // Server sends salt and b_pub to client

    // Client computes the public A value and the clientVerifier containing the key, m1, and m2
    let mut a = [0u8; 64];
    rng.fill_bytes(&mut a);
    let client_verifier = client
        .process_reply(&a, username, auth_pwd, salt, &b_pub)
        .unwrap();
    let a_pub = client.compute_public_ephemeral(&a);
    let client_proof = client_verifier.proof();

    // Client sends a_pub and client_proof to server (M1)

    // Server processes verification data
    let server_verifier = server.process_reply(&b, &verifier, &a_pub).unwrap();
    println!("Client verification on server");
    server_verifier.verify_client(client_proof).unwrap();
    let server_proof = server_verifier.proof();
    let server_key = server_verifier.key();

    // Server sends server_proof to server (M2)

    // Client verifies server
    println!("Server verification on client");
    client_verifier.verify_server(server_proof).unwrap();
    let client_key = client_verifier.key();

    // our keys almost must equal but just an extra check
    assert_eq!(
        server_key, client_key,
        "server and client keys are not equal"
    );
}

#[test]
fn good_password() {
    auth_test(b"password", b"password");
}

#[test]
#[should_panic]
fn bad_password() {
    auth_test(b"password", b"paSsword");
}
