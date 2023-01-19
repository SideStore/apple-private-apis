// use icloud_auth::ani
use std::sync::Arc;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use srp::{
    client::{SrpClient, SrpClientVerifier},
    groups::G_2048,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug() {
        // not a real account
        let bytes_a = base64::decode("XChHXELsQ+ljxTFbvRMUsGJxiDIlOh9f8e+JzoegmVcOdAXXtPNzkHpAbAgSjyA+vXrTA93+BUu8EJ9+4xZu9g==").unwrap();
        let username = "apple3@f1sh.me";
        let password = "WaffleTest123";
        let salt = base64::decode("6fK6ailLUcp2kJswJVrKjQ==").unwrap();
        let iters = 20832;

        let mut password_hasher = sha2::Sha256::new();
        password_hasher.update(&password.as_bytes());
        let hashed_password = password_hasher.finalize();
        // println!("Hashed password: {:?}", base64::encode(&hashed_password));

        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(
            &hashed_password,
            &salt,
            iters as u32,
            &mut password_buf,
        );
        // println!("PBKDF2 Encrypted password: {:?}",base64::encode(&password_buf));

        let identity_hash = SrpClient::<Sha256>::compute_identity_hash(&[], &password_buf);
        let x = SrpClient::<Sha256>::compute_x(identity_hash.as_slice(), &salt);

        // apub: N2XHuh/4P1urPoBvDocF0RCRIl2pliZYqg9p6wGH0nnJdckJPn3M00jEqoM4teqH03HjG1murdcZiNHb5YayufW//+asW01XB7nYIIVvGiUFLRypYITEKYWBQ6h2q02GaZspYJKy98V8Fwcvr0ri+al7zJo1X1aoRKINyjV5TywhhwmTleI1qJkf+JBRYKKqO1XFtOTpQsysWD3ZJdK3K78kSgT3q0kXE3oDRMiHPAO77GFJZErYTuvI6QPRbOgcrn+RKV6AsjR5tUQAoSGRdtibdZTAQijJg788qVg+OFVCNZoY9GYVxa+Ze1bPGdkkgCYicTE8iNFG9KlJ+QpKgQ==

        let a_random = base64::decode("ywN1O32vmBogb5Fyt9M7Tn8bbzLtDDbcYgPFpSy8n9E=").unwrap();
        let client = SrpClient::<Sha256>::new(&G_2048);

        let a_pub_compute =
            SrpClient::<Sha256>::compute_a_pub(&client, &BigUint::from_bytes_be(&a_random));
        // expect it to be same to a_pub
        println!(
            "compute a_pub: {:?}",
            base64::encode(&a_pub_compute.to_bytes_be())
        );

        let b_pub = base64::decode("HlWxsRmNi/9DCGxYCoqCTfdSvpbx3mrgFLQfOsgf3Rojn7MQQN/g63PwlBghUcVVB4//yAaRRnz/VIByl8thA9AKuVZl8k52PAHKSh4e7TuXSeYCFr0+GYu8/hFdMDl42219uzSuOXuaKGVKq6hxEAf3n3uXXgQRkXWtLFJ5nn1wq/emf46hYAHzc/pYyvckAdh9WDCw95IXbzKD8LcPw/0ZQoydMuXgW2ZKZ52fiyEs94IZ7L5RLL7jY1nVdwtsp2fxeqiZ3DNmVZ2GdNrbJGT//160tyd2evtUtehr8ygXNzjWdjV0cc4+1F38ywSPFyieVzVTYzDywRllgo3A5A==").unwrap();
        println!("fixed b_pub: {:?}", base64::encode(&b_pub));
        println!("");

        println!("salt: {:?} iterations: {:?}", base64::encode(&salt), iters);

        let verifier: SrpClientVerifier<Sha256> = SrpClient::<Sha256>::process_reply(
            &client,
            &a_random,
            // &a_pub,
            username.as_bytes(),
            &password_buf,
            &salt,
            &b_pub,
        )
        .unwrap();

        let m = verifier.proof();
    }

    #[test]
    fn print_n_g() {
        // println!("Print N/G test: ");
        // println!("g2048 g: {:?}", &G_2048.g);
        // println!("g2048 n: {:?}", &G_2048.n);
    }
}
