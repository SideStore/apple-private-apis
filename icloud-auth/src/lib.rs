mod anisette;
mod client;
pub use client::AppleAccount;
#[derive(Debug)]
pub enum Error {
    HttpRequest,
    Parse,
    AuthSrp,
}

// login test

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_gsa_auth() {
        println!("gsa auth test");
        let password = std::env::var("apple_password").unwrap();
        let email = std::env::var("apple_email").unwrap();
        let ad = anisette::AnisetteData::from_url(anisette::SIDELOADLY_ANISETTE).unwrap();
        print!("{:?}", ad);
        let appleid_closure = move || (email.clone(), password.clone());
        // ask console for 2fa code
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input
        };
        let _ = client::AppleAccount::login(appleid_closure, tfa_closure, ad);
    }
}
