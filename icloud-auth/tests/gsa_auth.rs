#[cfg(test)]
mod tests {
    use icloud_auth::*;

    #[test]
    fn gsa_auth() {
        println!("gsa auth test");
        let password = std::env::var("apple_password").unwrap();
        let email = std::env::var("apple_email").unwrap();
        let appleid_closure = move || (email.clone(), password.clone());
        // ask console for 2fa code, make sure it is only 6 digits, no extra characters
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        };
        let acc = AppleAccount::login(appleid_closure, tfa_closure);
        let spd_plist = acc.unwrap().spd.unwrap();
        // turn plist::dictonary into json
        let spd_json = serde_json::to_string(&spd_plist).unwrap();

        println!("{:?}", spd_json);
        println!("gsa auth test done");
    }
}
