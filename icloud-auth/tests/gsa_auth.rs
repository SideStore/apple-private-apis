#[cfg(test)]
mod tests {
    use icloud_auth::*;

    #[tokio::test]
    async fn gsa_auth() {
        println!("gsa auth test");
        let email = std::env::var("apple_email").unwrap_or_else(|_| {
            println!("Enter Apple email: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        });

        let password = std::env::var("apple_password").unwrap_or_else(|_| {
            println!("Enter Apple password: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        });

        let appleid_closure = move || (email.clone(), password.clone());
        // ask console for 2fa code, make sure it is only 6 digits, no extra characters
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        };
        let acc = AppleAccount::login(appleid_closure, tfa_closure).await;

        println!("here");
        return;
        let account = acc.unwrap();
        let spd_plist = account.clone().spd.unwrap();
        // turn plist::dictonary into json
        let spd_json = serde_json::to_string(&spd_plist).unwrap();

        println!("{:?}", spd_json);

        let auth_token = account.clone().get_app_token("com.apple.gs.xcode.auth").await;
        println!("auth_token: {:?}", auth_token.unwrap().auth_token);
        println!("gsa auth test done");
    }
}
