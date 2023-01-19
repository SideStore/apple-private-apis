// use crate::{anisette::AnisetteData, client::GsaClient, Error};

// pub fn login<F, G>(appleid: F, tfa: G) -> Result<GsaClient, Error>
// where
//     F: Fn() -> (String, String),
//     G: Fn() -> String,
// {
//     let anisette = AnisetteData::from_url(crate::anisette::SIDELOADLY_ANISETTE)?;
//     let looped = login_loop(appleid, tfa, &mut GsaClient::new(anisette));

//     match looped {
//         Ok(gsa_client) => Ok(gsa_client.clone()),
//         Err(e) => Err(e),
//     }
// }

// fn login_loop<F, G>(appleid: F, tfa: G, gsa_client: &mut GsaClient) -> Result<GsaClient, Error>
// where
//     F: Fn() -> (String, String),
//     G: Fn() -> String,
// {
//     let (username, password) = appleid();
//     let srp_response = gsa_client.auth_srp(username, password);
//     if !srp_response.is_ok() {
//         return Err(Error::AuthSrp);
//     }

//     if gsa_client.needs2FA {
//         let send_tfa_response = gsa_client.send_2fa_to_devices();
//         if !send_tfa_response.is_ok() {
//             return Err(Error::AuthSrp);
//         }
//         let tfa_code = tfa();
//         let tfa_response = gsa_client.verify_2fa(&tfa_code);

//         if !tfa_response.is_ok() {
//             return Err(Error::AuthSrp);
//         }
//         return login_loop(appleid, tfa, gsa_client);
//     }

//     Ok(gsa_client.clone())
// }
