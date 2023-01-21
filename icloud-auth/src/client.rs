use std::str::FromStr;

use crate::anisette::AnisetteData;
use crate::Error;
use aes::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use reqwest::{
    blocking::{Client, ClientBuilder, Response},
    header::{HeaderMap, HeaderName, HeaderValue},
    Certificate,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use srp::{
    client::{SrpClient, SrpClientVerifier},
    groups::G_2048,
};

const GSA_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";
const APPLE_ROOT: &[u8] = include_bytes!("./apple_root.der");

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequestBody {
    #[serde(rename = "A2k")]
    a_pub: plist::Value,
    cpd: plist::Dictionary,
    #[serde(rename = "o")]
    operation: String,
    ps: Vec<String>,
    #[serde(rename = "u")]
    username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RequestHeader {
    #[serde(rename = "Version")]
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: InitRequestBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequestBody {
    #[serde(rename = "M1")]
    m: plist::Value,
    cpd: plist::Dictionary,
    c: String,
    #[serde(rename = "o")]
    operation: String,
    #[serde(rename = "u")]
    username: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: ChallengeRequestBody,
}

#[derive(Clone)]
pub struct AppleAccount {
    //TODO: move this to omnisette
    pub anisette: AnisetteData,
    // pub spd:  Option<plist::Dictionary>,
    //mutable spd
    pub spd: Option<plist::Dictionary>,
    client: Client,
}
//Just make it return a custom enum, with LoggedIn(account: AppleAccount) or Needs2FA(FinishLoginDel: fn(i32) -> TFAResponse)
pub enum LoginResponse {
    LoggedIn(AppleAccount),
    // NeedsSMS2FASent(Send2FAToDevices),
    NeedsDevice2FA(),
    Needs2FAVerification(),
    NeedsLogin(),
    Failed(Error),
}

// impl Send2FAToDevices {
//     pub fn send_2fa_to_devices(&self) -> LoginResponse {
//         self.account.send_2fa_to_devices().unwrap()
//     }
// }

// impl Verify2FA {
//     pub fn verify_2fa(&self, tfa_code: &str) -> LoginResponse {
//         self.account.verify_2fa(&tfa_code).unwrap()
//     }
// }

impl AppleAccount {
    pub fn new(anisette: AnisetteData) -> Self {
        let client = ClientBuilder::new()
            .add_root_certificate(Certificate::from_der(APPLE_ROOT).unwrap())
            .http1_title_case_headers()
            .connection_verbose(true)
            .build()
            .unwrap();

        AppleAccount {
            client,
            anisette,
            spd: None,
        }
    }

    /// # Arguments
    ///
    /// * `appleid_closure` - A closure that takes no arguments and returns a tuple of the Apple ID and password
    /// * `tfa_closure` - A closure that takes no arguments and returns the 2FA code
    /// * `anisette` - AnisetteData
    /// # Examples
    ///
    /// ```
    /// use icloud_auth::AppleAccount;
    /// use omnisette::AnisetteData;
    ///
    /// let anisette = AnisetteData::new();
    /// let account = AppleAccount::login(
    ///   || ("test@waffle.me", "password")
    ///   || "123123",
    ///  anisette
    /// );
    /// ```
    /// Note: You would not provide the 2FA code like this, you would have to actually ask input for it.
    //TODO: add login_with_anisette and login, where login autodetcts anisette
    pub fn login<F: Fn() -> (String, String), G: Fn() -> String>(
        appleid_closure: F,
        tfa_closure: G,
        anisette: AnisetteData,
    ) -> Result<AppleAccount, Error> {
        let mut _self = AppleAccount::new(anisette);
        let (username, password) = appleid_closure();
        let mut response = _self.login_email_pass(username.clone(), password.clone())?;
        loop {
            match response {
                LoginResponse::NeedsDevice2FA() => response = _self.send_2fa_to_devices().unwrap(),
                LoginResponse::Needs2FAVerification() => {
                    response = _self.verify_2fa(tfa_closure()).unwrap()
                }
                LoginResponse::NeedsLogin() => {
                    response = _self.login_email_pass(username.clone(), password.clone())?
                }
                LoginResponse::LoggedIn(ac) => return Ok(ac),
                LoginResponse::Failed(e) => return Err(e),
            }
        }
    }

    pub fn login_email_pass(
        &mut self,
        username: String,
        password: String,
    ) -> Result<LoginResponse, Error> {
        let parse_response = |res: Result<Response, reqwest::Error>| {
            let res: plist::Dictionary =
                plist::from_bytes(res.unwrap().text().unwrap().as_bytes()).unwrap();
            let res: plist::Value = res.get("Response").unwrap().to_owned();
            match res {
                plist::Value::Dictionary(dict) => dict,
                _ => panic!("Invalid response"),
            }
        };

        let srp_client = SrpClient::<Sha256>::new(&G_2048);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );
        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.insert(
            "User-Agent",
            HeaderValue::from_str("akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0").unwrap(),
        );
        gsa_headers.insert(
            "X-MMe-Client-Info",
            HeaderValue::from_str(&self.anisette.x_mme_client_info).unwrap(),
        );

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let body = InitRequestBody {
            a_pub: plist::Value::Data(a_pub),
            cpd: self.anisette.to_cpd(),
            operation: "init".to_string(),
            ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
            username: username.clone(),
        };

        let packet = InitRequest {
            header: header.clone(),
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet).unwrap();
        let buffer = String::from_utf8(buffer).unwrap();

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send();

        let res = parse_response(res);
        let err_check = Self::check_error(&res);
        if err_check.is_err() {
            return Err(err_check.err().unwrap());
        }
        println!("{:?}", res);
        let salt = res.get("s").unwrap().as_data().unwrap();
        let b_pub = res.get("B").unwrap().as_data().unwrap();
        let iters = res.get("i").unwrap().as_signed_integer().unwrap();
        let c = res.get("c").unwrap().as_string().unwrap();

        let mut password_hasher = sha2::Sha256::new();
        password_hasher.update(&password.as_bytes());
        let hashed_password = password_hasher.finalize();

        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(
            &hashed_password,
            salt,
            iters as u32,
            &mut password_buf,
        );

        let verifier: SrpClientVerifier<Sha256> = srp_client
            .process_reply(&a, &username.as_bytes(), &password_buf, salt, b_pub)
            .unwrap();

        let m = verifier.proof();

        let body = ChallengeRequestBody {
            m: plist::Value::Data(m.to_vec()),
            c: c.to_string(),
            cpd: self.anisette.to_cpd(),
            operation: "complete".to_string(),
            username,
        };

        let packet = ChallengeRequest {
            header,
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet).unwrap();
        let buffer = String::from_utf8(buffer).unwrap();

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send();

        let res = parse_response(res);
        let err_check = Self::check_error(&res);
        if err_check.is_err() {
            return Err(err_check.err().unwrap());
        }
        println!("{:?}", res);
        let m2 = res.get("M2").unwrap().as_data().unwrap();
        verifier.verify_server(&m2).unwrap();

        let spd = res.get("spd").unwrap().as_data().unwrap();
        let decrypted_spd = Self::decrypt_cbc(&verifier, spd);
        let decoded_spd: plist::Dictionary = plist::from_bytes(&decrypted_spd).unwrap();

        let status = res.get("Status").unwrap().as_dictionary().unwrap();

        let needs2fa = match status.get("au") {
            Some(plist::Value::String(s)) => {
                if s == "trustedDeviceSecondaryAuth" {
                    println!("Trusted device authentication required");
                    true
                } else {
                    println!("Unknown auth value {}", s);
                    // PHONE AUTH WILL CAUSE ERRORS!
                    false
                }
            }
            _ => false,
        };

        self.spd = Some(decoded_spd);

        if needs2fa {
            return Ok(LoginResponse::NeedsDevice2FA());
        }

        Ok(LoginResponse::LoggedIn(self.clone().to_owned()))
    }

    fn create_session_key(usr: &SrpClientVerifier<Sha256>, name: &str) -> Vec<u8> {
        Hmac::<Sha256>::new_from_slice(&usr.key())
            .unwrap()
            .chain_update(name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec()
    }

    fn decrypt_cbc(usr: &SrpClientVerifier<Sha256>, data: &[u8]) -> Vec<u8> {
        let extra_data_key = Self::create_session_key(usr, "extra data key:");
        let extra_data_iv = Self::create_session_key(usr, "extra data iv:");
        let extra_data_iv = &extra_data_iv[..16];

        cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)
            .unwrap()
            .decrypt_padded_vec_mut::<Pkcs7>(&data)
            .unwrap()
    }

    pub fn send_2fa_to_devices(&self) -> Result<LoginResponse, crate::Error> {
        let headers = self.build_2fa_headers();

        let res = self
            .client
            .get("https://gsa.apple.com/auth/verify/trusteddevice")
            .headers(headers)
            .send();

        if !res.as_ref().unwrap().status().is_success() {
            return Err(Error::AuthSrp);
        }

        return Ok(LoginResponse::Needs2FAVerification());
    }
    pub fn verify_2fa(&self, code: String) -> Result<LoginResponse, Error> {
        let headers = self.build_2fa_headers();
        println!("Recieved code: {}", code);
        let res = self
            .client
            .get("https://gsa.apple.com/grandslam/GsService2/validate")
            .headers(headers)
            .header(
                HeaderName::from_str("security-code").unwrap(),
                HeaderValue::from_str(&code).unwrap(),
            )
            .send();

        let res: plist::Dictionary =
            plist::from_bytes(res.unwrap().text().unwrap().as_bytes()).unwrap();

        let err_check = Self::check_error(&res);
        if err_check.is_err() {
            return Err(err_check.err().unwrap());
        }

        Ok(LoginResponse::LoggedIn(self.clone()))
    }

    fn check_error(res: &plist::Dictionary) -> Result<(), Error> {
        let res = match res.get("Status") {
            Some(plist::Value::Dictionary(d)) => d,
            _ => &res,
        };

        if res.get("ec").unwrap().as_signed_integer().unwrap() != 0 {
            return Err(Error::AuthSrpWithMessage(
                res.get("ec").unwrap().as_signed_integer().unwrap(),
                res.get("em").unwrap().as_string().unwrap().to_owned(),
            ));
        }

        Ok(())
    }

    fn build_2fa_headers(&self) -> HeaderMap {
        let spd = self.spd.as_ref().unwrap();
        let dsid = spd.get("adsid").unwrap().as_string().unwrap();
        let token = spd.get("GsIdmsToken").unwrap().as_string().unwrap();

        let identity_token = base64::encode(format!("{}:{}", dsid, token));

        let mut headers = HeaderMap::new();
        self.anisette.headers_dict(true).iter().for_each(|(k, v)| {
            headers.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v.as_string().unwrap()).unwrap(),
            );
        });

        headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );
        headers.insert("Accept", HeaderValue::from_str("text/x-xml-plist").unwrap());
        headers.insert("User-Agent", HeaderValue::from_str("Xcode").unwrap());
        headers.insert("Accept-Language", HeaderValue::from_str("en-us").unwrap());
        headers.append(
            "X-Apple-Identity-Token",
            HeaderValue::from_str(&identity_token).unwrap(),
        );
        headers.insert(
            "X-Apple-App-Info",
            HeaderValue::from_str("com.apple.gs.xcode.auth").unwrap(),
        );

        headers.insert(
            "X-Xcode-Version",
            HeaderValue::from_str("11.2 (11B41)").unwrap(),
        );

        headers.insert(
            "Loc",
            HeaderValue::from_str(&self.anisette.x_apple_locale).unwrap(),
        );

        headers
    }
}
