use std::str::FromStr;

// use crate::anisette::AnisetteData;
use crate::{anisette::AnisetteData, Error};
use aes::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use omnisette::AnisetteConfiguration;
use reqwest::{
    Client, ClientBuilder, Response,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokenRequestBody {
    app: Vec<String>,
    c: plist::Value,
    cpd: plist::Dictionary,
    #[serde(rename = "o")]
    operation: String,
    t: String,
    u: String,
    checksum: plist::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokenRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: AuthTokenRequestBody,
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

#[derive(Clone)]
pub struct AppToken {
    pub app_tokens: plist::Dictionary,
    pub auth_token: String,
    pub app: String,
}
//Just make it return a custom enum, with LoggedIn(account: AppleAccount) or Needs2FA(FinishLoginDel: fn(i32) -> TFAResponse)
pub enum LoginResponse {
    LoggedIn,
    // NeedsSMS2FASent(Send2FAToDevices),
    NeedsDevice2FA,
    Needs2FAVerification,
    NeedsSMS2FA,
    NeedsSMS2FAVerification(VerifyBody),
    NeedsExtraStep(String),
    NeedsLogin,
    Failed(Error),
}

#[derive(Serialize)]
struct VerifyCode {
    code: String,
}

#[derive(Serialize)]
struct PhoneNumber {
    id: u32
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyBody {
    phone_number: PhoneNumber,
    mode: String,
    security_code: Option<VerifyCode>
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedPhoneNumber {
    pub number_with_dial_code: String,
    pub last_two_digits: String,
    pub push_mode: String,
    pub id: u32
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtras {
    pub trusted_phone_numbers: Vec<TrustedPhoneNumber>,
    pub recovery_url: Option<String>,
    pub cant_use_phone_number_url: Option<String>,
    pub dont_have_access_url: Option<String>,
    pub recovery_web_url: Option<String>,
    pub repair_phone_number_url: Option<String>,
    pub repair_phone_number_web_url: Option<String>,
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

async fn parse_response(res: Result<Response, reqwest::Error>) -> Result<plist::Dictionary, crate::Error> {
    let res = res?.text().await?;
    let res: plist::Dictionary = plist::from_bytes(res.as_bytes())?;
    let res: plist::Value = res.get("Response").unwrap().to_owned();
    match res {
        plist::Value::Dictionary(dict) => Ok(dict),
        _ => Err(crate::Error::Parse),
    }
}

impl AppleAccount {
    pub async fn new(config: AnisetteConfiguration) -> Result<Self, crate::Error> {
        let anisette = AnisetteData::new(config).await?;
        Ok(Self::new_with_anisette(anisette)?)
    }

    pub fn new_with_anisette(anisette: AnisetteData) -> Result<Self, crate::Error> {
        let client = ClientBuilder::new()
            .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
            .http1_title_case_headers()
            .connection_verbose(true)
            .build()?;

        Ok(AppleAccount {
            client,
            anisette,
            spd: None,
        })
    }

    pub async fn login(
        appleid_closure: impl Fn() -> (String, String),
        tfa_closure: impl Fn() -> String,
        config: AnisetteConfiguration,
    ) -> Result<AppleAccount, Error> {
        let anisette = AnisetteData::new(config).await?;
        AppleAccount::login_with_anisette(appleid_closure, tfa_closure, anisette).await
    }

    pub async fn get_app_token(&self, app_name: &str) -> Result<AppToken, Error> {
        let spd = self.spd.as_ref().unwrap();
        // println!("spd: {:#?}", spd);
        let dsid = spd.get("adsid").unwrap().as_string().unwrap();
        let auth_token = spd.get("GsIdmsToken").unwrap().as_string().unwrap();

        let sk = spd.get("sk").unwrap().as_data().unwrap();
        let c = spd.get("c").unwrap().as_data().unwrap();
        println!("adsid: {}", dsid);
        println!("GsIdmsToken: {}", auth_token);
        // println!("spd: {:#?}", spd);
        println!("sk: {:#?}", sk);
        println!("c: {:#?}", c);

        let checksum = Self::create_checksum(&sk.to_vec(), dsid, app_name);

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
            HeaderValue::from_str(&self.anisette.get_header("x-mme-client-info")?).unwrap(),
        );

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let body = AuthTokenRequestBody {
            cpd: self.anisette.to_plist(true, false, false),
            app: vec![app_name.to_string()],
            c: plist::Value::Data(c.to_vec()),
            operation: "apptokens".to_owned(),
            t: auth_token.to_string(),
            u: dsid.to_string(),
            checksum: plist::Value::Data(checksum),
        };

        let packet = AuthTokenRequest {
            header: header.clone(),
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        println!("{:?}", gsa_headers.clone());
        println!("{:?}", buffer);

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await;
        let res = parse_response(res).await?;
        let err_check = Self::check_error(&res);
        if err_check.is_err() {
            return Err(err_check.err().unwrap());
        }
        println!("{:?}", res);
        todo!()
    }

    fn create_checksum(session_key: &Vec<u8>, dsid: &str, app_name: &str) -> Vec<u8> {
        Hmac::<Sha256>::new_from_slice(&session_key)
            .unwrap()
            .chain_update("apptokens".as_bytes())
            .chain_update(dsid.as_bytes())
            .chain_update(app_name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec()
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
    pub async fn login_with_anisette<F: Fn() -> (String, String), G: Fn() -> String>(
        appleid_closure: F,
        tfa_closure: G,
        anisette: AnisetteData,
    ) -> Result<AppleAccount, Error> {
        let mut _self = AppleAccount::new_with_anisette(anisette)?;
        let (username, password) = appleid_closure();
        let mut response = _self.login_email_pass(username.clone(), password.clone()).await?;
        loop {
            match response {
                LoginResponse::NeedsDevice2FA => response = _self.send_2fa_to_devices().await?,
                LoginResponse::Needs2FAVerification => {
                    response = _self.verify_2fa(tfa_closure()).await?
                }
                LoginResponse::NeedsSMS2FA => {
                    response = _self.send_sms_2fa_to_devices(1).await?
                }
                LoginResponse::NeedsSMS2FAVerification(body) => {
                    response = _self.verify_sms_2fa(tfa_closure(), body).await?
                }
                LoginResponse::NeedsLogin => {
                    response = _self.login_email_pass(username.clone(), password.clone()).await?
                }
                LoginResponse::LoggedIn => return Ok(_self),
                LoginResponse::Failed(e) => return Err(e),
                LoginResponse::NeedsExtraStep(step) => return Err(Error::ExtraStep(step))
            }
        }
    }

    pub fn get_pet(&self) -> String {
        self.spd.as_ref().unwrap().get("t").unwrap().as_dictionary().unwrap().get("com.apple.gs.idms.pet")
            .unwrap().as_dictionary().unwrap().get("token").unwrap().as_string().unwrap().to_string()
    }

    pub async fn login_email_pass(
        &mut self,
        username: String,
        password: String,
    ) -> Result<LoginResponse, Error> {
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
            HeaderValue::from_str(&self.anisette.get_header("x-mme-client-info")?).unwrap(),
        );

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let body = InitRequestBody {
            a_pub: plist::Value::Data(a_pub),
            cpd: self.anisette.to_plist(true, false, false),
            operation: "init".to_string(),
            ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
            username: username.clone(),
        };

        let packet = InitRequest {
            header: header.clone(),
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        // println!("{:?}", gsa_headers.clone());
        // println!("{:?}", buffer);

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await;

        let res = parse_response(res).await?;
        let err_check = Self::check_error(&res);
        if err_check.is_err() {
            return Err(err_check.err().unwrap());
        }
        // println!("{:?}", res);
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
            cpd: self.anisette.to_plist(true, false, false),
            operation: "complete".to_string(),
            username,
        };

        let packet = ChallengeRequest {
            header,
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await;

        let res = parse_response(res).await?;
        let err_check = Self::check_error(&res);
        if err_check.is_err() {
            return Err(err_check.err().unwrap());
        }
        // println!("{:?}", res);
        let m2 = res.get("M2").unwrap().as_data().unwrap();
        verifier.verify_server(&m2).unwrap();

        let spd = res.get("spd").unwrap().as_data().unwrap();
        let decrypted_spd = Self::decrypt_cbc(&verifier, spd);
        let decoded_spd: plist::Dictionary = plist::from_bytes(&decrypted_spd).unwrap();

        let status = res.get("Status").unwrap().as_dictionary().unwrap();

        self.spd = Some(decoded_spd);

        if let Some(plist::Value::String(s)) = status.get("au") {
            return match s.as_str() {
                "trustedDeviceSecondaryAuth" => Ok(LoginResponse::NeedsDevice2FA),
                "secondaryAuth" => Ok(LoginResponse::NeedsSMS2FA),
                _unk => Ok(LoginResponse::NeedsExtraStep(_unk.to_string()))
            }
        }

        Ok(LoginResponse::LoggedIn)
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

    pub async fn send_2fa_to_devices(&self) -> Result<LoginResponse, crate::Error> {
        let headers = self.build_2fa_headers(false);

        let res = self
            .client
            .get("https://gsa.apple.com/auth/verify/trusteddevice")
            .headers(headers)
            .send().await?;

        if !res.status().is_success() {
            return Err(Error::AuthSrp);
        }

        return Ok(LoginResponse::Needs2FAVerification);
    }

    pub async fn send_sms_2fa_to_devices(&self, phone_id: u32) -> Result<LoginResponse, crate::Error> {
        let headers = self.build_2fa_headers(true);

        let body = VerifyBody {
            phone_number: PhoneNumber {
                id: phone_id
            },
            mode: "sms".to_string(),
            security_code: None
        };

        let res = self
            .client
            .put("https://gsa.apple.com/auth/verify/phone/")
            .headers(headers)
            .json(&body)
            .send().await?;

        if !res.status().is_success() {
            return Err(Error::AuthSrp);
        }

        return Ok(LoginResponse::NeedsSMS2FAVerification(body));
    }

    pub async fn get_auth_extras(&self) -> Result<AuthenticationExtras, Error> {
        let headers = self.build_2fa_headers(true);

        Ok(self.client
            .get("https://gsa.apple.com/auth")
            .headers(headers)
            .header("Accept", "application/json")
            .send().await?
            .json::<AuthenticationExtras>().await?)
    }

    pub async fn verify_2fa(&self, code: String) -> Result<LoginResponse, Error> {
        let headers = self.build_2fa_headers(false);
        // println!("Recieved code: {}", code);
        let res = self
            .client
            .get("https://gsa.apple.com/grandslam/GsService2/validate")
            .headers(headers)
            .header(
                HeaderName::from_str("security-code").unwrap(),
                HeaderValue::from_str(&code).unwrap(),
            )
            .send().await?;

        let res: plist::Dictionary =
            plist::from_bytes(res.text().await?.as_bytes())?;

        Self::check_error(&res)?;

        Ok(LoginResponse::NeedsLogin)
    }

    pub async fn verify_sms_2fa(&self, code: String, mut body: VerifyBody) -> Result<LoginResponse, Error> {
        let headers = self.build_2fa_headers(true);
        // println!("Recieved code: {}", code);

        body.security_code = Some(VerifyCode { code });

        let res = self
            .client
            .post("https://gsa.apple.com/auth/verify/phone/securitycode")
            .headers(headers)
            .json(&body)
            .send().await?;

        if res.status() != 200 {
            return Err(Error::AuthSrp);
        }

        Ok(LoginResponse::NeedsLogin)
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

    pub fn build_2fa_headers(&self, sms: bool) -> HeaderMap {
        let spd = self.spd.as_ref().unwrap();
        let dsid = spd.get("adsid").unwrap().as_string().unwrap();
        let token = spd.get("GsIdmsToken").unwrap().as_string().unwrap();

        let identity_token = base64::encode(format!("{}:{}", dsid, token));

        let mut headers = HeaderMap::new();
        self.anisette
            .generate_headers(false, true, true)
            .iter()
            .for_each(|(k, v)| {
                headers.append(
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            });

        if !sms {
            headers.insert(
                "Content-Type",
                HeaderValue::from_str("text/x-xml-plist").unwrap(),
            );
            headers.insert("Accept", HeaderValue::from_str("text/x-xml-plist").unwrap());
        }
        headers.insert("User-Agent", HeaderValue::from_str("Xcode").unwrap());
        headers.insert("Accept-Language", HeaderValue::from_str("en-us").unwrap());
        headers.append(
            "X-Apple-Identity-Token",
            HeaderValue::from_str(&identity_token).unwrap(),
        );

        headers.insert(
            "Loc",
            HeaderValue::from_str(&self.anisette.get_header("x-apple-locale").unwrap()).unwrap(),
        );

        headers
    }
}
