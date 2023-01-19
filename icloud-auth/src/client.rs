use crate::anisette::AnisetteData;
use crate::Error;
use aes::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use srp::{
    client::{SrpClient, SrpClientVerifier},
    groups::G_2048,
};
use std::sync::Arc;
use ureq::AgentBuilder;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

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
    pub anisette: AnisetteData,
    pub spd: Option<plist::Dictionary>,
}
//Just make it return a custom enum, with LoggedIn(account: AppleAccount) or Needs2FA(FinishLoginDel: fn(i32) -> TFAResponse)
pub enum LoginResponse {
    LoggedIn(AppleAccount),
    // NeedsSMS2FASent(Send2FAToDevices),
    NeedsDevice2FA(Send2FAToDevices),
    Needs2FAVerification(Verify2FA),
    Failed(Error),
}

//Send2FAToDevices and Verify2FA are just functions that take the same arguments as the original functions, but return a LoginResponse
//This way, you can just call the function and get a LoginResponse, and you don't have to worry about the state of the AppleAccount
//You can also just make them methods on AppleAccount, but I think this is cleaner
pub struct Send2FAToDevices {
    pub account: AppleAccount,
    pub spd: plist::Dictionary,
}
pub struct Verify2FA {
    pub account: AppleAccount,
    pub spd: plist::Dictionary,
}

impl Send2FAToDevices {
    pub fn send_2fa_to_devices(&self) -> LoginResponse {
        let mut client = self.account.clone();
        let response = client.send_2fa_to_devices();
        if response.is_ok() {
            LoginResponse::Needs2FAVerification(Verify2FA {
                account: client,
                spd: self.spd.clone(),
            })
        } else {
            LoginResponse::Failed(Error::AuthSrp)
        }
    }
}

impl Verify2FA {
    pub fn verify_2fa(&self, tfa_code: &str) -> LoginResponse {
        let client = self.account.clone();
        let response = client.verify_2fa(tfa_code);
        if response.is_ok() {
            LoginResponse::LoggedIn(client)
        } else {
            LoginResponse::Failed(Error::AuthSrp)
        }
    }
}

impl AppleAccount {
    pub fn new(anisette: AnisetteData) -> Self {
        AppleAccount {
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
    pub fn login<F: Fn() -> (String, String), G: Fn() -> String>(
        appleid_closure: F,
        tfa_closure: G,
        anisette: AnisetteData,
    ) -> Result<LoginResponse, Error> {
        let mut _self = AppleAccount {
            anisette,
            spd: None,
        };
        let (username, password) = appleid_closure();
        let mut response = _self.login_email_pass(username, password)?;
        loop {
            match response {
                LoginResponse::NeedsDevice2FA(cb) => response = cb.send_2fa_to_devices(),
                LoginResponse::Needs2FAVerification(cb) => response = cb.verify_2fa(&tfa_closure()),
                LoginResponse::LoggedIn(_) => return Ok(response),
                LoginResponse::Failed(e) => return Err(e),
            }
        }
    }

    pub fn login_email_pass(
        &mut self,
        username: String,
        password: String,
    ) -> Result<LoginResponse, Error> {
        let client = SrpClient::<Sha256>::new(&G_2048);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = client.compute_public_ephemeral(&a);

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
        println!("Body: {buffer}");

        let mut store = RootCertStore::empty();
        store.add_parsable_certificates(&[APPLE_ROOT.to_vec()]);
        let rustls_cli = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(store)
            .with_no_client_auth();
        let agent = AgentBuilder::new().tls_config(Arc::new(rustls_cli)).build();
        let res = agent
            .post(GSA_ENDPOINT)
            .set("Content-Type", "text/x-xml-plist")
            .set("Accept", "*/*")
            .set("User-Agent", "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0")
            .set("X-MMe-Client-Info", &self.anisette.x_mme_client_info)
            .send_string(&buffer)
            .unwrap();

        let res = res.into_string().unwrap();

        println!("{res}");

        let res: plist::Dictionary = plist::from_bytes(res.as_bytes()).unwrap();
        let res: plist::Value = res.get("Response").unwrap().to_owned();
        let res = match res {
            plist::Value::Dictionary(dict) => dict,
            _ => panic!("Invalid response"),
        };
        let salt = res.get("s").unwrap().as_data().unwrap();
        println!("Salt (base64): {}", base64::encode(salt));
        let b_pub = res.get("B").unwrap().as_data().unwrap();
        let iters = res.get("i").unwrap().as_signed_integer().unwrap();
        println!("Iterations: {}", iters);
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

        let verifier: SrpClientVerifier<Sha256> = client
            .process_reply(&a, &username.as_bytes(), &password_buf, salt, b_pub)
            .unwrap();

        let m = verifier.proof();
        println!("M: {:?}", m);

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
        println!("Body: {buffer}");

        let res = agent
            .post(GSA_ENDPOINT)
            .set("Content-Type", "text/x-xml-plist")
            .set("Accept", "*/*")
            .set("User-Agent", "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0")
            .set("X-MMe-Client-Info", &self.anisette.x_mme_client_info)
            .send_string(&buffer)
            .unwrap();

        let res = res.into_string().unwrap();

        println!("{res}");

        let res: plist::Dictionary = plist::from_bytes(res.as_bytes()).unwrap();
        let res: plist::Value = res.get("Response").unwrap().to_owned();
        let res = match res {
            plist::Value::Dictionary(dict) => dict,
            _ => panic!("Invalid response"),
        };

        let m2 = res.get("M2").unwrap().as_data().unwrap();
        println!("M2: {:?}", m2);
        verifier.verify_server(&m2).unwrap();

        print!("Success!");
        println!("shared key {:?}", base64::encode(verifier.key()));

        let spd = res.get("spd").unwrap().as_data().unwrap();
        let decrypted_spd = Self::decrypt_cbc(&verifier, spd);
        let decoded_spd: plist::Dictionary = plist::from_bytes(&decrypted_spd).unwrap();

        let status = res.get("Status").unwrap().as_dictionary().unwrap();

        let needs2FA = match status.get("au") {
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

        // if needs 2fa, return enum needs2fa

        if needs2FA {
            return Ok(LoginResponse::NeedsDevice2FA(Send2FAToDevices {
                account: self.clone(),
                spd: decoded_spd,
            }));
        }

        Ok(LoginResponse::LoggedIn(self.clone()))
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

    pub fn send_2fa_to_devices(&self) -> Result<(), Error> {
        todo!()
    }
    pub fn verify_2fa(&self, code: &str) -> Result<(), Error> {
        todo!()
    }
}
