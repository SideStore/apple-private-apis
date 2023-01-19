// Jackson Coxson

use serde::{Deserialize, Serialize};

use crate::Error;

pub const SIDELOADLY_ANISETTE: &str = "https://ani.f1sh.me/";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnisetteData {
    #[serde(rename(deserialize = "X-Apple-I-Client-Time"))]
    pub x_apple_i_client_time: String,
    #[serde(rename(deserialize = "X-Apple-I-MD"))]
    pub x_apple_i_md: String,
    #[serde(rename(deserialize = "X-Apple-I-MD-LU"))]
    pub x_apple_i_md_lu: String,
    #[serde(rename(deserialize = "X-Apple-I-MD-M"))]
    pub x_apple_i_md_m: String,
    #[serde(rename(deserialize = "X-Apple-I-MD-RINFO"))]
    pub x_apple_i_md_rinfo: String,
    #[serde(rename(deserialize = "X-Apple-I-SRL-NO"))]
    pub x_apple_i_srl_no: String,
    #[serde(rename(deserialize = "X-Apple-I-TimeZone"))]
    pub x_apple_i_timezone: String,
    #[serde(rename(deserialize = "X-Apple-Locale"))]
    pub x_apple_locale: String,
    #[serde(rename(deserialize = "X-MMe-Client-Info"))]
    pub x_mme_client_info: String,
    #[serde(rename(deserialize = "X-Mme-Device-Id"))]
    pub x_mme_device_id: String,
}

impl AnisetteData {
    /// Fetches the data at an anisette server
    pub fn from_url(url: impl Into<String>) -> Result<Self, crate::Error> {
        let body = match ureq::get(&url.into()).call() {
            Ok(b) => match b.into_string() {
                Ok(b) => b,
                Err(_) => {
                    return Err(Error::HttpRequest);
                }
            },
            Err(_) => {
                return Err(Error::HttpRequest);
            }
        };

        let body = match serde_json::from_str::<AnisetteData>(&body) {
            Ok(b) => b,
            Err(_) => return Err(Error::Parse),
        };

        Ok(body)
    }

    pub fn to_cpd(&self) -> plist::Dictionary {
        let mut cpd = plist::Dictionary::new();
        cpd.insert(
            "X-Apple-I-Client-Time".to_owned(),
            plist::Value::String(self.x_apple_i_client_time.clone()),
        );
        cpd.insert(
            "X-Apple-I-MD".to_owned(),
            plist::Value::String(self.x_apple_i_md.clone()),
        );
        cpd.insert(
            "X-Apple-I-MD-LU".to_owned(),
            plist::Value::String(self.x_apple_i_md_lu.clone()),
        );
        cpd.insert(
            "X-Apple-I-MD-M".to_owned(),
            plist::Value::String(self.x_apple_i_md_m.clone()),
        );

        let rinfo = self.x_apple_i_md_rinfo.parse::<u32>().unwrap();
        cpd.insert(
            "X-Apple-I-MD-RINFO".to_owned(),
            plist::Value::Integer(rinfo.into()),
        );
        cpd.insert(
            "X-Apple-I-SRL-NO".to_owned(),
            plist::Value::String(self.x_apple_i_srl_no.clone()),
        );
        cpd.insert(
            "X-Apple-I-TimeZone".to_owned(),
            plist::Value::String(self.x_apple_i_timezone.clone()),
        );
        cpd.insert(
            "X-Apple-Locale".to_owned(),
            plist::Value::String(self.x_apple_locale.clone()),
        );
        cpd.insert(
            "X-Mme-Device-Id".to_owned(),
            plist::Value::String(self.x_mme_device_id.clone()),
        );
        cpd.insert("bootstrap".to_owned(), plist::Value::Boolean(true));
        cpd.insert("icscrec".to_owned(), plist::Value::Boolean(true));
        cpd.insert("loc".to_owned(), plist::Value::String("en_GB".to_owned()));
        cpd.insert("pbe".to_owned(), plist::Value::Boolean(false));
        cpd.insert("prkgen".to_owned(), plist::Value::Boolean(true));
        cpd.insert("svct".to_owned(), plist::Value::String("iCloud".to_owned()));

        cpd
    }
}
