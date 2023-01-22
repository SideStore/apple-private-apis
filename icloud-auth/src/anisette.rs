use crate::Error;
use omnisette::{AnisetteConfiguration, AnisetteHeaders};
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
}

impl AnisetteData {
    /// Fetches the data at an anisette server
    pub fn new() -> Result<Self, crate::Error> {
        let mut base_headers = match AnisetteHeaders::get_anisette_headers_provider(
            AnisetteConfiguration::new()
                .set_configuration_path(PathBuf::new().join("anisette_test"))
                .set_anisette_url("https://ani.f1sh.me".to_string()),
        ) {
            Ok(mut b) => match b.get_authentication_headers() {
                Ok(b) => b,
                Err(_) => return Err(Error::ErrorGettingAnisette),
            },
            Err(_) => {
                return Err(Error::HttpRequest);
            }
        };

        Ok(AnisetteData { base_headers })
    }

    pub fn generate_headers(
        &self,
        cpd: bool,
        client_info: bool,
        app_info: bool,
    ) -> HashMap<String, String> {
        let mut headers = self.base_headers.clone();
        let old_client_info = headers.remove("X-Mme-Client-Info");
        if client_info {
            let client_info = match old_client_info {
                Some(v) => {
                    let temp = v.as_str();

                    temp.replace(
                        temp.split('<').nth(3).unwrap().split('>').nth(0).unwrap(),
                        "com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)",
                    )
                }
                None => {
                    return headers;
                }
            };
            headers.insert("X-Mme-Client-Info".to_owned(), client_info.to_owned());
        }

        if app_info {
            headers.insert(
                "X-Apple-App-Info".to_owned(),
                "com.apple.gs.xcode.auth".to_owned(),
            );
            headers.insert("X-Xcode-Version".to_owned(), "11.2 (11B41)".to_owned());
        }

        if cpd {
            headers.insert("bootstrap".to_owned(), "true".to_owned());
            headers.insert("icscrec".to_owned(), "true".to_owned());
            headers.insert("loc".to_owned(), "en_GB".to_owned());
            headers.insert("pbe".to_owned(), "false".to_owned());
            headers.insert("prkgen".to_owned(), "true".to_owned());
            headers.insert("svct".to_owned(), "iCloud".to_owned());
        }

        headers
    }

    pub fn to_plist(&self, cpd: bool, client_info: bool, app_info: bool) -> plist::Dictionary {
        let mut plist = plist::Dictionary::new();
        for (key, value) in self.generate_headers(cpd, client_info, app_info).iter() {
            plist.insert(key.to_owned(), plist::Value::String(value.to_owned()));
        }

        plist
    }

    pub fn get_header(&self, header: &str) -> Result<String, Error> {
        let headers = self
            .generate_headers(true, true, true)
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect::<HashMap<String, String>>();

        match headers.get(&header.to_lowercase()) {
            Some(v) => Ok(v.to_string()),
            None => Err(Error::Parse),
        }
    }
}
