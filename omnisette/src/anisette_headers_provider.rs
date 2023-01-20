use anyhow::{Result};
use std::collections::HashMap;

pub trait AnisetteHeadersProvider {
    fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>>;
}

impl dyn AnisetteHeadersProvider {
    // Normalizes headers to ensure that all the required headers are given.
    pub fn get_authentication_headers(&mut self) -> Result<HashMap<String, String>> {
        let mut headers = self.get_anisette_headers()?;

        if let Some(client_info) = headers.remove("X-MMe-Client-Info") {
            headers.insert("X-Mme-Client-Info".to_string(), client_info);
        }

        Ok(headers)
    }
}
