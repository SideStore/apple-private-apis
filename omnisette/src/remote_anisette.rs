use anyhow::Result;
use std::collections::HashMap;
use crate::anisette_headers_provider::AnisetteHeadersProvider;

pub struct RemoteAnisetteProvider {
    url: String
}

impl RemoteAnisetteProvider {
    pub fn new(url: &str) -> RemoteAnisetteProvider {
        RemoteAnisetteProvider {
            url: url.to_string()
        }
    }
}

impl AnisetteHeadersProvider for RemoteAnisetteProvider {
    fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>> {
        Ok(reqwest::blocking::get(&self.url)?.json()?)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use crate::adi_proxy::ADIProxyAnisetteProvider;
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::DEFAULT_ANISETTE_URL;
    use crate::remote_anisette::RemoteAnisetteProvider;

    #[test]
    fn fetch_anisette_remote() -> Result<()> {
        let mut provider = RemoteAnisetteProvider::new(DEFAULT_ANISETTE_URL);
        println!("Remote headers: {:?}", (&mut provider as &mut dyn AnisetteHeadersProvider).get_authentication_headers()?);
        Ok(())
    }
}
