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
    fn get_anisette_headers(&self) -> HashMap<String, String> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use crate::adi_proxy::ADIProxyAnisetteProvider;
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::FALLBACK_ANISETTE_URL;
    use crate::remote_anisette::RemoteAnisetteProvider;

    #[test]
    fn fetch_anisette_remote() -> Result<()> {
        RemoteAnisetteProvider::new(FALLBACK_ANISETTE_URL).get_anisette_headers();
        Ok(())
    }
}
