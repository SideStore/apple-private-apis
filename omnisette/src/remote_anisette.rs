use crate::{anisette_headers_provider::AnisetteHeadersProvider, AnisetteError};
#[cfg(not(feature = "async"))]
use reqwest::blocking::get;
#[cfg(feature = "async")]
use reqwest::get;
use std::collections::HashMap;

pub struct RemoteAnisetteProvider {
    url: String,
}

impl RemoteAnisetteProvider {
    pub fn new(url: String) -> RemoteAnisetteProvider {
        RemoteAnisetteProvider { url }
    }
}

#[cfg_attr(feature = "async", async_trait::async_trait)]
impl AnisetteHeadersProvider for RemoteAnisetteProvider {
    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn get_anisette_headers(
        &mut self,
        _skip_provisioning: bool,
    ) -> Result<HashMap<String, String>, AnisetteError> {
        Ok(get(&self.url).await?.json().await?)
    }
}

#[cfg(all(test, not(feature = "async")))]
mod tests {
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::remote_anisette::RemoteAnisetteProvider;
    use crate::DEFAULT_ANISETTE_URL;
    use log::info;

    #[test]
    fn fetch_anisette_remote() -> Result<(), AnisetteError> {
        crate::tests::init_logger();

        let mut provider = RemoteAnisetteProvider::new(DEFAULT_ANISETTE_URL.to_string());
        info!(
            "Remote headers: {:?}",
            (&mut provider as &mut dyn AnisetteHeadersProvider).get_authentication_headers()?
        );
        Ok(())
    }
}
