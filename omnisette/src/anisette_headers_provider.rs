use anyhow::Result;
use std::collections::HashMap;

#[cfg_attr(feature = "async", async_trait::async_trait(?Send))]
pub trait AnisetteHeadersProvider {
    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn get_anisette_headers(&mut self, skip_provisioning: bool) -> Result<HashMap<String, String>>;

    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn get_authentication_headers(&mut self) -> Result<HashMap<String, String>> {
        let headers = self.get_anisette_headers(false).await?;
        Ok(self.normalize_headers(headers))
    }

    /// Normalizes headers to ensure that all the required headers are given.
    fn normalize_headers(&mut self, mut headers: HashMap<String, String>) -> HashMap<String, String> {
        if let Some(client_info) = headers.remove("X-MMe-Client-Info") {
            headers.insert("X-Mme-Client-Info".to_string(), client_info);
        }

        headers
    }
}
