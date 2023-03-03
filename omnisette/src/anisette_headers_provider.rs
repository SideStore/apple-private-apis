use anyhow::Result;
use std::collections::HashMap;

#[cfg_attr(feature = "async", async_trait::async_trait(?Send))]
pub trait AnisetteHeadersProvider {
    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>>;

    // Normalizes headers to ensure that all the required headers are given.
    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn get_authentication_headers(&mut self) -> Result<HashMap<String, String>> {
        let mut headers = self.get_anisette_headers().await?;

        if let Some(client_info) = headers.remove("X-MMe-Client-Info") {
            headers.insert("X-Mme-Client-Info".to_string(), client_info);
        }

        Ok(headers)
    }
}
